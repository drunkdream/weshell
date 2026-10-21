#pragma once

#include "common.h"

namespace gp {

// Minimal in-memory IStream used to feed a crafted OBJREF to
// CoUnmarshalInterface.
class MemoryIStream : public IStream {
public:
    MemoryIStream(const void* data, size_t size);

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override;
    ULONG STDMETHODCALLTYPE AddRef() override;
    ULONG STDMETHODCALLTYPE Release() override;

    HRESULT STDMETHODCALLTYPE Read(void* pv, ULONG cb, ULONG* pcbRead) override;
    HRESULT STDMETHODCALLTYPE Write(const void* pv, ULONG cb, ULONG* pcbWritten) override;

    HRESULT STDMETHODCALLTYPE Seek(LARGE_INTEGER dlibMove, DWORD dwOrigin, ULARGE_INTEGER* plibNewPosition) override;
    HRESULT STDMETHODCALLTYPE SetSize(ULARGE_INTEGER libNewSize) override;
    HRESULT STDMETHODCALLTYPE CopyTo(IStream* pstm, ULARGE_INTEGER cb, ULARGE_INTEGER* pcbRead, ULARGE_INTEGER* pcbWritten) override;
    HRESULT STDMETHODCALLTYPE Commit(DWORD grfCommitFlags) override;
    HRESULT STDMETHODCALLTYPE Revert() override;
    HRESULT STDMETHODCALLTYPE LockRegion(ULARGE_INTEGER libOffset, ULARGE_INTEGER cb, DWORD dwLockType) override;
    HRESULT STDMETHODCALLTYPE UnlockRegion(ULARGE_INTEGER libOffset, ULARGE_INTEGER cb, DWORD dwLockType) override;
    HRESULT STDMETHODCALLTYPE Stat(STATSTG* pstatstg, DWORD grfStatFlag) override;
    HRESULT STDMETHODCALLTYPE Clone(IStream** ppstm) override;

private:
    ~MemoryIStream() = default;

    std::vector<uint8_t> data_;
    size_t position_ = 0;
    LONG refCount_ = 1;
};

}  // namespace gp
