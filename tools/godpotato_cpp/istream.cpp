#include "istream.h"

#include <algorithm>
#include <cstring>

namespace gp {

MemoryIStream::MemoryIStream(const void* data, size_t size) {
    if (data && size) {
        data_.assign(static_cast<const uint8_t*>(data), static_cast<const uint8_t*>(data) + size);
    }
}

HRESULT STDMETHODCALLTYPE MemoryIStream::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    if (riid == IID_IUnknown || riid == IID_IStream || riid == IID_ISequentialStream) {
        *ppv = static_cast<IStream*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

ULONG STDMETHODCALLTYPE MemoryIStream::AddRef() {
    return static_cast<ULONG>(InterlockedIncrement(&refCount_));
}

ULONG STDMETHODCALLTYPE MemoryIStream::Release() {
    LONG count = InterlockedDecrement(&refCount_);
    if (count == 0) delete this;
    return static_cast<ULONG>(count);
}

HRESULT STDMETHODCALLTYPE MemoryIStream::Read(void* pv, ULONG cb, ULONG* pcbRead) {
    if (!pv && cb) return STG_E_INVALIDPOINTER;
    size_t remaining = data_.size() - std::min(position_, data_.size());
    size_t count = std::min<size_t>(cb, remaining);
    if (count) memcpy(pv, data_.data() + position_, count);
    position_ += count;
    if (pcbRead) *pcbRead = static_cast<ULONG>(count);
    return count == cb ? S_OK : S_FALSE;
}

HRESULT STDMETHODCALLTYPE MemoryIStream::Write(const void* pv, ULONG cb, ULONG* pcbWritten) {
    if (!pv && cb) return STG_E_INVALIDPOINTER;
    if (position_ + cb > data_.size()) data_.resize(position_ + cb);
    if (cb) memcpy(data_.data() + position_, pv, cb);
    position_ += cb;
    if (pcbWritten) *pcbWritten = cb;
    return S_OK;
}

HRESULT STDMETHODCALLTYPE MemoryIStream::Seek(LARGE_INTEGER dlibMove, DWORD dwOrigin, ULARGE_INTEGER* plibNewPosition) {
    int64_t base = 0;
    switch (dwOrigin) {
        case STREAM_SEEK_SET: base = 0; break;
        case STREAM_SEEK_CUR: base = static_cast<int64_t>(position_); break;
        case STREAM_SEEK_END: base = static_cast<int64_t>(data_.size()); break;
        default: return STG_E_INVALIDFUNCTION;
    }
    int64_t next = base + dlibMove.QuadPart;
    if (next < 0) return STG_E_INVALIDFUNCTION;
    position_ = static_cast<size_t>(next);
    if (plibNewPosition) plibNewPosition->QuadPart = static_cast<ULONGLONG>(position_);
    return S_OK;
}

HRESULT STDMETHODCALLTYPE MemoryIStream::SetSize(ULARGE_INTEGER libNewSize) {
    data_.resize(static_cast<size_t>(libNewSize.QuadPart));
    return S_OK;
}

HRESULT STDMETHODCALLTYPE MemoryIStream::CopyTo(IStream* pstm, ULARGE_INTEGER cb, ULARGE_INTEGER* pcbRead, ULARGE_INTEGER* pcbWritten) {
    if (!pstm) return STG_E_INVALIDPOINTER;
    uint64_t remaining = data_.size() - std::min(position_, data_.size());
    uint64_t count = std::min<uint64_t>(cb.QuadPart, remaining);
    ULONG written = 0;
    HRESULT hr = pstm->Write(data_.data() + position_, static_cast<ULONG>(count), &written);
    position_ += written;
    if (pcbRead) pcbRead->QuadPart = written;
    if (pcbWritten) pcbWritten->QuadPart = written;
    return hr;
}

HRESULT STDMETHODCALLTYPE MemoryIStream::Commit(DWORD) {
    return S_OK;
}

HRESULT STDMETHODCALLTYPE MemoryIStream::Revert() {
    return E_NOTIMPL;
}

HRESULT STDMETHODCALLTYPE MemoryIStream::LockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD) {
    return STG_E_INVALIDFUNCTION;
}

HRESULT STDMETHODCALLTYPE MemoryIStream::UnlockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD) {
    return STG_E_INVALIDFUNCTION;
}

HRESULT STDMETHODCALLTYPE MemoryIStream::Stat(STATSTG* pstatstg, DWORD) {
    if (!pstatstg) return STG_E_INVALIDPOINTER;
    memset(pstatstg, 0, sizeof(*pstatstg));
    pstatstg->type = STGTY_STREAM;
    pstatstg->cbSize.QuadPart = data_.size();
    return S_OK;
}

HRESULT STDMETHODCALLTYPE MemoryIStream::Clone(IStream** ppstm) {
    if (!ppstm) return STG_E_INVALIDPOINTER;
    *ppstm = nullptr;
    return E_NOTIMPL;
}

}  // namespace gp
