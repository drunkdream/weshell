#include "objref.h"

#include <cstring>

namespace gp {
namespace {

void WriteU16(std::vector<uint8_t>& b, uint16_t v) {
    b.push_back(static_cast<uint8_t>(v & 0xFF));
    b.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
}

void WriteU32(std::vector<uint8_t>& b, uint32_t v) {
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
}

void WriteU64(std::vector<uint8_t>& b, uint64_t v) {
    for (int i = 0; i < 8; ++i) b.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
}

void AppendUTF16LE(std::vector<uint8_t>& b, const std::string& s) {
    for (unsigned char c : s) {
        b.push_back(c);
        b.push_back(0);
    }
}

uint16_t ReadU16(const std::vector<uint8_t>& d, size_t off) {
    return static_cast<uint16_t>(d[off] | (d[off + 1] << 8));
}

uint32_t ReadU32(const std::vector<uint8_t>& d, size_t off) {
    return static_cast<uint32_t>(d[off]) |
           (static_cast<uint32_t>(d[off + 1]) << 8) |
           (static_cast<uint32_t>(d[off + 2]) << 16) |
           (static_cast<uint32_t>(d[off + 3]) << 24);
}

uint64_t ReadU64(const std::vector<uint8_t>& d, size_t off) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | d[off + i];
    return v;
}

}  // namespace

bool ParseObjRef(const std::vector<uint8_t>& data, ParsedObjRef& out) {
    if (data.size() < 24) return false;
    if (ReadU32(data, 0) != kObjRefSignature) return false;

    uint32_t flags = ReadU32(data, 4);
    memcpy(out.iid, data.data() + 8, 16);

    if ((flags & 1) == 0) {
        out.hasStandard = false;
        return true;
    }

    size_t off = 24;
    if (data.size() < off + 40) return false;

    out.standard.flags = ReadU32(data, off);
    out.standard.publicRefs = ReadU32(data, off + 4);
    out.standard.oxid = ReadU64(data, off + 8);
    out.standard.oid = ReadU64(data, off + 16);
    memcpy(out.standard.ipid, data.data() + off + 24, 16);
    out.hasStandard = true;
    return true;
}

std::vector<uint8_t> BuildObjRef(const uint8_t iid[16],
                                 const ObjRefStandard& standard,
                                 TowerProtocol tower,
                                 const std::string& networkAddress) {
    // STRINGBINDING: tower id + UTF-16 address + two NUL wchars
    // (same byte layout as the C# GodPotato BinaryWriter serializer).
    std::vector<uint8_t> stringBinding;
    WriteU16(stringBinding, static_cast<uint16_t>(tower));
    AppendUTF16LE(stringBinding, networkAddress);
    WriteU16(stringBinding, 0);
    WriteU16(stringBinding, 0);

    // SECURITYBINDING: authn svc, authz svc, empty principal, two NUL wchars.
    std::vector<uint8_t> securityBinding;
    WriteU16(securityBinding, 0x0a);
    WriteU16(securityBinding, 0xffff);
    WriteU16(securityBinding, 0);
    WriteU16(securityBinding, 0);

    uint16_t numEntries = static_cast<uint16_t>((stringBinding.size() + securityBinding.size()) / 2);
    uint16_t securityOffset = static_cast<uint16_t>(stringBinding.size() / 2);

    std::vector<uint8_t> out;
    out.reserve(24 + 40 + 4 + stringBinding.size() + securityBinding.size());

    WriteU32(out, kObjRefSignature);
    WriteU32(out, 1);  // OBJREF_STANDARD
    out.insert(out.end(), iid, iid + 16);

    WriteU32(out, standard.flags);
    WriteU32(out, standard.publicRefs);
    WriteU64(out, standard.oxid);
    WriteU64(out, standard.oid);
    out.insert(out.end(), standard.ipid, standard.ipid + 16);

    WriteU16(out, numEntries);
    WriteU16(out, securityOffset);
    out.insert(out.end(), stringBinding.begin(), stringBinding.end());
    out.insert(out.end(), securityBinding.begin(), securityBinding.end());
    return out;
}

}  // namespace gp
