#pragma once

#include "common.h"

namespace gp {

constexpr uint32_t kObjRefSignature = 0x574f454d;  // "MEOW"

enum class TowerProtocol : uint16_t {
    TCP = 0x07,
    NAMED_PIPE = 0x10,
};

struct ObjRefStandard {
    uint32_t flags = 0;
    uint32_t publicRefs = 0;
    uint64_t oxid = 0;
    uint64_t oid = 0;
    uint8_t ipid[16] = {};
};

struct ParsedObjRef {
    uint8_t iid[16] = {};
    bool hasStandard = false;
    ObjRefStandard standard;
};

bool ParseObjRef(const std::vector<uint8_t>& data, ParsedObjRef& out);

// Serializes a standard OBJREF whose DUALSTRINGARRAY holds a single string
// binding plus an unauthenticated security binding (authn 0xa / authz 0xffff).
std::vector<uint8_t> BuildObjRef(const uint8_t iid[16],
                                 const ObjRefStandard& standard,
                                 TowerProtocol tower,
                                 const std::string& networkAddress);

}  // namespace gp
