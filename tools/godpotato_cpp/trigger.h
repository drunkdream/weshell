#pragma once

#include "common.h"

class GodPotatoContext;

// Port of GodPotatoUnmarshalTrigger: builds a STANDARD OBJREF for a real local
// COM object, rewrites its DUALSTRINGARRAY to point at 127.0.0.1, and calls
// CoUnmarshalInterface so rpcss resolves the OXID through our hooked UseProtseq.
int RunTrigger(GodPotatoContext& context, void** unmarshaled);
