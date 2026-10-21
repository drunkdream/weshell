package shell

import (
	"strings"
	"testing"
)

// TestModCallVbsKeepsHandlerForCall 锁住 modCall 的错误策略：调用 wsh_mod 前后必须始终留在
// On Error Resume Next 之下，调用之后统一收口。
// 背景：wsh_mod 自身有两段没开 handler 的窗口（读 Session、InStr 预检），一旦在调用前
// On Error GoTo 0，这些窗口出错会逃逸成 HTTP 500，前端拿不到任何错误信息。
func TestModCallVbsKeepsHandlerForCall(t *testing.T) {
	a := aspShell{vbs: true}
	got := a.modCall("fs.list", a.encodeArgs(map[string]any{"dir": "."}))

	if strings.Contains(got, "On Error GoTo 0\nwsh_mod") {
		t.Fatalf("不得在调用 wsh_mod 前关闭错误处理（错误会逃逸成 HTTP 500）:\n%s", got)
	}
	// 不再重复 On Error Resume Next：重水合前缀已打开且不会关掉
	if strings.Contains(got, "On Error Resume Next") {
		t.Fatalf("modCall 不应重复 On Error Resume Next（重水合已建立）:\n%s", got)
	}
	call := `wsh_mod "fs.list", wadict`
	i := strings.Index(got, call)
	if i < 0 {
		t.Fatalf("缺少 wsh_mod 调用:\n%s", got)
	}
	if !strings.Contains(got[i:], `wsh_err("CALL_FAILED")`) {
		t.Fatalf("调用之后必须统一收口:\n%s", got)
	}
}

// TestBootDefinesWshErr 锁住错误格式化器在缓存机件里，且带上 Err.Description 与转义。
func TestBootDefinesWshErr(t *testing.T) {
	if !strings.Contains(wshAspBootstrapVBS, "Function wsh_err(tag)") {
		t.Fatalf("机件缺少 wsh_err 定义")
	}
	if !strings.Contains(wshAspBootstrapVBS, "Err.Description") {
		t.Fatalf("wsh_err 应带上 Err.Description")
	}
	if !strings.Contains(wshAspBootstrapVBS, vbsJSuf) {
		t.Fatalf("wsh_err 应复用 vbsJPre/vbsJSuf 转义")
	}
}

// TestBootSyntaxStaysInline 锁住 BOOT_SYNTAX 必须内联自足：它正是「机件本身坏了」的路径，
// 此时 wsh_err 尚未定义，调它只会得到空回显。
func TestBootSyntaxStaysInline(t *testing.T) {
	if !strings.Contains(wshAspRehydrateVBS, "BOOT_SYNTAX") {
		t.Fatalf("重水合应内联报 BOOT_SYNTAX:\n%s", wshAspRehydrateVBS)
	}
	if strings.Contains(wshAspRehydrateVBS, `wsh_err("BOOT_SYNTAX")`) {
		t.Fatalf("BOOT_SYNTAX 不得依赖 wsh_err（机件损坏时它尚未定义）:\n%s", wshAspRehydrateVBS)
	}
}

// TestModCallJSWrapsCall 锁住 JScript 侧同样用 try/catch 包住 wsh_mod 调用。
func TestModCallJSWrapsCall(t *testing.T) {
	j := aspShell{}
	got := j.modCall("fs.list", encodeArgsPacked(map[string]any{"dir": "."}))
	if !strings.HasPrefix(got, "try{") {
		t.Fatalf("JScript 侧应 try 包住 wsh_mod 调用:\n%s", got)
	}
	if !strings.Contains(got, "CALL_FAILED") {
		t.Fatalf("JScript 侧 catch 应回 CALL_FAILED:\n%s", got)
	}
}

// TestVbsJSONEscapeNewline 锁住换行必须转成 JSON 的 \n（两个字符）。
// 裸 Chr(10) 会让 Go 的 encoding/json 以 "invalid character '\n' in string literal"
// 拒绝整条回显，proc.kill 的 Trim(out) 多行输出与 CALL_FAILED 的错误描述都会踩到。
func TestVbsJSONEscapeNewline(t *testing.T) {
	if !strings.Contains(vbsJSuf, `vbCrLf, Chr(92) & "n"`) {
		t.Fatalf("vbsJSuf 必须把 vbCrLf 转成 \\n 两个字符:\n%s", vbsJSuf)
	}
}

// TestBootIsASCII 锁住机件源码必须纯 ASCII：它经 vbsStr 原样嵌入页面、不经过 cleanVbs，
// 非 ASCII 字节会被按 GBK 误解析而破坏 VBScript 词法。
func TestBootIsASCII(t *testing.T) {
	for name, s := range map[string]string{
		"wshAspBootstrapVBS": wshAspBootstrapVBS,
		"wshAspRehydrateVBS": wshAspRehydrateVBS,
	} {
		for i, r := range s {
			if r > 127 {
				t.Fatalf("%s 含非 ASCII 字符（偏移 %d）", name, i)
			}
		}
	}
}
