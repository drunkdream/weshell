// Package api 提供 weshell 管理端的 HTTP 接口。
//
// 接口挂载在 /api 前缀下，以 JSON 交互。每次命令执行都会留下一条审计记录，
// 便于教学复盘与责任追溯。
package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"weshell/internal/shell"
	"weshell/internal/store"
)

// maxRequestBytes 限制接口请求体大小。
const maxRequestBytes = 1 << 20 // 1 MiB

// 单台主机端口扫描的每批端口数。分批目的是让「单次靶机脚本执行」控制在靶机自身
// 脚本超时内（ASP 默认 Server.ScriptTimeout≈90s、PHP 默认 max_execution_time=30s），
// 同时保证单次 weshell→靶机请求耗时尽量 ≤30s。每端口最坏等待约 2s
// （ASP 见 vbsPortScan/aspPortScan 的 SetTimeouts，PHP 见 fsockopen 的第 5 参），
// 故 12 端口/批 ≈24s，落在 30s 预算内。
const scanBatchPorts = 12

// 内网多主机扫描每批的主机数。多主机走 HostScan（先存活探测再扫端口），单台主机
// 最坏约 23s（探测+完整端口，见各模板超时）。每批 1 台即可保证单次请求 ≤30s；
// 若愿接受更长的单请求，可酌情调大，但密集/全在线网段可能超出 30s 预算。
const scanHostChunk = 1

// splitPortList 把逗号分隔的端口串按每 n 个切成多批，返回每批的逗号串。
// n<=0 时整体作为一批返回；空串返回空切片。
func splitPortList(s string, n int) []string {
	parts := strings.Split(s, ",")
	if n <= 0 {
		return []string{s}
	}
	out := make([]string, 0, (len(parts)+n-1)/n)
	for i := 0; i < len(parts); i += n {
		end := i + n
		if end > len(parts) {
			end = len(parts)
		}
		out = append(out, strings.Join(parts[i:end], ","))
	}
	return out
}

// chunkStrings 把字符串切片按每 n 个切成多批。n<=0 时退化为每批 1 个。
func chunkStrings(ss []string, n int) [][]string {
	if n <= 0 {
		n = 1
	}
	out := make([][]string, 0, (len(ss)+n-1)/n)
	for i := 0; i < len(ss); i += n {
		end := i + n
		if end > len(ss) {
			end = len(ss)
		}
		out = append(out, ss[i:end])
	}
	return out
}

// probeMark 是新增靶标时用于探测 shell 是否工作的回显标记。
const probeMark = "__weshell_probe__"

// Config 是接口层的运行参数。
type Config struct {
	// Timeout 为单次命令执行的超时时间。
	Timeout time.Duration
	// Token 非空时，接口要求调用方提供匹配的访问令牌。
	Token string
	// LabURL 是本机的默认靶机地址（对应启动参数 -lab）。
	// 只用于前端常驻展示，不参与任何请求。
	LabURL string
}

// Server 承载 /api 下的全部路由。
type Server struct {
	store  *store.Store
	logger *log.Logger
	cfg    Config
	mux    *http.ServeMux
}

// New 构造接口服务，返回值可直接挂到 /api/ 前缀下。
func New(logger *log.Logger, st *store.Store, cfg Config) *Server {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	s := &Server{
		store:  st,
		logger: logger,
		cfg:    cfg,
		mux:    http.NewServeMux(),
	}
	s.mux.HandleFunc("/api/config", s.wrap(s.handleConfig))
	s.mux.HandleFunc("/api/types", s.wrap(s.handleTypes))
	s.mux.HandleFunc("/api/targets", s.wrap(s.handleTargets))
	s.mux.HandleFunc("/api/targets/", s.wrap(s.handleTargetItem))
	s.mux.HandleFunc("/api/settings", s.wrap(s.handleSettings))
	s.mux.HandleFunc("/api/history", s.wrap(s.handleHistory))
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// wrap 串联令牌校验与请求体大小限制。
func (s *Server) wrap(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			writeJSON(w, http.StatusUnauthorized, newError("未提供有效访问令牌"))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
		h(w, r)
	}
}

// authorized 校验调用方令牌。未配置令牌时放行。
func (s *Server) authorized(r *http.Request) bool {
	if s.cfg.Token == "" {
		return true
	}
	got := r.Header.Get("X-Auth-Token")
	if got == "" {
		got = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.Token)) == 1
}

// ---------- 路由实现 ----------

// handleConfig 返回前端展示所需的运行期配置。
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, newError("只支持 GET"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"labUrl":         s.cfg.LabURL,
		"timeoutSeconds": int(s.cfg.Timeout / time.Second),
		"userAgent":      s.store.GetSettings().UserAgent,
	})
}

// handleSettings 处理 /api/settings：GET 读取全局设置，PUT 更新。
// 目前仅含 userAgent：空串=默认标识，"random"=每次随机，其余为固定 UA。
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.store.GetSettings())
	case http.MethodPut:
		var in struct {
			UserAgent string `json:"userAgent"`
		}
		if !decodeJSON(w, r, &in) {
			return
		}
		if err := s.store.SetSettings(store.GlobalSettings{UserAgent: strings.TrimSpace(in.UserAgent)}); err != nil {
			writeJSON(w, http.StatusInternalServerError, newError(err.Error()))
			return
		}
		s.logger.Printf("更新全局设置 userAgent=%q", in.UserAgent)
		writeJSON(w, http.StatusOK, s.store.GetSettings())
	default:
		writeJSON(w, http.StatusMethodNotAllowed, newError("只支持 GET / PUT"))
	}
}

// handleTypes 返回支持的连接类型清单，含靶机侧样本，用于前端下拉框与教学对照。
func (s *Server) handleTypes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, newError("只支持 GET"))
		return
	}
	writeJSON(w, http.StatusOK, shell.Types())
}

// handleTargets 处理集合：GET 列出，POST 新增。
func (s *Server) handleTargets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.store.List())
	case http.MethodPost:
		var in targetInput
		if !decodeJSON(w, r, &in) {
			return
		}
		t, err := in.normalize()
		if err != nil {
			writeJSON(w, http.StatusBadRequest, newError(err.Error()))
			return
		}

		// 不再强制探测：保存靶标不依赖靶机当前是否可达，录入永远成功。
		// 连通性验证交给列表项的「测试连接」按钮（POST /api/targets/{id}/verify），
		// 由用户主动触发，避免靶机暂时不通时反而无法登记信息。
		t.Verified = false

		created, err := s.store.Add(t)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, newError(err.Error()))
			return
		}
		s.logger.Printf("新增靶标 %s <%s>", created.Name, created.URL)
		writeJSON(w, http.StatusCreated, created)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, newError("只支持 GET / POST"))
	}
}

// handleTargetItem 处理 /api/targets/{id}[/exec]。
func (s *Server) handleTargetItem(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/targets/"), "/")
	parts := strings.Split(rest, "/")
	id := parts[0]
	if id == "" {
		writeJSON(w, http.StatusBadRequest, newError("缺少靶标 ID"))
		return
	}

	// 文件管理：/api/targets/{id}/fs/{op}
	if len(parts) >= 2 && parts[1] == "fs" {
		s.handleFS(w, r, id, parts[2:])
		return
	}

	// 系统监控：/api/targets/{id}/sys/info
	if len(parts) >= 2 && parts[1] == "sys" {
		s.handleSys(w, r, id)
		return
	}

	// 进程管理：/api/targets/{id}/proc/{list|kill}
	if len(parts) >= 2 && parts[1] == "proc" {
		if len(parts) >= 3 && parts[2] == "kill" {
			s.handleProcKill(w, r, id)
			return
		}
		s.handleProc(w, r, id)
		return
	}

	// 报文探查：/api/targets/{id}/headers（返回请求头 / 响应头，供教学观察真实流量）
	if len(parts) >= 2 && parts[1] == "headers" {
		s.handleHeaders(w, r, id)
		return
	}

	// 监听端口：/api/targets/{id}/ports
	if len(parts) >= 2 && parts[1] == "ports" {
		s.handlePorts(w, r, id)
		return
	}

	// 端口扫描：/api/targets/{id}/scan?host=&ports=
	if len(parts) >= 2 && parts[1] == "scan" {
		s.handleScan(w, r, id)
		return
	}

	// PHP 环境能力研判：/api/targets/{id}/phpinfo
	if len(parts) >= 2 && parts[1] == "phpinfo" {
		s.handlePhpInfo(w, r, id)
		return
	}

	// 测试连接：/api/targets/{id}/verify（主动验证 shell 是否可达且能回显，不阻塞保存）
	if len(parts) >= 2 && parts[1] == "verify" && r.Method == http.MethodPost {
		s.handleVerify(w, r, id)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if len(parts) != 1 {
			writeJSON(w, http.StatusNotFound, newError("接口不存在"))
			return
		}
		t, ok := s.store.Get(id)
		if !ok {
			writeJSON(w, http.StatusNotFound, newError("靶标不存在"))
			return
		}
		writeJSON(w, http.StatusOK, t)

	case http.MethodPut:
		if len(parts) != 1 {
			writeJSON(w, http.StatusNotFound, newError("接口不存在"))
			return
		}
		old, ok := s.store.Get(id)
		if !ok {
			writeJSON(w, http.StatusNotFound, newError("靶标不存在"))
			return
		}
		var in targetInput
		if !decodeJSON(w, r, &in) {
			return
		}
		t, err := in.normalize()
		if err != nil {
			writeJSON(w, http.StatusBadRequest, newError(err.Error()))
			return
		}
		// 不再强制探测：URL 变化只重置验证状态，真实连通性由「测试连接」主动验证。
		t.Verified = old.Verified
		if t.URL != old.URL {
			t.Verified = false
		}
		updated, err := s.store.Update(id, t)
		if err != nil {
			writeJSON(w, http.StatusNotFound, newError(err.Error()))
			return
		}
		s.logger.Printf("更新靶标 %s <%s>", updated.Name, updated.URL)
		writeJSON(w, http.StatusOK, updated)

	case http.MethodDelete:
		if len(parts) != 1 {
			writeJSON(w, http.StatusNotFound, newError("接口不存在"))
			return
		}
		if err := s.store.Delete(id); err != nil {
			writeJSON(w, http.StatusNotFound, newError(err.Error()))
			return
		}
		s.logger.Printf("删除靶标 %s", id)
		writeJSON(w, http.StatusOK, map[string]string{"deleted": id})

	case http.MethodPost:
		if len(parts) == 2 && parts[1] == "exec" {
			s.execCommand(w, r, id)
			return
		}
		writeJSON(w, http.StatusNotFound, newError("接口不存在"))

	default:
		writeJSON(w, http.StatusMethodNotAllowed, newError("不支持的请求方法"))
	}
}

// execInput 是命令执行的请求体。
type execInput struct {
	Command string `json:"command"`
}

// fsInput 是文件写入/删除操作的请求体。
type fsInput struct {
	Path   string `json:"path"`
	Base64 string `json:"base64"`
}

// handleFS 处理 /api/targets/{id}/fs/{op} 下的文件管理操作。
// op ∈ {list, read, download, write, upload, delete}：
//   - list/read/download 用 GET + path 查询参数
//   - write/upload/delete 用 POST + JSON 体 {path, base64?}
//
// 仅 php-eval / asp 类型靶机支持（php-cmd 无法稳妥地做结构化文件读写）。
func (s *Server) handleFS(w http.ResponseWriter, r *http.Request, id string, sub []string) {
	if len(sub) == 0 || sub[0] == "" {
		writeJSON(w, http.StatusNotFound, newError("文件操作不存在"))
		return
	}
	op := sub[0]
	t, ok := s.store.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, newError("靶标不存在"))
		return
	}
	if t.ShellType != shell.TypeEval && t.ShellType != shell.TypeAsp && t.ShellType != shell.TypeAspVbs {
		writeJSON(w, http.StatusBadRequest, newError("文件管理仅支持 php-eval / asp 类型靶机"))
		return
	}
	o := s.execOpts(t)
	qx := r.URL.Query()

	switch r.Method {
	case http.MethodGet:
		switch op {
		case "list":
			dir := qx.Get("path")
			if dir == "" {
				dir = "."
			}
			entries, resolved, err := shell.FsList(r.Context(), o, dir)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, newError(err.Error()))
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"path": resolved, "entries": entries})
		case "read", "download":
			path := qx.Get("path")
			if path == "" {
				writeJSON(w, http.StatusBadRequest, newError("缺少 path 参数"))
				return
			}
			f, err := shell.FsRead(r.Context(), o, path)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, newError(err.Error()))
				return
			}
			writeJSON(w, http.StatusOK, f)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, newError("不支持的文件读取操作: "+op))
		}

	case http.MethodPost:
		var in fsInput
		if !decodeJSON(w, r, &in) {
			return
		}
		switch op {
		case "write", "upload":
			if in.Path == "" {
				writeJSON(w, http.StatusBadRequest, newError("缺少 path"))
				return
			}
			if err := shell.FsWrite(r.Context(), o, in.Path, in.Base64); err != nil {
				writeJSON(w, http.StatusBadRequest, newError(err.Error()))
				return
			}
			s.auditFS(id, "write", in.Path, true)
			writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		case "delete":
			if in.Path == "" {
				writeJSON(w, http.StatusBadRequest, newError("缺少 path"))
				return
			}
			if err := shell.FsDelete(r.Context(), o, in.Path); err != nil {
				writeJSON(w, http.StatusBadRequest, newError(err.Error()))
				return
			}
			s.auditFS(id, "delete", in.Path, true)
			writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		default:
			writeJSON(w, http.StatusMethodNotAllowed, newError("不支持的文件写入操作: "+op))
		}

	default:
		writeJSON(w, http.StatusMethodNotAllowed, newError("不支持的请求方法"))
	}
}

// handleSys 处理 /api/targets/{id}/sys/info：读取靶机系统资源概览。
// 仅 php-eval / asp 类型靶机支持（需要提交 PHP / JScript 采集代码）。
func (s *Server) handleSys(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, newError("只支持 GET"))
		return
	}
	t, ok := s.store.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, newError("靶标不存在"))
		return
	}
	if t.ShellType != shell.TypeEval && t.ShellType != shell.TypeAsp && t.ShellType != shell.TypeAspVbs {
		writeJSON(w, http.StatusBadRequest, newError("系统监控仅支持 php-eval / asp 类型靶机"))
		return
	}
	o := s.execOpts(t)
	info, err := shell.Monitor(r.Context(), o)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, newError(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// handleProc 处理 /api/targets/{id}/proc/list：读取靶机进程列表（含 PPID）。
// 仅 php-eval / asp 类型靶机支持（需要提交 PHP / JScript 采集代码）。
func (s *Server) handleProc(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, newError("只支持 GET"))
		return
	}
	t, ok := s.store.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, newError("靶标不存在"))
		return
	}
	if t.ShellType != shell.TypeEval && t.ShellType != shell.TypeAsp && t.ShellType != shell.TypeAspVbs {
		writeJSON(w, http.StatusBadRequest, newError("进程管理仅支持 php-eval / asp 类型靶机"))
		return
	}
	o := s.execOpts(t)
	info, err := shell.ProcList(r.Context(), o)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, newError(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// handleProcKill 处理 /api/targets/{id}/proc/kill：向靶机进程发送信号结束它。
// php-eval 走 posix_kill / kill，asp 走 taskkill；POST 入参 {pid, signal}，signal 缺省为 15 (SIGTERM)。
func (s *Server) handleProcKill(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, newError("只支持 POST"))
		return
	}
	t, ok := s.store.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, newError("靶标不存在"))
		return
	}
	if t.ShellType != shell.TypeEval && t.ShellType != shell.TypeAsp && t.ShellType != shell.TypeAspVbs {
		writeJSON(w, http.StatusBadRequest, newError("进程管理仅支持 php-eval / asp 类型靶机"))
		return
	}
	var in struct {
		PID    string `json:"pid"`
		Signal int    `json:"signal"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.PID == "" {
		writeJSON(w, http.StatusBadRequest, newError("缺少 pid"))
		return
	}
	sig := in.Signal
	if sig == 0 {
		sig = 15
	}
	o := s.execOpts(t)
	res, err := shell.ProcKill(r.Context(), o, in.PID, sig)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, newError(err.Error()))
		return
	}
	ok2, _ := res["ok"].(bool)
	s.store.TouchLastUsed(id)
	s.store.AppendRecord(store.CommandRecord{
		TargetID: id,
		Command:  "proc:kill " + in.PID + " sig " + strconv.Itoa(sig),
		OK:       ok2,
	})
	writeJSON(w, http.StatusOK, res)
}

// handlePorts 处理 /api/targets/{id}/ports：读取靶机监听端口列表（含 PID/进程名）。
// 仅 php-eval / asp 类型靶机支持（需要提交 PHP / JScript 采集代码）。
func (s *Server) handlePorts(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, newError("只支持 GET"))
		return
	}
	t, ok := s.store.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, newError("靶标不存在"))
		return
	}
	if t.ShellType != shell.TypeEval && t.ShellType != shell.TypeAsp && t.ShellType != shell.TypeAspVbs {
		writeJSON(w, http.StatusBadRequest, newError("端口监听仅支持 php-eval / asp 类型靶机"))
		return
	}
	o := s.execOpts(t)
	info, err := shell.PortsList(r.Context(), o)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, newError(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// handleScan 处理 /api/targets/{id}/scan?host=&ports=：对目标主机做 TCP 端口扫描。
// 仅 php-eval / asp 类型靶机支持（依赖靶机侧 fsockopen / WinHttpRequest）。
// host 为目标地址（IP 或域名），ports 为端口规格（如 "80"、"1-1000"、"21,22,80,443"），
// 缺省时扫描一组常见端口。
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, newError("只支持 GET"))
		return
	}
	t, ok := s.store.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, newError("靶标不存在"))
		return
	}
	if t.ShellType != shell.TypeEval && t.ShellType != shell.TypeAsp && t.ShellType != shell.TypeAspVbs {
		writeJSON(w, http.StatusBadRequest, newError("端口扫描仅支持 php-eval / asp 类型靶机"))
		return
	}
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	if host == "" {
		writeJSON(w, http.StatusBadRequest, newError("缺少目标主机 host 参数"))
		return
	}
	ports := strings.TrimSpace(r.URL.Query().Get("ports"))
	if ports == "" {
		ports = "21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,8080"
	}
	hosts, err := shell.ExpandHosts(host)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, newError(err.Error()))
		return
	}
	o := s.execOpts(t)
	if len(hosts) == 1 {
		// 单台主机：把端口拆成小批逐批下发靶机扫描并合并结果。
		// 拆批不是为了防 Go 侧超时，而是让「单次靶机脚本执行」控制在靶机自身脚本超时内
		// （ASP 默认 Server.ScriptTimeout≈90s、PHP 默认 max_execution_time=30s），
		// 否则大端口列表会被靶机自己掐掉返回 500，Go 侧把超时放再大也没用。
		expanded, err := shell.ExpandPorts(ports)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, newError(err.Error()))
			return
		}
		batches := splitPortList(expanded, scanBatchPorts)
		merged := make([]any, 0, 64)
		var totalElapsed float64
		for _, b := range batches {
			pc := len(strings.Split(b, ","))
			to := time.Duration(pc)*3500*time.Millisecond + 10*time.Second
			if to > 30*time.Minute {
				to = 30 * time.Minute
			}
			o.Timeout = to
			info, err := shell.PortScan(r.Context(), o, hosts[0], b)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, newError(err.Error()))
				return
			}
			if ok, _ := info["ok"].(bool); !ok {
				writeJSON(w, http.StatusBadRequest, newError(fmt.Sprintf("%v", info["error"])))
				return
			}
			if ps, ok := info["ports"].([]any); ok {
				merged = append(merged, ps...)
			}
			if e, ok := info["elapsed"].(float64); ok {
				totalElapsed += e
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"host":    hosts[0],
			"ports":   merged,
			"elapsed": totalElapsed,
		})
		return
	}
	// 多台主机：按 scanHostChunk 分小批，每批在靶机上完成「存活探测 + 端口扫描」后返回并合并。
	// 分小批是为了让每次 weshell→靶机请求耗时尽量 ≤30s（单台主机最坏约 23s），
	// 避免一次性全量请求被靶机脚本超时（ASP≈90s / PHP=30s）或自身 30s 预算掐断。
	probeCount := len(strings.Split(shell.ScanProbePorts, ","))
	portCount := len(strings.Split(ports, ","))
	perHost := time.Duration(probeCount)*600*time.Millisecond + time.Duration(portCount)*1200*time.Millisecond
	chunks := chunkStrings(hosts, scanHostChunk)
	mergedHosts := make([]any, 0, len(hosts))
	var totalElapsed float64
	for _, ch := range chunks {
		cto := perHost*time.Duration(len(ch)) + 20*time.Second
		if cto > 30*time.Minute {
			cto = 30 * time.Minute
		}
		if cto < o.Timeout {
			cto = o.Timeout
		}
		o.Timeout = cto
		info, err := shell.HostScan(r.Context(), o, ch, ports, shell.ScanProbePorts)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, newError(err.Error()))
			return
		}
		if ok, _ := info["ok"].(bool); !ok {
			writeJSON(w, http.StatusBadRequest, newError(fmt.Sprintf("%v", info["error"])))
			return
		}
		if hs, ok := info["hosts"].([]any); ok {
			mergedHosts = append(mergedHosts, hs...)
		}
		if e, ok := info["elapsed"].(float64); ok {
			totalElapsed += e
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"hosts":   mergedHosts,
		"elapsed": totalElapsed,
	})
}

// php-eval 返回 PHP 环境信息（版本 / 禁用函数 / open_basedir 等）；
// asp 返回 ASP 环境信息（脚本引擎 / 关键 COM 组件可用性等）。两者均仅各自类型支持。
func (s *Server) handlePhpInfo(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, newError("只支持 GET"))
		return
	}
	t, ok := s.store.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, newError("靶标不存在"))
		return
	}
	if t.ShellType != shell.TypeEval && t.ShellType != shell.TypeAsp && t.ShellType != shell.TypeAspVbs {
		writeJSON(w, http.StatusBadRequest, newError("环境能力仅支持 php-eval / asp 类型靶机"))
		return
	}
	o := s.execOpts(t)
	var info map[string]any
	var err error
	if t.ShellType == shell.TypeAsp || t.ShellType == shell.TypeAspVbs {
		info, err = shell.AspEnv(r.Context(), o)
	} else {
		info, err = shell.PhpInfo(r.Context(), o)
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, newError(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// handleHeaders 处理 /api/targets/{id}/headers：向靶标发一次探测请求，
// 返回管理端实际构造的请求头与靶机返回的响应头。三种连接类型通用，不依赖靶机侧脚本能力。
func (s *Server) handleHeaders(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, newError("只支持 GET"))
		return
	}
	t, ok := s.store.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, newError("靶标不存在"))
		return
	}
	o := s.execOpts(t)
	res := shell.Inspect(r.Context(), o)
	s.store.TouchLastUsed(id)
	writeJSON(w, http.StatusOK, res)
}

// handleVerify 处理 /api/targets/{id}/verify：主动验证 shell 是否可达且能正常回显。
// 与保存解耦——保存永远成功，连通性验证由用户点「测试连接」触发，结果持久化到靶标上。
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, newError("只支持 POST"))
		return
	}
	t, ok := s.store.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, newError("靶标不存在"))
		return
	}
	probe := shell.Execute(r.Context(), s.execOpts(t).WithCommand("echo "+probeMark))
	verified := probe.OK && strings.Contains(probe.Output, probeMark)

	// 持久化验证结果，便于列表展示是否已验证、以及教学时区分「登记了但没连上」。
	t.Verified = verified
	if _, err := s.store.Update(id, t); err != nil {
		s.logger.Printf("更新靶标 %s 验证状态失败: %v", id, err)
	}
	s.store.TouchLastUsed(id)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":        probe.OK,
		"verified":  verified,
		"status":    probe.Status,
		"latencyMs": probe.LatencyMS,
		"error":     probe.Error,
		"output":    probe.Output,
	})
}
func (s *Server) auditFS(id, op, path string, ok bool) {
	s.store.TouchLastUsed(id)
	s.store.AppendRecord(store.CommandRecord{
		TargetID: id,
		Command:  "fs:" + op + " " + path,
		OK:       ok,
	})
}

// execCommand 对靶标执行一次命令，记录审计日志，并把结果返回给前端。
func (s *Server) execCommand(w http.ResponseWriter, r *http.Request, id string) {
	t, ok := s.store.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, newError("靶标不存在"))
		return
	}
	var in execInput
	if !decodeJSON(w, r, &in) {
		return
	}

	// 审计日志先行落地：即便靶机无响应，也能留下「谁执行了什么」的痕迹。
	s.logger.Printf("执行命令 target=%s<%s> command=%q", t.Name, t.URL, truncate(in.Command, 300))

	res := shell.Execute(r.Context(), s.execOpts(t).WithCommand(in.Command))

	// 失败时单独打一行，避免「HTTP 200 + body 里 ok:false」把问题藏起来，
	// 否则只看访问日志会误以为一切正常。
	if !res.OK {
		s.logger.Printf("命令执行失败 target=%s<%s> command=%q error=%q latency=%dms",
			t.Name, t.URL, truncate(in.Command, 300), firstLine(res.Error), res.LatencyMS)
	}

	s.store.TouchLastUsed(id)
	s.store.AppendRecord(store.CommandRecord{
		TargetID:  id,
		Command:   in.Command,
		OK:        res.OK,
		LatencyMS: res.LatencyMS,
		Message:   firstLine(res.Error),
	})
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, newError("只支持 GET"))
		return
	}
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	writeJSON(w, http.StatusOK, s.store.History(limit))
}

// ---------- 入参与响应 ----------

// targetInput 是靶标的新增/更新入参。
type targetInput struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	ShellType string `json:"shellType"`
	Param     string `json:"param"`
	Method    string `json:"method"`
	Proxy     string `json:"proxy"`
	Note      string `json:"note"`
}

// normalize 校验并规范化入参。
func (in targetInput) normalize() (store.Target, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return store.Target{}, errors.New("靶标名称不能为空")
	}
	rawURL := strings.TrimSpace(in.URL)
	u, err := url.Parse(rawURL)
	if err != nil {
		return store.Target{}, fmt.Errorf("URL 无法解析: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return store.Target{}, errors.New("URL 必须以 http:// 或 https:// 开头")
	}
	if u.Host == "" {
		return store.Target{}, errors.New("URL 缺少主机名")
	}
	param := strings.TrimSpace(in.Param)
	if param == "" {
		return store.Target{}, errors.New("连接参数名不能为空")
	}
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	if method == "" {
		method = http.MethodPost
	}
	if method != http.MethodGet && method != http.MethodPost {
		return store.Target{}, errors.New("请求方法只能是 GET 或 POST")
	}
	if !shell.Valid(in.ShellType) {
		return store.Target{}, fmt.Errorf("未知的连接类型: %q", in.ShellType)
	}
	proxy := strings.TrimSpace(in.Proxy)
	if proxy != "" {
		if _, err := shell.ProxyURL(proxy); err != nil {
			return store.Target{}, err
		}
	}
	return store.Target{
		Name:      name,
		URL:       rawURL,
		ShellType: in.ShellType,
		Param:     param,
		Method:    method,
		Proxy:     proxy,
		Note:      strings.TrimSpace(in.Note),
	}, nil
}

// execOpts 由靶标信息与全局设置构造一次执行的 ExecOptions：自动带上该靶机的代理，
// 以及全局设置里的 User-Agent（默认 / 固定 / 随机）。
func (s *Server) execOpts(t store.Target) shell.ExecOptions {
	return shell.ExecOptions{
		TargetURL: t.URL,
		Param:     t.Param,
		Method:    t.Method,
		Type:      t.ShellType,
		Timeout:   s.cfg.Timeout,
		Proxy:     t.Proxy,
		UserAgent: s.store.GetSettings().UserAgent,
	}
}

// apiError 是统一的错误响应体。
type apiError struct {
	Error string `json:"error"`
	Time  string `json:"time"`
}

func newError(msg string) apiError {
	return apiError{Error: msg, Time: time.Now().Format(time.RFC3339)}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, newError("请求体 JSON 解析失败: "+err.Error()))
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("[weshell] 写出 JSON 响应失败: %v", err)
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "..."
}
