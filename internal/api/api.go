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
	})
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
		var in targetInput
		if !decodeJSON(w, r, &in) {
			return
		}
		t, err := in.normalize()
		if err != nil {
			writeJSON(w, http.StatusBadRequest, newError(err.Error()))
			return
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

	res := shell.Execute(r.Context(), shell.ExecOptions{
		TargetURL: t.URL,
		Param:     t.Param,
		Method:    t.Method,
		Type:      t.ShellType,
		Command:   in.Command,
		Timeout:   s.cfg.Timeout,
	})

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
	return store.Target{
		Name:      name,
		URL:       rawURL,
		ShellType: in.ShellType,
		Param:     param,
		Method:    method,
		Note:      strings.TrimSpace(in.Note),
	}, nil
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
