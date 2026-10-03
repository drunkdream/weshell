// Command weshell 是一个用于 CTF 靶场与安全教学的 Webshell 管理端。
//
// 设计边界：只实现靶标管理与「HTTP 通信 + 命令执行回显」。
// 不含流量加密/混淆/免杀/WAF 绕过，不含提权或后门植入能力。
// 使用前请确认目标靶机为你自有或已获得明确授权的环境。
package main

import (
	"embed"
	"errors"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"weshell/internal/api"
	"weshell/internal/store"
)

//go:embed web
var webAssets embed.FS

func main() {
	listen := flag.String("listen", "127.0.0.1:8848", "HTTP 监听地址")
	data := flag.String("data", "", "数据文件路径，默认 $HOME/.weshell/data.json")
	timeout := flag.Duration("timeout", 15*time.Second, "单次命令执行的超时时间")
	auth := flag.String("auth", "", "简易令牌；设置后前端需提供 X-Auth-Token 才能调用接口")
	lab := flag.String("lab", "", "本机靶机地址，前端常驻显示，例如 http://127.0.0.1:8081/shell.php")
	accessLog := flag.Bool("access-log", true, "是否打印每个 HTTP 请求的访问日志（默认开启）")
	flag.Parse()

	logger := log.New(os.Stdout, "[weshell] ", log.LstdFlags|log.LUTC)

	dataPath := *data
	if dataPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			logger.Fatalf("获取用户主目录失败: %v", err)
		}
		dataPath = filepath.Join(home, ".weshell", "data.json")
	}

	st, err := store.Open(dataPath)
	if err != nil {
		logger.Fatalf("加载数据失败: %v", err)
	}

	webRoot, err := fs.Sub(webAssets, "web")
	if err != nil {
		logger.Fatalf("挂载前端资源失败: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/", api.New(logger, st, api.Config{
		Timeout: *timeout,
		Token:   *auth,
		LabURL:  *lab,
	}))
	mux.Handle("/", http.FileServer(http.FS(webRoot)))

	handler := http.Handler(mux)
	if *accessLog {
		handler = withAccessLog(logger, mux)
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	logger.Printf("管理端已启动: http://%s", *listen)
	logger.Printf("数据文件: %s", dataPath)
	logger.Printf("请确认所有靶标均为你自有或已获授权的 CTF/教学靶机")
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Fatalf("服务异常退出: %v", err)
	}
}

// withAccessLog 打印每个 HTTP 请求的访问日志：来源、方法、路径、状态码与耗时。
//
// 命令执行另有单独的审计日志（见 internal/api），那里记录的是「谁对哪个靶机
// 执行了什么命令」，与这里的访问日志互补。
func withAccessLog(logger *log.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		logger.Printf("%s %s %s %d %s",
			clientIP(r), r.Method, r.URL.RequestURI(), rec.status,
			time.Since(start).Round(time.Millisecond))
	})
}

// statusRecorder 包住 ResponseWriter 以捕获实际写出的状态码。
type statusRecorder struct {
	http.ResponseWriter
	status int
	// written 用于兜底：若处理器从未显式调用 WriteHeader，则以 200 计。
	written bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.written {
		r.status = code
		r.written = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.written {
		r.written = true
	}
	return r.ResponseWriter.Write(b)
}

// clientIP 取客户端地址。优先信任反向代理传递的 X-Forwarded-For，
// 取不到时退回 TCP 远端地址（去掉端口号）。
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		return host[:i]
	}
	return host
}
