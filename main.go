// Command weshell 是一个用于 CTF 靶场与安全教学的 Webshell 管理端。
//
// 设计边界：只实现靶标管理与「HTTP 通信 + 命令执行回显」。
// 不含流量加密/混淆/免杀/WAF 绕过，不含后门植入能力。
// 内嵌 PrintSpoofer.exe 仅用于你自有或已获明确授权的 Windows 靶机，
// 通过 SeImpersonate / 命名管道冒充提权至 SYSTEM 的教学演示，使用前请确认目标授权状态。
package main

import (
	"embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"weshell/internal/api"
	"weshell/internal/shell"
	"weshell/internal/store"
)

//go:embed web
var webAssets embed.FS

//go:embed tools/printspoofer/PrintSpoofer.exe
var printSpooferEXE []byte

//go:embed tools/godpotato_cpp/godpotato_cpp.exe
var godPotatoCppEXE []byte

//go:embed tools/godpotato/godpotato.exe
var godPotatoGoEXE []byte

func main() {
	listen := flag.String("listen", "127.0.0.1:8848", "HTTP 监听地址")
	data := flag.String("data", "", "数据文件路径，默认 $HOME/.weshell/data.json")
	timeout := flag.Duration("timeout", 15*time.Second, "单次命令执行的超时时间")
	auth := flag.String("auth", "", "简易令牌；设置后前端需提供 X-Auth-Token 才能调用接口")
	lab := flag.String("lab", "", "本机靶机地址，前端常驻显示，例如 http://127.0.0.1:8081/shell.php")
	accessLog := flag.Bool("access-log", true, "是否打印每个 HTTP 请求的访问日志（默认开启）")
	logLevel := flag.String("log-level", "info", "日志级别：trace/debug/info/warn/error/fatal/panic（默认 info）")
	logFile := flag.String("log-file", "", "日志文件路径；设置后日志同时写入该文件（追加写入）")
	flag.Parse()

	logger, closeLog, err := newLogger(*logLevel, *logFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	defer closeLog()

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
		Timeout:         *timeout,
		Token:           *auth,
		LabURL:          *lab,
		PrintSpooferEXE: printSpooferEXE,
		GodPotatoCppEXE: godPotatoCppEXE,
		GodPotatoGoEXE:  godPotatoGoEXE,
	}))
	// 前端资源经 go:embed 内嵌且无内容指纹，若不禁用缓存，改了 web/ 重新编译后浏览器仍会用
	// 缓存的旧 app.js / index.html，表现为「看不到新提权工具/命令框/输出」。故强制 no-store。
	mux.Handle("/", noCache(http.FileServer(http.FS(webRoot))))

	// 让 shell 包（发给靶机的请求日志）复用同一个带前缀的 logger，统一输出到 stdout。
	shell.SetLogger(logger)

	handler := http.Handler(mux)
	if *accessLog {
		handler = withAccessLog(logger, mux)
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	logger.Infof("管理端已启动: http://%s", *listen)
	logger.Infof("数据文件: %s", dataPath)
	logger.Infof("请确认所有靶标均为你自有或已获授权的 CTF/教学靶机")
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Fatalf("服务异常退出: %v", err)
	}
}

// noCache 给前端静态资源响应加禁止缓存头，确保重新编译内嵌资源后浏览器立即拿到最新版本。
func noCache(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		h.ServeHTTP(w, r)
	})
}

// newLogger 创建 logrus 日志器：使用自定义格式（时间戳 + 级别 + 消息），并按 level 设置日志级别；
// 若 logFile 非空，日志同时（tee）写入该文件（追加写入），便于持久化与事后审计。
// 先校验 level，再打开日志文件——level 非法时不会误建文件。level 非法或文件打不开均返回错误。
// 第二个返回值是关闭函数：用于关闭日志文件句柄（未指定文件时为 no-op）。
func newLogger(level, logFile string) (*logrus.Logger, func(), error) {
	l := logrus.New()
	l.SetFormatter(&weshellFormatter{})
	lvl, err := logrus.ParseLevel(strings.ToLower(strings.TrimSpace(level)))
	if err != nil {
		return nil, nil, fmt.Errorf("无效的日志级别 %q（可选 trace/debug/info/warn/error/fatal/panic）: %w", level, err)
	}
	l.SetLevel(lvl)

	closeFn := func() {}
	var out io.Writer = os.Stdout
	if strings.TrimSpace(logFile) != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, nil, fmt.Errorf("打开日志文件 %q 失败: %w", logFile, err)
		}
		out = io.MultiWriter(os.Stdout, f)
		closeFn = func() { _ = f.Close() }
	}
	l.SetOutput(out)
	return l, closeFn, nil
}

// weshellFormatter 输出形如 `2006/01/02 15:04:05 INFO msg` 的单行日志，
// 保留标准库 logger 的时间戳风格，并补上日志级别。
type weshellFormatter struct{}

func (f *weshellFormatter) Format(e *logrus.Entry) ([]byte, error) {
	var b strings.Builder
	b.WriteString(e.Time.UTC().Format("2006/01/02 15:04:05"))
	b.WriteByte(' ')
	b.WriteString(strings.ToUpper(e.Level.String()))
	b.WriteByte(' ')
	b.WriteString(e.Message)
	if len(e.Data) > 0 {
		b.WriteByte(' ')
		b.WriteString(fmt.Sprint(e.Data))
	}
	b.WriteByte('\n')
	return []byte(b.String()), nil
}

// withAccessLog 打印每个 HTTP 请求的访问日志：来源、方法、路径、状态码与耗时。
//
// 命令执行另有单独的审计日志（见 internal/api 与 internal/shell），那里记录的是
// 「谁对哪个靶机执行了什么命令、发给靶机的请求参数/回包大小」，与这里的访问日志互补。
func withAccessLog(logger logrus.FieldLogger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		logger.Infof("%s %s %s %d %s",
			clientIP(r), r.Method, r.URL.RequestURI(), rec.status,
			time.Since(start).Round(time.Millisecond))
	})
}

// statusRecorder 包住 ResponseWriter 以捕获实际写出的状态码。
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool // 是否已有过状态写入（兜底以 200 计）
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
