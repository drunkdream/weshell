package shell

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

// TestSendLogsPayloadAtDebug 验证：debug 级别下，发给靶机的 payload 会被打印，
// 且包含 "webshell payload" 标识与 payload 正文。
func TestSendLogsPayloadAtDebug(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	code := "public class WshRunner{ /* debug-payload-marker */ }"

	var buf bytes.Buffer
	dl := logrus.New()
	dl.SetOutput(&buf)
	dl.SetLevel(logrus.DebugLevel)

	old := Logger
	Logger = dl
	res := newAspnet().Code(context.Background(),
		ExecOptions{Type: TypeAspnet, TargetURL: srv.URL, Param: "x"}, code)
	Logger = old

	if !res.OK {
		t.Fatalf("Code 失败: %q", res.Error)
	}
	got := buf.String()
	if !strings.Contains(got, "webshell payload") {
		t.Fatalf("debug 日志缺少 payload 标识行，实际: %q", got)
	}
	if !strings.Contains(got, "debug-payload-marker") {
		t.Fatalf("debug 日志未包含 payload 正文，实际: %q", got)
	}
}

// TestSendNoPayloadAtInfo 验证：info 级别（默认）下不打印 payload 正文。
func TestSendNoPayloadAtInfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	code := "public class WshRunner{ /* info-should-not-log-marker */ }"

	var buf bytes.Buffer
	il := logrus.New()
	il.SetOutput(&buf)
	il.SetLevel(logrus.InfoLevel)

	old := Logger
	Logger = il
	res := newAspnet().Code(context.Background(),
		ExecOptions{Type: TypeAspnet, TargetURL: srv.URL, Param: "x"}, code)
	Logger = old

	if !res.OK {
		t.Fatalf("Code 失败: %q", res.Error)
	}
	if strings.Contains(buf.String(), "info-should-not-log-marker") {
		t.Fatalf("info 级别不应打印 payload 正文，实际: %q", buf.String())
	}
}
