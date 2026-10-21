package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNewLoggerWritesFile 验证：指定 logFile 时，日志会同时写入该文件，
// 以时间戳开头（无 [weshell] 前缀）、含级别字段与消息正文。
func TestNewLoggerWritesFile(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "weshell.log")

	l, closeLog, err := newLogger("info", logPath)
	if err != nil {
		t.Fatalf("newLogger 失败: %v", err)
	}
	defer closeLog() // 关闭文件句柄，避免 Windows 上句柄占用导致 TempDir 清理失败
	l.Infof("hello-%s", "file")

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("读取日志文件失败: %v", err)
	}
	got := string(data)
	if strings.HasPrefix(got, "[weshell] ") {
		t.Fatalf("日志不应再带 [weshell] 前缀，实际: %q", got)
	}
	if !strings.Contains(got, " INFO ") {
		t.Fatalf("日志缺少级别字段，实际: %q", got)
	}
	if !strings.Contains(got, "hello-file") {
		t.Fatalf("日志未包含消息正文，实际: %q", got)
	}
}

// TestNewLoggerBadLevelNoFile 验证：level 非法时返回错误，且不会创建日志文件
// （级别校验先于打开文件）。
func TestNewLoggerBadLevelNoFile(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "should_not_exist.log")

	if _, _, err := newLogger("bogus", logPath); err == nil {
		t.Fatalf("非法级别应返回错误")
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("非法级别不应创建日志文件，stat=%v", err)
	}
}

// TestNewLoggerEmptyFileStdoutOnly 验证：logFile 为空时仅输出到 stdout，不报错。
func TestNewLoggerEmptyFileStdoutOnly(t *testing.T) {
	l, _, err := newLogger("info", "")
	if err != nil {
		t.Fatalf("newLogger(info, \"\") 失败: %v", err)
	}
	if l == nil {
		t.Fatalf("logger 不应为 nil")
	}
}
