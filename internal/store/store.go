// Package store 负责 weshell 靶标数据与命令审计记录的持久化。
//
// 数据保存在单个 JSON 文件里（默认 $HOME/.weshell/data.json），
// 目标是纯标准库实现、无外部依赖，方便教学环境随身带一个二进制跑起来。
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Target 描述一个被管理的 Webshell 端点。
type Target struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	URL        string    `json:"url"`
	ShellType  string    `json:"shellType"`
	Param      string    `json:"param"`
	Method     string    `json:"method"`
	CreatedAt  time.Time `json:"createdAt"`
	LastUsedAt time.Time `json:"lastUsedAt,omitempty"`
	Note       string    `json:"note"`
}

// CommandRecord 是一次命令执行的审计记录。
type CommandRecord struct {
	ID        string    `json:"id"`
	TargetID  string    `json:"targetId"`
	Command   string    `json:"command"`
	OK        bool      `json:"ok"`
	LatencyMS int64     `json:"latencyMs"`
	Message   string    `json:"message,omitempty"`
	Time      time.Time `json:"time"`
}

type document struct {
	Targets []Target        `json:"targets"`
	History []CommandRecord `json:"history"`
}

const (
	maxHistory  = 500
	historyKeep = 300
)

// Store 是线程安全的内存数据仓储，并负责落盘。
type Store struct {
	mu   sync.Mutex
	path string
	doc  document
}

// Open 打开（必要时创建）数据文件中的仓储。
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %w", err)
	}
	s := &Store{path: path, doc: document{}}
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, fmt.Errorf("读取数据文件失败: %w", err)
	}
	if len(raw) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(raw, &s.doc); err != nil {
		return nil, fmt.Errorf("数据文件解析失败: %w", err)
	}
	if s.doc.Targets == nil {
		s.doc.Targets = []Target{}
	}
	return s, nil
}

// Get 按 ID 查找靶标，返回副本以避免调用方改动内部状态。
func (s *Store) Get(id string) (Target, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.doc.Targets {
		if t.ID == id {
			return t, true
		}
	}
	return Target{}, false
}

// List 返回全部靶标副本。
func (s *Store) List() []Target {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Target, len(s.doc.Targets))
	copy(out, s.doc.Targets)
	return out
}

// Add 新增靶标，ID 由服务端生成。
func (s *Store) Add(t Target) (Target, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, exist := range s.doc.Targets {
		if exist.ID == t.ID {
			return Target{}, fmt.Errorf("靶标 ID 已存在: %s", t.ID)
		}
	}
	t.ID = newID()
	t.CreatedAt = time.Now()
	s.doc.Targets = append(s.doc.Targets, t)
	if err := s.saveLocked(); err != nil {
		return Target{}, err
	}
	return t, nil
}

// Update 整体替换指定 ID 的靶标内容。
func (s *Store) Update(id string, t Target) (Target, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, exist := range s.doc.Targets {
		if exist.ID == id {
			t.ID = id
			t.CreatedAt = exist.CreatedAt
			s.doc.Targets[i] = t
			if err := s.saveLocked(); err != nil {
				return Target{}, err
			}
			return t, nil
		}
	}
	return Target{}, fmt.Errorf("靶标不存在: %s", id)
}

// Delete 删除指定 ID 的靶标。
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, t := range s.doc.Targets {
		if t.ID == id {
			s.doc.Targets = append(s.doc.Targets[:i], s.doc.Targets[i+1:]...)
			return s.saveLocked()
		}
	}
	return fmt.Errorf("靶标不存在: %s", id)
}

// TouchLastUsed 更新靶标的最后使用时间。
func (s *Store) TouchLastUsed(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.doc.Targets {
		if s.doc.Targets[i].ID == id {
			s.doc.Targets[i].LastUsedAt = time.Now()
			return
		}
	}
}

// AppendRecord 追加一条命令执行审计记录，并按上限裁剪。
func (s *Store) AppendRecord(r CommandRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.ID == "" {
		r.ID = newID()
	}
	if r.Time.IsZero() {
		r.Time = time.Now()
	}
	s.doc.History = append(s.doc.History, r)
	if len(s.doc.History) > maxHistory {
		s.doc.History = append([]CommandRecord{}, s.doc.History[len(s.doc.History)-historyKeep:]...)
	}
	// 审计记录落盘失败不应中断正在进行的命令执行，仅提示。
	if err := s.saveLocked(); err != nil {
		fmt.Fprintf(os.Stderr, "[weshell] 审计记录落盘失败: %v\n", err)
	}
}

// History 返回最近的命令执行记录。
func (s *Store) History(limit int) []CommandRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := s.doc.History
	if limit <= 0 || limit > len(all) {
		limit = len(all)
	}
	out := make([]CommandRecord, limit)
	copy(out, all[len(all)-limit:])
	return out
}

// saveLocked 采用「写临时文件 + rename」落盘，避免异常退出时留下半截 JSON。
// 调用前必须持有 s.mu。
func (s *Store) saveLocked() error {
	raw, err := json.MarshalIndent(s.doc, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化失败: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return fmt.Errorf("写入临时文件失败: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("替换数据文件失败: %w", err)
	}
	return nil
}

// newID 生成带时间前缀的随机 ID，便于排序与肉眼识别创建顺序。
func newID() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("%d-unknown", time.Now().UnixNano())
	}
	return time.Now().Format("20060102150405") + "-" + hex.EncodeToString(buf[:])
}
