// Package activity reads local OpenSSH authentication logs independently of login.
package activity

import (
	"Heimdall/internal/agent/native"
	"Heimdall/internal/synchronization"
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"
)

var accepted = regexp.MustCompile(`Accepted \S+ for ([a-zA-Z0-9_.-]{1,64}) from ([0-9a-fA-F:.]+) port [0-9]+`)
var failed = regexp.MustCompile(`(?:Failed \S+ for (?:invalid user )?|Invalid user )([a-zA-Z0-9_.-]{1,64}) from ([0-9a-fA-F:.]+)`)

func Parse(line string, managed func(string) bool, now time.Time) (synchronization.ActivityEvent, bool) {
	event := synchronization.ActivityEvent{ObservedAt: now.UTC(), Severity: "info"}
	if match := accepted.FindStringSubmatch(line); match != nil {
		event.Login = match[1]
		event.Address = match[2]
		event.Kind = "managed_login"
		if !managed(event.Login) {
			event.Kind = "unmanaged_login"
			event.Severity = "warning"
			if event.Login == "root" {
				event.Severity = "critical"
			}
		}
		return event, true
	}
	if match := failed.FindStringSubmatch(line); match != nil {
		event.Login = match[1]
		event.Address = match[2]
		event.Kind = "failed_authentication"
		return event, true
	}
	return event, false
}

type journal struct {
	Offset int64                           `json:"offset"`
	Source string                          `json:"source"`
	Events []synchronization.ActivityEvent `json:"events"`
}
type Log struct {
	Path, State string
	mu          sync.Mutex
	journal     journal
	err         error
	failures    map[string][]time.Time
}

func New(path, state string) (*Log, error) {
	l := &Log{Path: path, State: state, failures: map[string][]time.Time{}}
	raw, err := os.ReadFile(state)
	if err == nil {
		err = json.Unmarshal(raw, &l.journal)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return l, nil
}
func (l *Log) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		l.poll()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (l *Log) save() error {
	raw, err := json.Marshal(l.journal)
	if err != nil {
		return err
	}
	return native.AtomicWrite(l.State, raw, 0600)
}
func (l *Log) poll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	previous := l.journal
	previous.Events = append([]synchronization.ActivityEvent{}, previous.Events...)
	l.err = l.read()
	if l.err != nil && len(l.journal.Events) < 10000 {
		l.journal = previous
	}
}
func (l *Log) read() error {
	info, err := os.Lstat(l.Path)
	if err != nil {
		return fmt.Errorf("authentication log unavailable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("authentication log must be a regular file")
	}
	file, err := os.Open(l.Path)
	if err != nil {
		return err
	}
	defer file.Close()
	actual, err := file.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(info, actual) {
		return errors.New("authentication log changed during open")
	}
	// Inode changes or truncation restart reading; event IDs include the source inode.
	source := fileSource(actual)
	if l.journal.Source != source || info.Size() < l.journal.Offset {
		l.journal.Source = source
		l.journal.Offset = 0
	}
	if _, err = file.Seek(l.journal.Offset, io.SeekStart); err != nil {
		return err
	}
	reader := bufio.NewReader(io.LimitReader(file, 1<<20))
	changed := false
	for len(l.journal.Events) < 10000 {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				return err
			}
			break
		}
		offset := l.journal.Offset
		l.journal.Offset += int64(len(line))
		changed = true
		if len(line) > 4096 {
			continue
		}
		now := time.Now()
		event, ok := Parse(line, func(login string) bool {
			info, err := os.Lstat(filepath.Join(native.ManagedDirectory(), "users", login+".json"))
			return err == nil && info.Mode().IsRegular()
		}, now)
		if !ok {
			continue
		}
		digest := sha256.Sum256([]byte(source + ":" + strconv.FormatInt(offset, 10) + ":" + line))
		event.ID = hex.EncodeToString(digest[:])
		if event.Kind == "failed_authentication" {
			if len(l.failures) >= 1024 {
				for key := range l.failures {
					delete(l.failures, key)
					break
				}
			}
			recent := l.failures[event.Address][:0]
			for _, at := range l.failures[event.Address] {
				if now.Sub(at) < time.Minute {
					recent = append(recent, at)
				}
			}
			if len(recent) < 20 {
				recent = append(recent, now)
			}
			l.failures[event.Address] = recent
			if len(recent) >= 5 {
				event.Severity = "warning"
			}
		}
		l.journal.Events = append(l.journal.Events, event)
	}
	if changed {
		if err = l.save(); err != nil {
			return err
		}
	}
	if len(l.journal.Events) >= 10000 {
		return errors.New("security telemetry spool is full; delivery is stalled")
	}
	return nil
}
func (l *Log) Batch() ([]synchronization.ActivityEvent, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	count := min(100, len(l.journal.Events))
	out := append([]synchronization.ActivityEvent{}, l.journal.Events[:count]...)
	return out, l.err
}
func (l *Log) Ack(ids []string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(ids) > 100 {
		return errors.New("ack limit exceeded")
	}
	set := map[string]bool{}
	for _, id := range ids {
		set[id] = true
	}
	next := []synchronization.ActivityEvent{}
	for _, event := range l.journal.Events {
		if !set[event.ID] {
			next = append(next, event)
		}
	}
	previous := l.journal.Events
	l.journal.Events = next
	if err := l.save(); err != nil {
		l.journal.Events = previous
		return err
	}
	return nil
}
func (l *Log) Health() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return l.err.Error()
	}
	if len(l.journal.Events) > 0 && time.Since(l.journal.Events[0].ObservedAt) > 2*time.Minute {
		return "security telemetry delivery has stalled"
	}
	return ""
}
