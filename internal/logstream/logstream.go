package logstream

import (
	"sync"
)

const defaultBufferSize = 500

// LogStream buffers recent log lines per server and broadcasts new lines to subscribers.
type LogStream struct {
	mu      sync.RWMutex
	buffers map[string]*ringBuffer
	subs    map[string]map[chan string]struct{}
	bufSize int
}

type ringBuffer struct {
	lines []string
	next  int
}

func newRingBuffer(size int) *ringBuffer {
	return &ringBuffer{lines: make([]string, 0, size)}
}

func (r *ringBuffer) add(line string) {
	if cap(r.lines) == 0 {
		return
	}
	if len(r.lines) < cap(r.lines) {
		r.lines = append(r.lines, line)
	} else {
		r.lines[r.next] = line
		r.next = (r.next + 1) % cap(r.lines)
	}
}

func (r *ringBuffer) copy() []string {
	if len(r.lines) == 0 {
		return nil
	}
	n := len(r.lines)
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = r.lines[(r.next+i)%n]
	}
	return out
}

// New creates a LogStream that keeps the last bufSize lines per server.
// If bufSize <= 0, defaultBufferSize is used.
func New(bufSize int) *LogStream {
	if bufSize <= 0 {
		bufSize = defaultBufferSize
	}
	return &LogStream{
		buffers: make(map[string]*ringBuffer),
		subs:    make(map[string]map[chan string]struct{}),
		bufSize: bufSize,
	}
}

// Broadcast appends the line to the server's buffer and sends it to all subscribers.
// Non-blocking: if a subscriber's channel is full, the line is dropped for that subscriber.
func (s *LogStream) Broadcast(serverID, line string) {
	if serverID == "" {
		return
	}
	s.mu.Lock()
	if s.buffers[serverID] == nil {
		s.buffers[serverID] = newRingBuffer(s.bufSize)
	}
	s.buffers[serverID].add(line)
	subs := s.subs[serverID]
	s.mu.Unlock()

	if len(subs) == 0 {
		return
	}
	for ch := range subs {
		select {
		case ch <- line:
		default:
			// subscriber slow, drop
		}
	}
}

// Subscribe returns the recent lines for the server and a channel for new lines.
// The caller must call Unsubscribe(serverID, ch) when done.
func (s *LogStream) Subscribe(serverID string) (recent []string, ch chan string) {
	if serverID == "" {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.buffers[serverID] != nil {
		recent = s.buffers[serverID].copy()
	}
	if s.subs[serverID] == nil {
		s.subs[serverID] = make(map[chan string]struct{})
	}
	sendCh := make(chan string, 64)
	s.subs[serverID][sendCh] = struct{}{}
	return recent, sendCh
}

// Unsubscribe removes the channel from the server's subscribers and closes it.
func (s *LogStream) Unsubscribe(serverID string, ch chan string) {
	if serverID == "" || ch == nil {
		return
	}
	s.mu.Lock()
	if subs := s.subs[serverID]; subs != nil {
		delete(subs, ch)
		if len(subs) == 0 {
			delete(s.subs, serverID)
		}
	}
	s.mu.Unlock()
	close(ch)
}
