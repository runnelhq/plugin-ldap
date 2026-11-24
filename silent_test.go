package main

import (
	"context"
	"net"
	"sync"
	"testing"
)

type silent struct {
	addr     string
	accepted chan struct{}
}

// silentServer accepts connections and never answers.
func silentServer(t *testing.T) *silent {
	t.Helper()
	var lc net.ListenConfig
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &silent{addr: l.Addr().String(), accepted: make(chan struct{}, 1)}
	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			select {
			case s.accepted <- struct{}{}:
			default:
			}
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return s
}
