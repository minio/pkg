// Copyright (c) 2015-2026 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package dedup

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type event struct {
	bucket string
	seq    int
}

func eventKey(e event) string { return e.bucket }

func newTestChan(t *testing.T, size int) *Chan[string, event] {
	t.Helper()
	c, err := NewChan(size, eventKey)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewChanValidation(t *testing.T) {
	if _, err := NewChan(0, eventKey); err == nil {
		t.Fatal("expected an error for size 0")
	}
	if _, err := NewChan[string, event](4, nil); err == nil {
		t.Fatal("expected an error for a nil key function")
	}
}

func TestDuplicateDroppedWhileQueued(t *testing.T) {
	ctx := context.Background()
	c := newTestChan(t, 4)

	if sent, err := c.Send(ctx, event{"a", 1}); !sent || err != nil {
		t.Fatalf("first send: sent=%v err=%v", sent, err)
	}
	if sent, err := c.Send(ctx, event{"a", 2}); sent || err != nil {
		t.Fatalf("duplicate send: sent=%v err=%v", sent, err)
	}
	if sent, err := c.TrySend(event{"a", 3}); sent || err != nil {
		t.Fatalf("duplicate try send: sent=%v err=%v", sent, err)
	}
	if got := c.Len(); got != 1 {
		t.Fatalf("expected 1 queued value, got %d", got)
	}

	v, ok := c.Recv(ctx)
	if !ok || v.seq != 1 {
		t.Fatalf("expected the first value, got %+v ok=%v", v, ok)
	}
	if sent, err := c.Send(ctx, event{"a", 4}); !sent || err != nil {
		t.Fatalf("send after receive: sent=%v err=%v", sent, err)
	}
}

func TestDistinctKeysQueueIndependently(t *testing.T) {
	ctx := context.Background()
	c := newTestChan(t, 3)

	for _, bucket := range []string{"a", "b", "c"} {
		if sent, err := c.Send(ctx, event{bucket, 0}); !sent || err != nil {
			t.Fatalf("send %q: sent=%v err=%v", bucket, sent, err)
		}
	}
	if got := c.Len(); got != 3 {
		t.Fatalf("expected 3 queued values, got %d", got)
	}
	for _, want := range []string{"a", "b", "c"} {
		v, ok := c.TryRecv()
		if !ok || v.bucket != want {
			t.Fatalf("expected %q, got %+v ok=%v", want, v, ok)
		}
	}
	if _, ok := c.TryRecv(); ok {
		t.Fatal("expected an empty channel")
	}
}

func TestTrySendFull(t *testing.T) {
	c := newTestChan(t, 1)

	if sent, err := c.TrySend(event{"a", 0}); !sent || err != nil {
		t.Fatalf("send: sent=%v err=%v", sent, err)
	}
	sent, err := c.TrySend(event{"b", 0})
	if sent || !errors.Is(err, ErrFull) {
		t.Fatalf("expected ErrFull, got sent=%v err=%v", sent, err)
	}
}

func TestSendBlocksUntilCapacity(t *testing.T) {
	ctx := context.Background()
	c := newTestChan(t, 1)

	if _, err := c.Send(ctx, event{"a", 0}); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		if sent, err := c.Send(ctx, event{"b", 0}); !sent || err != nil {
			t.Errorf("blocked send: sent=%v err=%v", sent, err)
		}
	}()

	select {
	case <-done:
		t.Fatal("send returned while the channel was full")
	case <-time.After(50 * time.Millisecond):
	}

	if _, ok := c.Recv(ctx); !ok {
		t.Fatal("expected a value")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("send did not return after capacity was freed")
	}
}

func TestSendContextCancel(t *testing.T) {
	c := newTestChan(t, 1)
	if _, err := c.Send(context.Background(), event{"a", 0}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	sent, err := c.Send(ctx, event{"b", 0})
	if sent || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected a deadline error, got sent=%v err=%v", sent, err)
	}
	if sent, err := c.TrySend(event{"b", 1}); sent || !errors.Is(err, ErrFull) {
		t.Fatalf("canceled send must not reserve a key: sent=%v err=%v", sent, err)
	}
}

func TestRecvContextCancel(t *testing.T) {
	c := newTestChan(t, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if _, ok := c.Recv(ctx); ok {
		t.Fatal("expected no value from an empty channel")
	}
}

func TestRecvPrefersQueuedValueOverCanceledContext(t *testing.T) {
	c := newTestChan(t, 1)
	if _, err := c.Send(context.Background(), event{"a", 0}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok := c.Recv(ctx); !ok {
		t.Fatal("expected the queued value")
	}
}

func TestClose(t *testing.T) {
	ctx := context.Background()
	c := newTestChan(t, 2)

	if _, err := c.Send(ctx, event{"a", 0}); err != nil {
		t.Fatal(err)
	}
	c.Close()
	c.Close()

	if sent, err := c.Send(ctx, event{"b", 0}); sent || !errors.Is(err, ErrClosed) {
		t.Fatalf("send after close: sent=%v err=%v", sent, err)
	}
	if sent, err := c.TrySend(event{"b", 0}); sent || !errors.Is(err, ErrClosed) {
		t.Fatalf("try send after close: sent=%v err=%v", sent, err)
	}
	if sent, err := c.Send(ctx, event{"a", 1}); sent || !errors.Is(err, ErrClosed) {
		t.Fatalf("duplicate send after close: sent=%v err=%v", sent, err)
	}
	if v, ok := c.Recv(ctx); !ok || v.bucket != "a" {
		t.Fatalf("expected the queued value to drain, got %+v ok=%v", v, ok)
	}
	if _, ok := c.Recv(ctx); ok {
		t.Fatal("expected no value from a closed and drained channel")
	}
}

func TestCloseUnblocksSend(t *testing.T) {
	ctx := context.Background()
	c := newTestChan(t, 1)
	if _, err := c.Send(ctx, event{"a", 0}); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := c.Send(ctx, event{"b", 0})
		done <- err
	}()

	time.Sleep(50 * time.Millisecond)
	c.Close()

	select {
	case err := <-done:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("expected ErrClosed, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not unblock the pending send")
	}
}

func TestConcurrentDuplicateSends(t *testing.T) {
	ctx := context.Background()
	c := newTestChan(t, 8)

	var wins atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sent, err := c.Send(ctx, event{"a", i})
			if err != nil {
				t.Errorf("send: %v", err)
				return
			}
			if sent {
				wins.Add(1)
			}
		}(i)
	}
	wg.Wait()

	if wins.Load() != 1 {
		t.Fatalf("expected exactly one send to win, got %d", wins.Load())
	}
	if got := c.Len(); got != 1 {
		t.Fatalf("expected 1 queued value, got %d", got)
	}
	if got := len(c.slots); got != 7 {
		t.Fatalf("expected 7 free slots, got %d", got)
	}
}

func TestConcurrentSendRecvLosesNothing(t *testing.T) {
	const (
		producers = 8
		perRun    = 500
		keys      = 16
		consumers = 4
	)
	ctx := context.Background()
	c := newTestChan(t, 4)

	var queued, received atomic.Int64

	var consumed sync.WaitGroup
	consumed.Add(consumers)
	for i := 0; i < consumers; i++ {
		go func() {
			defer consumed.Done()
			for {
				if _, ok := c.Recv(ctx); !ok {
					return
				}
				received.Add(1)
			}
		}()
	}

	var produced sync.WaitGroup
	produced.Add(producers)
	for p := 0; p < producers; p++ {
		go func(p int) {
			defer produced.Done()
			for i := 0; i < perRun; i++ {
				sent, err := c.Send(ctx, event{strconv.Itoa((p*perRun + i) % keys), i})
				if err != nil {
					t.Errorf("send: %v", err)
					return
				}
				if sent {
					queued.Add(1)
				}
			}
		}(p)
	}

	produced.Wait()
	c.Close()
	consumed.Wait()

	if queued.Load() != received.Load() {
		t.Fatalf("queued %d values but received %d", queued.Load(), received.Load())
	}
	if got := c.Len(); got != 0 {
		t.Fatalf("expected an empty channel, got %d", got)
	}
	c.mu.Lock()
	pending := len(c.pending)
	c.mu.Unlock()
	if pending != 0 {
		t.Fatalf("expected no reserved keys, got %d", pending)
	}
	if got := len(c.slots); got != 4 {
		t.Fatalf("expected all slots returned, got %d", got)
	}
}
