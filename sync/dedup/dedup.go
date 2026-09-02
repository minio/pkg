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

// Package dedup provides a bounded, de-duplicating channel. A value whose key
// is already queued is dropped instead of being enqueued a second time, which
// makes it suitable for coalescing repeated notifications about the same
// entity into a single unit of work.
package dedup

import (
	"context"
	"errors"
	"sync"
)

// ErrClosed is returned by send operations on a closed Chan.
var ErrClosed = errors.New("dedup: channel is closed")

// ErrFull is returned by TrySend when the channel is at capacity.
var ErrFull = errors.New("dedup: channel is full")

// Chan is a buffered channel of T that holds at most one queued value per
// key K. Keys are derived from values and stay reserved until the value is
// received, so a duplicate is only dropped while its predecessor is still
// waiting to be consumed.
//
// Chan is safe for concurrent use. It is not a Go channel and cannot be used
// in a select statement; the context aware Send and Recv serve that purpose.
type Chan[K comparable, T any] struct {
	key    func(T) K
	items  chan entry[K, T]
	slots  chan struct{}
	closed chan struct{}
	once   sync.Once

	mu      sync.Mutex
	pending map[K]struct{}
}

type entry[K comparable, T any] struct {
	key K
	val T
}

// NewChan returns a Chan buffering up to size values, keyed by key. key must
// return the same result every time it is called for a given value.
func NewChan[K comparable, T any](size int, key func(T) K) (*Chan[K, T], error) {
	if size <= 0 {
		return nil, errors.New("dedup: size must be > 0")
	}
	if key == nil {
		return nil, errors.New("dedup: key must not be nil")
	}
	c := &Chan[K, T]{
		key:     key,
		items:   make(chan entry[K, T], size),
		slots:   make(chan struct{}, size),
		closed:  make(chan struct{}),
		pending: make(map[K]struct{}, size),
	}
	for i := 0; i < size; i++ {
		c.slots <- struct{}{}
	}
	return c, nil
}

// Send queues v, blocking while the channel is full. It reports whether v was
// queued; a false return with a nil error means an equal key was already
// queued. It returns ErrClosed once the channel is closed and the context
// error if ctx ends first.
func (c *Chan[K, T]) Send(ctx context.Context, v T) (bool, error) {
	select {
	case <-c.closed:
		return false, ErrClosed
	default:
	}
	k := c.key(v)
	if c.queued(k) {
		return false, nil
	}
	select {
	case <-c.slots:
	case <-c.closed:
		return false, ErrClosed
	case <-ctx.Done():
		return false, ctx.Err()
	}
	return c.enqueue(k, v), nil
}

// TrySend queues v without blocking. It reports whether v was queued; a false
// return with a nil error means an equal key was already queued. It returns
// ErrFull if the channel is at capacity and ErrClosed once it is closed.
func (c *Chan[K, T]) TrySend(v T) (bool, error) {
	select {
	case <-c.closed:
		return false, ErrClosed
	default:
	}
	k := c.key(v)
	if c.queued(k) {
		return false, nil
	}
	select {
	case <-c.slots:
	default:
		return false, ErrFull
	}
	return c.enqueue(k, v), nil
}

// Recv returns the next queued value, blocking until one arrives. It reports
// false once ctx ends, or once the channel is closed and drained. Receiving a
// value frees its key, so an equal value may be queued again.
func (c *Chan[K, T]) Recv(ctx context.Context) (T, bool) {
	if v, ok := c.TryRecv(); ok {
		return v, true
	}
	select {
	case e := <-c.items:
		c.release(e)
		return e.val, true
	case <-c.closed:
		return c.TryRecv()
	case <-ctx.Done():
		var zero T
		return zero, false
	}
}

// TryRecv returns the next queued value without blocking, reporting false if
// none is queued.
func (c *Chan[K, T]) TryRecv() (T, bool) {
	select {
	case e := <-c.items:
		c.release(e)
		return e.val, true
	default:
		var zero T
		return zero, false
	}
}

// Len returns the number of queued values.
func (c *Chan[K, T]) Len() int {
	return len(c.items)
}

// Close stops further sends. Already queued values remain available to Recv.
// Close may be called more than once.
func (c *Chan[K, T]) Close() {
	c.once.Do(func() { close(c.closed) })
}

func (c *Chan[K, T]) queued(k K) bool {
	c.mu.Lock()
	_, ok := c.pending[k]
	c.mu.Unlock()
	return ok
}

// enqueue is called holding a slot, so neither the send to items nor the
// return of the slot can block.
func (c *Chan[K, T]) enqueue(k K, v T) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.pending[k]; ok {
		c.slots <- struct{}{}
		return false
	}
	c.pending[k] = struct{}{}
	c.items <- entry[K, T]{key: k, val: v}
	return true
}

func (c *Chan[K, T]) release(e entry[K, T]) {
	c.mu.Lock()
	delete(c.pending, e.key)
	c.mu.Unlock()
	c.slots <- struct{}{}
}
