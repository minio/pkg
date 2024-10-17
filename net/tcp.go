// Copyright (c) 2015-2024 MinIO, Inc.
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

package net

import (
	"syscall"
	"time"
)

// A TCPConfig structure is used to configure
// a TCP client or server connections.
type TCPConfig struct {
	// IdleTimeout is the maximum time duration for idle connections
	// before they are forcibly closed.
	IdleTimeout time.Duration

	// UserTimeout is the maximum amount of time that transmitted
	// data may remain unacknowledged before forcefully closing the
	// connection.
	//
	// Moreover, when used with TCP keepalives, UserTimeout
	// overrides keepalive to determine when to close a connection
	// due to keepalive failure.
	//
	// If empty, no TCP user timeout is set.
	UserTimeout time.Duration

	// SendBufSize sets a custom send buffer size on the TCP socket if
	// not zero.
	SendBufSize int

	// RecvBufSize, sets a custom receive buffer size on the TCP socket if
	// not zero.
	RecvBufSize int

	// If true, sets TCP_NODELAY on the network connection which
	// disables Nagle's algorithm such that small packages are not
	// combined into larger ones but sent right away.
	NoDelay bool

	// If non-empty, create a TCP socket on the given virtual routing
	// and forwarding (VRF) interface.
	Interface string

	// Trace is a callback for debug logging
	Trace func(string)
}

// Control applies the TCPConfig to a raw network connection before dialing.
//
// Network and address parameters passed to Control function are not
// necessarily the ones passed to Dial. For example, passing "tcp" to Dial
// will cause the Control function to be called with "tcp4" or "tcp6".
func (c *TCPConfig) Control(network, address string, rc syscall.RawConn) error {
	return c.control(network, address, rc)
}

// Clone returns a copy of a TCPConfig structure.
func (c *TCPConfig) Clone() *TCPConfig {
	if c == nil {
		return nil
	}
	return &TCPConfig{
		IdleTimeout: c.IdleTimeout,
		UserTimeout: c.UserTimeout,
		SendBufSize: c.SendBufSize,
		RecvBufSize: c.RecvBufSize,
		NoDelay:     c.NoDelay,
		Interface:   c.Interface,
		Trace:       c.Trace,
	}
}
