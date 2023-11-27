// Copyright (c) 2022-2023 MinIO, Inc.
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

package sftp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

type (
	// LogType defined various types of logs and errors
	// that can happen within the SFTP implementation
	LogType string
)

var (
	// ErrMissingConnectionHandlerFunction ...
	ErrMissingConnectionHandlerFunction = errors.New("new connection handler is not defined")
	// ErrMissingSSHConfig ...
	ErrMissingSSHConfig = errors.New("ssh Config is not defined")
	// ErrMissingLoggerInterface ...
	ErrMissingLoggerInterface = errors.New("logger interface is not defined")
	// ErrInvalidPort ...
	ErrInvalidPort = errors.New("port must not be 0 or bigger then 65535")
)

const (
	// ServerStarted is logged when the SFTP server is first launched.
	ServerStarted LogType = "server-started"
	// ChannelNotSession is logged when the SFTP receives a request for a new channel which is NOT of type 'session'.
	ChannelNotSession LogType = "channel-not-session"
	// AcceptNetworkError is logged when there is an error accepting network connections within the listener.
	AcceptNetworkError LogType = "accept-network-error"
	// SSHKeyExchangeError is logged when there is an error performing a key exchange between the SFTP client and server.
	SSHKeyExchangeError LogType = "ssh-key-exchange-error"
	// AcceptChannelError is logged when there is an error while trying to accept the new request channel.
	AcceptChannelError LogType = "accept-channel-error"
)

// Logger implements a basic logging interface
// for the SFTP server.
type Logger interface {
	Info(tag LogType, msg string)
	Error(tag LogType, err error)
}

// Server implements a composable SFTP Server.
type Server struct {
	quit                 chan struct{}
	port                 int
	publicIP             string
	sshConfig            ssh.ServerConfig
	sshHandshakeDeadline time.Duration
	logger               Logger
	beforeHandle         func(conn net.Conn, err error) (acceptConn bool)
	handleSFTPSession    func(channel ssh.Channel, sconn *ssh.ServerConn)
	listener             net.Listener
}

// ShutDown calls the cancel context and shuts
// down the SFTP server.
func (s *Server) ShutDown() (err error) {
	close(s.quit)
	err = s.listener.Close()
	return
}

// Options defines required configurations
// used when calling NewServer().
type Options struct {
	Port      int
	PublicIP  string
	Logger    Logger
	SSHConfig *ssh.ServerConfig
	// ConnectionKeepAlive controls how long the connection keep-alive duration is set to.
	ConnectionKeepAlive time.Duration
	// SSHHandshakeDeadline controls the time.Duration which ssh session
	// have to complete their handshake. This option is not a part of the
	// ssh.ServerConfig so we had to implement it separately.
	SSHHandshakeDeadline time.Duration
	// BeforeHandle will be executed before `HandleSFTPSession` and before
	// error checking happens during the socket listener.Accept().
	//
	// if acceptConn is true the connection will be accepted, if not
	// the .Close() method is called and the connection dropped.
	BeforeHandle func(conn net.Conn, err error) (acceptConn bool)
	// HandleSFTPSession is executed when a new SFTP session is requested.
	HandleSFTPSession func(channel ssh.Channel, sconn *ssh.ServerConn)
}

// NewServer composes a new Server{} object from the options given.
//
// It is recommended to use (2*time.Minute) as the SSHHandshakeDeadline.
// 2 minutes is the default deadline for OpenSSH servers/clients.
func NewServer(options *Options) (sftpServer *Server, err error) {
	if options.HandleSFTPSession == nil {
		return nil, ErrMissingConnectionHandlerFunction
	}
	if options.SSHConfig == nil {
		return nil, ErrMissingSSHConfig
	}
	if options.Logger == nil {
		return nil, ErrMissingLoggerInterface
	}
	if options.Port < 1 || options.Port > 65535 {
		return nil, ErrInvalidPort
	}
	// It is recommended to use (2*time.Minute) as the SSHHandshakeDeadline.
	// 2 minutes is the default deadline for OpenSSH servers/clients.
	if options.SSHHandshakeDeadline == 0 {
		options.SSHHandshakeDeadline = time.Minute * 2
	}

	lc := new(net.ListenConfig)
	if options.ConnectionKeepAlive != 0 {
		lc.KeepAlive = options.ConnectionKeepAlive
	}

	sftpServer = new(Server)

	// net.Listener does not respect the context cancelFunc.
	// Hence we just pass it a normal context.Background()
	sftpServer.listener, err = lc.Listen(
		context.Background(),
		"tcp",
		net.JoinHostPort(options.PublicIP, strconv.Itoa(options.Port)),
	)
	if err != nil {
		return
	}

	sftpServer.publicIP = options.PublicIP
	sftpServer.port = options.Port
	sftpServer.sshConfig = *options.SSHConfig
	sftpServer.sshHandshakeDeadline = options.SSHHandshakeDeadline
	sftpServer.beforeHandle = options.BeforeHandle
	sftpServer.handleSFTPSession = options.HandleSFTPSession
	sftpServer.logger = options.Logger
	sftpServer.quit = make(chan struct{})
	return
}

// Listen starts the SFTP server
func (s *Server) Listen() (err error) {
	s.logger.Info(ServerStarted,
		"SFTP Server listening on "+
			net.JoinHostPort(s.publicIP, strconv.Itoa(s.port)),
	)

	for {
		conn, err := s.listener.Accept()
		if s.beforeHandle != nil && !s.beforeHandle(conn, err) {
			if conn != nil {
				conn.Close()
			}
			continue
		}
		if err != nil {
			select {
			case <-s.quit:
				return nil
			default:
			}
			// Temporary() is deprecated but since it's been deployed to
			// current production builds I do not want to simply switch it out.
			// ISSUE: https://github.com/golang/go/issues/45729
			// According to golang updates the Temporary() functionality was
			// not changed but the method simply marked deprecated, hence
			// it is alright to keep it implemented for consistency.
			// UPDATE: https://go-review.googlesource.com/c/go/+/340261
			ne, ok := err.(net.Error)
			if ok && (ne.Timeout() || ne.Temporary()) {
				s.logger.Error(
					AcceptNetworkError,
					fmt.Errorf("error accepting connections: %w", err),
				)
				continue
			}
			return err
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	// Before use, a handshake must be performed on the incoming net.Conn.
	conn.SetDeadline(time.Now().Add(s.sshHandshakeDeadline))
	sconn, chans, reqs, err := ssh.NewServerConn(conn, &s.sshConfig)
	if err != nil {
		s.logger.Error(SSHKeyExchangeError, err)
		return
	}

	// Once we are done with SSH handshake, remove deadline.
	conn.SetDeadline(time.Time{})

	// The incoming Request channel must be serviced.
	go ssh.DiscardRequests(reqs)

	// Service the incoming Channel channel.
	for newChannel := range chans {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of an SFTP session, this is "subsystem"
		// with a payload string of "<length=4>sftp"
		if newChannel.ChannelType() != "session" {
			s.logger.Info(
				ChannelNotSession,
				"Channel type is not a session",
			)
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			s.logger.Error(
				AcceptChannelError,
				fmt.Errorf("unable to accept request from channel: %w", err),
			)
			continue
		}

		// Sessions have out-of-band requests such as "shell",
		// "pty-req" and "env".  Here we handle only the
		// "subsystem" request.
		go func(in <-chan *ssh.Request) {
			for req := range in {
				ok := false
				if req.Type == "subsystem" {
					if len(req.Payload) > 4 && string(req.Payload[4:]) == "sftp" {
						ok = true
						go s.handleSFTPSession(channel, sconn)
					}
				}

				if req.WantReply {
					// We only reply to SSH packets that have `sftp` payload, all other
					// packets are rejected
					req.Reply(ok, nil)
				}
			}
		}(requests)
	}
}
