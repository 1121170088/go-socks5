package socks5

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/things-go/go-socks5/statute"
	"io"
	"net"

	"github.com/things-go/go-socks5/bufferpool"
)

// Option user's option
type Option func(s *Server)

// WithBufferPool can be provided to implement custom buffer pool
// By default, buffer pool use size is 32k
func WithBufferPool(bufferPool bufferpool.BufPool) Option {
	return func(s *Server) {
		s.bufferPool = bufferPool
	}
}

// WithAuthMethods can be provided to implement custom authentication
// By default, "auth-less" mode is enabled.
// For password-based auth use UserPassAuthenticator.
func WithAuthMethods(authMethods []Authenticator) Option {
	return func(s *Server) {
		s.authMethods = append(s.authMethods, authMethods...)
	}
}

// WithCredential If provided, username/password authentication is enabled,
// by appending a UserPassAuthenticator to AuthMethods. If not provided,
// and AUthMethods is nil, then "auth-less" mode is enabled.
func WithCredential(cs CredentialStore) Option {
	return func(s *Server) {
		s.credentials = cs
	}
}

// WithResolver can be provided to do custom name resolution.
// Defaults to DNSResolver if not provided.
func WithResolver(res NameResolver) Option {
	return func(s *Server) {
		s.resolver = res
	}
}

// WithRule is provided to enable custom logic around permitting
// various commands. If not provided, NewPermitAll is used.
func WithRule(rule RuleSet) Option {
	return func(s *Server) {
		s.rules = rule
	}
}

// WithRewriter can be used to transparently rewrite addresses.
// This is invoked before the RuleSet is invoked.
// Defaults to NoRewrite.
func WithRewriter(rew AddressRewriter) Option {
	return func(s *Server) {
		s.rewriter = rew
	}
}

// WithBindIP is used for bind or udp associate
func WithBindIP(ip net.IP) Option {
	return func(s *Server) {
		if len(ip) != 0 {
			s.bindIP = make(net.IP, 0, len(ip))
			s.bindIP = append(s.bindIP, ip...)
		}
	}
}

// WithLogger can be used to provide a custom log target.
// Defaults to io.Discard.
func WithLogger(l Logger) Option {
	return func(s *Server) {
		s.logger = l
	}
}

// WithDial Optional function for dialing out.
// The callback set by WithDialAndRequest will be called first.
func WithDial(dial func(ctx context.Context, network, addr string) (net.Conn, error)) Option {
	return func(s *Server) {
		s.dial = dial
	}
}

// WithDialAndRequest Optional function for dialing out with the access of request detail.
func WithDialAndRequest(
	dial func(ctx context.Context, network, addr string, request *Request) (net.Conn, error),
) Option {
	return func(s *Server) {
		s.dialWithRequest = dial
	}
}

// WithGPool can be provided to do custom goroutine pool.
func WithGPool(pool GPool) Option {
	return func(s *Server) {
		s.gPool = pool
	}
}

// WithConnectHandle is used to handle a user's connect command
func WithConnectHandle(h func(ctx context.Context, writer io.Writer, request *Request) error) Option {
	return func(s *Server) {
		s.userConnectHandle = h
	}
}

// WithBindHandle is used to handle a user's bind command
func WithBindHandle(h func(ctx context.Context, writer io.Writer, request *Request) error) Option {
	return func(s *Server) {
		s.userBindHandle = h
	}
}

// WithAssociateHandle is used to handle a user's associate command
func WithAssociateHandle(h func(ctx context.Context, writer io.Writer, request *Request) error) Option {
	return func(s *Server) {
		s.userAssociateHandle = h
	}
}

func WithUpstream(upstream string) Option {
	return func(s *Server) {
		if upstream == "" {
			return
		}
		s.hasUpstream = true
		MaxAddrLen := 1 + 1 + 255 + 2

		const (
			AtypIPv4       = 1
			AtypDomainName = 3
			AtypIPv6       = 4
		)

		ReadAddr := func(r io.Reader, b []byte) ([]byte, error) {
			if len(b) < MaxAddrLen {
				return nil, io.ErrShortBuffer
			}
			_, err := io.ReadFull(r, b[:1]) // read 1st byte for address type
			if err != nil {
				return nil, err
			}

			switch b[0] {
			case AtypDomainName:
				_, err = io.ReadFull(r, b[1:2]) // read 2nd byte for domain length
				if err != nil {
					return nil, err
				}
				domainLength := uint16(b[1])
				_, err = io.ReadFull(r, b[2:2+domainLength+2])
				return b[:1+1+domainLength+2], err
			case AtypIPv4:
				_, err = io.ReadFull(r, b[1:1+net.IPv4len+2])
				return b[:1+net.IPv4len+2], err
			case AtypIPv6:
				_, err = io.ReadFull(r, b[1:1+net.IPv6len+2])
				return b[:1+net.IPv6len+2], err
			}

			return nil, errors.New("ErrAddressNotSupported")
		}

		clientHandshake := func(rw io.ReadWriter, addr []byte) ([]byte, error) {

			var command byte = 1
			buf := make([]byte, MaxAddrLen)
			var err error

			// VER, NMETHODS, METHODS
			_, err = rw.Write([]byte{5, 1, 0})
			if err != nil {
				return nil, err
			}

			// VER, METHOD
			if _, err := io.ReadFull(rw, buf[:2]); err != nil {
				return nil, err
			}

			if buf[0] != 5 {
				return nil, errors.New("SOCKS version error")
			}

			// VER, CMD, RSV, ADDR
			if _, err := rw.Write(bytes.Join([][]byte{{5, command, 0}, addr}, []byte{})); err != nil {
				return nil, err
			}

			// VER, REP, RSV
			if _, err := io.ReadFull(rw, buf[:3]); err != nil {
				return nil, err
			}

			return ReadAddr(rw, buf)
		}

		serializesSocksAddr := func( request *Request) []byte {
			return request.Bytes()[3:]
		}
		connectHandle := func(ctx context.Context, writer io.Writer, request *Request) error {

			dialer := &net.Dialer{}
			c, err := dialer.DialContext(ctx, "tcp", upstream)
			if err != nil {
				return err
			}
			defer c.Close()

			if _, err := clientHandshake(c, serializesSocksAddr(request)); err != nil {
				return err
			}

			// Send success
			if err := SendReply(writer, statute.RepSuccess, c.LocalAddr()); err != nil {
				return fmt.Errorf("failed to send reply, %v", err)
			}
			// Start proxying
			errCh := make(chan error, 2)
			s.goFunc(func() { errCh <- s.Proxy(c, request.Reader) })
			s.goFunc(func() { errCh <- s.Proxy(writer, c) })
			// Wait
			for i := 0; i < 2; i++ {
				e := <-errCh
				if e != nil {
					// return from this function closes target (and conn).
					return e
				}
			}
			return nil
		}
		s.userConnectHandle = connectHandle
	}
}
