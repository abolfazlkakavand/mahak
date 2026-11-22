package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func isClientHello(b []byte) bool {
	return len(b) >= 6 && b[0] == 0x16 && b[1] == 0x03 && b[5] == 0x01
}

// readFirst reads the client's first flight. For TLS it waits until the whole
// first record is in, so the ClientHello can be replayed with several
// strategies.
func readFirst(c net.Conn, wait time.Duration) ([]byte, error) {
	_ = c.SetReadDeadline(time.Now().Add(wait))
	defer c.SetReadDeadline(time.Time{})
	var buf []byte
	tmp := make([]byte, 4096)
	need := 0
	for {
		n, err := c.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			return buf, err
		}
		if need == 0 && len(buf) >= 5 {
			if buf[0] == 0x16 && buf[1] == 0x03 {
				need = 5 + int(buf[3])<<8 + int(buf[4])
			} else {
				return buf, nil
			}
		}
		if need != 0 && len(buf) >= need {
			return buf, nil
		}
	}
}

func (e *Engine) handleSocks(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 262)
	if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 5 {
		return
	}
	if _, err := io.ReadFull(c, buf[:int(buf[1])]); err != nil {
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	if _, err := io.ReadFull(c, buf[:4]); err != nil || buf[0] != 5 {
		return
	}
	cmd, atyp := buf[1], buf[3]
	var host string
	switch atyp {
	case 1:
		if _, err := io.ReadFull(c, buf[:4]); err != nil {
			return
		}
		host = net.IP(append([]byte(nil), buf[:4]...)).String()
	case 3:
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return
		}
		n := int(buf[0])
		if _, err := io.ReadFull(c, buf[:n]); err != nil {
			return
		}
		host = string(buf[:n])
	case 4:
		if _, err := io.ReadFull(c, buf[:16]); err != nil {
			return
		}
		host = net.IP(append([]byte(nil), buf[:16]...)).String()
	default:
		return
	}
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return
	}
	port := int(buf[0])<<8 | int(buf[1])
	if cmd != 1 {
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})

	first, err := readFirst(c, 3*time.Second)
	if err != nil && len(first) == 0 && !isTimeout(err) {
		return
	}
	if isClientHello(first) {
		cut := 5 + int(first[3])<<8 + int(first[4])
		var extra []byte
		if cut < len(first) {
			extra = first[cut:]
			first = first[:cut]
		}
		e.proxyTLS(ctx, c, host, port, first, extra)
		return
	}
	e.proxyPlain(ctx, c, host, port, first)
}

var _ = fmt.Sprintf
