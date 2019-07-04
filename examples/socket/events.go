package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"

	tracing "github.com/adriansr/socket_tracer"
)

type event interface {
	fmt.Stringer
	Update(*state)
}

type socketEvent struct {
	Meta     tracing.Metadata `kprobe:"metadata"`
	Domain   int              `kprobe:"domain"`
	Type     int              `kprobe:"type"`
	Protocol int              `kprobe:"protocol"`
}

type socketRetEvent struct {
	Meta tracing.Metadata `kprobe:"metadata"`
	FD   int              `kprobe:"fd"`
}

type closeEvent struct {
	Meta tracing.Metadata `kprobe:"metadata"`
	FD   int              `kprobe:"fd"`
}

type acceptRetEvent struct {
	Meta tracing.Metadata `kprobe:"metadata"`
	FD   int              `kprobe:"fd"`
}

type tcpV4ConnectCall struct {
	Meta    tracing.Metadata `kprobe:"metadata"`
	Address uint32           `kprobe:"addr"`
	Port    uint16           `kprobe:"port"`
}

type tcpV4ConnectResult struct {
	Meta   tracing.Metadata `kprobe:"metadata"`
	Retval int              `kprobe:"retval"`
}

type bind4Call struct {
	Meta    tracing.Metadata `kprobe:"metadata"`
	Address uint32           `kprobe:"addr"`
	Port    uint16           `kprobe:"port"`
}

func (e *tcpV4ConnectResult) String() string {
	return fmt.Sprintf("%s <- connect %s", header(e.Meta), kernErrorDesc(e.Retval))
}

func (e *tcpV4ConnectResult) Update(*state) {
	// TODO
}

func (e *tcpV4ConnectCall) String() string {
	var buf [4]byte
	tracing.MachineEndian.PutUint32(buf[:], e.Address)
	addr := net.IPv4(buf[0], buf[1], buf[2], buf[3])
	tracing.MachineEndian.PutUint16(buf[:], e.Port)
	port := binary.BigEndian.Uint16(buf[:])
	return fmt.Sprintf(
		"%s connect(%s, %d)",
		header(e.Meta),
		addr.String(),
		port)
}

func (e *tcpV4ConnectCall) Update(*state) {
	// TODO
}

func (e *bind4Call) String() string {
	var buf [4]byte
	tracing.MachineEndian.PutUint32(buf[:], e.Address)
	addr := net.IPv4(buf[0], buf[1], buf[2], buf[3])
	tracing.MachineEndian.PutUint16(buf[:], e.Port)
	port := binary.BigEndian.Uint16(buf[:])
	return fmt.Sprintf(
		"%s bind(%s, %d)",
		header(e.Meta),
		addr.String(),
		port)
}

func (e *bind4Call) Update(*state) {
	// TODO
}

// Adjust timestamp length to always be 30 char by adding trailing zeroes to
// subsecond field:
// 32.86225Z --> 32.862250000Z
// time.Format removes trailing zeroes and messes with alignment.
func adjustRFC3339NanoLength(in string) string {
	const N = 30
	n := len(in)
	if n == N {
		return in
	}
	b := append([]byte(in), make([]byte, N-n)...)
	for i := n - 1; i < N-1; i++ {
		b[i] = '0'
	}
	b[N-1] = 'Z'
	return string(b)
}

func header(meta tracing.Metadata) string {
	ts := adjustRFC3339NanoLength(timeRef.ToTime(meta.Timestamp).Format(time.RFC3339Nano))
	return fmt.Sprintf("%s probe=%d pid=%d tid=%d",
		ts,
		meta.EventID,
		meta.PID,
		meta.TID)
}

func (e *socketEvent) String() string {
	return fmt.Sprintf(
		"%s socket(%d, %d, %d)",
		header(e.Meta),
		e.Domain,
		e.Type,
		e.Protocol)
}

func (e *socketEvent) Update(s *state) {
	s.ThreadEnter(e.Meta.TID, e)
}

func (e *acceptRetEvent) String() string {
	return fmt.Sprintf(
		"%s accept()",
		header(e.Meta))
}

func (e *acceptRetEvent) Update(s *state) {

}

func (e *closeEvent) String() string {
	return fmt.Sprintf(
		"%s close(%d)",
		header(e.Meta),
		e.FD)
}

func kernErrorDesc(retval int) string {
	switch {
	case retval < 0:
		errno := syscall.Errno(0 - retval)
		return fmt.Sprintf("failed errno=%d (%s)", errno, errno.Error())
	case retval == 0:
		return "ok"
	default:
		return fmt.Sprintf("ok (value=%d)", retval)
	}
}

func (e *closeEvent) Update(s *state) {
	s.SocketClose(e.Meta.PID, e.FD)
}

func (e *socketRetEvent) String() string {
	if e.FD < 0 {
		errno := syscall.Errno(0 - e.FD)
		return fmt.Sprintf("%s socket failed errno=%d (%s)", header(e.Meta), errno, errno.Error())
	}
	return fmt.Sprintf("%s socket fd=%d", header(e.Meta), e.FD)
}

func (e *socketRetEvent) Update(s *state) {
	args := s.ThreadLeave(e.Meta.TID)
	if args == nil {
		return
	}
	s.SocketCreate(&socket{
		pid: e.Meta.PID,
		fd:  e.FD,
	})
}
