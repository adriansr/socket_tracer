// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

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

type tcpV4ConnectCall struct {
	Meta  tracing.Metadata `kprobe:"metadata"`
	Sock  uintptr          `kprobe:"sock"`
	LAddr uint32           `kprobe:"laddr"`
	LPort uint16           `kprobe:"lport"`
	RAddr uint32           `kprobe:"addr"`
	RPort uint16           `kprobe:"port"`
}

type tcpV4ConnectResult struct {
	Meta   tracing.Metadata `kprobe:"metadata"`
	Retval int              `kprobe:"retval"`
}

type tcpSetStateCall struct {
	Meta  tracing.Metadata `kprobe:"metadata"`
	Sock  uintptr          `kprobe:"sock"`
	State int              `kprobe:"state"`
}

type tcpAcceptCall struct {
	Meta  tracing.Metadata `kprobe:"metadata"`
	Sock  uintptr          `kprobe:"sock"`
	LAddr uint32           `kprobe:"laddr"`
	LPort uint16           `kprobe:"lport"`
}

type tcpAcceptResult struct {
	Meta  tracing.Metadata `kprobe:"metadata"`
	Sock  uintptr          `kprobe:"sock"`
	RAddr uint32           `kprobe:"raddr"`
	RPort uint16           `kprobe:"rport"`
}

type tcpSendMsgCall struct {
	Meta  tracing.Metadata `kprobe:"metadata"`
	Sock  uintptr          `kprobe:"sock"`
	Size  uintptr          `kprobe:"size"`
	LAddr uint32           `kprobe:"laddr"`
	LPort uint16           `kprobe:"lport"`
	RAddr uint32           `kprobe:"raddr"`
	RPort uint16           `kprobe:"rport"`
}

type ipLocalOutCall struct {
	Meta tracing.Metadata `kprobe:"metadata"`
	Sock uintptr          `kprobe:"sock"`
}

type tcpV4DoRcv struct {
	Meta tracing.Metadata `kprobe:"metadata"`
	Sock uintptr          `kprobe:"sock"`
}

type tcpRcvEstablished struct {
	Meta  tracing.Metadata `kprobe:"metadata"`
	Sock  uintptr          `kprobe:"sock"`
	Size  int              `kprobe:"size"`
	LAddr uint32           `kprobe:"laddr"`
	LPort uint16           `kprobe:"lport"`
	RAddr uint32           `kprobe:"raddr"`
	RPort uint16           `kprobe:"rport"`
}

type udpSendMsgCall struct {
	Meta  tracing.Metadata `kprobe:"metadata"`
	Sock  uintptr          `kprobe:"sock"`
	Size  uintptr          `kprobe:"size"`
	LAddr uint32           `kprobe:"laddr"`
	LPort uint16           `kprobe:"lport"`
	RAddr uint32           `kprobe:"raddr"`
	RPort uint16           `kprobe:"rport"`
}

type inetCreateCall struct {
	Meta  tracing.Metadata `kprobe:"metadata"`
	Sock  uintptr          `kprobe:"sock"`
	Proto int              `kprobe:"proto"`
}

type inetSockDestruct struct {
	Meta tracing.Metadata `kprobe:"metadata"`
	Sock uintptr          `kprobe:"sock"`
}

func (e *inetCreateCall) String() string {
	return fmt.Sprintf("%s inet_create(sock=0x%x, proto=%d)", header(e.Meta), e.Sock, e.Proto)
}

func (e *inetCreateCall) Update(*state) {

}

func (e *inetSockDestruct) String() string {
	return fmt.Sprintf("%s inet_sock_destruct(sock=0x%x)", header(e.Meta), e.Sock)
}

func (e *inetSockDestruct) Update(*state) {

}

var tcpStates = []string{
	"(zero)",
	"TCP_ESTABLISHED",
	"TCP_SYN_SENT",
	"TCP_SYN_RECV",
	"TCP_FIN_WAIT1",
	"TCP_FIN_WAIT2",
	"TCP_TIME_WAIT",
	"TCP_CLOSE",
	"TCP_CLOSE_WAIT",
	"TCP_LAST_ACK",
	"TCP_LISTEN",
	"TCP_CLOSING",
	"TCP_NEW_SYN_RECV",
}

func (e *tcpSendMsgCall) String() string {
	var buf [4]byte
	tracing.MachineEndian.PutUint32(buf[:], e.LAddr)
	laddr := net.IPv4(buf[0], buf[1], buf[2], buf[3])
	tracing.MachineEndian.PutUint16(buf[:], e.LPort)
	lport := binary.BigEndian.Uint16(buf[:])
	tracing.MachineEndian.PutUint32(buf[:], e.RAddr)
	raddr := net.IPv4(buf[0], buf[1], buf[2], buf[3])
	tracing.MachineEndian.PutUint16(buf[:], e.RPort)
	rport := binary.BigEndian.Uint16(buf[:])
	return fmt.Sprintf(
		"%s tcp_sendmsg(sock=0x%x, len=%d, %s:%d -> %s:%d)",
		header(e.Meta),
		e.Sock,
		e.Size,
		laddr.String(),
		lport,
		raddr.String(),
		rport)
}

func (e *tcpSendMsgCall) Update(*state) {
	// TODO
}

func (e *udpSendMsgCall) String() string {
	var buf [4]byte
	tracing.MachineEndian.PutUint32(buf[:], e.LAddr)
	laddr := net.IPv4(buf[0], buf[1], buf[2], buf[3])
	tracing.MachineEndian.PutUint16(buf[:], e.LPort)
	lport := binary.BigEndian.Uint16(buf[:])
	tracing.MachineEndian.PutUint32(buf[:], e.RAddr)
	raddr := net.IPv4(buf[0], buf[1], buf[2], buf[3])
	tracing.MachineEndian.PutUint16(buf[:], e.RPort)
	rport := binary.BigEndian.Uint16(buf[:])
	return fmt.Sprintf(
		"%s udp_sendmsg(sock=0x%x, len=%d, %s:%d -> %s:%d)",
		header(e.Meta),
		e.Sock,
		e.Size,
		laddr.String(),
		lport,
		raddr.String(),
		rport)
}

func (e *udpSendMsgCall) Update(*state) {
	// TODO
}

func (e *ipLocalOutCall) String() string {
	return fmt.Sprintf(
		"%s ip_local_out(sock=0x%x)",
		header(e.Meta),
		e.Sock)
}

func (e *ipLocalOutCall) Update(*state) {
	// TODO
}

func (e *tcpV4DoRcv) String() string {
	return fmt.Sprintf(
		"%s tcp_v4_do_rcv(sock=0x%x)",
		header(e.Meta),
		e.Sock)
}

func (e *tcpV4DoRcv) Update(*state) {
	// TODO
}

func (e *tcpRcvEstablished) String() string {
	var buf [4]byte
	tracing.MachineEndian.PutUint32(buf[:], e.LAddr)
	laddr := net.IPv4(buf[0], buf[1], buf[2], buf[3])
	tracing.MachineEndian.PutUint16(buf[:], e.LPort)
	lport := binary.BigEndian.Uint16(buf[:])
	tracing.MachineEndian.PutUint32(buf[:], e.RAddr)
	raddr := net.IPv4(buf[0], buf[1], buf[2], buf[3])
	tracing.MachineEndian.PutUint16(buf[:], e.RPort)
	rport := binary.BigEndian.Uint16(buf[:])
	return fmt.Sprintf(
		"%s tcp_recv_established(sock=0x%x, size=%d, %s:%d <- %s:%d)",
		header(e.Meta),
		e.Sock,
		e.Size,
		laddr.String(),
		lport,
		raddr.String(),
		rport)
}

func (e *tcpRcvEstablished) Update(*state) {
	// TODO
}

func (e *tcpAcceptCall) String() string {
	var buf [4]byte
	tracing.MachineEndian.PutUint32(buf[:], e.LAddr)
	laddr := net.IPv4(buf[0], buf[1], buf[2], buf[3])
	tracing.MachineEndian.PutUint16(buf[:], e.LPort)
	lport := binary.BigEndian.Uint16(buf[:])
	return fmt.Sprintf("%s accept(sock=0x%x, laddr=%s, lport=%d)", header(e.Meta), e.Sock, laddr.String(), lport)
}

func (e *tcpAcceptCall) Update(*state) {
	//panic("implement me")
}

func (e *tcpAcceptResult) String() string {
	var buf [4]byte
	tracing.MachineEndian.PutUint32(buf[:], e.RAddr)
	raddr := net.IPv4(buf[0], buf[1], buf[2], buf[3])
	tracing.MachineEndian.PutUint16(buf[:], e.RPort)
	rport := binary.BigEndian.Uint16(buf[:])
	return fmt.Sprintf("%s <- accept(sock=0x%x, raddr=%s, rport=%d)", header(e.Meta), e.Sock, raddr.String(), rport)
}

func (e *tcpAcceptResult) Update(*state) {
	//panic("implement me")
}

func (e *tcpSetStateCall) String() string {
	ss := fmt.Sprintf("(unknown:%d)", e.State)
	if e.State < len(tcpStates) {
		ss = tcpStates[e.State]
	}
	return fmt.Sprintf("%s state(sock=0x%x) %s", header(e.Meta), e.Sock, ss)
}

func (e *tcpSetStateCall) Update(*state) {
	//panic("implement me")
}

func (e *tcpV4ConnectResult) String() string {
	return fmt.Sprintf("%s <- connect %s", header(e.Meta), kernErrorDesc(e.Retval))
}

func (e *tcpV4ConnectResult) Update(*state) {
	// TODO
}

func (e *tcpV4ConnectCall) String() string {
	var buf [4]byte
	tracing.MachineEndian.PutUint32(buf[:], e.LAddr)
	laddr := net.IPv4(buf[0], buf[1], buf[2], buf[3])
	tracing.MachineEndian.PutUint16(buf[:], e.LPort)
	lport := binary.BigEndian.Uint16(buf[:])
	tracing.MachineEndian.PutUint32(buf[:], e.RAddr)
	raddr := net.IPv4(buf[0], buf[1], buf[2], buf[3])
	tracing.MachineEndian.PutUint16(buf[:], e.RPort)
	rport := binary.BigEndian.Uint16(buf[:])
	return fmt.Sprintf(
		"%s connect(sock=0x%x, %s:%d -> %s:%d)",
		header(e.Meta),
		e.Sock,
		laddr.String(),
		lport,
		raddr.String(),
		rport)
}

func (e *tcpV4ConnectCall) Update(*state) {
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
