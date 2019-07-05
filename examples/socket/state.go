// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"fmt"
	"net"
	"time"
)

type socketType uint8

const (
	socketTCP socketType = iota
	socketUDP
)

type socket struct {
	created   time.Time
	fd        int
	pid       uint32
	typ       socketType
	src, dest net.Addr
}

type process struct {
	socks map[int]*socket
}

type state struct {
	st   *stats
	pids map[uint32]*process
	tids map[uint32]event
}

func NewState(st *stats) state {
	return state{
		tids: make(map[uint32]event),
		pids: make(map[uint32]*process),
		st:   st,
	}
}

func (s *state) ThreadEnter(tid uint32, ev event) {
	if prev, hasPrev := s.tids[tid]; hasPrev {
		panic(fmt.Sprintf("tid=%d already has an event: %v", tid, prev))
	}
	s.tids[tid] = ev
}

func (s *state) ThreadLeave(tid uint32) (ev event) {
	ev = s.tids[tid]
	delete(s.tids, tid)
	return
}

func (s *state) onSocketClose(sock *socket) {
	src := "(nil)"
	dst := src
	if sock.src != nil {
		src = sock.src.String()
	}
	if sock.dest != nil {
		dst = sock.dest.String()
	}
	s.st.Output(
		fmt.Sprintf("flow %s -> %s duration %s",
			src,
			dst,
			time.Since(sock.created)))
}

func (s *state) SocketClose(pid uint32, fd int) {
	if process, ok := s.pids[pid]; ok {
		if socket, ok := process.socks[fd]; ok {
			s.onSocketClose(socket)
			delete(process.socks, fd)
		}
	}
}

func (s *state) SocketCreate(sock *socket) {
	proc, ok := s.pids[sock.pid]
	if !ok {
		proc = &process{
			socks: make(map[int]*socket),
		}
		s.pids[sock.pid] = proc
	}
	if prev, found := proc.socks[sock.fd]; found {
		panic(fmt.Sprintf("pid=%d fd=%d already exists: %v", sock.pid, sock.fd, prev))
	}
	proc.socks[sock.fd] = sock
}
