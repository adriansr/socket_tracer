// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type flowProto uint8

const (
	protoUnknown flowProto = 0
	protoTCP               = unix.IPPROTO_TCP
	protoUDP               = unix.IPPROTO_UDP
)

type endpoint struct {
	addr           net.Addr
	packets, bytes uint64
}

type flow struct {
	sock              uintptr
	proto             flowProto
	created, lastSeen time.Time
	process           *process
	src, dst          endpoint

	prev, next *flow
}

type flowList struct {
	head, tail *flow
}

type process struct {
	pid        uint32
	name, path string
	args       []string
}

type state struct {
	sync.Mutex
	st        *stats
	processes map[uint32]*process
	flows     map[uintptr]*flow
	threads   map[uint32]event

	lru, done flowList
}

var kernelProcess = process{
	pid:  0,
	name: "[kernel_task]",
}

func NewState(st *stats) *state {
	s := &state{
		st:        st,
		processes: make(map[uint32]*process),
		flows:     make(map[uintptr]*flow),
		threads:   make(map[uint32]event),
	}
	go s.reapLoop()
	return s
}

func (s *state) DoneFlows() flowList {
	s.Lock()
	defer s.Unlock()
	r := s.done
	s.done = flowList{}
	return r
}

func (s *state) reapLoop() {
	t := time.NewTicker(time.Second / 4)
	for range t.C {
		flows := s.DoneFlows()
		for flow := flows.get(); flow != nil; flow = flows.get() {
			if flow.src.addr == nil ||
				flow.dst.addr == nil ||
				flow.process == nil {
				continue
			}
			s.st.Output(fmt.Sprintf("terminated flow %s -> %s proto %d process [%d] %s duration %v sent %d bytes %d packets recv %d bytes / %d packets",
				flow.src.addr.String(),
				flow.dst.addr.String(),
				flow.proto,
				flow.process.pid,
				flow.process.name,
				flow.lastSeen.Sub(flow.created),
				flow.src.bytes,
				flow.src.packets,
				flow.dst.bytes,
				flow.dst.packets))
		}
	}
}

func (s *state) CreateProcess(p *process) {
	if p == nil || p.pid == 0 {
		return
	}
	s.Lock()
	defer s.Unlock()
	if prev, found := s.processes[p.pid]; found {
		if len(p.args) <= len(prev.args) {
			return
		}
	}
	s.processes[p.pid] = p
}

func (s *state) DestroyProcess(pid uint32) {
	if pid == 0 {
		return
	}
	s.Lock()
	defer s.Unlock()
	delete(s.processes, pid)
}

func (s *state) getProcess(pid uint32) *process {
	if pid == 0 {
		return &kernelProcess
	}
	return s.processes[pid]
}

func (s *state) ThreadEnter(tid uint32, ev event) {
	if prev, hasPrev := s.threads[tid]; hasPrev {
		fmt.Fprintf(os.Stderr, "tid=%d already has an event: %v", tid, prev)
	}
	s.threads[tid] = ev
}

func (s *state) ThreadLeave(tid uint32) (ev event, found bool) {
	if ev, found = s.threads[tid]; found {
		delete(s.threads, tid)
	}
	return
}

// CreateSock allocates a new sock in the system
func (s *state) CreateFlow(ptr uintptr, pid uint32, time time.Time) {
	s.Lock()
	defer s.Unlock()
	// sock ptr is reused
	if prev, found := s.flows[ptr]; found {
		s.onFlowTerminated(prev)
	}
	flow := new(flow)
	flow.sock = ptr
	flow.process = s.getProcess(pid)
	flow.created, flow.lastSeen = time, time
	s.flows[ptr] = flow
	s.lru.add(flow)
}

func (s *state) TerminateFlow(ptr uintptr, pid uint32, time time.Time) {
	s.Lock()
	defer s.Unlock()
	flow, found := s.flows[ptr]
	if !found {
		return
	}
	flow.lastSeen = time
	s.onFlowTerminated(flow)
}

func (s *state) UpdateFlow(pid uint32, flow *flow) {
	s.Lock()
	defer s.Unlock()
	prev, found := s.flows[flow.sock]
	if !found {
		flow.process = s.getProcess(pid)
		flow.created = flow.lastSeen
		s.flows[flow.sock] = flow
		s.lru.add(flow)
		return
	}
	prev.lastSeen = flow.lastSeen
	if flow.proto != prev.proto {
		if prev.proto == protoUnknown {
			prev.proto = flow.proto
		} else {
			// Error...
		}
	}
	if prev.process.pid == 0 && flow.process.pid != 0 {
		prev.process = s.getProcess(pid)
	}
	prev.src.addr = flow.src.addr
	prev.dst.addr = flow.dst.addr
	s.lru.remove(prev)
	s.lru.add(prev)
}

func (s *state) DataOut(ptr uintptr, pid uint32, numPackets, numBytes uint64, time time.Time) {
	s.Lock()
	defer s.Unlock()
	f, found := s.flows[ptr]
	if !found {
		f = &flow{
			sock:    ptr,
			process: s.getProcess(pid),
			created: time,
		}
		s.flows[ptr] = f
	}
	f.lastSeen = time
	f.src.packets += numPackets
	f.src.bytes += numBytes
	s.lru.remove(f)
	s.lru.add(f)
}

func (s *state) DataIn(ptr uintptr, pid uint32, numPackets, numBytes uint64, time time.Time) {
	s.Lock()
	defer s.Unlock()
	f, found := s.flows[ptr]
	if !found {
		f = &flow{
			sock:    ptr,
			process: s.getProcess(pid),
			created: time,
		}
		s.flows[ptr] = f
	}
	f.lastSeen = time
	f.dst.packets += numPackets
	f.dst.bytes += numBytes
	s.lru.remove(f)
	s.lru.add(f)
}

func (s *state) onFlowTerminated(f *flow) {
	if _, found := s.flows[f.sock]; !found {
		return
	}
	delete(s.flows, f.sock)
	s.lru.remove(f)
	if f.proto != protoUnknown {
		s.done.add(f)
	}
}

func (l *flowList) add(f *flow) {
	if l.tail == nil {
		l.head = f
		l.tail = f
		f.next = nil
		f.prev = nil
		return
	}
	l.tail.next = f
	f.prev = l.tail
	l.tail = f
	f.next = nil
}

func (l *flowList) peek() *flow {
	return l.head
}

func (l *flowList) get() *flow {
	f := l.head
	if f != nil {
		l.head = f.next
		if l.tail == f {
			l.tail = nil
		}
	}
	return f
}

func (l *flowList) remove(f *flow) {
	if f.prev != nil {
		f.prev.next = f.next
	}
	if f.next != nil {
		f.next.prev = f.prev
	}
}
