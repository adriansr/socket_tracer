// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"bytes"
	"fmt"
	"os"
	"text/template"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix/linux/perf"

	tracing "github.com/adriansr/socket_tracer"
)

var constants = map[string]interface{}{
	"AF_INET":     2,
	"AF_INET6":    10,
	"SOCK_STREAM": 2,
}

var timeRef TimeReference

var probes = []struct {
	probe tracing.Probe
	alloc tracing.AllocateFn
}{
	/*
		{
			// x86_64 : %rdi, %rsi, %rdx, %rcx, %r8 and %r9. The kernel interface uses %rdi, %rsi, %rdx, %r10, %r8 and %r9.

			probe: tracing.Probe{
				//Type:      tracing.TypeKRetProbe,
				Name:      "sys_socket_in",
				Address:   "sys_socket",
				Fetchargs: "domain=%di type=%si protocol=%dx",
				Filter:    "(domain=={{.AF_INET}} || domain=={{.AF_INET6}}) && type=={{.SOCK_STREAM}}",
			},
			alloc: func() interface{} {
				return new(socketEvent)
			},
		},
		{
			probe: tracing.Probe{
				Type:      tracing.TypeKRetProbe,
				Name:      "sys_socket_out",
				Address:   "sys_socket",
				Fetchargs: "fd=%ax",
			},
			alloc: func() interface{} {
				return new(socketRetEvent)
			},
		},
		{
			probe: tracing.Probe{
				Name:      "sys_close_in",
				Address:   "sys_close",
				Fetchargs: "fd=%di",
			},
			alloc: func() interface{} {
				return new(closeEvent)
			},
		},
		{
			probe: tracing.Probe{
				Type:      tracing.TypeKRetProbe,
				Name:      "accept_out",
				Address:   "sys_accept",
				Fetchargs: "fd=%ax",
			},
			alloc: func() interface{} {
				return new(acceptRetEvent)
			},
		},*/

	{
		probe: tracing.Probe{
			Name:      "tcp4_connect_in",
			Address:   "tcp_v4_connect",
			Fetchargs: "sock=%di laddr=+{{.INET_SOCK_LADDR}}(%di):u32 lport=+{{.INET_SOCK_LPORT}}(%di):u16 af=+{{.SOCKADDR_IN_AF}}(%si):u16 addr=+{{.SOCKADDR_IN_ADDR}}(%si):u32 port=+{{.SOCKADDR_IN_PORT}}(%si):u16",
			Filter:    "af=={{.AF_INET}}",
		},
		alloc: func() interface{} {
			return new(tcpV4ConnectCall)
		},
	},
	{
		probe: tracing.Probe{
			Type:      tracing.TypeKRetProbe,
			Name:      "tcp4_connect_out",
			Address:   "tcp_v4_connect",
			Fetchargs: "retval=%ax",
		},
		alloc: func() interface{} {
			return new(tcpV4ConnectResult)
		},
	},

	/*{
		// inet_bind is for explicit bind(...) calls, not useful
		probe: tracing.Probe{
			Name:      "inet_bind4_in",
			Address:   "inet_bind",
			Fetchargs: "af=+{{.SOCKADDR_IN_AF}}(%si):u16 addr=+{{.SOCKADDR_IN_ADDR}}(%si):u32 port=+{{.SOCKADDR_IN_PORT}}(%si):u16",
			Filter:    "af=={{.AF_INET}}",
		},
		alloc: func() interface{} {
			return new(bind4Call)
		},
	},*/
	{
		probe: tracing.Probe{
			Name:      "tcp_v4_init_sock",
			Address:   "tcp_v4_init_sock", // can't fail, no need for retval
			Fetchargs: "sock=%di",
		},
		alloc: func() interface{} {
			return new(tcpv4InitSock)
		},
	},
	{
		probe: tracing.Probe{
			Name:      "inet_csk_accept_in",
			Address:   "inet_csk_accept",
			Fetchargs: "sock=%di laddr=+{{.INET_SOCK_LADDR}}(%di):u32 lport=+{{.INET_SOCK_LPORT}}(%di):u16",
		},
		alloc: func() interface{} {
			return new(tcpAcceptCall)
		},
	},
	{
		probe: tracing.Probe{
			Type:      tracing.TypeKRetProbe,
			Name:      "inet_csk_accept_out",
			Address:   "inet_csk_accept",
			Fetchargs: "sock=%ax raddr=+{{.INET_SOCK_LADDR}}(%ax):u32 rport=+{{.INET_SOCK_LPORT}}(%ax):u16",
		},
		alloc: func() interface{} {
			return new(tcpAcceptResult)
		},
	},
	{
		probe: tracing.Probe{
			Name:      "tcp_set_state",
			Address:   "tcp_set_state",
			Fetchargs: "sock=%di state=%si",
		},
		alloc: func() interface{} {
			return new(tcpSetStateCall)
		},
	},
	{
		// TODO: tcp_sendmsg arguments may not be stable between kernels!
		//       2.6 has 1st unused arg (stripped?) and struct socket * instead of struct sock *
		probe: tracing.Probe{
			Name:      "tcp_sendmsg_in",
			Address:   "tcp_sendmsg",
			Fetchargs: "sock=%di size=%dx laddr=+{{.INET_SOCK_LADDR}}(%di):u32 lport=+{{.INET_SOCK_LPORT}}(%di):u16 raddr=+{{.INET_SOCK_RADDR}}(%di):u32 rport=+{{.INET_SOCK_RPORT}}(%di):u16",
			// TODO: development remove!
			//       ignoring local 22 port
			Filter: "lport!=0x1600",
		},
		alloc: func() interface{} {
			return new(tcpSendMsgCall)
		},
	},
	{
		// This probe is for counting sent IPv4 packets.
		// If for some reason we want to only count TCP data packets and ignore
		// ACKs & company, we need to monitor tcp_push or similar.
		//
		// Also: This might not account for TSO. A single call to ip_local_out
		//       could result in multiple packets being sent.
		probe: tracing.Probe{
			Name:      "ip_local_out_call",
			Address:   "ip_local_out",
			Fetchargs: "sock=%si",
		},
		alloc: func() interface{} {
			return new(ipLocalOutCall)
		},
	},

	{
		// This probe is for counting sent IPv4 packets.
		// If for some reason we want to only count TCP data packets and ignore
		// ACKs & company, we need to monitor tcp_push or similar.
		//
		// Also: This might not account for TSO. A single call to ip_local_out
		//       could result in multiple packets being sent.
		probe: tracing.Probe{
			Name:      "tcp_v4_do_rcv_call",
			Address:   "tcp_v4_do_rcv",
			Fetchargs: "sock=%di",
		},
		alloc: func() interface{} {
			return new(tcpV4DoRcv)
		},
	},

	{
		probe: tracing.Probe{
			Name:      "tcp_rcv_established",
			Address:   "tcp_rcv_established",
			Fetchargs: "sock=%di size=%cx laddr=+{{.INET_SOCK_LADDR}}(%di):u32 lport=+{{.INET_SOCK_LPORT}}(%di):u16 raddr=+{{.INET_SOCK_RADDR}}(%di):u32 rport=+{{.INET_SOCK_RPORT}}(%di):u16",
			// TODO: development remove!
			//       ignoring local 22 port
			Filter: "lport!=0x1600",
		},
		alloc: func() interface{} {
			return new(tcpRcvEstablished)
		},
	},
}

func interpolate(s string) string {
	buf := &bytes.Buffer{}
	if err := template.Must(template.New("").Parse(s)).Execute(buf, constants); err != nil {
		panic(err)
	}
	return buf.String()
}

func merge(dest map[string]interface{}, src map[string]interface{}) error {
	for k, v := range src {
		if prev, found := dest[k]; found {
			return fmt.Errorf("attempt to redefine key '%s'. previous value:'%s' new value:'%s'", k, prev, v)
		}
		dest[k] = v
	}
	return nil
}

func registerProbe(
	probe tracing.Probe,
	allocator tracing.AllocateFn,
	debugFS *tracing.TraceFS,
	channel *tracing.PerfChannel) error {

	// TODO CHECKS:
	// - Probe name/group can't have a slash '-'
	// - Use of xNN types
	// - Use of string types
	// - Use of $comm

	probe.Fetchargs = interpolate(probe.Fetchargs)
	probe.Filter = interpolate(probe.Filter)

	err := debugFS.AddKProbe(probe)
	if err != nil {
		return errors.Wrapf(err, "unable to register probe %s", probe.String())
	}
	desc, err := debugFS.LoadProbeDescription(probe)
	if err != nil {
		return errors.Wrapf(err, "unable to get format of probe %s", probe.String())
	}
	decoder, err := tracing.NewStructDecoder(desc, allocator)
	if err != nil {
		return errors.Wrapf(err, "unable to build decoder for probe %s", probe.String())
	}
	if err := channel.MonitorProbe(desc, decoder); err != nil {
		return errors.Wrapf(err, "unable to monitor probe %s", probe.String())
	}
	return nil
}

func main() {
	debugFS, err := tracing.NewTraceFS()
	if err != nil {
		panic(err)
	}
	if err := debugFS.RemoveAllKProbes(); err != nil {
		panic(err)
	}
	defer debugFS.RemoveAllKProbes()

	if err := GuessAll(debugFS, constants); err != nil {
		panic(err)
	}

	channel, err := tracing.NewPerfChannel(
		tracing.WithBufferSize(4096),
		tracing.WithErrBufferSize(1),
		tracing.WithLostBufferSize(256),
		tracing.WithRingSizeExponent(7),
		tracing.WithTID(perf.AllThreads),
		tracing.WithTimestamp())
	if err != nil {
		panic(err)
	}

	for _, p := range probes {
		if err := registerProbe(p.probe, p.alloc, debugFS, channel); err != nil {
			panic(err)
		}
	}

	done := make(chan struct{}, 0)
	defer close(done)

	output := stats{
		output: make(chan string, 1024),
	}
	st := NewState(&output)
	go output.Run(time.Second/4, done)

	if err := channel.Run(); err != nil {
		panic(err)
	}

	for active := true; active; {
		select {
		case iface, ok := <-channel.C():
			if !ok {
				break
			}
			output.Received()
			v, ok := iface.(event)
			if !ok {
				panic(fmt.Sprintf("not a stringer type: %T", iface))
			}
			output.Output(v.String())
			v.Update(&st)

		case err := <-channel.ErrC():
			_, _ = fmt.Fprintf(os.Stderr, "Err received from channel: %v\n", err)
			active = false

		case numLost := <-channel.LostC():
			output.Lost(numLost)
		}
	}
}
