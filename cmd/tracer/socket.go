// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"fmt"
	"os"
	"os/signal"
	"time"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix/linux/perf"

	tracing "github.com/adriansr/socket_tracer"
)

var templateVars = GuessResult{
	"AF_INET":     2,
	"AF_INET6":    10,
	"IPPROTO_TCP": 6,
	"IPPROTO_UDP": 17,
	"SOCK_STREAM": 2,

	// functions

	// Offset for the ith element on an array of pointers,
	"POINTER_INDEX": func(index int) int {
		return int(unsafe.Sizeof(uintptr(0))) * index
	},
}

type ProbeDef struct {
	Probe   tracing.Probe
	Decoder func(desc tracing.ProbeDescription) (tracing.Decoder, error)
}

var probes = []ProbeDef{

	/***************************************************************************
	 * RUNNING PROCESSES
	 **************************************************************************/

	{
		Probe: tracing.Probe{
			Name:    "sys_execve",
			Address: "{{.SYS_EXECVE}}",
			Fetchargs: fmt.Sprintf("path=%s argptrs=%s param0=%s param1=%s param2=%s param3=%s param4=%s",
				makeMemoryDump("{{.EP1}}", 0, maxProgArgLen),                                  // path
				makeMemoryDump("{{.EP2}}", 0, int((maxProgArgs+1)*unsafe.Sizeof(uintptr(0)))), // argptrs
				makeMemoryDump("+{{call .POINTER_INDEX 0}}({{.EP2}})", 0, maxProgArgLen),      // param0
				makeMemoryDump("+{{call .POINTER_INDEX 1}}({{.EP2}})", 0, maxProgArgLen),      // param1
				makeMemoryDump("+{{call .POINTER_INDEX 2}}({{.EP2}})", 0, maxProgArgLen),      // param2
				makeMemoryDump("+{{call .POINTER_INDEX 3}}({{.EP2}})", 0, maxProgArgLen),      // param3
				makeMemoryDump("+{{call .POINTER_INDEX 4}}({{.EP2}})", 0, maxProgArgLen),      // param4
			),
		},
		Decoder: func(desc tracing.ProbeDescription) (decoder tracing.Decoder, e error) {
			return tracing.NewStructDecoder(desc, func() interface{} {
				return new(execveCall)
			})
		},
	},

	{
		Probe: tracing.Probe{
			Name:    "do_exit",
			Address: "do_exit",
		},
		Decoder: func(desc tracing.ProbeDescription) (decoder tracing.Decoder, e error) {
			return tracing.NewStructDecoder(desc, func() interface{} {
				return new(doExit)
			})
		},
	},

	/***************************************************************************
	 * IPv4
	 **************************************************************************/

	// IPv4/TCP/UDP socket created. Good for associating sockets with pids.
	// ** This is a struct socket* not a struct sock* **
	//
	//  " inet_create(socket=0xffff9f1ddadb8080, proto=17) "
	{
		Probe: tracing.Probe{
			Name:      "sock_init_data",
			Address:   "sock_init_data",
			Fetchargs: "socket={{.P1}} sock={{.P2}}",
		},
		Decoder: func(desc tracing.ProbeDescription) (decoder tracing.Decoder, e error) {
			return tracing.NewStructDecoder(desc, func() interface{} {
				return new(sockInitData)
			})
		},
	},

	// IPv4/TCP/UDP socket released. Good for associating sockets with pids.
	// ** This is a struct socket* not a struct sock* **
	//
	//  " inet_create(socket=0xffff9f1ddadb8080, proto=17) "
	{
		Probe: tracing.Probe{
			Name:      "inet_release",
			Address:   "inet_release",
			Fetchargs: "socket={{.P1}} sock=+{{.SOCKET_SOCK}}({{.P1}})",
		},
		Decoder: func(desc tracing.ProbeDescription) (decoder tracing.Decoder, e error) {
			return tracing.NewStructDecoder(desc, func() interface{} {
				return new(inetReleaseCall)
			})
		},
	},

	/***************************************************************************
	 * IPv4 / TCP
	 **************************************************************************/

	// An IPv4 / TCP socket connect attempt:
	//
	//  " connect(sock=0xffff9f1ddd216040, 0.0.0.0:0 -> 151.101.66.217:443) "
	{
		Probe: tracing.Probe{
			Name:      "tcp4_connect_in",
			Address:   "tcp_v4_connect",
			Fetchargs: "sock={{.P1}} laddr=+{{.INET_SOCK_LADDR}}({{.P1}}):u32 lport=+{{.INET_SOCK_LPORT}}({{.P1}}):u16 af=+{{.SOCKADDR_IN_AF}}({{.P2}}):u16 addr=+{{.SOCKADDR_IN_ADDR}}({{.P2}}):u32 port=+{{.SOCKADDR_IN_PORT}}({{.P2}}):u16",
			Filter:    "af=={{.AF_INET}}",
		},
		Decoder: func(desc tracing.ProbeDescription) (decoder tracing.Decoder, e error) {
			return tracing.NewStructDecoder(desc, func() interface{} {
				return new(tcpV4ConnectCall)
			})
		},
	},

	// Result of IPv4/TCP connect:
	//
	//  " <- connect ok (retval==0 or retval==-ERRNO) "
	{
		Probe: tracing.Probe{
			Type:      tracing.TypeKRetProbe,
			Name:      "tcp4_connect_out",
			Address:   "tcp_v4_connect",
			Fetchargs: "retval={{.RET}}",
		},
		Decoder: func(desc tracing.ProbeDescription) (decoder tracing.Decoder, e error) {
			return tracing.NewStructDecoder(desc, func() interface{} {
				return new(tcpV4ConnectResult)
			})
		},
	},

	// Call to accept (usually blocking).
	//
	//  " accept(sock=0xffff9f1ddb3c4040, laddr=0.0.0.0, lport=0) "
	{
		Probe: tracing.Probe{
			Name:      "inet_csk_accept_call",
			Address:   "inet_csk_accept",
			Fetchargs: "sock={{.P1}} laddr=+{{.INET_SOCK_LADDR}}({{.P1}}):u32 lport=+{{.INET_SOCK_LPORT}}({{.P1}}):u16",
		},
		Decoder: func(desc tracing.ProbeDescription) (decoder tracing.Decoder, e error) {
			return tracing.NewStructDecoder(desc, func() interface{} {
				return new(tcpAcceptCall)
			})
		},
	},

	// Return of accept(). Local side is usually zero so not fetched. Needs
	// further I/O to populate source.Good for marking a connection as inbound.
	//
	//  " <- accept(sock=0xffff9f1ddc5eb780, raddr=10.0.2.15, rport=22) "
	{
		Probe: tracing.Probe{
			Type:      tracing.TypeKRetProbe,
			Name:      "inet_csk_accept_ret",
			Address:   "inet_csk_accept",
			Fetchargs: "sock={{.RET}} raddr=+{{.INET_SOCK_LADDR}}({{.RET}}):u32 rport=+{{.INET_SOCK_LPORT}}({{.RET}}):u16",
		},
		Decoder: func(desc tracing.ProbeDescription) (decoder tracing.Decoder, e error) {
			return tracing.NewStructDecoder(desc, func() interface{} {
				return new(tcpAcceptResult)
			})
		},
	},

	// Called each time a TCP (IPv4? IPv6?) socket changes state (TCP_SYN_SENT, TCP_ESTABLISHED, etc).
	//
	//  " state(sock=0xffff9f1ddd216040) TCP_SYN_SENT "
	{
		Probe: tracing.Probe{
			Name:      "tcp_set_state",
			Address:   "tcp_set_state",
			Fetchargs: "sock={{.P1}} state={{.P2}}",
		},
		Decoder: func(desc tracing.ProbeDescription) (decoder tracing.Decoder, e error) {
			return tracing.NewStructDecoder(desc, func() interface{} {
				return new(tcpSetStateCall)
			})
		},
	},

	// Data is sent via TCP (IPv4, IPv6?).
	// Good for (payload) data counters and getting full sock src and dest.
	// Not valid for packet counters, sock behaves as a stream.
	//
	//  " tcp_sendmsg(sock=0xffff9f1ddd216040, len=517, 10.0.2.15:55310 -> 151.101.66.217:443) "
	{
		// TODO: tcp_sendmsg arguments may not be stable between kernels!
		//       2.6 has 1st unused arg (stripped?) and struct socket * instead of struct sock *
		Probe: tracing.Probe{
			Name:      "tcp_sendmsg_in",
			Address:   "tcp_sendmsg",
			Fetchargs: "sock={{.TCP_SENDMSG_SOCK}} size={{.TCP_SENDMSG_LEN}} laddr=+{{.INET_SOCK_LADDR}}({{.TCP_SENDMSG_SOCK}}):u32 lport=+{{.INET_SOCK_LPORT}}({{.TCP_SENDMSG_SOCK}}):u16 raddr=+{{.INET_SOCK_RADDR}}({{.TCP_SENDMSG_SOCK}}):u32 rport=+{{.INET_SOCK_RPORT}}({{.TCP_SENDMSG_SOCK}}):u16",
			// TODO: development remove!
			//       ignoring local 22 port
			Filter: "lport!=0x1600",
		},
		Decoder: func(desc tracing.ProbeDescription) (decoder tracing.Decoder, e error) {
			return tracing.NewStructDecoder(desc, func() interface{} {
				return new(tcpSendMsgCall)
			})
		},
	},

	// IP packet (ipv4 only?) is sent. Acceptable as a packet counter,
	// But the actual data sent might span multiple packets if TSO is in use.
	//
	// (lport is fetched just for the sake of dev mode filtering).
	//
	//  " ip_local_out(sock=0xffff9f1ddd216040) "
	{
		Probe: tracing.Probe{
			Name:      "ip_local_out_call",
			Address:   "{{.IP_LOCAL_OUT}}",
			Fetchargs: "sock={{.IP_LOCAL_OUT_SOCK}} lport=+{{.INET_SOCK_LPORT}}({{.IP_LOCAL_OUT_SOCK}}):u16 len=+{{.SK_BUFF_LEN}}({{.IP_LOCAL_OUT_SK_BUFF}})",
			// TODO: development remove!
			//       ignoring local 22 port
			Filter: "lport != 0x1600",
		},
		Decoder: func(desc tracing.ProbeDescription) (decoder tracing.Decoder, e error) {
			return tracing.NewStructDecoder(desc, func() interface{} {
				return new(ipLocalOutCall)
			})
		},
	},

	// Count received IPv4/TCP packets.
	// TODO: To better align with output side, try to find a fn to count all IP
	//       packets.
	//
	//  " tcp_v4_do_rcv(sock=0xffff9f1ddd216040) "
	{
		Probe: tracing.Probe{
			Name:      "tcp_v4_do_rcv_call",
			Address:   "tcp_v4_do_rcv",
			Fetchargs: "sock={{.P1}} lport=+{{.INET_SOCK_LPORT}}({{.P1}}):u16",
			// TODO: development remove!
			//       ignoring local 22 port
			Filter: "lport != 0x1600",
		},
		Decoder: func(desc tracing.ProbeDescription) (decoder tracing.Decoder, e error) {
			return tracing.NewStructDecoder(desc, func() interface{} {
				return new(tcpV4DoRcv)
			})
		},
	},

	// TCP (IPv4 only?) data receive. Good for counting (payload) bytes recv'd.
	//
	//  " tcp_recv_established(sock=0xffff9f1ddd216040, size=20, 10.0.2.15:55310 <- 151.101.66.217:443) "
	//
	// TODO:
	// - len argument missing from 4.15
	// - 3.x outputs a len that is bigger than it's supposed to be, as in includes tcp header?
	//   but it's not a multiple of 4..
	{
		Probe: tracing.Probe{
			Name:      "tcp_rcv_established",
			Address:   "tcp_rcv_established",
			Fetchargs: "sock={{.P1}} size={{.P4}} laddr=+{{.INET_SOCK_LADDR}}({{.P1}}):u32 lport=+{{.INET_SOCK_LPORT}}({{.P1}}):u16 raddr=+{{.INET_SOCK_RADDR}}({{.P1}}):u32 rport=+{{.INET_SOCK_RPORT}}({{.P1}}):u16",
			// TODO: development remove!
			//       ignoring local 22 port
			Filter: "lport!=0x1600",
		},
		Decoder: func(desc tracing.ProbeDescription) (decoder tracing.Decoder, e error) {
			return tracing.NewStructDecoder(desc, func() interface{} {
				return new(tcpRcvEstablished)
			})
		},
	},

	/***************************************************************************
	 * IPv4 / UDP
	 **************************************************************************/

	/* UDP (IPv4 only?) send datagram. Good for counting payload bytes.
	   Also this should always be a packet. If we find a way to count packets
	   Here and ignore ip_local_out for UDP, it might avoid large-offload issues.
	*/
	{
		Probe: tracing.Probe{
			Name:      "udp_sendmsg_in",
			Address:   "udp_sendmsg",
			Fetchargs: "sock={{.UDP_SENDMSG_SOCK}} size={{.UDP_SENDMSG_LEN}} laddr=+{{.INET_SOCK_LADDR}}({{.UDP_SENDMSG_SOCK}}):u32 lport=+{{.INET_SOCK_LPORT}}({{.UDP_SENDMSG_SOCK}}):u16 raddr=+{{.INET_SOCK_RADDR}}({{.UDP_SENDMSG_SOCK}}):u32 rport=+{{.INET_SOCK_RPORT}}({{.UDP_SENDMSG_SOCK}}):u16",
		},
		Decoder: func(desc tracing.ProbeDescription) (decoder tracing.Decoder, e error) {
			return tracing.NewStructDecoder(desc, func() interface{} {
				return new(udpSendMsgCall)
			})
		},
	},
}

func init() {
	// Register arch-specific variables for interpolation
	if err := merge(templateVars, archVariables); err != nil {
		panic(err)
	}
}

func registerProbe(
	probe ProbeDef,
	debugFS *tracing.TraceFS,
	channel *tracing.PerfChannel) error {

	// TODO CHECKS:
	// - Probe name/group can't have a slash '-'
	// - Use of xNN types
	// - Use of string types
	// - Use of $comm

	p := templateVars.Apply(probe.Probe)

	err := debugFS.AddKProbe(p)
	if err != nil {
		return errors.Wrapf(err, "unable to register probe %s", p.String())
	}
	desc, err := debugFS.LoadProbeDescription(p)
	if err != nil {
		return errors.Wrapf(err, "unable to get format of probe %s", p.String())
	}
	decoder, err := probe.Decoder(desc)
	if err != nil {
		return errors.Wrapf(err, "unable to build decoder for probe %s", p.String())
	}
	if err := channel.MonitorProbe(desc, decoder); err != nil {
		return errors.Wrapf(err, "unable to monitor probe %s", p.String())
	}

	fmt.Fprintf(os.Stderr, "Registered probe:'%s' filter:'%s'\n", p.String(), p.Filter)
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
	defer func() {
		if err = debugFS.RemoveAllKProbes(); err != nil {
			panic(err)
		}
	}()

	altFns, err := ResolveFunctions(debugFS, map[string][]string{
		"SYS_EXECVE":   {"SyS_execve", "sys_execve"},
		"IP_LOCAL_OUT": {"ip_local_out", "ip_local_out_sk"},
	})
	if err := merge(templateVars, altFns); err != nil {
		panic(err)
	}

	if err := GuessAll(debugFS, templateVars); err != nil {
		panic(err)
	}

	fmt.Fprintf(os.Stderr, "Resolved %d variables:\n", len(templateVars))
	for k, v := range templateVars {
		fmt.Fprintf(os.Stderr, "   %s=%+v\n", k, v)
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
	defer channel.Close()

	for _, p := range probes {
		if err := registerProbe(p, debugFS, channel); err != nil {
			panic(err)
		}
	}

	done := make(chan struct{}, 0)
	defer close(done)

	output := NewStats(time.Second / 4)
	defer output.Close()

	st := NewState(output)

	if err := channel.Run(); err != nil {
		panic(err)
	}

	sigC := make(chan os.Signal, 1)
	defer close(sigC)
	signal.Notify(sigC, os.Interrupt)

	for running := true; running; {
		select {
		case <-sigC:
			running = false

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
			running = false

		case numLost := <-channel.LostC():
			output.Lost(numLost)
		}
	}
}
