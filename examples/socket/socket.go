// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
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
	/***************************************************************************
	 * IPv4
	 **************************************************************************/

	// IPv4/TCP/UDP socket created. Good for associating socks with pids.
	//
	//  " inet_create(sock=0xffff9f1ddadb8080, proto=17) "
	{
		probe: tracing.Probe{
			Name:      "inet_create",
			Address:   "inet_create",
			Fetchargs: "sock=%si proto=%dx",
			Filter:    "proto==6 || proto==17", // TCP or UDP
		},
		alloc: func() interface{} {
			return new(inetCreateCall)
		},
	},

	// IPv4 socket destructed. Good for terminating flows.
	// void return value.
	//
	//  " inet_create(sock=0xffff9f1ddadb8080, proto=17) "
	{
		probe: tracing.Probe{
			Name:      "inet_sock_destruct",
			Address:   "inet_sock_destruct",
			Fetchargs: "sock=%di",
		},
		alloc: func() interface{} {
			return new(inetSockDestruct)
		},
	},

	/***************************************************************************
	 * IPv4 / TCP
	 **************************************************************************/

	// An IPv4 / TCP socket connect attempt:
	//
	//  " connect(sock=0xffff9f1ddd216040, 0.0.0.0:0 -> 151.101.66.217:443) "
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

	// Result of IPv4/TCP connect:
	//
	//  " <- connect ok (retval==0 or retval==-ERRNO) "
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

	// Call to accept (usually blocking).
	//
	//  " accept(sock=0xffff9f1ddb3c4040, laddr=0.0.0.0, lport=0) "
	{
		probe: tracing.Probe{
			Name:      "inet_csk_accept_call",
			Address:   "inet_csk_accept",
			Fetchargs: "sock=%di laddr=+{{.INET_SOCK_LADDR}}(%di):u32 lport=+{{.INET_SOCK_LPORT}}(%di):u16",
		},
		alloc: func() interface{} {
			return new(tcpAcceptCall)
		},
	},

	// Return of accept(). Local side is usually zero so not fetched. Needs
	// further I/O to populate source.Good for marking a connection as inbound.
	//
	//  " <- accept(sock=0xffff9f1ddc5eb780, raddr=10.0.2.15, rport=22) "
	{
		probe: tracing.Probe{
			Type:      tracing.TypeKRetProbe,
			Name:      "inet_csk_accept_ret",
			Address:   "inet_csk_accept",
			Fetchargs: "sock=%ax raddr=+{{.INET_SOCK_LADDR}}(%ax):u32 rport=+{{.INET_SOCK_LPORT}}(%ax):u16",
		},
		alloc: func() interface{} {
			return new(tcpAcceptResult)
		},
	},

	// Called each time a TCP (IPv4? IPv6?) socket changes state (TCP_SYN_SENT, TCP_ESTABLISHED, etc).
	//
	//  " state(sock=0xffff9f1ddd216040) TCP_SYN_SENT "
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

	// Data is sent via TCP (IPv4, IPv6?).
	// Good for (payload) data counters and getting full sock src and dest.
	// Not valid for packet counters, sock behaves as a stream.
	//
	//  " tcp_sendmsg(sock=0xffff9f1ddd216040, len=517, 10.0.2.15:55310 -> 151.101.66.217:443) "
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

	// IP packet (ipv4 only?) is sent. Acceptable as a packet counter,
	// But the actual data sent might span multiple packets if TSO is in use.
	//
	// (lport is fetched just for the sake of dev mode filtering).
	//
	//  " ip_local_out(sock=0xffff9f1ddd216040) "
	{
		probe: tracing.Probe{
			Name:      "ip_local_out_call",
			Address:   "ip_local_out",
			Fetchargs: "sock=%si lport=+{{.INET_SOCK_LPORT}}(%si):u16",
			// TODO: development remove!
			//       ignoring local 22 port
			Filter: "lport != 0x1600",
		},
		alloc: func() interface{} {
			return new(ipLocalOutCall)
		},
	},

	// Count received IPv4/TCP packets.
	// TODO: To better align with output side, try to find a fn to count all IP
	//       packets.
	//
	//  " tcp_v4_do_rcv(sock=0xffff9f1ddd216040) "
	{
		probe: tracing.Probe{
			Name:      "tcp_v4_do_rcv_call",
			Address:   "tcp_v4_do_rcv",
			Fetchargs: "sock=%di lport=+{{.INET_SOCK_LPORT}}(%di):u16",
			// TODO: development remove!
			//       ignoring local 22 port
			Filter: "lport != 0x1600",
		},
		alloc: func() interface{} {
			return new(tcpV4DoRcv)
		},
	},

	// TCP (IPv4 only?) data receive. Good for counting (payload) bytes recv'd.
	//
	//  " tcp_recv_established(sock=0xffff9f1ddd216040, size=20, 10.0.2.15:55310 <- 151.101.66.217:443) "
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

	/***************************************************************************
	 * IPv4 / UDP
	 **************************************************************************/

	/* UDP (IPv4 only?) send datagram. Good for counting payload bytes.
	   Also this should always be a packet. If we find a way to count packets
	   Here and ignore ip_local_out for UDP, it might avoid large-offload issues.
	*/
	{
		probe: tracing.Probe{
			Name:      "udp_sendmsg_in",
			Address:   "udp_sendmsg",
			Fetchargs: "sock=%di size=%dx laddr=+{{.INET_SOCK_LADDR}}(%di):u32 lport=+{{.INET_SOCK_LPORT}}(%di):u16 raddr=+{{.INET_SOCK_RADDR}}(%di):u32 rport=+{{.INET_SOCK_RPORT}}(%di):u16",
		},
		alloc: func() interface{} {
			return new(udpSendMsgCall)
		},
	},

	// TODO: udp_destroy_sock
	// TODO: inet_sock_destruct
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
