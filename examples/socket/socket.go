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
			Fetchargs: "af=+{{.SOCKADDR_IN_AF}}(%si):u16 addr=+{{.SOCKADDR_IN_ADDR}}(%si):u32 port=+{{.SOCKADDR_IN_PORT}}(%si):u16",
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

	offSockAddrIn, err := Guess(debugFS, guessStructSockAddrIn)
	if err != nil {
		panic(err)
	}
	_, _ = fmt.Fprintf(os.Stderr, "Guessed offsets for struct sockaddr_in: %+v\n", offSockAddrIn)

	if err := merge(constants, offSockAddrIn); err != nil {
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
