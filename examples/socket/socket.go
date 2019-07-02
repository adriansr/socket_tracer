package main

import (
	"bytes"
	"fmt"
	"os"
	"syscall"
	"text/template"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix/linux/perf"

	tracing "github.com/adriansr/socket_tracer"
)

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
	{
		// x86_64 : %rdi, %rsi, %rdx, %rcx, %r8 and %r9. The kernel interface uses %rdi, %rsi, %rdx, %r10, %r8 and %r9.

		probe: tracing.Probe{
			//Type:      tracing.TypeKRetProbe,
			Name:      "sys_socket_in",
			Address:   "sys_socket",
			Fetchargs: "domain=%di type=%si protocol=%dx",
			Filter:    interpolate("(domain=={{.AF_INET}} || domain=={{.AF_INET6}}) && type=={{.SOCK_STREAM}}"),
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
	},
}

func header(meta tracing.Metadata) string {
	return fmt.Sprintf("%s probe=%d tid=%d",
		timeRef.ToTime(meta.Timestamp).Format(time.RFC3339Nano),
		meta.EventID,
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

func (e *acceptRetEvent) String() string {
	pgpid, err := syscall.Getpgid(int(e.Meta.TID))
	if err != nil {
		return fmt.Sprintf("%s accept -- getpgpid() failed %v", err)
	}
	flag := "same"
	if pgpid != int(e.Meta.TID) {
		flag = "**DIFFERENT**"
	}
	return fmt.Sprintf(
		"%s accept() pid=%d %s",
		header(e.Meta),
		pgpid,
		flag)
}

func (e *closeEvent) String() string {
	return fmt.Sprintf(
		"%s close(%d)",
		header(e.Meta),
		e.FD)
}

func (e *socketRetEvent) String() string {
	if e.FD < 0 {
		errno := syscall.Errno(0 - e.FD)
		return fmt.Sprintf("%s socket failed errno=%d (%s)", header(e.Meta), errno, errno.Error())
	}
	return fmt.Sprintf("%s socket fd=%d", header(e.Meta), e.FD)
}

func interpolate(s string) string {
	buf := &bytes.Buffer{}
	if err := template.Must(template.New("").Parse(s)).Execute(buf, constants); err != nil {
		panic(err)
	}
	return buf.String()
}

func registerProbe(
	probe tracing.Probe,
	allocator tracing.AllocateFn,
	debugFS *tracing.TraceFS,
	channel *tracing.PerfChannel) error {

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

	channel, err := tracing.NewPerfChannel(
		tracing.WithBufferSize(4096),
		tracing.WithErrBufferSize(1),
		tracing.WithLostBufferSize(256),
		tracing.WithRingSizeExponent(7),
		tracing.WithPID(perf.AllThreads),
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

	st := stats{
		output: make(chan string, 1024),
	}
	go st.Run(time.Second/4, done)

	if err := channel.Run(); err != nil {
		panic(err)
	}

	const output = true

	for active := true; active; {
		select {
		case iface, ok := <-channel.C():
			if !ok {
				break
			}
			st.Received()
			if output {
				v, ok := iface.(fmt.Stringer)
				if !ok {
					panic(fmt.Sprintf("not a stringer type: %T", iface))
				}
				st.Output(v.String())
			}

		case err := <-channel.ErrC():
			fmt.Fprintf(os.Stderr, "Err received from channel: %v\n", err)
			active = false

		case numLost := <-channel.LostC():
			st.Lost(numLost)
		}
	}
}
