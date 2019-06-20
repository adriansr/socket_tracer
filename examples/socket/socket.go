package main

import (
	"fmt"
	"os"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix/linux/perf"

	tracing "github.com/adriansr/socket_tracer"
)

type connectEvent struct {
	Meta tracing.Metadata `kprobe:"metadata"`
	PID  uint32           `kprobe:"common_pid"`
}
type acceptEvent struct {
	Meta tracing.Metadata `kprobe:"metadata"`
	PID  uint32           `kprobe:"common_pid"`
}

func registerProbe(
	probe tracing.Probe,
	allocator tracing.AllocateFn,
	debugFS *tracing.DebugFS,
	channel *tracing.PerfChannel) error {

	err := debugFS.AddKProbe(probe)
	if err != nil {
		return errors.Wrapf(err, "unable to register probe %s", probe.String())
	}
	desc, err := debugFS.LoadProbeFormat(probe)
	if err != nil {
		return errors.Wrapf(err, "unable to get format of probe %s", probe.String())
	}

	decoder, err := tracing.NewStructDecoder(desc, allocator)
	if err != nil {
		return errors.Wrapf(err, "unable to build decoder for probe %s", probe.String())
	}
	if err := channel.MonitorProbe(desc.ID, decoder); err != nil {
		return errors.Wrapf(err, "unable to monitor probe %s", probe.String())
	}
	return nil
}

func main() {
	debugFS := tracing.NewDebugFS()
	channel, err := tracing.NewPerfChannel(
		tracing.WithBufferSize(4096),
		tracing.WithErrBufferSize(1),
		tracing.WithLostBufferSize(256),
		tracing.WithRingSizeExponent(5),
		tracing.WithPID(perf.AllThreads),
		tracing.WithTimestamp())
	if err != nil {
		panic(err)
	}

	for _, p := range []struct {
		probe tracing.Probe
		alloc tracing.AllocateFn
	}{
		{
			probe: tracing.Probe{
				Type:    tracing.TypeKRetProbe,
				Name:    "connect",
				Address: "sys_connect",
			},
			alloc: func() interface{} {
				return new(connectEvent)
			},
		},
		{
			probe: tracing.Probe{
				Type:    tracing.TypeKRetProbe,
				Name:    "accept",
				Address: "sys_accept",
			},
			alloc: func() interface{} {
				return new(acceptEvent)
			},
		},
	} {
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

	var t TimeReference
	for active := true; active; {
		select {
		case iface, ok := <-channel.C():
			if !ok {
				break
			}
			st.Received()
			switch v := iface.(type) {
			case *connectEvent:
				st.Output(fmt.Sprintf("%v pid=%d [%d] connect()", t.ToTime(v.Meta.Timestamp).Format(time.RFC3339Nano), v.PID, v.Meta.EventID))
			case *acceptEvent:
				st.Output(fmt.Sprintf("%v pid=%d [%d] accept()", t.ToTime(v.Meta.Timestamp).Format(time.RFC3339Nano), v.PID, v.Meta.EventID))
			}

		case err := <-channel.ErrC():
			fmt.Fprintf(os.Stderr, "Err received from channel: %v\n", err)
			active = false

		case numLost := <-channel.LostC():
			st.Lost(numLost)
		}
	}
}
