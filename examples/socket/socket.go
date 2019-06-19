package main

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix/linux/perf"

	tracing "github.com/adriansr/socket_tracer"
)

func main() {
	evs := tracing.NewEventTracing(tracing.DefaultDebugFSPath)
	probe := tracing.Probe{
		Type:    tracing.TypeKRetProbe,
		Name:    "connect",
		Address: "sys_connect",
		//Fetchargs: "path=+0(%di):string flags=%si mode=%cx",
	}
	err := evs.AddKProbe(probe)
	if err != nil {
		panic(err)
	}
	defer evs.RemoveKProbe(probe)
	desc, err := evs.LoadProbeFormat(probe)
	if err != nil {
		panic(err)
	}

	fmt.Fprintf(os.Stderr, "Installed probe %d\n", desc.ID)

	type connectEvent struct {
		Meta tracing.Meta `kprobe:"metadata"`
		PID  uint32       `kprobe:"common_pid"`
	}
	var allocFn = func() interface{} {
		return new(connectEvent)
	}
	decoder, err := tracing.NewStructDecoder(desc, allocFn)
	if err != nil {
		panic(err)
	}

	channel, err := tracing.NewPerfChannel(desc.ID,
		tracing.WithBufferSize(4096),
		tracing.WithErrBufferSize(1),
		tracing.WithLostBufferSize(256),
		tracing.WithRingSizeExponent(5),
		tracing.WithPID(perf.AllThreads),
		tracing.WithTimestamp())
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := channel.Close(); err != nil {
			panic(err)
		}
	}()

	if err := channel.Run(decoder); err != nil {
		panic(err)
	}

	done := make(chan struct{}, 0)
	defer close(done)

	st := stats{
		output: make(chan string, 1024),
	}
	go st.Run(time.Second/4, done)

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
				st.Output(fmt.Sprintf("%v pid=%d connect()", t.ToTime(v.Meta.Timestamp).Format(time.RFC3339Nano), v.PID))
			}

		case err := <-channel.ErrC():
			fmt.Fprintf(os.Stderr, "Err received from channel: %v\n", err)
			active = false

		case numLost := <-channel.LostC():
			st.Lost(numLost)
		}
	}
}
