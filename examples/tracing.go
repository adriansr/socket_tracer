package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix/linux/perf"

	tracing "github.com/adriansr/socket_tracer"
)

var recvCount, lostCount uint64

func statsLoop(done <-chan struct{}) {

	lastRecv := atomic.LoadUint64(&recvCount)
	lastLost := atomic.LoadUint64(&lostCount)
	lastCheck := time.Now()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for t := range ticker.C {
		select {
		case <-done:
			return
		default:
		}

		elapsed := t.Sub(lastCheck)
		recv := atomic.LoadUint64(&recvCount)
		lost := atomic.LoadUint64(&lostCount)

		fmt.Fprintf(os.Stderr, "Read %d lost %d (%.01f eps / %.01f lps)\n",
			recv, lost,
			float64(recv-lastRecv)/elapsed.Seconds(),
			float64(lost-lastLost)/elapsed.Seconds())

		lastCheck, lastRecv, lastLost = t, recv, lost
	}
}

func main() {
	evs, err := tracing.NewDebugFS()
	if err != nil {
		panic(err)
	}
	probe := tracing.Probe{
		Name:      "test_kprobe",
		Address:   "sys_open",
		Fetchargs: "path=+0(%di):string flags=%si mode=%cx",
	}
	err = evs.AddKProbe(probe)
	if err != nil {
		panic(err)
	}
	defer evs.RemoveKProbe(probe)
	desc, err := evs.LoadProbeFormat(probe)
	if err != nil {
		panic(err)
	}

	var decoder tracing.Decoder
	const useStructDecoder = false
	if useStructDecoder {
		type myStruct struct {
			//Exe string `kprobe:"exe"`
			PID uint32 `kprobe:"common_pid"`
			AX  int64  `kprobe:"ax"`
			BX  uint8  `kprobe:"bx"`
			CX  int32  `kprobe:"cx"`
			DX  uint16 `kprobe:"dx"`
		}
		var allocFn = func() interface{} {
			return new(myStruct)
		}
		if decoder, err = tracing.NewStructDecoder(desc, allocFn); err != nil {
			panic(err)
		}
	} else {
		decoder = tracing.NewMapDecoder(desc)
	}

	channel, err := tracing.NewPerfChannel(desc.ID,
		tracing.WithBufferSize(4096),
		tracing.WithErrBufferSize(1),
		tracing.WithLostBufferSize(256),
		tracing.WithRingSizeExponent(0),
		tracing.WithPID(perf.AllThreads))

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
	go statsLoop(done)

	go func() {
		time.Sleep(time.Second * 3)
		f, err := os.Open("/proc/sys/kernel/perf_event_paranoid")
		if err != nil {
			panic(err)
		}
		defer f.Close()
		cnt, err := ioutil.ReadAll(f)
		if err != nil {
			panic(err)
		}
		fmt.Fprintf(os.Stderr, "YYY: paranoid: %s\n", string(cnt))
	}()

	for active := true; active; {
		select {
		case iface, ok := <-channel.C():
			if !ok {
				break
			}
			atomic.AddUint64(&recvCount, 1)
			data := iface.(map[string]interface{})
			_, err = fmt.Fprintf(os.Stderr, "Got event len=%d\n", len(data))
			if err != nil {
				panic(err)
			}

			fmt.Fprintf(os.Stderr, "%s event:\n", time.Now().Format(time.RFC3339Nano))
			for k := range desc.Fields {
				v := data[k]
				fmt.Fprintf(os.Stderr, "    %s: %v\n", k, v)
			}
			fmt.Fprintf(os.Stderr, "    raw:\n%s\n", data["_raw_"])

		case err := <-channel.ErrC():
			fmt.Fprintf(os.Stderr, "Err received from channel: %v\n", err)
			active = false

		case numLost := <-channel.LostC():
			atomic.AddUint64(&lostCount, numLost)
		}
	}
}
