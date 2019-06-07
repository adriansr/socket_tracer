package main

import (
	"fmt"
	"os"
	"time"

	tracing "github.com/adriansr/socket_tracer"
)

func main() {

	evs := tracing.NewEventTracing(tracing.DefaultDebugFSPath)
	if err := evs.RemoveAllKProbes(); err != nil {
		panic(err)
	}
	probe := tracing.KProbe{
		Name:      "test_kprobe",
		Address:   "sys_accept",
		Fetchargs: "ax=%ax bx=%bx:u8 cx=%cx:u32 dx=%dx:s16",
	}
	err := evs.AddKProbe(probe)
	if err != nil {
		panic(err)
	}
	desc, err := evs.LoadKProbeFormat(probe)
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

	channel, err := tracing.NewPerfChannel(desc.ID)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := channel.Close(); err != nil {
			panic(err)
		}
	}()

	sampleC, errC, err := channel.Run(decoder)
	if err != nil {
		panic(err)
	}

	for active := true; active; {
		select {
		case iface, ok := <-sampleC:
			if !ok {
				break
			}
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

		case err := <-errC:
			fmt.Fprintf(os.Stderr, "Err received from channel:", err)
			active = false
		}
	}
}
