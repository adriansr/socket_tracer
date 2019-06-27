package main

import (
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	tracer "github.com/adriansr/socket_tracer"
)

type fn struct {
	f func(string) string
}

func main() {
	if len(os.Args) > 1 {
		fmt.Fprintf(os.Stderr, "%s\n", strings.ToLower("HoLa Ke ASe?"))
		return
	}
	exe, err := os.Executable()
	if err != nil {
		panic(err)
	}
	ff := fn{f: strings.ToLower}
	ptr := **(**uintptr)(unsafe.Pointer(&ff))
	uprobe := tracer.Probe{
		Type:      tracer.TypeUProbe,
		Name:      "self",
		Address:   fmt.Sprintf("%s:0x%x", exe, ptr-0x400000),
		Fetchargs: "strlen=+0x10(%sp)",
	}
	fmt.Fprintf(os.Stderr, "XXX PROBE: %s\n", uprobe.String())
	evs, err := tracer.NewDebugFS()
	if err != nil {
		panic(err)
	}
	if err := evs.AddUProbe(uprobe); err != nil {
		panic(err)
	}
	defer evs.RemoveUProbe(uprobe)
	format, err := evs.LoadProbeFormat(uprobe)
	if err != nil {
		panic(err)
	}
	decoder := tracer.NewMapDecoder(format)
	channel, err := tracer.NewPerfChannel(format.ID)
	if err != nil {
		panic(err)
	}
	if err := channel.Run(decoder); err != nil {
		panic(err)
	}

	go func() {
		time.Sleep(4 * time.Second)
		fmt.Fprintf(os.Stderr, "%s\n", strings.ToLower("HoLa Ke ASe?"))
	}()
	for active := true; active; {
		select {
		case iface, ok := <-channel.C():
			if !ok {
				break
			}
			data := iface.(map[string]interface{})
			_, err = fmt.Fprintf(os.Stderr, "Got event len=%d\n", len(data))
			if err != nil {
				panic(err)
			}

			fmt.Fprintf(os.Stderr, "%s event:\n", time.Now().Format(time.RFC3339Nano))
			for k := range format.Fields {
				v := data[k]
				fmt.Fprintf(os.Stderr, "    %s: %v\n", k, v)
			}
			if raw, ok := data["_raw_"]; ok {
				fmt.Fprintf(os.Stderr, "    raw:\n%s\n", raw)
			}

		case err := <-channel.ErrC():
			fmt.Fprintf(os.Stderr, "Err received from channel: %v\n", err)
			active = false

		case <-channel.LostC():
		}
	}
}
