// +build ignore

package main

import "C"
import (
	"context"
	"fmt"
	"os"
	"unsafe"

	"acln.ro/perf"
)
const KProbeEvent perf.EventType = 6 // unix.PERF_TYPE_KPROBE

const (
	KProbeConfig uint64 = iota
	KRetProbeConfig
)

func main() {
	if !perf.Supported() {
		panic("perf_event_open not supported by this kernel")
	}

	attr := new(perf.Attr)
	//if err := perf.Tracepoint("syscalls", "sys_enter_connect").Configure(attr); err != nil {
	//	panic(err)
	//}

	kFnName := []byte("sys_socket")
	kFnName = append(kFnName, 0)
	kFnNamePtr := uint64(uintptr(unsafe.Pointer(&kFnName[0])))
	attr.Type = KProbeEvent
	attr.Config = KProbeConfig
	attr.Options = perf.Options{

	}
	attr.SetSamplePeriod(1)
	attr.SetWakeupEvents(1)
	attr.Config1 = kFnNamePtr // Name of Kprobe
	attr.Config2 = 0 // Offset for Kprobe

	// attr.Label = ...
	//fmt.Fprintf(os.Stderr, "> attr = %+v\n", *attr)
	z := attr.SysAttr()
	fmt.Fprintf(os.Stderr, "> attr = %+v\n", z)

	ev, err := perf.Open(attr, perf.AllThreads, 0, nil)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := ev.Close(); err != nil {
			panic(err)
		}
	}()

	if err := ev.Enable(); err != nil {
		panic(err)
	}
	defer func() {
		if err := ev.Disable(); err != nil {
			panic(err)
		}
	}()

	if err := ev.MapRing(); err != nil {
		panic(err)
	}

	for {
		fmt.Fprintf(os.Stderr, "Reading records...\n")
		//ctx, _ := context.WithTimeout(context.Background(), time.Second)
		ctx := context.Background()
		record, err := ev.ReadRecord(ctx)
		if err != nil {
			panic(err)
		}

		if s, ok := record.(*perf.SampleRecord); ok {
			fmt.Fprintf(os.Stderr,"Got sample record %+v\n", v)
		}
		switch v := record.(type) {
		case *perf.SampleRecord:
			fmt.Fprintf(os.Stderr,"Got sample record %+v\n", v)
		case *perf.SampleGroupRecord:
			fmt.Fprintf(os.Stderr,"Got sample group record %+v\n", v)
		default:
			fmt.Fprintf(os.Stderr,"Got unknown record %+v\n", record.Header())
		}

	}
}
