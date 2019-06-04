// +build ignore

package main

import "C"
import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"

	"acln.ro/perf"
)

func main() {
	if !perf.Supported() {
		panic("perf_event_open not supported by this kernel")
		//fmt.Fprintf(os.Stderr, "WARNING: perf_event_open might not be supported")
	}
	if len(os.Args) != 2 {
		panic(len(os.Args))
	}
	probeID, err := strconv.Atoi(os.Args[1])
	if err != nil {
		panic(err)
	}

	attr := new(perf.Attr)
	/*
	        struct perf_event_attr attr = {0,};
	        attr.type = PERF_TYPE_TRACEPOINT;
	        attr.sample_type = PERF_SAMPLE_RAW;
	        attr.sample_period = 1;
	        attr.wakeup_events = 1;
	        attr.config = tracepoint_id;
	*/
	attr.Type = perf.TracepointEvent
	attr.SetSamplePeriod(1)
	attr.SetWakeupEvents(1)
	attr.Config = uint64(probeID)
	attr.SampleFormat = perf.SampleFormat{
		//IntrRegisters: true,
		//CPU: true,
		//Addr: true,
		Raw: true,
		//IntrRegisters: true,
	}

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
		/*record, err := ev.ReadRecord(ctx)
		if err != nil {
			panic(err)
		}

		if s, ok := record.(*perf.SampleRecord); ok {
			s.
			fmt.Fprintf(os.Stderr,"Got sample record %+v\n", s)
		} else {
			fmt.Fprintf(os.Stderr, "Got record %+v\n", record.Header())
		}
		*/
			var raw perf.RawRecord
		if err := ev.ReadRawRecord(ctx, &raw); err != nil {
			panic(err)
		}
		fmt.Fprintf(os.Stderr, "raw event %+v:\n%s\n", raw.Header, hex.Dump(raw.Data))
	}
}
