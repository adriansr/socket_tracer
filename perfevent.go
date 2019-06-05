// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package socket_tracer

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"acln.ro/perf"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

var (
	ErrUnsupported    = errors.New("perf_event_open is not supported by this kernel")
	ErrAlreadyRunning = errors.New("channel already running")
	ErrNotRunning     = errors.New("channel not running")
)

type PerfChannel struct {
	done    chan struct{}
	ev      *perf.Event
	running uintptr
}

func NewPerfChannel(kprobe KProbeDesc) (channel *PerfChannel, err error) {
	if !perf.Supported() {
		return nil, ErrUnsupported
	}

	attr := new(perf.Attr)
	attr.Type = perf.TracepointEvent
	attr.SetSamplePeriod(1)
	attr.SetWakeupEvents(1)
	attr.Config = uint64(kprobe.ID)
	attr.SampleFormat = perf.SampleFormat{Raw: true}

	// TODO: #CPU?
	ev, err := perf.Open(attr, perf.AllThreads, 0, nil)
	if err != nil {
		return nil, err
	}

	channel = new(PerfChannel)
	channel.ev = ev
	channel.done = make(chan struct{})
	return channel, nil
}

func (c *PerfChannel) Run(decoder Decoder) (sampleC <-chan interface{}, errC <-chan error, err error) {
	if !atomic.CompareAndSwapUintptr(&c.running, 0, 1) {
		return nil, nil, ErrAlreadyRunning
	}
	if err := c.ev.Enable(); err != nil {
		atomic.StoreUintptr(&c.running, 0)
		return nil, nil, errors.Wrap(err, "perf channel enable failed")
	}
	if err := c.ev.MapRing(); err != nil {
		return nil, nil, errors.Wrap(err, "perf channel mapring failed")
	}
	sC := make(chan interface{})
	eC := make(chan error, 1)
	go channelLoop(c.ev, decoder, sC, eC, c.done)
	return sC, eC, nil
}

func (c *PerfChannel) Close() error {
	if !atomic.CompareAndSwapUintptr(&c.running, 1, 0) {
		return ErrNotRunning
	}
	close(c.done)
	return nil
}

func channelLoop(ev *perf.Event, decoder Decoder, sampleC chan<- interface{}, errC chan<- error, done <-chan struct{}) {
	defer ev.Close()
	defer ev.Disable()

mainloop:
	for {
		fmt.Fprintf(os.Stderr, "Reading samples...\n")
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second))
		var raw perf.RawRecord
		err := ev.ReadRawRecord(ctx, &raw)
		if ctx.Err() != nil {
			continue
		}
		cancel()
		if err != nil {
			errC <- err
			break
		}
		select {
		case <-done:
			break mainloop
		default:
		}
		if raw.Header.Type != unix.PERF_RECORD_SAMPLE {
			continue
		}

		output, err := decoder.Decode(raw.Data)
		if err != nil {
			errC <- err
			continue
		}
		sampleC <- output
	}
}
