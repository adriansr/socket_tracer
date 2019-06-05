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
	// ErrUnsupported error indicates that perf_event_open is not available
	// in the current kernel.
	ErrUnsupported = errors.New("perf_event_open is not supported by this kernel")

	// ErrAlreadyRunning error is returned when a PerfChannel has already
	// started after a call to run.
	ErrAlreadyRunning = errors.New("channel already running")

	// ErrNotRunning error is returned by PerfChannel#Close when it has not been
	// started.
	ErrNotRunning = errors.New("channel not running")
)

// PerfChannel represents a channel to receive perf events.
type PerfChannel struct {
	done    chan struct{}
	ev      *perf.Event
	running uintptr
}

// NewPerfChannel creates a new perf channel in order to receive events for
// the given probe ID.
func NewPerfChannel(kprobeID int) (channel *PerfChannel, err error) {
	if !perf.Supported() {
		return nil, ErrUnsupported
	}

	attr := new(perf.Attr)
	attr.Type = perf.TracepointEvent
	attr.SetSamplePeriod(1)
	attr.SetWakeupEvents(1)
	attr.Config = uint64(kprobeID)
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

// Run enables the configured probe and starts receiving perf events.
// sampleC is the channel where decoded perf events are received.
// errC is the channel where errors are received.
//
// The format of the received events depends on the Decoder used.
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

// Close closes the channel.
func (c *PerfChannel) Close() error {
	if !atomic.CompareAndSwapUintptr(&c.running, 1, 2) {
		return ErrNotRunning
	}
	close(c.done)
	return nil
}

func channelLoop(ev *perf.Event, decoder Decoder, sampleC chan<- interface{}, errC chan<- error, done <-chan struct{}) {
	defer ev.Close()
	defer ev.Disable()
	defer close(sampleC)
	defer close(errC)

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
