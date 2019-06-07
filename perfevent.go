// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package socket_tracer

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
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
	sC      chan interface{}
	eC      chan error
	evs     []*perf.Event
	running uintptr
	wg      sync.WaitGroup
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
	attr.SampleFormat = perf.SampleFormat{
		// Careful, Adding more fields here changes the raw data format.
		// Time: true,
		Raw: true,
	}

	evs := make([]*perf.Event, runtime.NumCPU())
	for idx := range evs {
		evs[idx], err = perf.Open(attr, perf.AllThreads, idx, nil)
		if err != nil {
			return nil, err
		}
	}

	channel = new(PerfChannel)
	channel.evs = evs
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
	c.sC = make(chan interface{}, 4096)
	c.eC = make(chan error, 64)

	for _, ev := range c.evs {
		if err := ev.Enable(); err != nil {
			return nil, nil, errors.Wrap(err, "perf channel enable failed")
		}
		if err := ev.MapRingNumPages(128); err != nil {
			return nil, nil, errors.Wrap(err, "perf channel mapring failed")
		}
		c.wg.Add(1)
		go c.channelLoop(ev, decoder)
	}

	go statsLoop(c.done)

	return c.sC, c.eC, nil
}

// Close closes the channel.
func (c *PerfChannel) Close() error {
	if !atomic.CompareAndSwapUintptr(&c.running, 1, 2) {
		return ErrNotRunning
	}
	close(c.done)
	c.wg.Wait()
	defer close(c.sC)
	defer close(c.eC)
	return nil
}

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

type doneWrapperContext <-chan struct{}

func (ctx doneWrapperContext) Deadline() (deadline time.Time, ok bool) {
	return time.Time{}, false
}

func (ctx doneWrapperContext) Done() <-chan struct{} {
	return (<-chan struct{})(ctx)
}

func (ctx doneWrapperContext) Err() error {
	select {
	case <-ctx.Done():
		return context.Canceled
	default:
	}
	return nil
}

func (ctx doneWrapperContext) Value(key interface{}) interface{} {
	return nil
}

func (c *PerfChannel) channelLoop(ev *perf.Event, decoder Decoder) {
	defer c.wg.Done()
	defer ev.Close()
	defer ev.Disable()

	ctx := doneWrapperContext(c.done)

	for {
		var raw perf.RawRecord
		err := ev.ReadRawRecord(ctx, &raw)
		if ctx.Err() != nil {
			fmt.Fprintf(os.Stderr, "Read loop terminated\n")
			break
		}
		if err != nil {
			c.eC <- err
			break
		}
		switch raw.Header.Type {
		case unix.PERF_RECORD_SAMPLE:
			output, err := decoder.Decode(raw.Data)
			atomic.AddUint64(&recvCount, 1)
			if err != nil {
				if false {
					c.eC <- err
				}
				continue
			}
			if false {
				c.sC <- output
			}

		case unix.PERF_RECORD_LOST:
			var lost uint64 = 1
			if len(raw.Data) >= 16 {
				lost = machineEndian.Uint64(raw.Data[8:])
			}
			atomic.AddUint64(&lostCount, lost)
		}
	}
}
