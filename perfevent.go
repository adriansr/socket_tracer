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
	attr.SampleFormat = perf.SampleFormat{
		// Careful, Adding more fields here changes the raw data format.
		// Time: true,
		Raw: true,
	}

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
	if err := c.ev.MapRingNumPages(2); err != nil {
		return nil, nil, errors.Wrap(err, "perf channel mapring failed")
	}
	sC := make(chan interface{}, 4096)
	eC := make(chan error, 64)
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

func channelLoop(ev *perf.Event, decoder Decoder, sampleC chan<- interface{}, errC chan<- error, done <-chan struct{}) {
	defer ev.Close()
	defer ev.Disable()
	defer close(sampleC)
	defer close(errC)

	go statsLoop(done)

mainloop:
	for {
		//fmt.Fprintf(os.Stderr, "Reading samples... (count=%d lost=%d)\n",
		//	atomic.LoadUint64(&recvCount), atomic.LoadUint64(&lostCount))
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
		switch raw.Header.Type {
		case unix.PERF_RECORD_SAMPLE:
			atomic.AddUint64(&recvCount, 1)
			output, err := decoder.Decode(raw.Data)
			if err != nil {
				if false {
					errC <- err
				}
				continue
			}
			if false {
				sampleC <- output
			}
			//time.Sleep(5 * time.Second)

		case unix.PERF_RECORD_LOST:
			//fmt.Fprintf(os.Stderr, "Got lost: %+v\n%s\n", raw.Header, hex.Dump(raw.Data))
			var lost uint64 = 1
			if len(raw.Data) >= 16 {
				lost = machineEndian.Uint64(raw.Data[8:])
			}
			atomic.AddUint64(&lostCount, lost)
			//return
		}
	}
}
