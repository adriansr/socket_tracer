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

	"github.com/acln0/perf"
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
	sampleC chan interface{}
	errC    chan error
	lostC   chan uint64

	// one perf.Event per CPU
	evs []*perf.Event

	running uintptr
	wg      sync.WaitGroup

	// Settings
	sizeSampleC int
	sizeErrC    int
	sizeLostC   int
	mappedPages int
	pid         int
}

type PerfChannelConf func(*PerfChannel) error

// NewPerfChannel creates a new perf channel in order to receive events for
// the given probe ID.
func NewPerfChannel(kprobeID int, cfg ...PerfChannelConf) (channel *PerfChannel, err error) {
	if !perf.Supported() {
		return nil, ErrUnsupported
	}

	// Defaults
	channel = new(PerfChannel)
	channel.sizeSampleC = 1024
	channel.sizeErrC = 8
	channel.sizeLostC = 64
	channel.mappedPages = 1
	channel.pid = perf.AllThreads

	// Set configuration
	for _, fun := range cfg {
		if err := fun(channel); err != nil {
			return nil, err
		}
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

	channel.evs = make([]*perf.Event, runtime.NumCPU())

	flags := unix.PERF_FLAG_FD_CLOEXEC
	for idx := range channel.evs {
		channel.evs[idx], err = perf.OpenWithFlags(attr, channel.pid, idx, nil, flags)
		if err != nil {
			if sysErr, ok := err.(*os.SyscallError); ok && sysErr.Err == unix.EINVAL && (flags&unix.PERF_FLAG_FD_CLOEXEC) != 0 {
				flags &= ^unix.PERF_FLAG_FD_CLOEXEC
				channel.evs[idx], err = perf.OpenWithFlags(attr, channel.pid, idx, nil, flags)
			}
			if err != nil {
				return nil, err
			}
		}
		if flags == 0 {
			fd, err := channel.evs[idx].FD()
			if err != nil {
				return nil, err
			}
			// Warn: no error checking possible
			unix.CloseOnExec(fd)
		}
	}

	channel.done = make(chan struct{}, 0)
	return channel, nil
}

func WithBufferSize(size int) PerfChannelConf {
	return func(channel *PerfChannel) error {
		if size < 0 {
			return fmt.Errorf("bad size for sample channel: %d", size)
		}
		channel.sizeSampleC = size
		return nil
	}
}

func WithErrBufferSize(size int) PerfChannelConf {
	return func(channel *PerfChannel) error {
		if size < 0 {
			return fmt.Errorf("bad size for err channel: %d", size)
		}
		channel.sizeErrC = size
		return nil
	}
}

func WithLostBufferSize(size int) PerfChannelConf {
	return func(channel *PerfChannel) error {
		if size < 0 {
			return fmt.Errorf("bad size for lost channel: %d", size)
		}
		channel.sizeLostC = size
		return nil
	}
}

func WithRingSizeExponent(exp int) PerfChannelConf {
	return func(channel *PerfChannel) error {
		if exp < 0 || exp > 18 {
			return fmt.Errorf("bad exponent for ring buffer: %d", exp)
		}
		channel.mappedPages = 1 << uint(exp)
		return nil
	}
}

func WithPID(pid int) PerfChannelConf {
	return func(channel *PerfChannel) error {
		if pid < -1 {
			return fmt.Errorf("bad pid for ring buffer: %d", pid)
		}
		channel.pid = pid
		return nil
	}
}

func (c *PerfChannel) C() <-chan interface{} {
	return c.sampleC
}

func (c *PerfChannel) ErrC() <-chan error {
	return c.errC
}

func (c *PerfChannel) LostC() <-chan uint64 {
	return c.lostC
}

// Run enables the configured probe and starts receiving perf events.
// sampleC is the channel where decoded perf events are received.
// errC is the channel where errors are received.
//
// The format of the received events depends on the Decoder used.
func (c *PerfChannel) Run(decoder Decoder) error {
	if !atomic.CompareAndSwapUintptr(&c.running, 0, 1) {
		return ErrAlreadyRunning
	}
	c.sampleC = make(chan interface{}, 4096)
	c.errC = make(chan error, 64)
	c.lostC = make(chan uint64, 64)

	for _, ev := range c.evs {
		if err := ev.Enable(); err != nil {
			return errors.Wrap(err, "perf channel enable failed")
		}
		if err := ev.MapRingNumPages(c.mappedPages); err != nil {
			return errors.Wrap(err, "perf channel mapring failed")
		}
		c.wg.Add(1)
		go c.channelLoop(ev, decoder)
	}

	return nil
}

// Close closes the channel.
func (c *PerfChannel) Close() error {
	if !atomic.CompareAndSwapUintptr(&c.running, 1, 2) {
		return ErrNotRunning
	}
	close(c.done)
	c.wg.Wait()
	defer close(c.sampleC)
	defer close(c.errC)
	defer close(c.lostC)
	return nil
}

// doneWrapperContext is a custom context.Context that is tailored to
// perf.Event.ReadRawRecord needs. It's used to avoid an expensive allocation
// before each call to ReadRawRecord while providing termination when
// the wrapped channel closes.
type doneWrapperContext <-chan struct{}

func (ctx doneWrapperContext) Deadline() (deadline time.Time, ok bool) {
	// No deadline
	return deadline, false
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
			return
		}
		if err != nil {
			c.errC <- err
			return
		}
		switch raw.Header.Type {
		case unix.PERF_RECORD_SAMPLE:
			output, err := decoder.Decode(raw.Data)
			if err != nil {
				c.errC <- err
				continue
			}
			c.sampleC <- output

		case unix.PERF_RECORD_LOST:
			var lost uint64
			if len(raw.Data) >= 16 {
				lost = machineEndian.Uint64(raw.Data[8:])
			}
			c.lostC <- lost
		}
	}
}
