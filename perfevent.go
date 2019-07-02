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
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
	"golang.org/x/sys/unix/linux/perf"
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

type stream struct {
	decoder Decoder
	probeID int
}

// PerfChannel represents a channel to receive perf events.
type PerfChannel struct {
	done    chan struct{}
	sampleC chan interface{}
	errC    chan error
	lostC   chan uint64

	// one perf.Event per CPU
	evs     []*perf.Event
	streams map[uint64]stream

	running uintptr
	wg      sync.WaitGroup

	// Settings
	attr        perf.Attr
	sizeSampleC int
	sizeErrC    int
	sizeLostC   int
	mappedPages int
	pid         int
	withTime    bool
}

type PerfChannelConf func(*PerfChannel) error

type Metadata struct {
	StreamID  uint64
	CPU       uint64
	Timestamp uint64

	// PID is really the TID. Both in the header and the probe raw data.
	TID uint32

	EventID int
}

// NewPerfChannel creates a new perf channel in order to receive events for
// the given probe ID.
func NewPerfChannel(cfg ...PerfChannelConf) (channel *PerfChannel, err error) {
	if !perf.Supported() {
		return nil, ErrUnsupported
	}

	// Defaults
	channel = &PerfChannel{
		sizeSampleC: 1024,
		sizeErrC:    8,
		sizeLostC:   64,
		mappedPages: 1,
		done:        make(chan struct{}, 0),
		streams:     make(map[uint64]stream),
		pid:         perf.AllThreads,
		attr: perf.Attr{
			Type: perf.TracepointEvent,
			SampleFormat: perf.SampleFormat{
				Raw:      true,
				StreamID: true,
				Tid:      true,
				CPU:      true,
			},
		},
	}
	channel.attr.SetSamplePeriod(1)
	channel.attr.SetWakeupEvents(1)

	// Set configuration
	for _, fun := range cfg {
		if err := fun(channel); err != nil {
			return nil, err
		}
	}
	return channel, nil
}

func (c *PerfChannel) MonitorProbe(desc ProbeDescription, decoder Decoder) error {
	c.attr.Config = uint64(desc.ID)
	doGroup := len(c.evs) > 0
	for idx := 0; idx < runtime.NumCPU(); idx++ {
		var group *perf.Event
		var flags int
		if doGroup {
			group = c.evs[idx]
			flags = unix.PERF_FLAG_FD_NO_GROUP | unix.PERF_FLAG_FD_OUTPUT
		}
		ev, err := perf.OpenWithFlags(&c.attr, c.pid, idx, group, flags)
		if err != nil {
			return err
		}
		cid, err := ev.ID()
		if err != nil {
			return err
		}
		fd, err := ev.FD()
		if err != nil {
			return err
		}
		if len(desc.Probe.Filter) > 0 {
			fbytes := []byte(desc.Probe.Filter + "\x00")
			_, _, errNo := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.PERF_EVENT_IOC_SET_FILTER, uintptr(unsafe.Pointer(&fbytes[0])))
			if errNo != 0 {
				return errors.Wrapf(errNo, "unable to set filter '%s'", desc.Probe.Filter)
			}
		}
		fmt.Fprintf(os.Stderr, "Registered channel ID: %d probe: %d CPU: %d\n", cid, desc.ID, idx)
		c.streams[cid] = stream{probeID: desc.ID, decoder: decoder}
		c.evs = append(c.evs, ev)

		if !doGroup {
			if err := ev.MapRingNumPages(c.mappedPages); err != nil {
				return errors.Wrap(err, "perf channel mapring failed")
			}
		}
	}
	return nil
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

func WithTimestamp() PerfChannelConf {
	return func(channel *PerfChannel) error {
		channel.attr.SampleFormat.Time = true
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
func (c *PerfChannel) Run() error {
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
	}
	for nCPU := 0; nCPU < runtime.NumCPU(); nCPU++ {
		c.wg.Add(1)
		go c.channelLoop(c.evs[nCPU])
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

var errMsgTooSmall = errors.New("perf event too small to parse")

func makeMetadata(eventID int, record *perf.SampleRecord) Metadata {
	return Metadata{
		StreamID:  record.StreamID,
		Timestamp: record.Time,
		TID:       record.Tid,
		EventID:   eventID,
	}
}

func (c *PerfChannel) channelLoop(ev *perf.Event) {
	defer c.wg.Done()
	defer ev.Close()
	defer ev.Disable()

	ctx := doneWrapperContext(c.done)

	for {
		record, err := ev.ReadRecord(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			c.errC <- err
			return
		}
		header := record.Header()
		switch header.Type {
		case unix.PERF_RECORD_SAMPLE:
			sample, ok := record.(*perf.SampleRecord)
			if !ok {
				c.errC <- errors.New("PERF_RECORD_SAMPLE is not a *perf.SampleRecord")
				return
			}
			stream := c.streams[sample.StreamID]
			if stream.decoder == nil {
				c.errC <- fmt.Errorf("no decoder for stream:%d", sample.StreamID)
				continue
			}
			meta := makeMetadata(stream.probeID, sample)
			output, err := stream.decoder.Decode(sample.Raw, meta)
			if err != nil {
				c.errC <- err
				continue
			}
			c.sampleC <- output

		case unix.PERF_RECORD_LOST:
			lost, ok := record.(*perf.LostRecord)
			if !ok {
				c.errC <- errors.New("PERF_RECORD_LOST is not a *perf.LostRecord")
				return
			}
			c.lostC <- lost.Lost
		}
	}
}
