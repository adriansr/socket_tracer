package main

import (
	"encoding/binary"
	"net"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	tracing "github.com/adriansr/socket_tracer"
)

const (
	magicPort  = 0xabcd
	magicIPv4  = 0x7f123456
	fetchBytes = 32
)

// Number of Qn fields here is tied to fetchBytes
type rawSockaddrIn struct {
	Meta tracing.Metadata `kprobe:"metadata"`
	Q0   uint64           `kprobe:"q0"`
	Q1   uint64           `kprobe:"q1"`
	Q2   uint64           `kprobe:"q2"`
	Q3   uint64           `kprobe:"q3"`
}

type structSockAddrInOffsets struct {
	offsetOfPort int
	offsetOfAddr int
}

func isMagicConnect(ev *rawSockaddrIn) (offs structSockAddrInOffsets, valid bool) {
	var arr [fetchBytes]byte
	tracing.MachineEndian.PutUint64(arr[0:8], ev.Q0)
	tracing.MachineEndian.PutUint64(arr[8:16], ev.Q1)
	tracing.MachineEndian.PutUint64(arr[16:24], ev.Q2)
	tracing.MachineEndian.PutUint64(arr[24:32], ev.Q3)

	if tracing.MachineEndian.Uint16(arr[0:2]) != unix.AF_INET {
		return offs, false
	}

	var off int
	for off = 2; off <= fetchBytes-2; off += 2 {
		if binary.BigEndian.Uint16(arr[off:]) == magicPort {
			break
		}
	}
	if off > fetchBytes-2 {
		return offs, false
	}
	offs.offsetOfPort = off

	for off = 2; off <= fetchBytes-4; off += 2 {
		if binary.BigEndian.Uint32(arr[off:]) == magicIPv4 {
			break
		}
	}
	if off > fetchBytes-4 {
		return offs, false
	}
	offs.offsetOfAddr = off
	return offs, true
}

func guessStructSockaddrIn(tfs *tracing.TraceFS) (offs structSockAddrInOffsets, err error) {
	probe := tracing.Probe{
		Name:      "offset_guess",
		Address:   "tcp_v4_connect",
		Fetchargs: "q0=+0(%si):u64 q1=+8(%si):u64 q2=+16(%si):u64 q3=+24(%si):u64",
	}

	if err := tfs.AddKProbe(probe); err != nil {
		return offs, errors.Wrapf(err, "failed to add kprobe '%s'", probe.String())
	}
	defer tfs.RemoveKProbe(probe)

	descr, err := tfs.LoadProbeDescription(probe)
	if err != nil {
		return offs, errors.Wrapf(err, "failed to load kprobe '%s' description", probe.String())
	}

	decoder, err := tracing.NewStructDecoder(descr, func() interface{} {
		return new(rawSockaddrIn)
	})
	if err != nil {
		return offs, errors.Wrap(err, "failed to create decoder")
	}

	timeout := time.Second * 5

	tidChan := make(chan int, 0)
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		tidChan <- syscall.Gettid()
		wg.Wait()

		dialer := net.Dialer{
			Timeout: timeout,
		}
		addr := net.TCPAddr{
			IP:   net.IPv4(magicIPv4>>24, (magicIPv4>>16)&0xff, (magicIPv4>>8)&0xff, magicIPv4&0xff),
			Port: magicPort,
		}
		conn, err := dialer.Dial("tcp", addr.String())
		if err == nil {
			conn.Close()
		}
	}()

	tid := <-tidChan

	perfchan, err := tracing.NewPerfChannel(
		tracing.WithBufferSize(8),
		tracing.WithErrBufferSize(1),
		tracing.WithLostBufferSize(8),
		tracing.WithRingSizeExponent(2),
		tracing.WithPID(tid))
	if err != nil {
		return offs, errors.Wrap(err, "failed to create perfchannel")
	}
	defer perfchan.Close()

	if err := perfchan.MonitorProbe(descr, decoder); err != nil {
		return offs, errors.Wrap(err, "failed to monitor probe")
	}

	if err := perfchan.Run(); err != nil {
		return offs, errors.Wrap(err, "failed to run perf channel")
	}

	timer := time.NewTimer(timeout)

	defer func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}()

	wg.Done()

	for {
		select {
		case <-timer.C:
			return offs, errors.New("timeout while waiting for event")

		case ev, ok := <-perfchan.C():
			if !ok {
				return offs, errors.New("perf channel closed unexpectedly")
			}
			str, ok := ev.(*rawSockaddrIn)
			if !ok {
				return offs, errors.New("unexpected event type")
			}
			if offs, ok = isMagicConnect(str); !ok {
				continue
			}
			return offs, nil

		case err := <-perfchan.ErrC():
			if err != nil {
				return offs, errors.Wrap(err, "error received from perf channel")
			}

		case <-perfchan.LostC():
			return offs, errors.Wrap(err, "event loss in perf channel")
		}
	}
}
