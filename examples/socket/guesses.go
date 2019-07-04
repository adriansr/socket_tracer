package main

import (
	"encoding/binary"
	"net"
	"time"

	tracing "github.com/adriansr/socket_tracer"
	"golang.org/x/sys/unix"
)

const (
	magicPort = 0xabcd
	magicIPv4 = 0x7f123456
)

// Number of Qn fields here is tied to fetchBytes
type byteDump32 struct {
	Meta tracing.Metadata `kprobe:"metadata"`
	Q0   uint64           `kprobe:"q0"`
	Q1   uint64           `kprobe:"q1"`
	Q2   uint64           `kprobe:"q2"`
	Q3   uint64           `kprobe:"q3"`
}

var guessStructSockAddrIn = GuessAction{
	Probe: tracing.Probe{
		Name:      "offset_guess",
		Address:   "tcp_v4_connect",
		Fetchargs: "q0=+0(%si):u64 q1=+8(%si):u64 q2=+16(%si):u64 q3=+24(%si):u64",
	},

	Timeout: time.Second * 5,

	Decoder: func(description tracing.ProbeDescription) (decoder tracing.Decoder, e error) {
		return tracing.NewStructDecoder(description, func() interface{} {
			return new(byteDump32)
		})
	},

	Validate: func(ev interface{}) (GuessResult, bool) {
		const fetchBytes = 32
		str, ok := ev.(*byteDump32)
		if !ok {
			return nil, false
		}
		arr := str.ToArray()

		if tracing.MachineEndian.Uint16(arr[0:2]) != unix.AF_INET {
			return nil, false
		}

		var off int
		for off = 2; off <= fetchBytes-2; off += 2 {
			if binary.BigEndian.Uint16(arr[off:]) == magicPort {
				break
			}
		}
		if off > fetchBytes-2 {
			return nil, false
		}
		offsetOfPort := off

		for off = 2; off <= fetchBytes-4; off += 2 {
			if binary.BigEndian.Uint32(arr[off:]) == magicIPv4 {
				break
			}
		}
		if off > fetchBytes-4 {
			return nil, false
		}
		offsetOfAddr := off
		return GuessResult{
			"SOCKADDR_IN_PORT": offsetOfPort,
			"SOCKADDR_IN_ADDR": offsetOfAddr,
		}, true
	},

	Trigger: func(timeout time.Duration) {
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
	},
}

func (d *byteDump32) ToArray() (array [32]byte) {
	tracing.MachineEndian.PutUint64(array[0:8], d.Q0)
	tracing.MachineEndian.PutUint64(array[8:16], d.Q1)
	tracing.MachineEndian.PutUint64(array[16:24], d.Q2)
	tracing.MachineEndian.PutUint64(array[24:32], d.Q3)
	return
}
