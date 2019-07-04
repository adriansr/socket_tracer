package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	tracing "github.com/adriansr/socket_tracer"
	"golang.org/x/sys/unix"
)

const (
	magicPort = 0xabcd
	magicIPv4 = 0x7f123456
)

func makeDump(param string, from, to int) string {
	var params []string
	for off := from; off < to; off += 8 {
		params = append(params, fmt.Sprintf("+%d(%s):u64", off, param))
	}
	return strings.Join(params, " ")
}

var guessStructSockAddrIn = GuessAction{
	Probe: tracing.Probe{
		Name:      "offset_guess",
		Address:   "tcp_v4_connect",
		Fetchargs: makeDump("%si", 0, 32),
	},

	Timeout: time.Second * 5,

	Decoder: func(description tracing.ProbeDescription) (decoder tracing.Decoder, e error) {
		return tracing.NewDumpDecoder(description)
	},

	Validate: func(ev interface{}) (GuessResult, bool) {
		arr := ev.([]byte)
		N := len(arr)
		if N < 32 {
			return nil, false
		}
		if tracing.MachineEndian.Uint16(arr[0:2]) != unix.AF_INET {
			return nil, false
		}

		var off int
		for off = 2; off <= N-2; off += 2 {
			if binary.BigEndian.Uint16(arr[off:]) == magicPort {
				break
			}
		}
		if off > N-2 {
			return nil, false
		}
		offsetOfPort := off

		for off = 2; off <= N-4; off += 2 {
			if binary.BigEndian.Uint32(arr[off:]) == magicIPv4 {
				break
			}
		}
		if off > N-4 {
			return nil, false
		}
		offsetOfAddr := off
		return GuessResult{
			// family is fixed at offset zero
			"SOCKADDR_IN_AF":   0,
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
