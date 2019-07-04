package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	tracing "github.com/adriansr/socket_tracer"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

const (
	magicPort = 0xabcd
	magicIPv4 = 0x7f123456
)

var guesses = []GuessAction{
	{
		Probe: tracing.Probe{
			Name:      "offset_guess",
			Address:   "tcp_v4_connect",
			Fetchargs: makeMemoryDump("%si", 0, 32),
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
	},
	/*{
		Probe: tracing.Probe{
			Name:      "inet_sock_guess",
			Address:   "tcp_v4_connect",
			Fetchargs: makeMemoryDump("%di", 0, 1024),
		},

		Timeout: time.Second * 5,

		Decoder: func(description tracing.ProbeDescription) (decoder tracing.Decoder, e error) {
			return tracing.NewDumpDecoder(description)
		},

		Validate: func(ev interface{}) (GuessResult, bool) {
			data := ev.([]byte)
			_, _ = fmt.Fprintf(os.Stderr,
				"dump:\n%s\n", hex.Dump(data))
			return nil, true
		},

		Trigger: func(timeout time.Duration) {
			sock, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
			if err != nil {
				panic(err)
			}
			var addr unix.SockaddrInet4
			binary.BigEndian.PutUint16(addr.Addr[:], magicPort)
			addr.Port = int(binary.BigEndian.Uint16(addr.Addr[:]))
			binary.BigEndian.PutUint32(addr.Addr[:], magicIPv4)
			if err := unix.Bind(sock, &addr); err != nil {
				panic(err)
			}
			addr.Port = ^addr.Port
			for i, v := range addr.Addr {
				addr.Addr[i] = ^v
			}
			unix.Connect(sock, &addr)
		},
	},*/
}

func GuessAll(tfs *tracing.TraceFS, target GuessResult) error {
	for _, guess := range guesses {
		guess.Probe.Fetchargs = interpolate(guess.Probe.Fetchargs)
		guess.Probe.Filter = interpolate(guess.Probe.Filter)
		r, err := Guess(tfs, guess)
		if err != nil {
			return errors.Wrapf(err, "%s failed", guess.Probe.Name)
		}
		if err := merge(target, r); err != nil {
			return errors.Wrapf(err, "failed to merge result of %s", guess.Probe.Name)
		}
		_, _ = fmt.Fprintf(os.Stderr, "Result of %s: %+v\n", guess.Probe.Name, r)
	}
	return nil
}

func makeMemoryDump(param string, from, to int) string {
	var params []string
	for off := from; off < to; off += 8 {
		params = append(params, fmt.Sprintf("+%d(%s):u64", off, param))
	}
	return strings.Join(params, " ")
}
