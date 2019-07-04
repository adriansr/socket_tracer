package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"

	tracing "github.com/adriansr/socket_tracer"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

var magicAddr = net.TCPAddr{
	IP:   net.IPv4(127, 0x12, 0x34, 0x56).To4(),
	Port: 0xABCD,
}

type MultiGuessAction struct {
	GuessAction
	Times  int
	Reduce func(results []GuessResult) (GuessResult, error)
}

type inetSockCtx struct {
	fd            int
	local, remote unix.SockaddrInet4
}

func indexAligned(buf []byte, needle []byte, start, align int) int {
	n := len(needle)
	if start&(align-1) != 0 {
		start = (start + align) & ^(align - 1)
	}
	var off, limit int
	for off, limit = start, len(buf)-n; off <= limit; off += align {
		if bytes.Equal(buf[off:off+n], needle) {
			return off
		}
	}
	return -1
}

var guesses = []interface{}{
	GuessAction{
		Probe: tracing.Probe{
			Name:      "sockaddr_in_guess",
			Address:   "tcp_v4_connect",
			Fetchargs: makeMemoryDump("%si", 0, 32),
		},

		Timeout: time.Second * 5,

		Decoder: func(description tracing.ProbeDescription) (decoder tracing.Decoder, e error) {
			return tracing.NewDumpDecoder(description)
		},

		Prepare: func() (ctx interface{}, err error) {
			return magicAddr, nil
		},

		Validate: func(ev interface{}, ctx interface{}) (GuessResult, bool) {
			magic := ctx.(net.TCPAddr)
			arr := ev.([]byte)
			if len(arr) < 8 {
				return nil, false
			}
			var needle [2]byte
			tracing.MachineEndian.PutUint16(needle[:], unix.AF_INET)
			offsetOfFamily := indexAligned(arr, needle[:], 0, 2)
			if offsetOfFamily == -1 {
				return nil, false
			}

			binary.BigEndian.PutUint16(needle[:], uint16(magic.Port))
			offsetOfPort := indexAligned(arr, needle[:], offsetOfFamily+2, 2)
			if offsetOfPort == -1 {
				return nil, false
			}

			offsetOfAddr := indexAligned(arr, []byte(magic.IP), offsetOfPort+2, 4)
			if offsetOfAddr == -1 {
				return nil, false
			}
			return GuessResult{
				"SOCKADDR_IN_AF":   offsetOfFamily,
				"SOCKADDR_IN_PORT": offsetOfPort,
				"SOCKADDR_IN_ADDR": offsetOfAddr,
			}, true
		},

		Trigger: func(timeout time.Duration, ctx interface{}) {
			addr := ctx.(net.TCPAddr)
			dialer := net.Dialer{
				Timeout: timeout,
			}
			conn, err := dialer.Dial("tcp", addr.String())
			if err == nil {
				conn.Close()
			}
		},
	},

	MultiGuessAction{
		GuessAction: GuessAction{
			Probe: tracing.Probe{
				Name:      "inet_sock_guess",
				Address:   "tcp_v4_connect",
				Fetchargs: makeMemoryDump("%di", 0, 2048),
			},

			Timeout: time.Second * 5,

			Decoder: func(description tracing.ProbeDescription) (decoder tracing.Decoder, e error) {
				return tracing.NewDumpDecoder(description)
			},

			Prepare: func() (ctx interface{}, err error) {
				myCtx := inetSockCtx{
					local: unix.SockaddrInet4{
						Port: 0,
						Addr: [4]byte{127, uint8(rand.Intn(256)), uint8(rand.Intn(256)), uint8(1 + rand.Intn(255))},
					},
				}
				myCtx.remote.Port = int(magicAddr.Port)
				copy(myCtx.remote.Addr[:], magicAddr.IP)

				myCtx.fd, err = unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
				if err != nil {
					return nil, err
				}
				if err = unix.Bind(myCtx.fd, &myCtx.local); err != nil {
					unix.Close(myCtx.fd)
					return nil, errors.Wrap(err, "bind failed")
				}
				sa, err := unix.Getsockname(myCtx.fd)
				if err != nil {
					unix.Close(myCtx.fd)
					return nil, errors.Wrap(err, "getsockname failed")
				}
				local, ok := sa.(*unix.SockaddrInet4)
				if !ok {
					unix.Close(myCtx.fd)
					return nil, errors.Wrap(err, "getsockname didn't return a struct sockaddr_in")
				}
				myCtx.local = *local
				return myCtx, nil
			},

			Terminate: func(ctx interface{}) {
				myCtx := ctx.(inetSockCtx)
				unix.Close(myCtx.fd)
			},

			Validate: func(ev interface{}, ctx interface{}) (GuessResult, bool) {
				myCtx := ctx.(inetSockCtx)
				data := ev.([]byte)
				//_, _ = fmt.Fprintf(os.Stderr, "dump: +%v %x\n%s\n", myCtx.local.Addr, myCtx.local.Port, hex.Dump(data))
				//return nil, true

				laddr := myCtx.local.Addr[:]
				lport := make([]byte, 2)
				binary.BigEndian.PutUint16(lport, uint16(myCtx.local.Port))

				var addrHits []int
				var portHits []int

				off := indexAligned(data, laddr, 0, 4)
				for off != -1 {
					addrHits = append(addrHits, off)
					off = indexAligned(data, laddr, off+4, 4)
				}

				off = indexAligned(data, lport, 0, 2)
				for off != -1 {
					portHits = append(portHits, off)
					off = indexAligned(data, lport, off+2, 2)
				}

				if len(addrHits) == 0 || len(portHits) == 0 {
					return nil, false
				}

				return GuessResult{
					"INET_SOCK_LADDR": addrHits,
					"INET_SOCK_LPORT": portHits,
				}, true
			},

			Trigger: func(timeout time.Duration, ctx interface{}) {
				myCtx := ctx.(inetSockCtx)
				unix.Connect(myCtx.fd, &myCtx.remote)
			},
		},

		Times: 8,

		Reduce: func(results []GuessResult) (result GuessResult, err error) {
			if result, err = consolidate(results); err != nil {
				return nil, err
			}

			getListField := func(key string) ([]int, error) {
				iface, ok := result[key]
				if !ok {
					return nil, fmt.Errorf("field %s not found", key)
				}
				list, ok := iface.([]int)
				if !ok {
					return nil, fmt.Errorf("field %s is not a list", key)
				}
				if len(list) == 0 {
					return nil, fmt.Errorf("field %s not detected", key)
				}
				return list, nil
			}

			portList, err := getListField("INET_SOCK_LPORT")
			if err != nil {
				return nil, err
			}
			if len(portList) != 1 {
				return nil, errors.New("field INET_SOCK_LPORT not consolidated")
			}
			port := portList[0]

			// INET_SOCK_LADDR usually has more than one match due to the laddr
			// being also present at the start of struct sock.

			addrList, err := getListField("INET_SOCK_LADDR")
			if err != nil {
				return nil, err
			}
			laddr := addrList[0]
			if n := len(addrList); n > 1 {
				for idx := n - 1; idx >= 0; idx-- {
					if addrList[idx] < port {
						laddr = addrList[idx]
						break
					}
				}
			}

			return GuessResult{
				"INET_SOCK_LADDR": laddr,
				"INET_SOCK_LPORT": port,
			}, nil
		},
	},
}

func multiGuess(tfs *tracing.TraceFS, guess MultiGuessAction) (result GuessResult, err error) {
	var results []GuessResult
	for idx := 1; idx <= guess.Times; idx++ {
		r, err := singleGuess(tfs, guess.GuessAction)
		if err != nil {
			return nil, err
		}
		_, _ = fmt.Fprintf(os.Stderr, "Result of %s try %d: %+v\n", guess.Probe.Name, idx, r)
		results = append(results, r)
	}
	return guess.Reduce(results)
}

func singleGuess(tfs *tracing.TraceFS, guess GuessAction) (result GuessResult, err error) {
	guess.Probe.Fetchargs = interpolate(guess.Probe.Fetchargs)
	guess.Probe.Filter = interpolate(guess.Probe.Filter)
	r, err := Guess(tfs, guess)
	if err != nil {
		return nil, errors.Wrapf(err, "%s failed", guess.Probe.Name)
	}
	return r, err
}

func consolidate(partials []GuessResult) (result GuessResult, err error) {
	if len(partials) == 0 {
		return nil, errors.New("empty resultset to consolidate")
	}
	result = make(GuessResult)

	for k, v := range partials[0] {
		baseList, ok := v.([]int)
		if !ok {
			return nil, fmt.Errorf("consolidating key '%s' is not a list", k)
		}
		for idx := 1; idx < len(partials); idx++ {
			v, found := partials[idx][k]
			if !found {
				return nil, fmt.Errorf("consolidating key '%s' missing in some results", k)
			}
			list, ok := v.([]int)
			if !ok {
				return nil, fmt.Errorf("consolidating key '%s' is not always a list", k)
			}
			var newList []int
			for _, num := range baseList {
				for _, nn := range list {
					if num == nn {
						newList = append(newList, num)
						break
					}
				}
			}
			baseList = newList
			if len(baseList) == 0 {
				break
			}
		}
		result[k] = baseList
	}
	return result, nil
}

func GuessAll(tfs *tracing.TraceFS, target GuessResult) (err error) {
	for _, iface := range guesses {
		var r GuessResult
		var name string
		switch guess := iface.(type) {
		case GuessAction:
			name = guess.Probe.Name
			r, err = singleGuess(tfs, guess)
		case MultiGuessAction:
			name = guess.Probe.Name
			r, err = multiGuess(tfs, guess)
		default:
			panic(iface)
		}
		if err := merge(target, r); err != nil {
			return errors.Wrapf(err, "failed to merge result of %s", name)
		}
		_, _ = fmt.Fprintf(os.Stderr, "Result of %s: %+v\n", name, r)
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
