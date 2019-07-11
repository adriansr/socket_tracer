// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

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
	"unsafe"

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
	local, remote  unix.SockaddrInet4
	server, client int
}

type tcpSendMsgArgCountGuess struct {
	Param3 uint `kprobe:"c"`
	Param4 uint `kprobe:"d"`
}

type udpSendMsgCountGuess struct {
	Param1 uintptr `kprobe:"a"`
	Param2 uintptr `kprobe:"b"`
	Param3 uintptr `kprobe:"c"`
	Param4 uintptr `kprobe:"d"`
}

type tcpClientServerCtx struct {
	client, server, accepted int
	written                  int
	srvAddr                  unix.SockaddrInet4
	extra                    uintptr
}

const skbuffDumpSize = 1000

type skbuffSockGuess struct {
	A2   uintptr              `kprobe:"param2"`
	Dump [skbuffDumpSize]byte `kprobe:"dump,greedy"`
}

var guesses = []interface{}{

	// Guess the offset of struct sockaddr_in members.
	// This could be hardcoded but feels safer to guess.
	//
	// Output:
	// 	SOCKADDR_IN_AF   : 0
	// 	SOCKADDR_IN_PORT : 2
	// 	SOCKADDR_IN_ADDR : 4
	GuessAction{
		Probes: []ProbeDef{
			{
				Probe: tracing.Probe{
					Name:      "sockaddr_in_guess",
					Address:   "tcp_v4_connect",
					Fetchargs: makeMemoryDump("{{.P2}}", 0, 32),
				},
				Decoder: func(description tracing.ProbeDescription) (decoder tracing.Decoder, e error) {
					return tracing.NewDumpDecoder(description)
				},
			},
		},

		Timeout: time.Second * 5,

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

	// Guess the position of interesting parameters in tcp_sendmsg.
	// It can have 3 (4.x) or 4 (2.x/3.x) params, with sock and size being
	// the first and third, or second and fourth.
	//
	// Do a send(...) of a certain size and expect either arg3 is the msg length
	// or arg3 is a pointer and arg4 is the length.
	//
	// Output:
	//  TCP_SENDMSG_SOCK : %dx
	//  TCP_SENDMSG_LEN  : +4(%sp)
	GuessAction{
		Probes: []ProbeDef{
			{
				Probe: tracing.Probe{
					Name:      "tcp_sendmsg_argcount_guess",
					Address:   "tcp_sendmsg",
					Fetchargs: "c={{.P3}} d={{.P4}}",
				},
				Decoder: func(description tracing.ProbeDescription) (decoder tracing.Decoder, e error) {
					return tracing.NewStructDecoder(description, func() interface{} {
						return new(tcpSendMsgArgCountGuess)
					})
				},
			},
		},

		Timeout: time.Second * 5,

		Prepare: func() (ctx interface{}, err error) {
			var srvAddr unix.SockaddrInet4
			cctx := &tcpClientServerCtx{}
			cctx.server, srvAddr, err = createSocket(unix.SockaddrInet4{})
			if err != nil {
				return nil, err
			}
			if err = unix.Listen(cctx.server, 1); err != nil {
				return nil, err
			}
			if cctx.client, _, err = createSocket(unix.SockaddrInet4{}); err != nil {
				return nil, err
			}
			if err = unix.Connect(cctx.client, &srvAddr); err != nil {
				return nil, err
			}
			if cctx.accepted, _, err = unix.Accept(cctx.server); err != nil {
				return nil, err
			}
			return cctx, nil
		},

		Validate: func(ev interface{}, ctx interface{}) (GuessResult, bool) {
			cctx := ctx.(*tcpClientServerCtx)
			event := ev.(*tcpSendMsgArgCountGuess)
			if cctx.written <= 0 {
				_, _ = fmt.Fprintf(os.Stderr, "ERROR: write failed for guess\n")
			}

			var sockParam, lenParam string
			switch {
			case event.Param3 == uint(cctx.written):
				// Linux ~4.15
				sockParam = templateVars["P1"].(string)
				lenParam = templateVars["P3"].(string)

			case event.Param4 == uint(cctx.written):
				// Older linux
				sockParam = templateVars["P2"].(string)
				lenParam = templateVars["P4"].(string)
			default:
				return nil, false
			}
			return GuessResult{
				"TCP_SENDMSG_SOCK": sockParam,
				"TCP_SENDMSG_LEN":  lenParam,
			}, true
		},

		Trigger: func(timeout time.Duration, ctx interface{}) {
			cctx := ctx.(*tcpClientServerCtx)
			cctx.written, _ = unix.Write(cctx.client, []byte("Hello World!\n"))
		},

		Terminate: func(ctx interface{}) {
			if ctx == nil {
				return
			}
			cctx := ctx.(*tcpClientServerCtx)
			unix.Close(cctx.accepted)
			unix.Close(cctx.server)
			unix.Close(cctx.client)
		},
	},

	// Guess the offsets within a struct inet_sock where the local and remote
	// addresses and ports are found.
	//
	// This is run 8 times to avoid birthdays.
	//
	// Most values appear multiple times within the struct, this is normal.
	// TODO: clustering to keep the offsets that are closer to each other.
	//
	// Output:
	// INET_SOCK_LADDR : 572
	// INET_SOCK_LPORT : 582
	// INET_SOCK_RADDR : 576
	// INET_SOCK_RPORT : 580
	MultiGuessAction{
		GuessAction: GuessAction{
			Probes: []ProbeDef{
				{
					Probe: tracing.Probe{
						Type:      tracing.TypeKRetProbe,
						Name:      "inet_sock_guess2",
						Address:   "inet_csk_accept",
						Fetchargs: makeMemoryDump("{{.RET}}", 0, 2048),
					},
					Decoder: func(description tracing.ProbeDescription) (decoder tracing.Decoder, e error) {
						return tracing.NewDumpDecoder(description)
					},
				},
			},

			Timeout: time.Second * 5,

			Prepare: func() (ctx interface{}, err error) {
				randomLocalIP := func() [4]byte {
					return [4]byte{127, uint8(rand.Intn(256)), uint8(rand.Intn(256)), uint8(1 + rand.Intn(255))}
				}

				myCtx := inetSockCtx{
					local: unix.SockaddrInet4{
						Port: 0,
						Addr: randomLocalIP(),
					},
					remote: unix.SockaddrInet4{
						Port: 0,
						Addr: randomLocalIP(),
					},
				}
				for bytes.Equal(myCtx.local.Addr[:], myCtx.remote.Addr[:]) {
					myCtx.remote.Addr = randomLocalIP()
				}
				if myCtx.server, myCtx.local, err = createSocket(myCtx.local); err != nil {
					return nil, errors.Wrap(err, "error creating server")
				}
				if myCtx.client, myCtx.remote, err = createSocket(myCtx.remote); err != nil {
					return nil, errors.Wrap(err, "error creating client")
				}
				if err = unix.Listen(myCtx.server, 1); err != nil {
					return nil, errors.Wrap(err, "error in listen")
				}
				return myCtx, nil
			},

			Terminate: func(ctx interface{}) {
				myCtx := ctx.(inetSockCtx)
				unix.Close(myCtx.client)
				unix.Close(myCtx.server)
			},

			Validate: func(ev interface{}, ctx interface{}) (GuessResult, bool) {
				myCtx := ctx.(inetSockCtx)
				data := ev.([]byte)

				laddr := myCtx.local.Addr[:]
				lport := make([]byte, 2)
				binary.BigEndian.PutUint16(lport, uint16(myCtx.local.Port))
				raddr := myCtx.remote.Addr[:]
				rport := make([]byte, 2)
				binary.BigEndian.PutUint16(rport, uint16(myCtx.remote.Port))
				var laddrHits []int
				var lportHits []int
				var raddrHits []int
				var rportHits []int

				off := indexAligned(data, laddr, 0, 4)
				for off != -1 {
					laddrHits = append(laddrHits, off)
					off = indexAligned(data, laddr, off+4, 4)
				}

				off = indexAligned(data, lport, 0, 2)
				for off != -1 {
					lportHits = append(lportHits, off)
					off = indexAligned(data, lport, off+2, 2)
				}

				off = indexAligned(data, raddr, 0, 4)
				for off != -1 {
					raddrHits = append(raddrHits, off)
					off = indexAligned(data, raddr, off+4, 4)
				}

				off = indexAligned(data, rport, 0, 2)
				for off != -1 {
					rportHits = append(rportHits, off)
					off = indexAligned(data, rport, off+2, 2)
				}

				if len(laddrHits) == 0 || len(lportHits) == 0 || len(raddrHits) == 0 || len(rportHits) == 0 {
					return nil, false
				}

				return GuessResult{
					"INET_SOCK_LADDR": laddrHits,
					"INET_SOCK_LPORT": lportHits,
					"INET_SOCK_RADDR": raddrHits,
					"INET_SOCK_RPORT": rportHits,
				}, true
			},

			Trigger: func(timeout time.Duration, ctx interface{}) {
				myCtx := ctx.(inetSockCtx)
				// TODO error check
				if err := unix.Connect(myCtx.client, &myCtx.local); err != nil {
					return
				}
				fd, _, err := unix.Accept(myCtx.server)
				if err != nil {
					return
				}
				unix.Close(fd)
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

			var offs [4]int
			for idx, key := range []string{
				"INET_SOCK_LADDR", "INET_SOCK_LPORT",
				"INET_SOCK_RADDR", "INET_SOCK_RPORT"} {
				list, err := getListField(key)
				if err != nil {
					return nil, err
				}
				offs[idx] = list[len(list)-1]
			}

			// TODO: clustering

			return GuessResult{
				"INET_SOCK_LADDR": offs[0],
				"INET_SOCK_LPORT": offs[1],
				"INET_SOCK_RADDR": offs[2],
				"INET_SOCK_RPORT": offs[3],
			}, nil
		},
	},

	// Guess how to get a struct sock* from an ip_local_out() call.
	// This function has two forms depending on kernel version:
	// - ip_local_out(struct sk_buff *skb) // 2.x/3.x
	// - ip_local_out(struct net *net, struct sock *sk, struct sk_buff *skb) // 4.x
	//
	// what it does is set a probe on tcp_sendmsg (guaranteed to have a *sock)
	// and in ip_local_out, which will be called by tcp_sendmsg.
	// It dumps the first param (which can be a struct net* or a struct sk_buff)
	// and gets the second param. Either the second param is the sock, or is it
	// found at some point in the dumped first param.
	//
	// Output:
	//  IP_LOCAL_OUT_SOCK : +16(%ax)
	GuessAction{
		Probes: []ProbeDef{
			{
				Probe: tracing.Probe{
					Name:    "ip_local_out_sock_guess",
					Address: "ip_local_out",
					Fetchargs: fmt.Sprintf("param2={{.P2}} dump=%s",
						makeMemoryDump("{{.P1}}", 0, skbuffDumpSize)),
				},
				Decoder: func(description tracing.ProbeDescription) (decoder tracing.Decoder, e error) {
					return tracing.NewStructDecoder(description, func() interface{} {
						return new(skbuffSockGuess)
					})
				},
			},
			{
				Probe: tracing.Probe{
					Name:      "tcp_sendmsg_in",
					Address:   "tcp_sendmsg",
					Fetchargs: "sock={{.TCP_SENDMSG_SOCK}} size={{.TCP_SENDMSG_LEN}} laddr=+{{.INET_SOCK_LADDR}}({{.TCP_SENDMSG_SOCK}}):u32 lport=+{{.INET_SOCK_LPORT}}({{.TCP_SENDMSG_SOCK}}):u16 raddr=+{{.INET_SOCK_RADDR}}({{.TCP_SENDMSG_SOCK}}):u32 rport=+{{.INET_SOCK_RPORT}}({{.TCP_SENDMSG_SOCK}}):u16",
				},
				Decoder: func(desc tracing.ProbeDescription) (decoder tracing.Decoder, e error) {
					return tracing.NewStructDecoder(desc, func() interface{} {
						return new(tcpSendMsgCall)
					})
				},
			},
		},

		Timeout: time.Second * 5,

		Prepare: func() (ctx interface{}, err error) {
			cctx := &tcpClientServerCtx{}
			cctx.server, cctx.srvAddr, err = createSocket(unix.SockaddrInet4{})
			if err != nil {
				return nil, err
			}
			if err = unix.Listen(cctx.server, 1); err != nil {
				return nil, err
			}
			if cctx.client, _, err = createSocket(unix.SockaddrInet4{}); err != nil {
				return nil, err
			}
			if err = unix.Connect(cctx.client, &cctx.srvAddr); err != nil {
				return nil, err
			}
			if cctx.accepted, _, err = unix.Accept(cctx.server); err != nil {
				return nil, err
			}
			return cctx, nil
		},

		Validate: func(ev interface{}, ctx interface{}) (GuessResult, bool) {
			cctx := ctx.(*tcpClientServerCtx)
			switch v := ev.(type) {
			case *tcpSendMsgCall:
				cctx.extra = v.Sock
				//return nil, false

			case *skbuffSockGuess:
				if cctx.extra == 0 {
					// No tcp_sendmsg received?
					return nil, false
				}
				if v.A2 == cctx.extra {
					return GuessResult{
						// Second argument to ip_local_out is the struct sock*
						"IP_LOCAL_OUT_SOCK": templateVars["P2"],
					}, true
				}
				const ptrLen = unsafe.Sizeof(cctx.extra)
				off := indexAligned(v.Dump[:], ((*[ptrLen]byte)(unsafe.Pointer(&cctx.extra)))[:], 0, int(ptrLen))
				if off != -1 {
					return GuessResult{
						// struct sock* is a field of struct pointed to by first argument
						"IP_LOCAL_OUT_SOCK": fmt.Sprintf("+%d(%s)", off, templateVars["P1"]),
					}, true
				}

			}
			return nil, false
		},

		Trigger: func(timeout time.Duration, ctx interface{}) {
			cctx := ctx.(*tcpClientServerCtx)
			buf := []byte("Hello World!\n")
			cctx.written, _ = unix.Write(cctx.client, buf)
			unix.Read(cctx.accepted, buf)
		},

		Terminate: func(ctx interface{}) {
			if ctx == nil {
				return
			}
			cctx := ctx.(*tcpClientServerCtx)
			unix.Close(cctx.accepted)
			unix.Close(cctx.server)
			unix.Close(cctx.client)
		},
	},

	// guess udp_sendmsg arguments:
	//
	//  int udp_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
	//                  size_t len) // 2.x / 3.x
	//
	//  int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len) // 4.x
	//
	// output:
	//  UDP_SENDMSG_LEN:+4(%sp)
	//  UDP_SENDMSG_SOCK:%dx
	GuessAction{
		Probes: []ProbeDef{
			{
				Probe: tracing.Probe{
					Name:      "udp_sendmsg_guess",
					Address:   "udp_sendmsg",
					Fetchargs: "a={{.P1}} b={{.P2}} c={{.P3}} d={{.P4}}",
				},
				Decoder: func(description tracing.ProbeDescription) (decoder tracing.Decoder, e error) {
					return tracing.NewStructDecoder(description, func() interface{} {
						return new(udpSendMsgCountGuess)
					})
				},
			},
		},

		Timeout: time.Second * 5,

		Prepare: func() (ctx interface{}, err error) {
			cctx := &tcpClientServerCtx{}
			cctx.server, cctx.srvAddr, err = createSocketWithProto(unix.SOCK_DGRAM, unix.SockaddrInet4{})
			if err != nil {
				return nil, err
			}
			if cctx.client, _, err = createSocketWithProto(unix.SOCK_DGRAM, unix.SockaddrInet4{}); err != nil {
				return nil, err
			}
			return cctx, nil
		},

		Validate: func(ev interface{}, ctx interface{}) (GuessResult, bool) {
			cctx := ctx.(*tcpClientServerCtx)
			if cctx.extra == 0 {
				return nil, false
			}
			event := ev.(*udpSendMsgCountGuess)
			if event.Param3 == cctx.extra {
				return GuessResult{
					"UDP_SENDMSG_SOCK": templateVars["P1"],
					"UDP_SENDMSG_LEN":  templateVars["P3"],
				}, true
			}
			if event.Param4 == cctx.extra {
				return GuessResult{
					"UDP_SENDMSG_SOCK": templateVars["P2"],
					"UDP_SENDMSG_LEN":  templateVars["P4"],
				}, true
			}
			return nil, false
		},

		Trigger: func(timeout time.Duration, ctx interface{}) {
			cctx := ctx.(*tcpClientServerCtx)
			buf := []byte("Hello World!\n")
			unix.Sendto(cctx.client, buf, unix.MSG_NOSIGNAL, &cctx.srvAddr)
			unix.Recvfrom(cctx.server, buf, 0)
			cctx.extra = uintptr(len(buf))
		},

		Terminate: func(ctx interface{}) {
			if ctx == nil {
				return
			}
			cctx := ctx.(*tcpClientServerCtx)
			unix.Close(cctx.server)
			unix.Close(cctx.client)
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
		_, _ = fmt.Fprintf(os.Stderr, "Result of %s try %d: %+v\n", guess.Probes[0].Probe.Name, idx, r)
		results = append(results, r)
	}
	return guess.Reduce(results)
}

func singleGuess(tfs *tracing.TraceFS, guess GuessAction) (result GuessResult, err error) {
	r, err := Guess(tfs, guess)
	if err != nil {
		return nil, errors.Wrapf(err, "%s failed", guess.Probes[0].Probe.Name)
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
			name = guess.Probes[0].Probe.Name
			r, err = singleGuess(tfs, guess)
		case MultiGuessAction:
			name = guess.Probes[0].Probe.Name
			r, err = multiGuess(tfs, guess)
		default:
			panic(iface)
		}
		if err != nil {
			return err
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

func createSocket(bindAddr unix.SockaddrInet4) (fd int, addr unix.SockaddrInet4, err error) {
	return createSocketWithProto(unix.SOCK_STREAM, bindAddr)
}

func createSocketWithProto(proto int, bindAddr unix.SockaddrInet4) (fd int, addr unix.SockaddrInet4, err error) {
	fd, err = unix.Socket(unix.AF_INET, proto, 0)
	if err != nil {
		return -1, addr, err
	}
	if err = unix.Bind(fd, &bindAddr); err != nil {
		unix.Close(fd)
		return -1, addr, errors.Wrap(err, "bind failed")
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		unix.Close(fd)
		return -1, addr, errors.Wrap(err, "getsockname failed")
	}
	addrptr, ok := sa.(*unix.SockaddrInet4)
	if !ok {
		unix.Close(fd)
		return -1, addr, errors.Wrap(err, "getsockname didn't return a struct sockaddr_in")
	}
	return fd, *addrptr, nil
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
