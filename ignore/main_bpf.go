// +build ignore

package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"

	"github.com/weaveworks/tcptracer-bpf/pkg/tracer"
)

type tcpTracer struct {
	evChan chan interface{}
	lost   uint64
}

func (t *tcpTracer) TCPEventV4(ev tracer.TcpV4) {
	t.evChan <- ev
}

func (t *tcpTracer) TCPEventV6(ev tracer.TcpV6) {
	t.evChan <- ev
}

func (t *tcpTracer) LostV4(count uint64) {
	t.lost += count
}

func (t *tcpTracer) LostV6(count uint64) {
	t.lost += count
}

func main() {
	shared := &tcpTracer{}
	shared.evChan = make(chan interface{})
	t, err := tracer.NewTracer(shared)
	if err != nil {
		panic(err)
	}

	t.Start()

	for _, sPid := range os.Args[1:] {
		pid, err := strconv.Atoi(sPid)
		if err != nil {
			panic(err)
		}
		if err = t.AddFdInstallWatcher(uint32(pid)); err != nil {
			panic(err)
		}
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	for exit := false; !exit; {
		select {
			case <-sig:
				exit = true
				break
			case ev := <-shared.evChan:
				switch v := ev.(type) {
				case tracer.TcpV4:
					fmt.Printf("Got TCPv4 %+v\n", v)
				case tracer.TcpV6:
					fmt.Printf("Got TCPv6 %+v\n", v)
				}
		}
	}
	t.Stop()
	print("Lost ", shared.lost)
}
