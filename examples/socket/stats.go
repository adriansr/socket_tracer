// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const clearline = "\r                                                                                \r"

type stats struct {
	recvCount, lostCount uint64
	output               chan string
	done                 chan struct{}
	wg                   sync.WaitGroup
}

func NewStats(reportPeriod time.Duration) *stats {
	s := &stats{
		output: make(chan string, 1024),
		done:   make(chan struct{}, 0),
	}
	s.wg.Add(1)
	go s.run(reportPeriod)
	return s
}

func (s *stats) Close() {
	close(s.done)
	s.wg.Wait()
}

func (s *stats) run(period time.Duration) {
	defer s.wg.Done()
	defer close(s.output)

	indicator := "-/|\\"
	lastRecv := atomic.LoadUint64(&s.recvCount)
	lastLost := atomic.LoadUint64(&s.lostCount)
	lastCheck := time.Now()

	ticker := time.NewTicker(period)
	defer ticker.Stop()

	dumpOutput := func() {
		for i := 0; i < 2; {
			select {
			case msg := <-s.output:
				if i == 0 {
					fmt.Fprint(os.Stderr, clearline)
					i = 1
				}
				fmt.Println(msg)
			default:
				i = 2
			}
		}
	}

	defer dumpOutput()

	counter := 0
	for t := range ticker.C {
		select {
		case _, act := <-s.done:
			if !act {
				s.Output(fmt.Sprintf("Terminated. Totals read %d lost %d",
					atomic.LoadUint64(&s.recvCount),
					atomic.LoadUint64(&s.lostCount)))
				return
			}
		default:
		}

		dumpOutput()

		counter++
		elapsed := t.Sub(lastCheck)
		recv := atomic.LoadUint64(&s.recvCount)
		lost := atomic.LoadUint64(&s.lostCount)

		fmt.Fprintf(os.Stderr, "\r[ %c Read %d lost %d (%.01f eps / %.01f lps)]  ",
			indicator[counter%len(indicator)],
			recv, lost,
			float64(recv-lastRecv)/elapsed.Seconds(),
			float64(lost-lastLost)/elapsed.Seconds())

		lastCheck, lastRecv, lastLost = t, recv, lost
	}
}

func (s *stats) Received() {
	atomic.AddUint64(&s.recvCount, 1)
}

func (s *stats) Lost(count uint64) {
	atomic.AddUint64(&s.lostCount, count)
}

func (s *stats) Output(event string) {
	s.output <- event
}
