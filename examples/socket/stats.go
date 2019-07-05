// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

const clearline = "\r                                                                                \r"

type stats struct {
	recvCount, lostCount uint64
	output               chan string
}

func (s *stats) Run(period time.Duration, done <-chan struct{}) {
	indicator := "-/|\\"
	lastRecv := atomic.LoadUint64(&s.recvCount)
	lastLost := atomic.LoadUint64(&s.lostCount)
	lastCheck := time.Now()

	ticker := time.NewTicker(period)
	defer ticker.Stop()

	counter := 0
	for t := range ticker.C {
		select {
		case <-done:
			return
		default:
		}

		counter++
		elapsed := t.Sub(lastCheck)
		recv := atomic.LoadUint64(&s.recvCount)
		lost := atomic.LoadUint64(&s.lostCount)

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

type TimeReference struct {
	timestamp uint64
	time      time.Time
}

func (t *TimeReference) ToTime(timestamp uint64) time.Time {
	if t.timestamp == 0 {
		t.time = time.Now()
		t.timestamp = timestamp
		return t.time
	}
	return t.time.Add(time.Duration(timestamp - t.timestamp))
}
