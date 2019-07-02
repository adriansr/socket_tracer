package main

import (
	"runtime"
	"sync"

	"golang.org/x/sys/unix"
)

func main() {
	var wg sync.WaitGroup
	for idx, N := 0, runtime.GOMAXPROCS(0); idx < N*4; idx++ {
		wg.Add(2)
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			for i := 0; ; i++ {
				unix.Accept(-1)
			}
			wg.Done()
		}()
	}
	wg.Wait()
}
