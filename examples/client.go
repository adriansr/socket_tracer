package main

import (
	"fmt"
	"os"
	"runtime"
	"sync"

	"golang.org/x/sys/unix"
)

func main() {
	var wg sync.WaitGroup
	fmt.Printf("My PID is %d\n", os.Getpid())
	for idx, N := 0, runtime.GOMAXPROCS(0); idx < N*4; idx++ {
		wg.Add(1)
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
