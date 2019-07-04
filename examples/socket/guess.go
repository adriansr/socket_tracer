package main

import (
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/errors"

	tracing "github.com/adriansr/socket_tracer"
)

// GuessResult stores the output of a Guess operation as a map of string keys
// and arbitrary values, usually offsets.
type GuessResult map[string]interface{}

// GuessAction is the representation of a guess to perform.
type GuessAction struct {
	// Probe is the probe that is going to be used for the guess.
	Probe tracing.Probe

	// Timeout that will be applied to the guess operation.
	Timeout time.Duration

	// Decoder returns a decoder of your choice. It determines the type of the
	// event passed to Validate.
	Decoder func(description tracing.ProbeDescription) (tracing.Decoder, error)

	// Prepare callback performs preparations for the trigger function and
	// has the opportunity to return an opaque context that will be then
	// passed to Trigger() and Validate().
	Prepare func() (interface{}, error)

	// Trigger is the callback that causes the given Probe to generate
	// a tracing record.
	Trigger func(timeout time.Duration, ctx interface{})

	// Validate must take a tracing record and determine if it's a valid guess.
	Validate func(event interface{}, ctx interface{}) (GuessResult, bool)
}

// Guess is a helper function to easily determine memory layouts of kernel structs
// and similar tasks.
// It installs the guesser's Probe, starts a perf channel and executes the
// Trigger function.
// Each record received through the perf channel is passed to the Validate
// function.
// It terminates once Validate founds a positive record or when the timeout
// expires.
func Guess(tfs *tracing.TraceFS, guesser GuessAction) (result GuessResult, err error) {
	probe := guesser.Probe
	if err := tfs.AddKProbe(probe); err != nil {
		return nil, errors.Wrapf(err, "failed to add kprobe '%s'", probe.String())
	}
	defer tfs.RemoveKProbe(probe)

	descr, err := tfs.LoadProbeDescription(probe)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load kprobe '%s' description", probe.String())
	}

	decoder, err := guesser.Decoder(descr)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create decoder")
	}

	timeout := guesser.Timeout

	type shared struct {
		tid int
		ctx interface{}
		err error
	}
	// channel to receive the TID and context from the trigger goroutine.
	tidChan := make(chan shared, 1)

	// this waitgroup will prevent execution of the trigger until the perf
	// channel is up and running.
	var wg sync.WaitGroup
	var once sync.Once
	wg.Add(1)
	defer once.Do(wg.Done)

	// Trigger goroutine.
	go func() {
		// Make sure it doesn't switch OS threads during it's lifetime.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, err := guesser.Prepare()
		tidChan <- shared{tid: syscall.Gettid(), ctx: ctx, err: err}
		if err != nil {
			return
		}

		wg.Wait()

		// Execute custom trigger
		guesser.Trigger(timeout, ctx)
	}()

	sharedState := <-tidChan
	if sharedState.err != nil {
		return nil, errors.Wrap(sharedState.err, "prepare failed")
	}

	perfchan, err := tracing.NewPerfChannel(
		tracing.WithBufferSize(8),
		tracing.WithErrBufferSize(1),
		tracing.WithLostBufferSize(8),
		tracing.WithRingSizeExponent(2),
		tracing.WithTID(sharedState.tid))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create perfchannel")
	}
	defer perfchan.Close()

	if err := perfchan.MonitorProbe(descr, decoder); err != nil {
		return nil, errors.Wrap(err, "failed to monitor probe")
	}

	if err := perfchan.Run(); err != nil {
		return nil, errors.Wrap(err, "failed to run perf channel")
	}

	timer := time.NewTimer(timeout)

	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}()

	// Allow the trigger to be fired
	once.Do(wg.Done)

	for {
		select {
		case <-timer.C:
			return nil, errors.New("timeout while waiting for event")

		case ev, ok := <-perfchan.C():
			if !ok {
				return nil, errors.New("perf channel closed unexpectedly")
			}
			if result, ok = guesser.Validate(ev, sharedState.ctx); !ok {
				continue
			}
			return result, nil

		case err := <-perfchan.ErrC():
			if err != nil {
				return nil, errors.Wrap(err, "error received from perf channel")
			}

		case <-perfchan.LostC():
			return nil, errors.Wrap(err, "event loss in perf channel")
		}
	}
}
