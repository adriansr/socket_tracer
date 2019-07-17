// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"bytes"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"text/template"
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
	Probes []ProbeDef

	// Timeout that will be applied to the guess operation.
	Timeout time.Duration

	// Prepare callback performs preparations for the trigger function and
	// has the opportunity to return an opaque context that will be then
	// passed to Trigger() and Validate().
	Prepare func() (interface{}, error)

	// Trigger is the callback that causes the given Probe to generate
	// a tracing record.
	Trigger func(timeout time.Duration, ctx interface{})

	// Validate must take a tracing record and determine if it's a valid guess.
	Validate func(event interface{}, ctx interface{}) (GuessResult, bool)

	Terminate func(ctx interface{})
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
	if guesser.Validate == nil || guesser.Trigger == nil {
		return nil, errors.New("required callback not defined")
	}
	decoders := make([]tracing.Decoder, 0, len(guesser.Probes))
	formats := make([]tracing.ProbeDescription, 0, len(guesser.Probes))
	for _, pdesc := range guesser.Probes {
		if pdesc.Decoder == nil {
			return nil, errors.New("nil decoder in probedesc")
		}
		pdesc.Probe = templateVars.Apply(pdesc.Probe)
		if err := tfs.AddKProbe(pdesc.Probe); err != nil {
			return nil, errors.Wrapf(err, "failed to add kprobe '%s'", pdesc.Probe.String())
		}

		descr, err := tfs.LoadProbeDescription(pdesc.Probe)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to load kprobe '%s' description", pdesc.Probe.String())
		}

		decoder, err := pdesc.Decoder(descr)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create decoder")
		}
		decoders = append(decoders, decoder)
		formats = append(formats, descr)
	}

	defer func() {
		if err := tfs.RemoveAllKProbes(); err != nil {
			panic(err)
		}
	}()

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
		defer close(tidChan)

		sh := shared{
			tid: syscall.Gettid(),
		}
		if guesser.Prepare != nil {
			sh.ctx, sh.err = guesser.Prepare()
		}
		tidChan <- sh
		if sh.err != nil {
			return
		}

		wg.Wait()

		// Execute custom trigger
		guesser.Trigger(timeout, sh.ctx)
	}()

	ctx := <-tidChan
	if ctx.err != nil {
		return nil, errors.Wrap(ctx.err, "prepare failed")
	}

	if guesser.Terminate != nil {
		defer func() {
			<-tidChan
			guesser.Terminate(ctx.ctx)
		}()
	}

	perfchan, err := tracing.NewPerfChannel(
		tracing.WithBufferSize(8),
		tracing.WithErrBufferSize(1),
		tracing.WithLostBufferSize(8),
		tracing.WithRingSizeExponent(2),
		tracing.WithTID(ctx.tid))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create perfchannel")
	}
	defer func() {
		if err := perfchan.Close(); err != nil {
			panic(err)
		}
	}()

	for i := range guesser.Probes {
		if err := perfchan.MonitorProbe(formats[i], decoders[i]); err != nil {
			return nil, errors.Wrap(err, "failed to monitor probe")
		}
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
	// Wait for trigger to finish firing
	<-tidChan

	for {
		select {
		case <-timer.C:
			return nil, errors.New("timeout while waiting for event")

		case ev, ok := <-perfchan.C():
			if !ok {
				return nil, errors.New("perf channel closed unexpectedly")
			}
			if result, ok = guesser.Validate(ev, ctx.ctx); !ok {
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

func ResolveFunctions(tfs *tracing.TraceFS, alternatives map[string][]string) (result GuessResult, err error) {
	fnList, err := tfs.AvailableFilterFunctions()
	functions := make(map[string]struct{}, len(fnList))
	result = make(GuessResult, len(alternatives))
	for _, fn := range fnList {
		functions[fn] = struct{}{}
	}
	for key, options := range alternatives {
		found := false
		for _, fn := range options {
			if _, found = functions[fn]; found {
				result[key] = fn
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("no function for %s found in %v", key, options)
		}
	}
	return result, nil
}

func (g GuessResult) interpolate(s string) string {
	buf := &bytes.Buffer{}
	if err := template.Must(template.New("").Parse(s)).Execute(buf, g); err != nil {
		panic(err)
	}
	return buf.String()
}

func merge(dest map[string]interface{}, src map[string]interface{}) error {
	for k, v := range src {
		if prev, found := dest[k]; found {
			return fmt.Errorf("attempt to redefine key '%s'. previous value:'%s' new value:'%s'", k, prev, v)
		}
		dest[k] = v
	}
	return nil
}

func (g GuessResult) Apply(p tracing.Probe) tracing.Probe {
	p.Address = g.interpolate(p.Address)
	p.Fetchargs = g.interpolate(p.Fetchargs)
	p.Filter = g.interpolate(p.Filter)
	return p
}
