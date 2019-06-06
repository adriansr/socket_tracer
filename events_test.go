// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package socket_tracer

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var rawMsg = []byte{
	0x44, 0x00, 0x00, 0x00, 0x9b, 0x05, 0x00, 0x00, 0xae, 0x0e, 0x00, 0x00,
	0xa0, 0x52, 0x23, 0xad, 0xff, 0xff, 0xff, 0xff, 0x3c, 0x00, 0x04, 0x00,
	0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x7d, 0x56, 0xe6, 0x62,
	0xc8, 0x99, 0xc4, 0x25, 0x73, 0x73, 0x68, 0x64, 0x00, 0x00, 0x00, 0x00,
}

func BenchmarkMapDecoder(b *testing.B) {
	evs := NewEventTracing(DefaultDebugFSPath)
	probe := KProbe{
		Group:     "test_group",
		Name:      "test_name",
		Address:   "sys_connect",
		Fetchargs: "exe=$comm fd=%di +0(%si):x64 +8(%si):u32 +16(%si):s16 +24(%si):u8",
	}
	err := evs.AddKProbe(probe)
	if err != nil {
		b.Fatal(err)
	}
	desc, err := evs.LoadKProbeFormat(probe)
	if err != nil {
		b.Fatal(err)
	}
	decoder := NewMapDecoder(desc)
	b.ResetTimer()
	var sum int = 0
	for i := 0; i < b.N; i++ {
		iface, err := decoder.Decode(rawMsg)
		if err != nil {
			b.Fatal(err)
		}
		m := iface.(map[string]interface{})

		for _, c := range m["exe"].(string) {
			sum += int(c)
		}
		sum += int(m["fd"].(uint64))
		sum += int(m["arg3"].(uint64))
		sum += int(m["arg4"].(uint32))
		sum += int(m["arg5"].(int16))
		sum += int(m["arg6"].(uint8))
	}
	b.StopTimer()
	b.Log("result sum=", sum)
	b.ReportAllocs()
}

// This test is to make sure that there is no delay between when a KProbe
// is added and its 'format' file is available, that is, LoadKProbeDescription
// can be called immediately after AddKProbe.
func TestAddKProbeIsNotRacy(t *testing.T) {
	evs := NewEventTracing(DefaultDebugFSPath)
	probe := KProbe{
		Group:     "test_group",
		Name:      "test_name",
		Address:   "sys_connect",
		Fetchargs: "exe=$comm fd=%di +0(%si):x64 +8(%si):u32 +16(%si):s16 +24(%si):u8",
	}
	defer func() {
		if err := evs.RemoveAllKProbes(); err != nil {
			t.Fatal(err)
		}
	}()
	for i := 0; i < 100; i++ {
		if err := evs.AddKProbe(probe); err != nil {
			t.Fatal(err)
		}
		if _, err := evs.LoadKProbeFormat(probe); err != nil {
			t.Fatal(err)
		}
		if err := evs.RemoveKProbe(probe); err != nil {
			t.Fatal(err)
		}
	}
}

func BenchmarkStructDecoder(b *testing.B) {

	evs := NewEventTracing(DefaultDebugFSPath)
	probe := KProbe{
		Group:     "test_group",
		Name:      "test_name",
		Address:   "sys_connect",
		Fetchargs: "exe=$comm fd=%di +0(%si):x64 +8(%si):u32 +16(%si):s16 +24(%si):u8",
	}
	err := evs.AddKProbe(probe)
	if err != nil {
		b.Fatal(err)
	}
	desc, err := evs.LoadKProbeFormat(probe)
	if err != nil {
		b.Fatal(err)
	}

	type myStruct struct {
		Type   uint16 `kprobe:"common_type"`
		Flags  uint8  `kprobe:"common_flags"`
		PCount uint8  `kprobe:"common_preempt_count"`
		PID    uint32 `kprobe:"common_pid"`
		IP     uint64 `kprobe:"__probe_ip"`
		Exe    string `kprobe:"exe"`
		Fd     uint64 `kprobe:"fd"`
		Arg3   uint64 `kprobe:"arg3"`
		Arg4   uint32 `kprobe:"arg4"`
		Arg5   uint16 `kprobe:"arg5"`
		Arg6   uint8  `kprobe:"arg6"`
	}
	var myAlloc AllocateFn = func() interface{} {
		return new(myStruct)
	}

	decoder, err := NewStructDecoder(desc, myAlloc)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	sum := 0
	for i := 0; i < b.N; i++ {
		iface, err := decoder.Decode(rawMsg)
		if err != nil {
			b.Fatal(err)
		}
		m := iface.(*myStruct)

		for _, c := range m.Exe {
			sum += int(c)
		}
		sum += int(m.Fd)
		sum += int(m.Arg3)
		sum += int(m.Arg4)
		sum += int(m.Arg5)
		sum += int(m.Arg6)
	}
	b.StopTimer()
	b.Log("result sum=", sum)
	b.ReportAllocs()
}

func TestKProbeReal(t *testing.T) {
	// Skipped ...
	//t.SkipNow()

	evs := NewEventTracing(DefaultDebugFSPath)
	listAll := func() []KProbe {
		list, err := evs.ListKProbes()
		if err != nil {
			t.Fatal(err)
		}
		t.Log("Read ", len(list), "kprobes")
		for idx, probe := range list {
			t.Log(idx, ": ", probe.String())
		}
		return list
	}
	for _, kprobe := range listAll() {
		if err := evs.RemoveKProbe(kprobe); err != nil {
			t.Fatal(err, kprobe.String())
		}
	}
	err := evs.AddKProbe(KProbe{
		Name:      "myprobe",
		Address:   "sys_connect",
		Fetchargs: "fd=%di +0(%si) +8(%si) +16(%si) +24(%si)",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = evs.AddKProbe(KProbe{
		Type:      TypeKRetProbe,
		Name:      "myretprobe",
		Address:   "do_sys_open",
		Fetchargs: "retval=%ax",
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := evs.RemoveAllKProbes(); err != nil {
		t.Fatal(err)
	}
	probe := KProbe{
		Name:    "test_kprobe",
		Address: "sys_accept",
		//Fetchargs: "exe=$comm fd=%di +0(%si) +8(%si) +16(%si) +24(%si) +99999(%ax):string",
		Fetchargs: "exe=$comm +0(+0(%dx)):string",
	}
	err = evs.AddKProbe(probe)
	if err != nil {
		t.Fatal(err)
	}
	desc, err := evs.LoadKProbeFormat(probe)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(os.Stderr, "desc=%+v\n", desc)
	decoder := NewMapDecoder(desc)
	/*type myStruct struct {
		//Exe string `kprobe:"exe"`
		PID uint32 `kprobe:"common_pid"`
	}
	var allocFn = func() interface{} {
		return new(myStruct)
	}
	decoder, err := NewStructDecoder(desc, allocFn)
	if err != nil {
		t.Fatal(err)
	}*/

	channel, err := NewPerfChannel(desc.ID)
	if err != nil {
		t.Fatal(err)
	}

	sampleC, errC, err := channel.Run(decoder)
	if err != nil {
		t.Fatal(err)
	}

	for active := true; active; {
		select {
		case iface, ok := <-sampleC:
			if !ok {
				break
			}
			data := iface.(map[string]interface{})
			_, err = fmt.Fprintf(os.Stderr, "Got event len=%d\n", len(data))
			if err != nil {
				panic(err)
			}
			fmt.Fprintf(os.Stderr, "%s event:\n", time.Now().Format(time.RFC3339Nano))
			for k := range desc.Fields {
				v := data[k]
				fmt.Fprintf(os.Stderr, "    %s: %v\n", k, v)
			}
			fmt.Fprintf(os.Stderr, "    raw:\n%s\n", data["_raw_"])
		case err := <-errC:
			t.Log("Err received from channel:", err)
			active = false
		}
	}

	err = channel.Close()
	if err != nil {
		t.Log("channel.Close returned err=", err)
	}

	t.Logf("Got description: %+v", desc)
	err = evs.RemoveKProbe(probe)
	if err != nil {
		t.Fatal(err)
	}
}

func TestKProbeEventsList(t *testing.T) {
	// Make dir to monitor.
	tmpDir, err := ioutil.TempDir("", "events_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	if err := os.MkdirAll(filepath.Join(tmpDir, "tracing"), 0700); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(filepath.Join(tmpDir, "tracing", "kprobe_events"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	_, err = file.WriteString(`
p:probe_1 fancy_function+0x0 exe=$comm fd=%di:u64 addr=+12(%si):x32
r:kprobe/My-Ret-Probe 0xfff30234111
p:some-other_group/myprobe sys_crash
something wrong here
w:future feature
`)
	if err != nil {
		t.Fatal(err)
	}

	evs := NewEventTracing(tmpDir)
	kprobes, err := evs.ListKProbes()
	if err != nil {
		panic(err)
	}
	expected := []KProbe{
		{
			Type:      TypeKProbe,
			Name:      "probe_1",
			Address:   "fancy_function+0x0",
			Fetchargs: "exe=$comm fd=%di:u64 addr=+12(%si):x32",
		},
		{
			Type:    TypeKRetProbe,
			Group:   "kprobe",
			Name:    "My-Ret-Probe",
			Address: "0xfff30234111",
		},
		{
			Group:   "some-other_group",
			Name:    "myprobe",
			Address: "sys_crash",
		},
	}
	assert.Equal(t, expected, kprobes)
}

func TestKProbeEventsAddRemoveKProbe(t *testing.T) {
	// Make dir to monitor.
	tmpDir, err := ioutil.TempDir("", "events_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	if err := os.MkdirAll(filepath.Join(tmpDir, "tracing"), 0700); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(filepath.Join(tmpDir, "tracing", "kprobe_events"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	baseContents := `
p:kprobe/existing fancy_function+0x0 exe=$comm fd=%di:u64 addr=+12(%si):x32
r:kprobe/My-Ret-Probe 0xfff30234111
something wrong here
w:future feature
`
	_, err = file.WriteString(baseContents)
	if err != nil {
		t.Fatal(err)
	}

	evs := NewEventTracing(tmpDir)
	p1 := KProbe{Group: "kprobe", Name: "myprobe", Address: "sys_open", Fetchargs: "path=+0(%di):string mode=%si"}
	p2 := KProbe{Type: TypeKRetProbe, Name: "myretprobe", Address: "0xffffff123456", Fetchargs: "+0(%di) +8(%di) +16(%di)"}
	assert.NoError(t, evs.AddKProbe(p1))
	assert.NoError(t, evs.AddKProbe(p2))
	assert.NoError(t, evs.RemoveKProbe(p1))
	assert.NoError(t, evs.RemoveKProbe(p2))

	off, err := file.Seek(int64(0), io.SeekStart)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), off)
	contents, err := ioutil.ReadAll(file)
	assert.NoError(t, err)
	expected := append([]byte(baseContents), []byte(
		`p:kprobe/myprobe sys_open path=+0(%di):string mode=%si
r:myretprobe 0xffffff123456 +0(%di) +8(%di) +16(%di)
-:kprobe/myprobe
-:myretprobe
`)...)
	assert.Equal(t, strings.Split(string(expected), "\n"), strings.Split(string(contents), "\n"))
}
