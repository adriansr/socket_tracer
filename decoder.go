// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package socket_tracer

import (
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"unsafe"
)

// Decoder decodes a raw event into an usable type.
type Decoder interface {
	Decode([]byte) (interface{}, error)
}

type mapDecoder []Field

// NewMapDecoder creates a new decoder that will parse raw tracing events
// into a map[string]interface{}. This decoder will decode all the fields
// described in the format.
// The map keys are the field names as given in the format.
// The map values are fixed-size integers for integer fields:
// uint8, uint16, uint32, uint64, or their signed counterpart, for signed fields.
// For string fields, the value is a string.
func NewMapDecoder(format KProbeFormat) Decoder {
	fields := make([]Field, 0, len(format.Fields))
	for _, field := range format.Fields {
		fields = append(fields, field)
	}
	sort.Slice(fields, func(i, j int) bool {
		return fields[i].Offset < fields[i].Offset
	})
	return mapDecoder(fields)
}

func (f mapDecoder) Decode(raw []byte) (mapIf interface{}, err error) {
	if raw, err = getPayload(raw); err != nil {
		return nil, err
	}
	n := len(raw)
	m := make(map[string]interface{}, len(f))
	if false {
		var r []string
		for i := range raw {
			r = append(r, hex.EncodeToString(raw[i:i+1]))
		}
		m["_raw_"] = strings.Join(r, ", 0x")
	}
	for _, field := range f {
		if field.Offset+field.Size > n {
			return nil, fmt.Errorf("perf event field %s overflows message of size %d", field.Name, n)
		}
		var value interface{}
		switch field.Type {
		case FieldTypeInteger:
			switch field.Size {
			case 1:
				if field.Signed {
					value = int8(raw[field.Offset])
				} else {
					value = uint8(raw[field.Offset])
				}
			case 2:
				if field.Signed {
					value = int16(machineEndian.Uint16(raw[field.Offset:]))
				} else {
					value = machineEndian.Uint16(raw[field.Offset:])
				}

			case 4:
				if field.Signed {
					value = int32(machineEndian.Uint32(raw[field.Offset:]))
				} else {
					value = machineEndian.Uint32(raw[field.Offset:])
				}

			case 8:
				if field.Signed {
					value = int64(machineEndian.Uint64(raw[field.Offset:]))
				} else {
					value = machineEndian.Uint64(raw[field.Offset:])
				}

			default:
				return nil, fmt.Errorf("bad size=%d for integer field=%s", field.Size, field.Name)
			}

		case FieldTypeString:
			offset := int(machineEndian.Uint16(raw[field.Offset:]))
			len := int(machineEndian.Uint16(raw[field.Offset+2:]))
			if offset+len > n {
				return nil, fmt.Errorf("perf event string data for field %s overflows message of size %d", field.Name, n)
			}
			value = string(raw[offset : offset+len])
		}
		m[field.Name] = value
	}
	return m, nil
}

// AllocateFn is the type of a function that allocates a custom struct
// to be used with StructDecoder. This function must return a pointer to
// a struct.
type AllocateFn func() interface{}

type fieldDecoder struct {
	typ  FieldType
	src  uintptr
	dst  uintptr
	len  uintptr
	name string
}

type structDecoder struct {
	alloc  AllocateFn
	fields []fieldDecoder
}

var intFields = map[reflect.Kind]struct{}{
	reflect.Int:    {},
	reflect.Int8:   {},
	reflect.Int16:  {},
	reflect.Int32:  {},
	reflect.Int64:  {},
	reflect.Uint8:  {},
	reflect.Uint16: {},
	reflect.Uint32: {},
	reflect.Uint64: {},
}

// NewMapDecoder creates a new decoder that will parse raw tracing events
// into a struct.
//
// This custom struct has to be annotated so that the required KProbeFormat
// fields are stored in the appropriate struct fields, as in:
//
//	type myStruct struct {
//		Type   uint16 `kprobe:"common_type"`
//		Flags  uint8  `kprobe:"common_flags"`
//		PCount uint8  `kprobe:"common_preempt_count"`
//		PID    uint32 `kprobe:"common_pid"`
//		IP     uint64 `kprobe:"__probe_ip"`
//		Exe    string `kprobe:"exe"`
//		Fd     uint64 `kprobe:"fd"`
//		Arg3   uint64 `kprobe:"arg3"`
//		Arg4   uint32 `kprobe:"arg4"`
//		Arg5   uint16 `kprobe:"arg5"`
//		Arg6   uint8  `kprobe:"arg6"`
//	}
//
// There's no need to map all fields in the event.
//
// The custom allocator has to return a pointer to the struct. There's no actual
// need to allocate a new struct each time, as long as the consumer of a perf
// event channel manages the lifetime of the returned structs.
//
// This decoder is faster than the map decoder and results in fewer allocations:
// Only string fields need to be allocated, plus the allocation by allocFn.
func NewStructDecoder(desc KProbeFormat, allocFn AllocateFn) (Decoder, error) {
	dec := new(structDecoder)
	dec.alloc = allocFn

	sample := allocFn()
	tSample := reflect.TypeOf(sample)
	if tSample.Kind() != reflect.Ptr {
		return nil, errors.New("allocator function doesn't return a pointer")
	}
	tSample = tSample.Elem()
	if tSample.Kind() != reflect.Struct {
		return nil, errors.New("allocator function doesn't return a pointer to a struct")
	}
	for i := 0; i < tSample.NumField(); i++ {
		outField := tSample.Field(i)
		name, found := outField.Tag.Lookup("kprobe")
		if !found {
			// Untagged field
			continue
		}
		inField, found := desc.Fields[name]
		if !found {
			return nil, fmt.Errorf("field '%s' not found in kprobe format description", name)
		}

		switch inField.Type {
		case FieldTypeInteger:
			if _, found := intFields[outField.Type.Kind()]; !found {
				return nil, fmt.Errorf("wrong struct field type for field '%s', fixed size integer required", name)
			}
			if outField.Type.Size() != uintptr(inField.Size) {
				return nil, fmt.Errorf("wrong struct field size for field '%s', got=%d required=%d",
					name, outField.Type.Size(), inField.Size)
			}

		case FieldTypeString:
			if outField.Type.Kind() != reflect.String {
				return nil, fmt.Errorf("wrong struct field type for field '%s', it should be string", name)
			}

		default:
			// Should not happen
			return nil, fmt.Errorf("unexpected field type for field '%s'", name)
		}
		dec.fields = append(dec.fields, fieldDecoder{
			typ:  inField.Type,
			src:  uintptr(inField.Offset),
			dst:  outField.Offset,
			len:  uintptr(inField.Size),
			name: name,
		})
	}
	sort.Slice(dec.fields, func(i, j int) bool {
		return dec.fields[i].src < dec.fields[i].dst
	})
	return dec, nil
}

func (d *structDecoder) Decode(raw []byte) (s interface{}, err error) {
	if raw, err = getPayload(raw); err != nil {
		return nil, err
	}
	n := uintptr(len(raw))

	s = d.alloc()
	uptr := reflect.ValueOf(s).Pointer()

	for _, dec := range d.fields {
		if dec.src+dec.len > n {
			return nil, fmt.Errorf("perf event field %s overflows message of size %d", dec.name, n)
		}
		switch dec.typ {
		case FieldTypeInteger:
			copy((*(*[8]byte)(unsafe.Pointer(uptr + dec.dst)))[:dec.len], raw[dec.src:dec.src+dec.len])

		case FieldTypeString:
			offset := uintptr(machineEndian.Uint16(raw[dec.src:]))
			len := uintptr(machineEndian.Uint16(raw[dec.src+2:]))
			if offset+len > n {
				return nil, fmt.Errorf("perf event string data for field %s overflows message of size %d", dec.name, n)
			}
			*((*string)(unsafe.Pointer(uptr + dec.dst))) = string(raw[offset : offset+len])
		}
	}

	return s, nil
}

func getPayload(raw []byte) ([]byte, error) {
	if len(raw) < 4 {
		return nil, errors.New("perf event to small to parse")
	}
	n := int(machineEndian.Uint32(raw))
	if len(raw) < n+4 {
		return nil, fmt.Errorf("perf event truncated. Expected %d got %d", n+4, len(raw))
	}
	return raw[4 : 4+n], nil
}
