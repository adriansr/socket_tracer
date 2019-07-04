// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package socket_tracer

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"unsafe"
)

// Decoder decodes a raw event into an usable type.
type Decoder interface {
	Decode(raw []byte, meta Metadata) (interface{}, error)
}

type mapDecoder []Field

// NewMapDecoder creates a new decoder that will parse raw tracing events
// into a map[string]interface{}. This decoder will decode all the fields
// described in the format.
// The map keys are the field names as given in the format.
// The map values are fixed-size integers for integer fields:
// uint8, uint16, uint32, uint64, or, for signed fields, their signed counterpart.
// For string fields, the value is a string.
// Null string fields will be the null interface.
func NewMapDecoder(format ProbeDescription) Decoder {
	fields := make([]Field, 0, len(format.Fields))
	for _, field := range format.Fields {
		fields = append(fields, field)
	}
	sort.Slice(fields, func(i, j int) bool {
		return fields[i].Offset < fields[j].Offset
	})
	return mapDecoder(fields)
}

func (f mapDecoder) Decode(raw []byte, meta Metadata) (mapIf interface{}, err error) {
	n := len(raw)
	m := make(map[string]interface{}, len(f)+1)
	m["meta"] = meta
	for _, field := range f {
		if field.Offset+field.Size > n {
			return nil, fmt.Errorf("perf event field %s overflows message of size %d", field.Name, n)
		}
		var value interface{}
		ptr := unsafe.Pointer(&raw[field.Offset])
		switch field.Type {
		case FieldTypeInteger:
			if value, err = readInt(ptr, uint8(field.Size), field.Signed); err != nil {
				return nil, fmt.Errorf("bad size=%d for integer field=%s", field.Size, field.Name)
			}

		case FieldTypeString:
			offset := int(MachineEndian.Uint16(raw[field.Offset:]))
			len := int(MachineEndian.Uint16(raw[field.Offset+2:]))
			if offset+len > n {
				return nil, fmt.Errorf("perf event string data for field %s overflows message of size %d", field.Name, n)
			}
			// (null) strings have data offset equal to string description offset
			if len != 0 || offset != field.Offset {
				if len > 0 && raw[offset+len-1] == 0 {
					len--
				}
				value = string(raw[offset : offset+len])
			}
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
	reflect.Int:     {},
	reflect.Int8:    {},
	reflect.Int16:   {},
	reflect.Int32:   {},
	reflect.Int64:   {},
	reflect.Uint:    {},
	reflect.Uint8:   {},
	reflect.Uint16:  {},
	reflect.Uint32:  {},
	reflect.Uint64:  {},
	reflect.Uintptr: {},
}

const maxIntSizeBytes = 8

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
func NewStructDecoder(desc ProbeDescription, allocFn AllocateFn) (Decoder, error) {
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
		if name == "metadata" {
			if outField.Type != reflect.TypeOf(Metadata{}) {
				return nil, errors.New("bad type for meta field")
			}
			dec.fields = append(dec.fields, fieldDecoder{
				name: name,
				typ:  FieldTypeMeta,
				dst:  outField.Offset,
				// src&len are unused, this avoids checking len against actual payload
				src: 0,
				len: 0,
			})
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
			// Paranoid
			if inField.Size > maxIntSizeBytes {
				return nil, fmt.Errorf("fix me: unexpected integer of size %d in field `%s`",
					inField.Size, name)
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
		return dec.fields[i].src < dec.fields[j].src
	})
	return dec, nil
}

func (d *structDecoder) Decode(raw []byte, meta Metadata) (s interface{}, err error) {
	n := uintptr(len(raw))

	// Allocate a new struct to fill
	s = d.alloc()

	// Get a raw pointer to the struct
	uptr := reflect.ValueOf(s).Pointer()

	for _, dec := range d.fields {
		if dec.src+dec.len > n {
			return nil, fmt.Errorf("perf event field %s overflows message of size %d", dec.name, n)
		}
		switch dec.typ {
		case FieldTypeInteger:
			dst := unsafe.Pointer(uptr + dec.dst)
			src := unsafe.Pointer(&raw[dec.src])
			if err := copyInt(dst, src, uint8(dec.len)); err != nil {
				return nil, fmt.Errorf("bad size=%d for integer field=%s", dec.len, dec.name)
			}

		case FieldTypeString:
			offset := uintptr(MachineEndian.Uint16(raw[dec.src:]))
			len := uintptr(MachineEndian.Uint16(raw[dec.src+2:]))
			if offset+len > n {
				return nil, fmt.Errorf("perf event string data for field %s overflows message of size %d", dec.name, n)
			}
			if len > 0 && raw[offset+len-1] == 0 {
				len--
			}
			*((*string)(unsafe.Pointer(uptr + dec.dst))) = string(raw[offset : offset+len])

		case FieldTypeMeta:
			*(*Metadata)(unsafe.Pointer(uptr + dec.dst)) = meta
		}

	}

	return s, nil
}
