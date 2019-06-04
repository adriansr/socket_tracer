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

type Decoder interface {
	Decode([]byte) (interface{}, error)
}

type mapDecoder []Field

func NewMapDecoder(desc KProbeDesc) Decoder {
	fields := make([]Field, 0, len(desc.Fields))
	for _, field := range desc.Fields {
		fields = append(fields, field)
	}
	sort.Slice(fields, func(i, j int) bool {
		return fields[i].Offset < fields[i].Offset
	})
	return mapDecoder(fields)
}

func getPayload(raw []byte) ([]byte, error) {
	if len(raw) < 4 {
		return nil, errors.New("perf event to small to parse")
	}
	n := int(MachineEndian.Uint32(raw))
	if len(raw) < n+4 {
		return nil, fmt.Errorf("perf event truncated. Expected %d got %d", n+4, len(raw))
	}
	return raw[4 : 4+n], nil
}

func (f mapDecoder) Decode(raw []byte) (mapIf interface{}, err error) {
	if raw, err = getPayload(raw); err != nil {
		return nil, err
	}
	n := len(raw)
	m := make(map[string]interface{}, n)
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
				value = uint8(raw[field.Offset])
			case 2:
				value = MachineEndian.Uint16(raw[field.Offset:])
			case 4:
				value = MachineEndian.Uint32(raw[field.Offset:])
			case 8:
				value = MachineEndian.Uint64(raw[field.Offset:])
			default:
				return nil, fmt.Errorf("bad size=%d for integer field=%s", field.Size, field.Name)
			}
		case FieldTypeString:
			offset := int(MachineEndian.Uint16(raw[field.Offset:]))
			len := int(MachineEndian.Uint16(raw[field.Offset+2:]))
			if offset+len > n {
				return nil, fmt.Errorf("perf event string data for field %s overflows message of size %d", field.Name, n)
			}
			value = string(raw[offset : offset+len])
		}
		m[field.Name] = value
	}
	return m, nil
}

type AllocateFn func() (interface{}, unsafe.Pointer)

type fieldDecoder struct {
	typ  FieldType
	src  uintptr
	dst  uintptr
	len  uintptr
	name string
}

type StructDecoder struct {
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

func NewStructDecoder(desc KProbeDesc, allocFn AllocateFn, mappings map[string]string) (Decoder, error) {
	dec := new(StructDecoder)
	dec.alloc = allocFn
	dec.fields = make([]fieldDecoder, 0, len(mappings))

	sample, _ := allocFn()
	tSample := reflect.ValueOf(sample).Elem().Type()
	if tSample.Kind() != reflect.Struct {
		return nil, errors.New("allocator function doesn't return a struct")
	}
	for name, destName := range mappings {
		inField, found := desc.Fields[name]
		if !found {
			return nil, fmt.Errorf("field '%s' not found in kprobe format description", name)
		}
		outField, found := tSample.FieldByName(destName)
		if !found {
			return nil, fmt.Errorf("struct field '%s' not found in structure", destName)
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

func (d *StructDecoder) Decode(raw []byte) (s interface{}, err error) {
	if raw, err = getPayload(raw); err != nil {
		return nil, err
	}
	n := uintptr(len(raw))

	var ptr unsafe.Pointer
	s, ptr = d.alloc()
	uptr := uintptr(ptr)

	for _, dec := range d.fields {
		if dec.src+dec.len > n {
			return nil, fmt.Errorf("perf event field %s overflows message of size %d", dec.name, n)
		}
		switch dec.typ {
		case FieldTypeInteger:
			copy((*(*[8]byte)(unsafe.Pointer(uptr + dec.dst)))[:dec.len], raw[dec.src:dec.src+dec.len])

		case FieldTypeString:
			offset := uintptr(MachineEndian.Uint16(raw[dec.src:]))
			len := uintptr(MachineEndian.Uint16(raw[dec.src+2:]))
			if offset+len > n {
				return nil, fmt.Errorf("perf event string data for field %s overflows message of size %d", dec.name, n)
			}
			*((*string)(unsafe.Pointer(uptr + dec.dst))) = string(raw[offset : offset+len])
		}
	}

	return s, nil
}

/*
name: test_name
ID: 1383
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long __probe_ip;	offset:8;	size:8;	signed:0;

print fmt: "(%lx)", REC->__probe_ip
*/

/*
 -> field:(type) name; offset:O; size:S; signed:Z;

 -> copy(ptr[structOFF:structOFF+S], src[O:O+S])

mapping:

type MyStruct struct {
	pid uint32
    flags uint8
    ctype int16
}

var sampleStruct MyStruct
xxx.Mapping(myStructAlloc,
	FieldUint32("common_pid", sampleStruct, &sampleStruct.pid),
    FieldUint8("common_flags", sampleStruct, &sampleStruct.flags)),
    FieldUint16("common_type", sampleStruct, &sampleStruct.ctype)),
*/
