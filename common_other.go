// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build !386,!amd64,!amd64p32

package socket_tracer

import (
	"errors"
	"unsafe"
)

var errBadSize = errors.New("bad size for integer")

func copyInt(dst unsafe.Pointer, src unsafe.Pointer, len uint8) error {
	copy((*(*[maxIntSizeBytes]byte)(src))[:len], (*(*[maxIntSizeBytes]byte)(src))[:len])
	return nil
}

func readInt(ptr unsafe.Pointer, len uint8, signed bool) (value interface{}, err error) {
	asSlice := (*(*[maxIntSizeBytes]byte)(ptr))[:]
	switch len {
	case 1:
		if signed {
			value = int8(asSlice[0])
		} else {
			value = uint8(asSlice[0])
		}
	case 2:
		if signed {
			value = int16(machineEndian.Uint16(asSlice))
		} else {
			value = machineEndian.Uint16(asSlice)
		}

	case 4:
		if signed {
			value = int32(machineEndian.Uint32(asSlice))
		} else {
			value = machineEndian.Uint32(asSlice)
		}

	case 8:
		if signed {
			value = int64(machineEndian.Uint64(asSlice))
		} else {
			value = machineEndian.Uint64(asSlice)
		}

	default:
		return nil, errBadSize
	}
	return
}