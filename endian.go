// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package socket_tracer

import (
	"encoding/binary"
	"unsafe"
)

var machineEndian = getCPUEndianness()

func getCPUEndianness() binary.ByteOrder {
	a := [2]byte{0x12, 0x34}
	asInt := *((*uint16)(unsafe.Pointer(&a[0])))
	switch asInt {
	case 0x1234:
		return binary.BigEndian
	case 0x3412:
		return binary.LittleEndian
	default:
		panic("couldn't figure out endianness")
	}
}
