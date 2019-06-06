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
	myInt32 := new(uint32)
	copy((*[4]byte)(unsafe.Pointer(myInt32))[:], []byte{0x12, 0x34, 0x56, 0x78})
	switch *myInt32 {
	case 0x12345678:
		return binary.BigEndian
	case 0x78563412:
		return binary.LittleEndian
	default:
		panic("couldn't figure out endianness")
	}
}
