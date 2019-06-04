package socket_tracer

import (
	"encoding/binary"
	"unsafe"
)

var MachineEndian = getCPUEndianness()

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
