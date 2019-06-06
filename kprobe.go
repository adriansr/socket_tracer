// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package socket_tracer

import (
	"strings"
)

// KProbeType represents the type of a kprobe.
type KProbeType uint8

const (
	TypeKProbe KProbeType = iota
	TypeKRetProbe
)

// KProbe represents a kprobe or kretprobe.
type KProbe struct {
	// Type tells whether this is a kprobe or a kretprobe.
	Type KProbeType

	// Group is the KProbe's group. If left unset, it will be automatically
	// set to "kprobes". This affects where the kprobe configuration resides
	// in `debugfs`:
	// /sys/kernel/debug/tracing/events/<group>/<name>
	Group string

	// Name is the name given to this KProbe. If left empty (not recommended),
	// the kernel will give it a name based on Address. Then it will be
	// necessary to list the installed KProbes and figure out which one it is,
	// so it can be used with LoadKProbeDescription.
	Name string

	// Address is the function name or address where the probe will be installed.
	// According to the docs: `[MOD:]SYM[+offs]|MEMADDR`.
	Address string

	// Fetchargs is the string of arguments that will be fetched when the probe
	// is hit.
	Fetchargs string
}

// String converts this KProbe to the textual representation expected by the Kernel.
func (kp *KProbe) String() string {
	var builder strings.Builder
	if kp.Type == TypeKProbe {
		builder.WriteString("p:")
	} else {
		builder.WriteString("r:")
	}
	if len(kp.Group) > 0 {
		builder.WriteString(kp.Group)
		builder.WriteByte('/')
	}
	builder.WriteString(kp.Name)
	builder.WriteByte(' ')
	builder.WriteString(kp.Address)
	builder.WriteByte(' ')
	builder.WriteString(kp.Fetchargs)
	return builder.String()
}

// RemoveString converts this probe to the textual representation needed to
// remove the probe.
func (kp *KProbe) RemoveString() string {
	var builder strings.Builder
	builder.WriteString("-:")
	if len(kp.Group) > 0 {
		builder.WriteString(kp.Group)
		builder.WriteByte('/')
	}
	builder.WriteString(kp.Name)
	return builder.String()
}

// EffectiveGroup is the actual group used to access this kprobe inside debugfs.
// It is the group given when setting the probe, or "kprobes" if unset.
func (kp *KProbe) EffectiveGroup() string {
	if len(kp.Group) > 0 {
		return kp.Group
	}
	return "kprobes"
}
