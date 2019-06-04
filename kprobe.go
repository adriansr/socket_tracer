package socket_tracer

import "strings"

type KProbeType uint8

const (
	TypeKProbe KProbeType = iota
	TypeKRetProbe
)

// KProbe defines kprobe settings
type KProbe struct {
	Type      KProbeType
	Group     string
	Name      string
	Address   string
	Fetchargs string
}

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

func (kp *KProbe) UninstallString() string {
	var builder strings.Builder
	builder.WriteString("-:")
	if len(kp.Group) > 0 {
		builder.WriteString(kp.Group)
		builder.WriteByte('/')
	}
	builder.WriteString(kp.Name)
	return builder.String()
}
