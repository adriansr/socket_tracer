// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package socket_tracer

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	// DefaultDebugFSPath is the usual path where `debugfs` is mounted.
	DefaultDebugFSPath = "/sys/kernel/debug"
)

var (
	kprobeRegexp *regexp.Regexp
	formatRegexp *regexp.Regexp
)

// EventTracing is an accessor to manage event tracing via debugfs.
type EventTracing struct {
	basePath string
}

func init() {
	var err error
	kprobeRegexp, err = regexp.Compile("^([pr]):(?:([^/ ]*)/)?([^/ ]+) ([^ ]+) ?(.*)")
	if err != nil {
		panic(err)
	}

	formatRegexp, err = regexp.Compile("\\s+([^:]+):([^;]*);")
	if err != nil {
		panic(err)
	}
}

// NewEventTracing creates a new accessor for the event tracing feature using
// the given path to a mounted `debugfs`.
// Pass `DefaultDebugFSPath` to use the default path.
func NewEventTracing(debugFSPath string) *EventTracing {
	return &EventTracing{
		basePath: debugFSPath,
	}
}

// ListKProbes lists the currently installed kprobes / kretprobes
func (dfs *EventTracing) ListKProbes() (kprobes []Probe, err error) {
	return dfs.listProbes(kprobeCfgFile)
}

// ListUProbes lists the currently installed uprobes / uretprobes
func (dfs *EventTracing) ListUProbes() (uprobes []Probe, err error) {
	return dfs.listProbes(uprobeCfgFile)
}

func (dfs *EventTracing) listProbes(filename string) (probes []Probe, err error) {
	mapping, ok := probeFileInfo[filename]
	if !ok {
		return nil, fmt.Errorf("unknown probe events file: %s", filename)
	}
	file, err := os.Open(filepath.Join(dfs.basePath, "tracing", filename))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if matches := kprobeRegexp.FindStringSubmatch(scanner.Text()); len(matches) == 6 {
			typ, ok := mapping[matches[1][0]]
			if !ok {
				return nil, fmt.Errorf("no mapping for probe of type '%c' in file %s", matches[1][0], filename)
			}
			probes = append(probes, Probe{
				Type:      typ,
				Group:     matches[2],
				Name:      matches[3],
				Address:   matches[4],
				Fetchargs: matches[5],
			})
		}
	}
	return probes, nil
}

// AddKProbe installs a new kprobe/kretprobe.
func (dfs *EventTracing) AddKProbe(probe Probe) error {
	return dfs.appendProbe(kprobeCfgFile, probe.String())
}

// RemoveKProbe removes an installed kprobe/kretprobe.
func (dfs *EventTracing) RemoveKProbe(probe Probe) error {
	return dfs.appendProbe(kprobeCfgFile, probe.RemoveString())
}

// AddUProbe installs a new uprobe/uretprobe.
func (dfs *EventTracing) AddUProbe(probe Probe) error {
	return dfs.appendProbe(uprobeCfgFile, probe.String())
}

// RemoveUProbe removes an installed uprobe/uretprobe.
func (dfs *EventTracing) RemoveUProbe(probe Probe) error {
	return dfs.appendProbe(uprobeCfgFile, probe.RemoveString())
}

// RemoveAllUProbes removes all installed kprobes and kretprobes.
func (dfs *EventTracing) RemoveAllKProbes() error {
	return dfs.removeAllProbes(kprobeCfgFile)
}

// RemoveAllUProbes removes all installed uprobes and uretprobes.
func (dfs *EventTracing) RemoveAllUProbes() error {
	return dfs.removeAllProbes(uprobeCfgFile)
}

func (dfs *EventTracing) removeAllProbes(filename string) error {
	file, err := os.OpenFile(filepath.Join(dfs.basePath, "tracing", filename), os.O_WRONLY|os.O_TRUNC|os.O_SYNC, 0)
	if err != nil {
		return err
	}
	return file.Close()
}

func (dfs *EventTracing) appendProbe(filename string, desc string) error {
	file, err := os.OpenFile(filepath.Join(dfs.basePath, "tracing", filename), os.O_WRONLY|os.O_APPEND|os.O_SYNC, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(desc + "\n")
	return err
}

// FieldType describes the type of a field in a event tracing probe.
type FieldType uint8

const (
	// FieldTypeInteger describes a fixed-size integer field.
	FieldTypeInteger = iota

	// FieldTypeString describes a string field.
	FieldTypeString
)

// Field describes a field returned by a event tracing probe.
type Field struct {
	// Name is the name given to the field.
	Name string

	// Offset of the field inside the raw event.
	Offset int

	// Size in bytes of the serialised field: 1, 2, 4, 8 for fixed size integers
	// or 4 for strings.
	Size int

	// Signed tells whether an integer is signed (true) or unsigned (false).
	Signed bool

	// Type of field.
	Type FieldType
}

// KProbeFormat describes a KProbe and the serialisation format used to encode
// its arguments into a tracing event.
type KProbeFormat struct {
	// ID is the numeric ID given to this kprobe/kretprobe by the kernel.
	ID int

	// Fields is a description of the fields (fetchargs) set by this kprobe.
	Fields map[string]Field
}

var integerTypes = map[string]uint8{
	"char":  1,
	"s8":    1,
	"u8":    1,
	"short": 2,
	"s16":   2,
	"u16":   2,
	"int":   4,
	"s32":   4,
	"u32":   4,
	"long":  8,
	"s64":   8,
	"u64":   8,
}

// LoadProbeFormat returns the format used for serialisation of the given
// kprobe/kretprobe into a tracing event. The probe needs to be installed
// for the kernel to provide its format.
func (dfs *EventTracing) LoadProbeFormat(probe Probe) (desc KProbeFormat, err error) {
	path := filepath.Join(dfs.basePath, "tracing/events", probe.EffectiveGroup(), probe.Name, "format")
	file, err := os.Open(path)
	if err != nil {
		return desc, err
	}
	desc.Fields = make(map[string]Field)
	scanner := bufio.NewScanner(file)
	parseFormat := false
	for scanner.Scan() {
		line := scanner.Text()
		if !parseFormat {
			// Parse the header
			parts := strings.SplitN(line, ": ", 2)
			switch {
			case len(parts) == 2 && parts[0] == "ID":
				if desc.ID, err = strconv.Atoi(parts[1]); err != nil {
					return desc, err
				}
			case len(parts) == 1 && parts[0] == "format:":
				parseFormat = true
			}
		} else {
			// Parse the fields
			// Ends on the first line that doesn't start with a TAB
			if len(line) > 0 && line[0] != '\t' && line[0] != ' ' {
				break
			}

			// Find all "<key>:<value>;" matches
			// The actual format is:
			// "\tfield:%s %s;\toffset:%u;\tsize:%u;\tsigned:%d;\n"
			var f Field
			matches := formatRegexp.FindAllStringSubmatch(line, -1)
			if len(matches) != 4 {
				continue
			}

			for _, match := range matches {
				if len(match) != 3 {
					continue
				}
				key, value := match[1], match[2]
				switch key {
				case "field":
					fparts := strings.Split(value, " ")
					n := len(fparts)
					if n < 2 {
						return desc, fmt.Errorf("bad format for kprobe '%s': `field` has no type: %s", probe.String(), value)
					}

					fparts, f.Name = fparts[:n-1], fparts[n-1]
					typeIdx, isDataLoc := -1, false

					for idx, part := range fparts {
						switch part {
						case "signed", "unsigned":
							// ignore
						case "__data_loc":
							isDataLoc = true
						default:
							if typeIdx != -1 {
								return desc, fmt.Errorf("bad format for kprobe '%s': unknown parameter=`%s` in type=`%s`", probe.String(), part, value)
							}
							typeIdx = idx
						}
					}
					if typeIdx == -1 {
						return desc, fmt.Errorf("bad format for kprobe '%s': type not found in `%s`", probe.String(), value)
					}
					intLen, isInt := integerTypes[fparts[typeIdx]]
					if isInt {
						f.Type = FieldTypeInteger
						f.Size = int(intLen)
					} else {
						if fparts[typeIdx] != "char[]" || !isDataLoc {
							return desc, fmt.Errorf("bad format for kprobe '%s': unsupported type in `%s`", probe.String(), value)
						}
						f.Type = FieldTypeString
					}

				case "offset":
					f.Offset, err = strconv.Atoi(value)
					if err != nil {
						return desc, err
					}

				case "size":
					prev := f.Size
					f.Size, err = strconv.Atoi(value)
					if err != nil {
						return desc, err
					}
					if prev != 0 && prev != f.Size {
						return desc, fmt.Errorf("bad format for kprobe '%s': int field length mismatch at `%s`", probe.String(), line)
					}

				case "signed":
					f.Signed = len(value) > 0 && value[0] == '1'
				}
			}
			if f.Type == FieldTypeString && f.Size != 4 {
				return desc, fmt.Errorf("bad format for kprobe '%s': unexpected size for string in `%s`", probe.String(), line)
			}
			desc.Fields[f.Name] = f
		}
	}
	return desc, nil
}
