// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package socket_tracer

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"acln.ro/perf"
)

const (
	DefaultDebugFSPath = "/sys/kernel/debug"
)

var (
	kprobeRegexp *regexp.Regexp
	formatRegexp *regexp.Regexp
)

type KProbeEvents struct {
	basePath   string
	eventsPath string
}

func init() {
	var err error
	kprobeRegexp, err = regexp.Compile("^([pr]):(?:([^/ ]*)/)?([^/ ]+) ([^ ]+) ?(.*)")
	if err != nil {
		panic(err)
	}
	// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	formatRegexp, err = regexp.Compile("\\s+([^:]+):([^;]*);")
	if err != nil {
		panic(err)
	}
}

func NewKProbeEvents(debugFSPath string) *KProbeEvents {
	return &KProbeEvents{
		basePath:   debugFSPath,
		eventsPath: filepath.Join(debugFSPath, "tracing/kprobe_events"),
	}
}

func (dfs *KProbeEvents) Supported() bool {
	return perf.Supported() && fileMode(dfs.eventsPath, 0600)
}

func (dfs *KProbeEvents) List() (kprobes []KProbe, err error) {
	file, err := os.Open(dfs.eventsPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if matches := kprobeRegexp.FindStringSubmatch(scanner.Text()); len(matches) == 6 {
			var typ KProbeType
			if matches[1][0] == 'r' {
				typ = TypeKRetProbe
			}
			kprobes = append(kprobes, KProbe{
				Type:      typ,
				Group:     matches[2],
				Name:      matches[3],
				Address:   matches[4],
				Fetchargs: matches[5],
			})
		}
	}
	return kprobes, nil
}

func (dfs *KProbeEvents) appendKProbe(desc string) error {
	file, err := os.OpenFile(dfs.eventsPath, os.O_WRONLY|os.O_APPEND|os.O_SYNC, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(desc + "\n")
	return err
}

func (dfs *KProbeEvents) AddKProbe(probe KProbe) error {
	return dfs.appendKProbe(probe.String())
}

func (dfs *KProbeEvents) RemoveKProbe(probe KProbe) error {
	return dfs.appendKProbe(probe.UninstallString())
}

type FieldType uint8

const (
	FieldTypeInteger = iota
	FieldTypeString
)

type Field struct {
	Name   string
	Offset int
	Size   int
	Signed bool
	Type   FieldType
}

type Fields map[string]Field

type KProbeDesc struct {
	ID     int
	Fields Fields
}

var integerTypes = map[string]int{
	"char":  1,
	"short": 2,
	"int":   4,
	"long":  8,
	"s8":    1,
	"s16":   2,
	"s32":   4,
	"s64":   8,
	"u8":    1,
	"u16":   2,
	"u32":   4,
	"u64":   8,
}

func (dfs *KProbeEvents) LoadKProbeDescription(probe KProbe) (desc KProbeDesc, err error) {
	group := "kprobe"
	if len(probe.Group) != 0 {
		group = probe.Group
	}
	path := filepath.Join(dfs.basePath, "tracing/events", group, probe.Name, "format")
	file, err := os.Open(path)
	if err != nil {
		return desc, err
	}
	desc.Fields = make(map[string]Field)
	scanner := bufio.NewScanner(file)
	parseFormat := false
	for scanner.Scan() {
		if !parseFormat {
			parts := strings.SplitN(scanner.Text(), ": ", 2)
			switch {
			case len(parts) == 2 && parts[0] == "ID":
				if desc.ID, err = strconv.Atoi(parts[1]); err != nil {
					return desc, err
				}
			case len(parts) == 1 && parts[0] == "format:":
				parseFormat = true
			}
		} else {
			var f Field
			matches := formatRegexp.FindAllStringSubmatch(scanner.Text(), -1)
			//fmt.Fprintf(os.Stderr, "XXX Got matches = %v\n", matches)
			if len(matches) != 4 {
				continue
			}
			for _, match := range matches {
				if len(match) != 3 {
					// TODO
					continue
				}
				key, value := match[1], match[2]
				switch key {
				case "field":
					fparts := strings.Split(value, " ")
					n := len(fparts)
					if n < 2 {
						// TODO
						panic(value)
					}
					f.Name = fparts[n-1]
					fparts = fparts[:n-1]
					typeIdx := -1
					isDataLoc := false
					//f.Type = strings.Join(fparts[:n-1], " ") // TODO cleanup
					for idx, part := range fparts {
						switch part {
						case "signed", "unsigned":
							// ignore
						case "__data_loc":
							isDataLoc = true
						default:
							if typeIdx != -1 {
								panic("extra arguments in type:" + value)
							}
							typeIdx = idx
						}
					}
					if typeIdx == -1 {
						panic("no type in:" + value)
					}
					intLen, isInt := integerTypes[fparts[typeIdx]]
					if isInt {
						f.Type = FieldTypeInteger
						f.Size = intLen
					} else {
						if fparts[typeIdx] != "char[]" || !isDataLoc {
							panic("bad string type:" + value)
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
						panic("int field length mismatch at:" + value)
					}
				case "signed":
					f.Signed = len(value) > 0 && value[0] != '0'
				}
			}
			if f.Type == FieldTypeString && f.Size != 4 {
				panic("wrong size for string:" + scanner.Text())
			}
			desc.Fields[f.Name] = f
		}
	}
	return desc, nil
}

func fileMode(path string, mode os.FileMode) bool {
	if fInfo, err := os.Stat(path); err == nil {
		return (fInfo.Mode() & (os.ModeDir | mode)) == mode
	}
	return false
}
