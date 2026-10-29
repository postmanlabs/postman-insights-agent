// SPDX-License-Identifier: Apache-2.0

package jvm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// HotSpot publishes its performance counters, and the arguments it really
// runs with, in a memory-mapped file: /tmp/hsperfdata_<user>/<nspid> (what
// jps and jstat read). Its vm arguments include those set through
// JAVA_TOOL_OPTIONS, JDK_JAVA_OPTIONS and argument files, which the command
// line does not show.

// perfDataMagic is the file's first four bytes, whatever its byte order:
// HotSpot stores the magic big-endian on every platform (on little-endian
// ones it writes 0xc0c0feca), and the byte after it gives the order of
// everything else. A little-endian file starts ca fe c0 c0 01.
var perfDataMagic = []byte{0xca, 0xfe, 0xc0, 0xc0}

const (
	perfDataPrologueSize = 32
	perfDataEntryHeader  = 20
	perfDataBigEndian    = 0
	perfDataLittleEndian = 1
)

// parsePerfData returns the string entries of a HotSpot perf data file
// (format version 2), by name.
func parsePerfData(b []byte) (map[string]string, error) {
	if len(b) < perfDataPrologueSize || !bytes.Equal(b[:4], perfDataMagic) {
		return nil, errors.New("not a HotSpot perf data file")
	}
	var order binary.ByteOrder
	switch b[4] {
	case perfDataBigEndian:
		order = binary.BigEndian
	case perfDataLittleEndian:
		order = binary.LittleEndian
	default:
		return nil, fmt.Errorf("perf data: unknown byte order %d", b[4])
	}
	if major := b[5]; major != 2 {
		return nil, fmt.Errorf("perf data: unsupported version %d", major)
	}
	off := int(int32(order.Uint32(b[24:28])))
	n := int(int32(order.Uint32(b[28:32])))
	if n < 0 || n > 1<<16 {
		return nil, fmt.Errorf("perf data: %d entries", n)
	}

	out := make(map[string]string)
	for i := 0; i < n; i++ {
		if off < perfDataPrologueSize || off+perfDataEntryHeader > len(b) {
			return nil, errors.New("perf data: truncated")
		}
		e := b[off:]
		length := int(int32(order.Uint32(e[0:4])))
		nameOff := int(int32(order.Uint32(e[4:8])))
		vecLen := int(int32(order.Uint32(e[8:12])))
		dataType := e[12]
		dataOff := int(int32(order.Uint32(e[16:20])))
		if length < perfDataEntryHeader || length > len(e) || nameOff < 0 || nameOff >= length || dataOff < 0 || dataOff > length {
			return nil, errors.New("perf data: bad entry")
		}
		entry := e[:length]
		name := cString(entry[nameOff:])
		// Strings are byte vectors, NUL-terminated within the vector.
		if dataType == 'B' && vecLen > 0 && dataOff+vecLen <= length {
			out[name] = cString(entry[dataOff : dataOff+vecLen])
		}
		off += length
	}
	return out, nil
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
