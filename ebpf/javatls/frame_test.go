// SPDX-License-Identifier: Apache-2.0

package javatls

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"testing"
)

type vectorFile struct {
	Magic      string          `json:"magic"`
	HeaderSize int             `json:"header_size"`
	Frames     []vectorFrame   `json:"frames"`
	Invalid    []vectorInvalid `json:"invalid"`
	Addresses  []vectorAddress `json:"addresses"`
}

type vectorAddress struct {
	Name       string `json:"name"`
	Local      string `json:"local"`
	LocalPort  uint16 `json:"local_port"`
	Remote     string `json:"remote"`
	RemotePort uint16 `json:"remote_port"`
	PayloadHex string `json:"payload_hex"`
}

func (va vectorAddress) address() Address {
	return Address{
		Local:  netip.AddrPortFrom(netip.MustParseAddr(va.Local), va.LocalPort),
		Remote: netip.AddrPortFrom(netip.MustParseAddr(va.Remote), va.RemotePort),
	}
}

type vectorFrame struct {
	Name       string `json:"name"`
	Version    uint8  `json:"version"`
	Op         uint8  `json:"op"`
	Flags      uint16 `json:"flags"`
	ConnID     string `json:"conn_id"`
	PeerAddr   string `json:"peer_addr"`
	PeerPort   uint16 `json:"peer_port"`
	TotalLen   uint32 `json:"total_len"`
	PayloadHex string `json:"payload_hex"`
	FrameHex   string `json:"frame_hex"`
}

type vectorInvalid struct {
	Name     string `json:"name"`
	FrameHex string `json:"frame_hex"`
	Error    string `json:"error"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/frames-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (vf vectorFrame) frame(t *testing.T) Frame {
	t.Helper()
	connID, err := strconv.ParseUint(vf.ConnID, 0, 64)
	if err != nil {
		t.Fatal(err)
	}
	f := Frame{
		Version:  vf.Version,
		Op:       vf.Op,
		Flags:    vf.Flags,
		ConnID:   connID,
		PeerPort: vf.PeerPort,
		TotalLen: vf.TotalLen,
		Payload:  mustHex(t, vf.PayloadHex),
	}
	if vf.PeerAddr != "" {
		f.PeerAddr = netip.MustParseAddr(vf.PeerAddr).As16()
	}
	return f
}

func TestVectorsHeader(t *testing.T) {
	v := loadVectors(t)
	magic, err := strconv.ParseUint(v.Magic, 0, 64)
	if err != nil {
		t.Fatal(err)
	}
	if magic != Magic {
		t.Errorf("vectors magic %#x, Magic %#x", magic, Magic)
	}
	if v.HeaderSize != HeaderSize {
		t.Errorf("vectors header_size %d, HeaderSize %d", v.HeaderSize, HeaderSize)
	}
	if len(v.Frames) == 0 || len(v.Invalid) == 0 || len(v.Addresses) == 0 {
		t.Fatal("vectors file has no frames")
	}
}

func TestVectorsEncode(t *testing.T) {
	for _, vf := range loadVectors(t).Frames {
		t.Run(vf.Name, func(t *testing.T) {
			got := vf.frame(t).Append(nil)
			if want := mustHex(t, vf.FrameHex); !bytes.Equal(got, want) {
				t.Errorf("encoded\n %x\nwant\n %x", got, want)
			}
		})
	}
}

func TestVectorsParse(t *testing.T) {
	for _, vf := range loadVectors(t).Frames {
		t.Run(vf.Name, func(t *testing.T) {
			got, err := Parse(mustHex(t, vf.FrameHex))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			want := vf.frame(t)
			if got.Version != want.Version || got.Op != want.Op || got.Flags != want.Flags ||
				got.ConnID != want.ConnID || got.PeerAddr != want.PeerAddr ||
				got.PeerPort != want.PeerPort || got.TotalLen != want.TotalLen ||
				!bytes.Equal(got.Payload, want.Payload) {
				t.Errorf("Parse = %+v\nwant %+v", got, want)
			}
			if vf.PeerAddr != "" {
				ap, ok := got.Peer()
				if !ok || ap.Addr().String() != vf.PeerAddr || ap.Port() != vf.PeerPort {
					t.Errorf("Peer() = %v, %v; want %s port %d", ap, ok, vf.PeerAddr, vf.PeerPort)
				}
			}
		})
	}
}

func TestVectorsInvalid(t *testing.T) {
	errs := map[string]error{
		"short":        ErrShort,
		"version":      ErrVersion,
		"op":           ErrOp,
		"reserved":     ErrReservedBits,
		"length":       ErrLength,
		"total_length": ErrTotalLength,
		"address":      ErrAddress,
	}
	for _, vi := range loadVectors(t).Invalid {
		t.Run(vi.Name, func(t *testing.T) {
			want, ok := errs[vi.Error]
			if !ok {
				t.Fatalf("unknown error kind %q in vectors", vi.Error)
			}
			if _, err := Parse(mustHex(t, vi.FrameHex)); !errors.Is(err, want) {
				t.Errorf("Parse error = %v, want %v", err, want)
			}
		})
	}
}

func TestVectorsAddress(t *testing.T) {
	for _, va := range loadVectors(t).Addresses {
		t.Run(va.Name, func(t *testing.T) {
			want := mustHex(t, va.PayloadHex)
			if got := va.address().Append(nil); !bytes.Equal(got, want) {
				t.Errorf("encoded\n %x\nwant\n %x", got, want)
			}
			got, err := ParseAddress(want)
			if err != nil {
				t.Fatalf("ParseAddress: %v", err)
			}
			if got != va.address() {
				t.Errorf("ParseAddress = %v, want %v", got, va.address())
			}
		})
	}
	// An IPv4-mapped address is encoded as IPv4 and decoded unmapped.
	mapped := Address{
		Local:  netip.MustParseAddrPort("[::ffff:10.0.0.5]:51234"),
		Remote: netip.MustParseAddrPort("10.1.2.3:8443"),
	}
	got, err := ParseAddress(mapped.Append(nil))
	if err != nil || got.Local != netip.MustParseAddrPort("10.0.0.5:51234") || got.Remote != mapped.Remote {
		t.Errorf("mapped round trip = %v, %v", got, err)
	}
}

func TestSSLCtx(t *testing.T) {
	if got := SSLCtx(42); got != 42|1<<63 || !IsJavaSSLCtx(got) {
		t.Errorf("SSLCtx(42) = %#x", got)
	}
	if IsJavaSSLCtx(0x00007f0012345678) {
		t.Error("a user-space pointer was classified as a Java connection id")
	}
}

// TestKernelHeaderInSync checks that the constants in the kernel's copy of the
// format (java_frame.h) match this package.
func TestKernelHeaderInSync(t *testing.T) {
	raw, err := os.ReadFile("../programs/java_frame.h")
	if err != nil {
		t.Fatal(err)
	}
	defines := map[string]uint64{}
	for _, m := range regexp.MustCompile(`(?m)^#define\s+(JAVA_\w+)\s+\(?([0-9A-Fa-fx]+)(?:ULL)?(?:\s*<<\s*(\d+))?\)?`).FindAllStringSubmatch(string(raw), -1) {
		v, err := strconv.ParseUint(m[2], 0, 64)
		if err != nil {
			t.Fatalf("%s: %v", m[1], err)
		}
		if m[3] != "" {
			shift, _ := strconv.Atoi(m[3])
			v <<= shift
		}
		defines[m[1]] = v
	}
	want := map[string]uint64{
		"JAVA_FRAME_MAGIC":             Magic,
		"JAVA_FRAME_VERSION_1":         uint64(Version1),
		"JAVA_FRAME_HEADER_SIZE":       HeaderSize,
		"JAVA_FRAME_OP_SEND":           uint64(OpSend),
		"JAVA_FRAME_OP_RECV":           uint64(OpRecv),
		"JAVA_FRAME_OP_HEARTBEAT":      uint64(OpHeartbeat),
		"JAVA_FRAME_OP_CLOSE":          uint64(OpClose),
		"JAVA_FRAME_OP_ADDRESS":        uint64(OpAddress),
		"JAVA_FRAME_ADDRESS_SIZE":      AddressSize,
		"JAVA_FRAME_FLAG_ROLE_KNOWN":   uint64(FlagRoleKnown),
		"JAVA_FRAME_FLAG_CLIENT_MODE":  uint64(FlagClientMode),
		"JAVA_FRAME_FLAG_PEER_KNOWN":   uint64(FlagPeerKnown),
		"JAVA_FRAME_FLAG_SOCKET":       uint64(FlagSocket),
		"JAVA_FRAME_FLAG_BEFORE_WRITE": uint64(FlagBeforeWrite),
		"JAVA_CONN_ID_TAG":             ConnIDTag,
	}
	for name, w := range want {
		got, ok := defines[name]
		if !ok {
			t.Errorf("java_frame.h does not define %s", name)
			continue
		}
		if got != w {
			t.Errorf("java_frame.h %s = %#x, Go has %#x", name, got, w)
		}
	}
	for name := range defines {
		if _, ok := want[name]; !ok {
			t.Errorf("java_frame.h defines %s, which this test does not check; add it to frame.go", name)
		}
	}

	// The struct's field order must match the Go offsets.
	fields := regexp.MustCompile(`(?m)^\s+__(u8|u16|u32|u64)\s+(\w+)(?:\[(\d+)\])?;`).FindAllStringSubmatch(string(raw), -1)
	wantFields := []struct {
		name string
		off  int
	}{
		{"version", offVersion}, {"op", offOp}, {"flags", offFlags}, {"payload_len", offPayloadLen},
		{"conn_id", offConnID}, {"peer_addr", offPeerAddr}, {"peer_port", offPeerPort},
		{"_reserved", offReserved}, {"total_len", offTotalLen},
	}
	if len(fields) != len(wantFields) {
		t.Fatalf("java_frame_header has %d fields, want %d", len(fields), len(wantFields))
	}
	off := 0
	for i, f := range fields {
		size := map[string]int{"u8": 1, "u16": 2, "u32": 4, "u64": 8}[f[1]]
		if f[3] != "" {
			n, _ := strconv.Atoi(f[3])
			size *= n
		}
		if f[2] != wantFields[i].name || off != wantFields[i].off {
			t.Errorf("field %d: java_frame.h has %s at offset %d, want %s at %d",
				i, f[2], off, wantFields[i].name, wantFields[i].off)
		}
		off += size
	}
	if off != HeaderSize {
		t.Errorf("java_frame_header is %d bytes, want %d", off, HeaderSize)
	}
}
