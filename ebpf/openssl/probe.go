package openssl

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	maxTLSData   = 512
	flagTruncate = 1
	dirWrite     = 1
	dirRead      = 2
)

// Direction describes the flow direction of the TLS payload relative to the
// instrumented process.
type Direction uint32

const (
	// DirectionClient is emitted when SSL_write is invoked (client -> server).
	DirectionClient Direction = dirWrite
	// DirectionServer is emitted when SSL_read returns data (server -> client).
	DirectionServer Direction = dirRead
)

func (d Direction) String() string {
	switch d {
	case DirectionClient:
		return "client"
	case DirectionServer:
		return "server"
	default:
		return fmt.Sprintf("unknown-%d", d)
	}
}

// Event represents a decrypted TLS payload captured via SSL_write / SSL_read.
type Event struct {
	Timestamp time.Time
	SSLPtr    uint64
	PID       int
	TID       int
	FD        int
	Direction Direction
	TotalLen  int
	Payload   []byte
	Truncated bool
}

// Options configure the OpenSSL probe.
type Options struct {
	// Libraries contains absolute paths to libssl shared objects. At least one
	// entry is required.
	Libraries []string
	// EventBuffer controls the size of the buffered channel returned by
	// Events(). Defaults to 256.
	EventBuffer int
}

// Probe loads the eBPF program and produces TLS payload events.
type Probe struct {
	objs   OpenSSLTLSObjects
	reader *ringbuf.Reader
	links  []link.Link

	events chan Event
	errs   chan error

	cancel    context.CancelFunc
	closeOnce sync.Once
}

// NewProbe loads the OpenSSL uprobe program and attaches it to all configured
// shared objects.
func NewProbe(ctx context.Context, opts Options) (*Probe, error) {
	if len(opts.Libraries) == 0 {
		return nil, errors.New("openssl: at least one library path is required")
	}
	if opts.EventBuffer <= 0 {
		opts.EventBuffer = 256
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("openssl: adjust memlock: %w", err)
	}

	var objs OpenSSLTLSObjects
	if err := LoadOpenSSLTLSObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("openssl: load objects: %w", err)
	}

	p := &Probe{
		objs:   objs,
		events: make(chan Event, opts.EventBuffer),
		errs:   make(chan error, opts.EventBuffer),
	}

	for _, lib := range opts.Libraries {
		exe, err := link.OpenExecutable(lib)
		if err != nil {
			p.Close()
			return nil, fmt.Errorf("openssl: open %s: %w", lib, err)
		}

		attach := func(sym string, prog *ebpf.Program) error {
			lk, err := exe.Uprobe(sym, prog, nil)
			if err != nil {
				return err
			}
			p.links = append(p.links, lk)
			return nil
		}

		attachRet := func(sym string, prog *ebpf.Program) error {
			lk, err := exe.Uretprobe(sym, prog, nil)
			if err != nil {
				return err
			}
			p.links = append(p.links, lk)
			return nil
		}

		if err := attach("SSL_set_fd", p.objs.HandleSslSetFd); err != nil {
			p.Close()
			return nil, fmt.Errorf("openssl: attach SSL_set_fd on %s: %w", lib, err)
		}
		if err := attach("SSL_free", p.objs.HandleSslFree); err != nil {
			p.Close()
			return nil, fmt.Errorf("openssl: attach SSL_free on %s: %w", lib, err)
		}
		if err := attach("SSL_write", p.objs.HandleSslWriteEntry); err != nil {
			p.Close()
			return nil, fmt.Errorf("openssl: attach SSL_write entry on %s: %w", lib, err)
		}
		if err := attachRet("SSL_write", p.objs.HandleSslWriteExit); err != nil {
			p.Close()
			return nil, fmt.Errorf("openssl: attach SSL_write exit on %s: %w", lib, err)
		}
		if err := attach("SSL_read", p.objs.HandleSslReadEntry); err != nil {
			p.Close()
			return nil, fmt.Errorf("openssl: attach SSL_read entry on %s: %w", lib, err)
		}
		if err := attachRet("SSL_read", p.objs.HandleSslReadExit); err != nil {
			p.Close()
			return nil, fmt.Errorf("openssl: attach SSL_read exit on %s: %w", lib, err)
		}

	}

	reader, err := ringbuf.NewReader(p.objs.TlsEvents)
	if err != nil {
		p.Close()
		return nil, fmt.Errorf("openssl: create ringbuf reader: %w", err)
	}
	p.reader = reader

	runCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	go p.run(runCtx)

	return p, nil
}

// Events returns the channel of TLS payload events.
func (p *Probe) Events() <-chan Event {
	return p.events
}

// Errors returns asynchronous errors emitted by the reader.
func (p *Probe) Errors() <-chan error {
	return p.errs
}

// Close detaches and releases all resources.
func (p *Probe) Close() error {
	var err error
	p.closeOnce.Do(func() {
		if p.cancel != nil {
			p.cancel()
		}
		if p.reader != nil {
			p.reader.Close()
		}
		for _, lk := range p.links {
			lk.Close()
		}
		err = p.objs.Close()
		close(p.events)
		close(p.errs)
	})
	return err
}

type rawEvent struct {
	TimestampNS uint64
	SSLPtr      uint64
	PID         uint32
	TID         uint32
	FD          int32
	TotalLen    uint32
	DataLen     uint32
	Direction   uint32
	Flags       uint32
	Data        [maxTLSData]byte
}

func (p *Probe) run(ctx context.Context) {
	defer func() {
		p.reader.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := p.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			p.enqueueError(fmt.Errorf("openssl: ringbuf read: %w", err))
			continue
		}

		var raw rawEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			p.enqueueError(fmt.Errorf("openssl: decode sample: %w", err))
			continue
		}

		payload := make([]byte, int(raw.DataLen))
		copy(payload, raw.Data[:raw.DataLen])

		evt := Event{
			Timestamp: time.Unix(0, int64(raw.TimestampNS)),
			SSLPtr:    raw.SSLPtr,
			PID:       int(raw.PID),
			TID:       int(raw.TID),
			FD:        int(raw.FD),
			Direction: Direction(raw.Direction),
			TotalLen:  int(raw.TotalLen),
			Payload:   payload,
			Truncated: raw.Flags&flagTruncate != 0,
		}

		select {
		case p.events <- evt:
		case <-ctx.Done():
			return
		}
	}
}

func (p *Probe) enqueueError(err error) {
	select {
	case p.errs <- err:
	default:
	}
}
