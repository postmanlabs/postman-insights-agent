// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package ebpf

import (
	"context"
	"encoding/binary"
	"time"

	ciliumebpf "github.com/cilium/ebpf"

	"github.com/postmanlabs/postman-insights-agent/ebpf/events"
	"github.com/postmanlabs/postman-insights-agent/ebpf/loader"
)

// preResolveLoop scans the BPF ssl_ctx_to_fd map every `interval` and resolves
// each (pid, fd) into a 4-tuple while the socket is still alive, caching
// results on the adapter. This bridges the race where SSL_set_fd → SSL_free
// happens faster than the ringbuf → adapter pipeline can drain.
//
// Without this, a late-arriving SSL_read/SSL_write event whose connection
// has already closed (socket fd reclaimed, /proc/<pid>/fd/<fd> gone) cannot
// resolve its 4-tuple and falls back to 0.0.0.0.
//
// Returns when ctx is cancelled.
func preResolveLoop(
	ctx context.Context,
	ldr *loader.Loader,
	resolver *events.Resolver,
	adapter *events.Adapter,
	interval time.Duration,
) {
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	if resolver == nil || adapter == nil {
		return
	}

	m := ldr.RateBucketsMap() // dummy initial reference; replaced below
	_ = m
	fdMap, ok := loaderSslFdMap(ldr)
	if !ok {
		return
	}

	t := time.NewTicker(interval)
	defer t.Stop()

	type key struct {
		Tgid uint32
		_    uint32
		Ssl  uint64
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			it := fdMap.Iterate()
			var k key
			var fd int32
			for it.Next(&k, &fd) {
				if fd < 0 {
					continue
				}
				info, err := resolver.Resolve(k.Tgid, fd)
				if err != nil {
					continue
				}
				adapter.PreResolve(k.Tgid, k.Ssl, fd, info)
			}
			_ = binary.LittleEndian // silence unused import
		}
	}
}

// loaderSslFdMap retrieves the ssl_ctx_to_fd map from the loader. We accept
// the loader because the bpf2go-generated map handle isn't exported directly.
func loaderSslFdMap(ldr *loader.Loader) (*ciliumebpf.Map, bool) {
	return ldr.SSLFdMap()
}
