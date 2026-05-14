// SPDX-License-Identifier: Apache-2.0
//
// Resolver maps (pid, fd) pairs into 4-tuple socket metadata by inspecting
// /proc. Adapted from the older origin/feature/capture-https branch
// (https/resolver.go) with these changes:
//
//   1. /proc/<pid>/net/tcp{,6} (per-PID, namespace-correct) instead of
//      /proc/net/tcp (host namespace only).
//   2. TTL cache is per-PID because socket inode IDs are only unique within
//      a netns.
//
// Thread-safe.

package events

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SocketInfo is the resolved 4-tuple for a socket.
type SocketInfo struct {
	LocalIP    net.IP
	LocalPort  int
	RemoteIP   net.IP
	RemotePort int
}

// Resolver caches /proc/<pid>/net/tcp{,6} contents keyed by socket inode.
type Resolver struct {
	ttl time.Duration

	mu     sync.Mutex
	perPID map[uint32]*pidCache
}

type pidCache struct {
	mu          sync.Mutex
	lastRefresh time.Time
	byInode     map[uint64]SocketInfo
}

// NewResolver constructs a resolver. ttl <= 0 defaults to 1s.
func NewResolver(ttl time.Duration) *Resolver {
	if ttl <= 0 {
		ttl = 1 * time.Second
	}
	return &Resolver{
		ttl:    ttl,
		perPID: make(map[uint32]*pidCache),
	}
}

// Resolve returns SocketInfo for (pid, fd). Returns an error if the fd is
// unknown / not a socket / not in /proc/<pid>/net/tcp{,6}.
func (r *Resolver) Resolve(pid uint32, fd int32) (SocketInfo, error) {
	if fd < 0 {
		return SocketInfo{}, errors.New("ebpf/events: fd is unknown (-1)")
	}
	inode, err := inodeFromFD(pid, int(fd))
	if err != nil {
		return SocketInfo{}, err
	}

	r.mu.Lock()
	c, ok := r.perPID[pid]
	if !ok {
		c = &pidCache{byInode: map[uint64]SocketInfo{}}
		r.perPID[pid] = c
	}
	r.mu.Unlock()

	// Try cached lookup; on miss, force a fresh refresh and retry.
	if info, ok := c.lookup(pid, inode, r.ttl, false); ok {
		return info, nil
	}
	if info, ok := c.lookup(pid, inode, r.ttl, true); ok {
		return info, nil
	}
	return SocketInfo{}, fmt.Errorf("ebpf/events: socket inode %d not in /proc/%d/net/tcp{,6}", inode, pid)
}

// Forget drops the cache for a PID (called on PID exit to bound memory).
func (r *Resolver) Forget(pid uint32) {
	r.mu.Lock()
	delete(r.perPID, pid)
	r.mu.Unlock()
}

// lookup refreshes the cache if needed (or forced), then returns inode hit.
func (c *pidCache) lookup(pid uint32, inode uint64, ttl time.Duration, force bool) (SocketInfo, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if force || time.Since(c.lastRefresh) > ttl {
		fresh := map[uint64]SocketInfo{}
		// Best-effort: tcp6 absent on IPv6-disabled hosts.
		_ = parseProcNetTCPForPID(pid, "tcp", fresh)
		_ = parseProcNetTCPForPID(pid, "tcp6", fresh)
		c.byInode = fresh
		c.lastRefresh = time.Now()
	}
	info, ok := c.byInode[inode]
	return info, ok
}

func inodeFromFD(pid uint32, fd int) (uint64, error) {
	linkPath := filepath.Join("/proc", strconv.Itoa(int(pid)), "fd", strconv.Itoa(fd))
	target, err := os.Readlink(linkPath)
	if err != nil {
		return 0, fmt.Errorf("ebpf/events: readlink %s: %w", linkPath, err)
	}
	if !strings.HasPrefix(target, "socket:[") {
		return 0, fmt.Errorf("ebpf/events: fd %s is not a socket (target=%s)", linkPath, target)
	}
	inodeStr := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
	return strconv.ParseUint(inodeStr, 10, 64)
}

func parseProcNetTCPForPID(pid uint32, which string, cache map[uint64]SocketInfo) error {
	path := filepath.Join("/proc", strconv.Itoa(int(pid)), "net", which)
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return scanner.Err()
	}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		localIP, localPort, err := parseProcAddress(fields[1])
		if err != nil {
			continue
		}
		remoteIP, remotePort, err := parseProcAddress(fields[2])
		if err != nil {
			continue
		}
		cache[inode] = SocketInfo{
			LocalIP:    localIP,
			LocalPort:  localPort,
			RemoteIP:   remoteIP,
			RemotePort: remotePort,
		}
	}
	return scanner.Err()
}

// parseProcAddress parses an /proc/net/tcp address column. IPv4 is 8 hex
// chars + ":HHHH" port; IPv6 is 32 hex chars. Bytes are stored host-endian
// per 4-byte word; we reverse to network order.
func parseProcAddress(addr string) (net.IP, int, error) {
	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		return nil, 0, fmt.Errorf("invalid address %s", addr)
	}
	port, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return nil, 0, err
	}
	ipHex := parts[0]
	switch len(ipHex) {
	case 8:
		b, err := hex.DecodeString(ipHex)
		if err != nil {
			return nil, 0, err
		}
		for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
			b[i], b[j] = b[j], b[i]
		}
		return net.IP(b), int(port), nil
	case 32:
		b, err := hex.DecodeString(ipHex)
		if err != nil {
			return nil, 0, err
		}
		for i := 0; i < len(b); i += 4 {
			for j, k := i, i+3; j < k; j, k = j+1, k-1 {
				b[j], b[k] = b[k], b[j]
			}
		}
		return net.IP(b), int(port), nil
	}
	return nil, 0, fmt.Errorf("unsupported address length %d in %s", len(ipHex), addr)
}
