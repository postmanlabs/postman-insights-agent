package https

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

type socketInfo struct {
    localIP   net.IP
    localPort int
    remoteIP  net.IP
    remotePort int
}

// socketResolver resolves (pid, fd) pairs into socket metadata by inspecting
// /proc. Results are cached for a short TTL to avoid hammering the fs.
type socketResolver struct {
    ttl time.Duration

    mu           sync.Mutex
    lastRefresh  time.Time
    cache        map[uint64]socketInfo
}

func newSocketResolver(ttl time.Duration) *socketResolver {
    return &socketResolver{
        ttl:   ttl,
        cache: make(map[uint64]socketInfo),
    }
}

func (r *socketResolver) Resolve(pid int, fd int) (socketInfo, error) {
    inode, err := inodeFromFD(pid, fd)
    if err != nil {
        return socketInfo{}, err
    }

    r.mu.Lock()
    defer r.mu.Unlock()

    if time.Since(r.lastRefresh) > r.ttl {
        if err := r.refreshLocked(); err != nil {
            return socketInfo{}, err
        }
    }

    info, ok := r.cache[inode]
    if ok {
        return info, nil
    }

    if err := r.refreshLocked(); err != nil {
        return socketInfo{}, err
    }

    info, ok = r.cache[inode]
    if !ok {
        return socketInfo{}, fmt.Errorf("https resolver: inode %d not found", inode)
    }
    return info, nil
}

func inodeFromFD(pid int, fd int) (uint64, error) {
    linkPath := filepath.Join("/proc", strconv.Itoa(pid), "fd", strconv.Itoa(fd))
    target, err := os.Readlink(linkPath)
    if err != nil {
        return 0, fmt.Errorf("https resolver: readlink %s: %w", linkPath, err)
    }
    if !strings.HasPrefix(target, "socket:[") {
        return 0, fmt.Errorf("https resolver: fd %s is not a socket (target=%s)", linkPath, target)
    }
    inodeStr := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
    inode, err := strconv.ParseUint(inodeStr, 10, 64)
    if err != nil {
        return 0, fmt.Errorf("https resolver: parse inode %s: %w", inodeStr, err)
    }
    return inode, nil
}

func (r *socketResolver) refreshLocked() error {
    cache := make(map[uint64]socketInfo)
    if err := parseProcNetTCP("/proc/net/tcp", cache); err != nil {
        return err
    }
    if err := parseProcNetTCP("/proc/net/tcp6", cache); err != nil {
        if !errors.Is(err, os.ErrNotExist) {
            return err
        }
    }
    r.cache = cache
    r.lastRefresh = time.Now()
    return nil
}

func parseProcNetTCP(path string, cache map[uint64]socketInfo) error {
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
        local := fields[1]
        remote := fields[2]
        inodeStr := fields[9]

        inode, err := strconv.ParseUint(inodeStr, 10, 64)
        if err != nil {
            continue
        }

        localIP, localPort, err := parseAddress(local)
        if err != nil {
            continue
        }
        remoteIP, remotePort, err := parseAddress(remote)
        if err != nil {
            continue
        }

        cache[inode] = socketInfo{
            localIP:    localIP,
            localPort:  localPort,
            remoteIP:   remoteIP,
            remotePort: remotePort,
        }
    }
    return scanner.Err()
}

func parseAddress(addr string) (net.IP, int, error) {
    parts := strings.Split(addr, ":")
    if len(parts) != 2 {
        return nil, 0, fmt.Errorf("invalid address %s", addr)
    }
    port, err := strconv.ParseInt(parts[1], 16, 32)
    if err != nil {
        return nil, 0, err
    }
    ipHex := parts[0]
    if len(ipHex) == 8 {
        bytes, err := hex.DecodeString(ipHex)
        if err != nil {
            return nil, 0, err
        }
        for i, j := 0, len(bytes)-1; i < j; i, j = i+1, j-1 {
            bytes[i], bytes[j] = bytes[j], bytes[i]
        }
        return net.IP(bytes), int(port), nil
    }
    if len(ipHex) == 32 {
        bytes, err := hex.DecodeString(ipHex)
        if err != nil {
            return nil, 0, err
        }
        for i := 0; i < len(bytes); i += 4 {
            for j, k := i, i+3; j < k; j, k = j+1, k-1 {
                bytes[j], bytes[k] = bytes[k], bytes[j]
            }
        }
        return net.IP(bytes), int(port), nil
    }
    return nil, 0, fmt.Errorf("unsupported address %s", addr)
}
