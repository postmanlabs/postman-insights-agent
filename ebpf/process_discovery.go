package ebpf

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

// DiscoverTLSProcesses scans /proc to find processes using TLS libraries
func DiscoverTLSProcesses() ([]ProcessInfo, error) {
	var processes []ProcessInfo

	// Common TLS library names to look for
	tlsLibPatterns := []*regexp.Regexp{
		regexp.MustCompile(`libssl\.so`),
		regexp.MustCompile(`libgnutls\.so`),
		regexp.MustCompile(`libssl3\.so`),
		regexp.MustCompile(`libcrypto\.so`),
	}

	// Scan /proc for processes
	procDir := "/proc"
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read /proc")
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pidStr := entry.Name()
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			// Not a PID directory
			continue
		}

		// Read process maps to find loaded TLS libraries
		mapsPath := filepath.Join(procDir, pidStr, "maps")
		libPath, err := findTLSLibraryInMaps(mapsPath, tlsLibPatterns)
		if err != nil {
			// Process may have exited or we don't have permission
			continue
		}

		if libPath != "" {
			// Get process name
			commPath := filepath.Join(procDir, pidStr, "comm")
			name := readProcessName(commPath)

			processes = append(processes, ProcessInfo{
				PID:     pid,
				LibPath: libPath,
				Name:    name,
			})

			printer.Debugf("Found TLS process: PID=%d, Name=%s, Library=%s\n", pid, name, libPath)
		}
	}

	return processes, nil
}

// findTLSLibraryInMaps reads /proc/<pid>/maps and looks for TLS libraries
func findTLSLibraryInMaps(mapsPath string, patterns []*regexp.Regexp) (string, error) {
	file, err := os.Open(mapsPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Maps file format: start-end perms offset dev inode pathname
		// We're interested in the pathname (last field)
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		pathname := fields[len(fields)-1]
		if pathname == "" {
			continue
		}

		// Check if this path matches any TLS library pattern
		for _, pattern := range patterns {
			if pattern.MatchString(pathname) {
				// Resolve symlink to get actual library path
				resolved, err := filepath.EvalSymlinks(pathname)
				if err == nil {
					return resolved, nil
				}
				return pathname, nil
			}
		}
	}

	return "", errors.New("no TLS library found")
}

// readProcessName reads the process name from /proc/<pid>/comm
func readProcessName(commPath string) string {
	data, err := os.ReadFile(commPath)
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

// WatchProcesses continuously monitors for new processes using TLS libraries
func WatchProcesses(callback func([]ProcessInfo) error, stop <-chan struct{}) error {
	// Initial discovery
	processes, err := DiscoverTLSProcesses()
	if err != nil {
		return errors.Wrap(err, "initial process discovery failed")
	}

	if len(processes) > 0 {
		if err := callback(processes); err != nil {
			return errors.Wrap(err, "callback failed")
		}
	}

	// TODO: Implement inotify or periodic polling to detect new processes
	// For now, this is a one-time discovery
	// In production, you'd want to:
	// 1. Use inotify on /proc to detect new PID directories
	// 2. Periodically re-scan for new processes
	// 3. Track which processes we've already attached to

	<-stop
	return nil
}

