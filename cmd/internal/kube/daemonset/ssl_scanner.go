package daemonset

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/postmanlabs/postman-insights-agent/printer"
)

// SSLLibraryInfo contains information about discovered SSL libraries in a container
type SSLLibraryInfo struct {
	ContainerID  string
	LibraryPaths []string
	LibraryType  string // "openssl", "boringssl", "gnutls", "go", "node", "java"
}

// ScanContainerSSLLibraries scans a container's filesystem (via containerd) for SSL libraries.
// Returns information about discovered libraries that eCapture can hook.
//
// For containerd, the container's root filesystem is mounted at:
// /run/containerd/io.containerd.runtime.v2.task/k8s.io/{containerID}/rootfs
//
// This function searches common library paths within that rootfs:
// - /lib, /lib64, /usr/lib, /usr/lib64 (Debian/Ubuntu/RHEL)
// - /lib, /usr/lib (Alpine/musl)
// - /usr/local/lib (custom builds)
func ScanContainerSSLLibraries(containerID string) (*SSLLibraryInfo, error) {
	if containerID == "" {
		return nil, fmt.Errorf("container ID cannot be empty")
	}

	// Path to container's root filesystem via containerd
	rootfsPath := fmt.Sprintf("/run/containerd/io.containerd.runtime.v2.task/k8s.io/%s/rootfs", containerID)

	// Check if rootfs exists
	if _, err := os.Stat(rootfsPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("container rootfs not found at %s", rootfsPath)
	}

	info := &SSLLibraryInfo{
		ContainerID:  containerID,
		LibraryPaths: []string{},
	}

	// Common library search paths (relative to rootfs)
	searchPaths := []string{
		"lib",
		"lib64",
		"usr/lib",
		"usr/lib64",
		"usr/local/lib",
		"lib/x86_64-linux-gnu",     // Debian/Ubuntu x86_64
		"lib/aarch64-linux-gnu",    // Debian/Ubuntu ARM64
		"usr/lib/x86_64-linux-gnu", // Debian/Ubuntu x86_64
		"usr/lib/aarch64-linux-gnu", // Debian/Ubuntu ARM64
	}

	// Search for SSL libraries
	for _, searchPath := range searchPaths {
		fullPath := filepath.Join(rootfsPath, searchPath)

		// Skip if path doesn't exist
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			continue
		}

		// Walk the directory looking for SSL libraries
		err := filepath.Walk(fullPath, func(path string, fileInfo os.FileInfo, err error) error {
			if err != nil {
				return nil // Skip errors, continue scanning
			}

			// Skip directories
			if fileInfo.IsDir() {
				return nil
			}

			filename := filepath.Base(path)

			// Match SSL library patterns
			// - libssl.so, libssl.so.1, libssl.so.1.1, libssl.so.3
			// Note: Only match libssl, not libcrypto (libcrypto doesn't have SSL_write/SSL_read symbols)
			if strings.Contains(filename, "libssl.so") {

				// Prefer versioned libraries (more specific)
				// e.g., libssl.so.3 over libssl.so
				if strings.Count(filename, ".") >= 2 {
					info.LibraryPaths = append(info.LibraryPaths, path)

					// Detect library type from version
					if strings.Contains(filename, "libssl.so.3") {
						info.LibraryType = "openssl-3.x"
					} else if strings.Contains(filename, "libssl.so.1.1") {
						info.LibraryType = "openssl-1.1.x"
					} else if strings.Contains(filename, "libssl.so.1.0") {
						info.LibraryType = "openssl-1.0.x"
					}
				}
			}

			return nil
		})

		if err != nil {
			printer.Debugf("Error scanning %s: %v\n", fullPath, err)
		}
	}

	// If no libraries found, check for special cases
	if len(info.LibraryPaths) == 0 {
		// Check for Go binaries (no libssl needed, uses crypto/tls)
		if goExecutable := detectGoExecutable(rootfsPath); goExecutable != "" {
			info.LibraryType = "go"
			info.LibraryPaths = []string{goExecutable}
			printer.Debugf("Detected Go application in container %s\n", containerID)
		}

		// Check for Node.js (statically linked SSL)
		if nodeExecutable := detectNodeExecutable(rootfsPath); nodeExecutable != "" {
			info.LibraryType = "node"
			info.LibraryPaths = []string{nodeExecutable}
			printer.Debugf("Detected Node.js application in container %s\n", containerID)
		}

		// Check for Java (uses custom SSL, not supported by eCapture)
		if javaExecutable := detectJavaExecutable(rootfsPath); javaExecutable != "" {
			info.LibraryType = "java"
			printer.Debugf("Detected Java application in container %s (HTTPS capture not supported)\n", containerID)
			return info, fmt.Errorf("Java applications use custom SSL implementation, not supported by eCapture")
		}
	}

	if len(info.LibraryPaths) == 0 && info.LibraryType == "" {
		return nil, fmt.Errorf("no SSL libraries found in container %s", containerID)
	}

	printer.Debugf("Found %d SSL library paths in container %s (type: %s)\n",
		len(info.LibraryPaths), containerID, info.LibraryType)

	return info, nil
}

// detectGoExecutable checks if the container has a Go binary
// Go binaries typically use crypto/tls (no shared libssl)
func detectGoExecutable(rootfsPath string) string {
	// Check common Go binary locations
	goBinaries := []string{
		"usr/local/bin/go",
		"usr/bin/go",
	}

	for _, binPath := range goBinaries {
		fullPath := filepath.Join(rootfsPath, binPath)
		if _, err := os.Stat(fullPath); err == nil {
			return fullPath
		}
	}

	return ""
}

// detectNodeExecutable checks if the container has Node.js
// Node.js statically links SSL, so we target the node binary itself
func detectNodeExecutable(rootfsPath string) string {
	// Check common Node.js binary locations
	nodeBinaries := []string{
		"usr/local/bin/node",
		"usr/bin/node",
		"bin/node",
	}

	for _, binPath := range nodeBinaries {
		fullPath := filepath.Join(rootfsPath, binPath)
		if _, err := os.Stat(fullPath); err == nil {
			return fullPath
		}
	}

	return ""
}

// detectJavaExecutable checks if the container has Java
// Java uses custom SSL (javax.net.ssl), not supported by eCapture
func detectJavaExecutable(rootfsPath string) string {
	// Check common Java binary locations
	javaBinaries := []string{
		"usr/local/openjdk*/bin/java",
		"usr/bin/java",
		"bin/java",
	}

	for _, binPattern := range javaBinaries {
		matches, _ := filepath.Glob(filepath.Join(rootfsPath, binPattern))
		if len(matches) > 0 {
			return matches[0]
		}
	}

	return ""
}
