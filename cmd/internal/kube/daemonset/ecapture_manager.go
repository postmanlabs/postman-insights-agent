package daemonset

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/postmanlabs/postman-insights-agent/printer"
)

// EcaptureProcess represents a running eCapture process for a specific pod
type EcaptureProcess struct {
	ContainerID string
	PodName     string
	OutputFile  string
	OutFileHandle *os.File
	Cmd         *exec.Cmd
	Ctx         context.Context
	Cancel      context.CancelFunc
	mu          sync.Mutex
}

// EcaptureManager manages eCapture processes for multiple pods
type EcaptureManager struct {
	processes map[string]*EcaptureProcess // keyed by containerID
	mu        sync.RWMutex
	outputDir string
}

// NewEcaptureManager creates a new eCapture manager
func NewEcaptureManager() *EcaptureManager {
	outputDir := "/tmp/ecapture-output"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		printer.Errorf("Failed to create eCapture output directory: %v\n", err)
	}

	return &EcaptureManager{
		processes: make(map[string]*EcaptureProcess),
		outputDir: outputDir,
	}
}

// StartCapture starts an eCapture process for a pod with the given SSL library info
// Returns the output file path where captured traffic will be written
func (m *EcaptureManager) StartCapture(containerID, podName string, sslInfo *SSLLibraryInfo) (string, error) {
	if sslInfo == nil || len(sslInfo.LibraryPaths) == 0 {
		return "", fmt.Errorf("no SSL library information available for pod %s", podName)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already running
	if proc, exists := m.processes[containerID]; exists {
		printer.Debugf("eCapture already running for container %s (pod: %s)\n", containerID, podName)
		return proc.OutputFile, nil
	}

	// Select the first SSL library path (or implement smarter selection logic)
	libPath := sslInfo.LibraryPaths[0]

	// Create output file for this pod's traffic
	outputFile := filepath.Join(m.outputDir, fmt.Sprintf("%s.txt", containerID))

	// Create context for cancellation
	ctx, cancel := context.WithCancel(context.Background())

	// Build eCapture command
	// eCapture command format: ecapture tls --libssl=<path>
	// Note: -w is for pcap format, we want text output to stdout which we'll redirect to file
	cmd := exec.CommandContext(ctx, "/ecapture", "tls",
		"--libssl="+libPath,
	)

	// Open output file for writing
	outFile, err := os.Create(outputFile)
	if err != nil {
		cancel()
		return "", fmt.Errorf("failed to create output file %s: %w", outputFile, err)
	}

	// Redirect stdout to file for capture, stderr to agent logs for debugging
	cmd.Stdout = outFile
	cmd.Stderr = os.Stderr

	printer.Infof("Starting eCapture for pod %s (container: %s, lib: %s)\n",
		podName, containerID, libPath)
	printer.Debugf("eCapture output will be written to: %s\n", outputFile)

	// Start the process
	if err := cmd.Start(); err != nil {
		cancel()
		return "", fmt.Errorf("failed to start eCapture for pod %s: %w", podName, err)
	}

	// Store process info
	proc := &EcaptureProcess{
		ContainerID:   containerID,
		PodName:       podName,
		OutputFile:    outputFile,
		OutFileHandle: outFile,
		Cmd:           cmd,
		Ctx:           ctx,
		Cancel:        cancel,
	}
	m.processes[containerID] = proc

	// Monitor process in goroutine
	go m.monitorProcess(proc)

	printer.Infof("eCapture started for pod %s, output: %s\n", podName, outputFile)
	printer.Debugf("eCapture process PID for pod %s: %d\n", podName, cmd.Process.Pid)
	return outputFile, nil
}

// StopCapture stops the eCapture process for a given container
func (m *EcaptureManager) StopCapture(containerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	proc, exists := m.processes[containerID]
	if !exists {
		return fmt.Errorf("no eCapture process found for container %s", containerID)
	}

	proc.mu.Lock()
	defer proc.mu.Unlock()

	printer.Infof("Stopping eCapture for pod %s (container: %s)\n", proc.PodName, containerID)

	// Cancel the context to signal shutdown
	proc.Cancel()

	// Wait for process to exit (with timeout)
	done := make(chan error, 1)
	go func() {
		done <- proc.Cmd.Wait()
	}()

	select {
	case <-time.After(5 * time.Second):
		// Force kill if graceful shutdown takes too long
		if proc.Cmd.Process != nil {
			proc.Cmd.Process.Kill()
		}
		printer.Warningf("eCapture process for pod %s did not exit gracefully, killed\n", proc.PodName)
	case err := <-done:
		if err != nil && err.Error() != "signal: killed" && err.Error() != "context canceled" {
			printer.Debugf("eCapture process for pod %s exited with error: %v\n", proc.PodName, err)
		}
	}

	// Close output file and log final size
	if proc.OutFileHandle != nil {
		fileInfo, _ := proc.OutFileHandle.Stat()
		proc.OutFileHandle.Close()
		if fileInfo != nil {
			printer.Infof("eCapture output file for pod %s closed, size: %d bytes\n", proc.PodName, fileInfo.Size())
		}
	}

	delete(m.processes, containerID)
	return nil
}

// GetOutputFile returns the output file path for a given container's eCapture process
func (m *EcaptureManager) GetOutputFile(containerID string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	proc, exists := m.processes[containerID]
	if !exists {
		return "", fmt.Errorf("no eCapture process found for container %s", containerID)
	}

	return proc.OutputFile, nil
}

// monitorProcess monitors an eCapture process and handles unexpected exits
func (m *EcaptureManager) monitorProcess(proc *EcaptureProcess) {
	err := proc.Cmd.Wait()

	// Check if this was an expected shutdown (context canceled)
	select {
	case <-proc.Ctx.Done():
		printer.Debugf("eCapture process for pod %s exited normally\n", proc.PodName)
		return
	default:
		// Unexpected exit
		if err != nil {
			printer.Errorf("eCapture process for pod %s exited unexpectedly: %v\n", proc.PodName, err)
		} else {
			printer.Warningf("eCapture process for pod %s exited unexpectedly without error\n", proc.PodName)
		}

		// Remove from map
		m.mu.Lock()
		delete(m.processes, proc.ContainerID)
		m.mu.Unlock()
	}
}

// Shutdown stops all running eCapture processes
func (m *EcaptureManager) Shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()

	printer.Infof("Shutting down eCapture manager, stopping %d processes\n", len(m.processes))

	for containerID := range m.processes {
		// Unlock for StopCapture call (which locks internally)
		m.mu.Unlock()
		if err := m.StopCapture(containerID); err != nil {
			printer.Errorf("Error stopping eCapture for container %s: %v\n", containerID, err)
		}
		m.mu.Lock()
	}
}
