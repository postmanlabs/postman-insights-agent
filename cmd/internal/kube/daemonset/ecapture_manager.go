package daemonset

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"

	"github.com/postmanlabs/postman-insights-agent/pcap"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

// EcaptureProcess represents a running eCapture process for a specific pod
type EcaptureProcess struct {
	ContainerID string
	PodName     string
	SSLPath     string
	// RestartAttempts tracks how many times we've retried after an unexpected exit.
	RestartAttempts int
	TextReader      *pcap.EcaptureTextReader // Reader for text mode output
	Cmd             *exec.Cmd
	Ctx             context.Context
	Cancel          context.CancelFunc
	mu              sync.Mutex
}

// EcaptureManager manages eCapture processes for multiple pods
type EcaptureManager struct {
	processes map[string]*EcaptureProcess // keyed by containerID
	mu        sync.RWMutex
}

// NewEcaptureManager creates a new eCapture manager
func NewEcaptureManager() *EcaptureManager {
	return &EcaptureManager{
		processes: make(map[string]*EcaptureProcess),
	}
}

// StartCapture starts an eCapture process for a pod with the given SSL library info
// Returns the container ID (used as identifier to retrieve frame channel later)
func (m *EcaptureManager) StartCapture(containerID, podName string, sslInfo *SSLLibraryInfo) (string, error) {
	if sslInfo == nil || len(sslInfo.LibraryPaths) == 0 {
		return "", fmt.Errorf("no SSL library information available for pod %s", podName)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already running
	if _, exists := m.processes[containerID]; exists {
		printer.Debugf("eCapture already running for container %s (pod: %s)\n", containerID, podName)
		return containerID, nil
	}

	// Select the first SSL library path (or implement smarter selection logic)
	libPath := sslInfo.LibraryPaths[0]

	// Create context for cancellation
	ctx, cancel := context.WithCancel(context.Background())

	// Build eCapture command in TEXT mode (outputs decrypted plaintext to stdout)
	// eCapture command format: ecapture tls --libssl=<path> -m text
	cmd := exec.CommandContext(ctx, "/ecapture", "tls",
		"--libssl="+libPath,
		"-m", "text",
	)

	printer.Infof("🔥 DEBUG: Starting eCapture in TEXT mode for pod %s\n", podName)
	printer.Infof("🔥 DEBUG: Container: %s\n", containerID)
	printer.Infof("🔥 DEBUG: SSL library: %s\n", libPath)
	printer.Infof("🔥 DEBUG: Command: %v\n", cmd.Args)

	// Capture stdout with pipe (NEVER write plaintext to disk)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return "", fmt.Errorf("failed to create stdout pipe for pod %s: %w", podName, err)
	}

	// Capture stderr to agent logs for debugging
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return "", fmt.Errorf("failed to create stderr pipe for pod %s: %w", podName, err)
	}

	// Start the process BEFORE creating reader (pipe must be ready)
	if err := cmd.Start(); err != nil {
		cancel()
		return "", fmt.Errorf("failed to start eCapture for pod %s: %w", podName, err)
	}

	// Create text reader to process stdout
	textReader := pcap.NewEcaptureTextReader(stdout, podName)
	textReader.Start()

	// Store process info
	proc := &EcaptureProcess{
		ContainerID: containerID,
		PodName:     podName,
		SSLPath:     libPath,
		TextReader:  textReader,
		Cmd:         cmd,
		Ctx:         ctx,
		Cancel:      cancel,
	}
	m.processes[containerID] = proc

	// Monitor process in goroutine
	go m.monitorProcess(proc)
	// Stream stderr
	go captureEcaptureStderr(proc.PodName, stderr)

	printer.Infof("eCapture TEXT mode started for pod %s (PID: %d)\n", podName, cmd.Process.Pid)
	printer.Debugf("eCapture will output decrypted HTTP/HTTPS traffic to in-memory channel\n")

	// Return container ID as identifier (used to retrieve frame channel later)
	return containerID, nil
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

	// Stop the text reader first
	if proc.TextReader != nil {
		proc.TextReader.Stop()
	}

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

	delete(m.processes, containerID)
	return nil
}

// GetFrameChannel returns the frame channel for a given container's eCapture process
func (m *EcaptureManager) GetFrameChannel(containerID string) (<-chan pcap.RawFrame, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	proc, exists := m.processes[containerID]
	if !exists {
		return nil, fmt.Errorf("no eCapture process found for container %s", containerID)
	}

	if proc.TextReader == nil {
		return nil, fmt.Errorf("text reader not initialized for container %s", containerID)
	}

	return proc.TextReader.FrameChannel(), nil
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

		// Attempt a single restart
		const maxRestartAttempts = 1
		if proc.RestartAttempts < maxRestartAttempts {
			proc.RestartAttempts++
			printer.Warningf("Retrying eCapture for pod %s (attempt %d/%d)\n", proc.PodName, proc.RestartAttempts, maxRestartAttempts)
			if err := m.restartCapture(proc); err != nil {
				printer.Errorf("Failed to restart eCapture for pod %s: %v\n", proc.PodName, err)
				m.mu.Lock()
				delete(m.processes, proc.ContainerID)
				m.mu.Unlock()
			}
			return
		}

		// Remove from map if we can't or won't restart
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

// restartCapture attempts to restart eCapture for a pod after an unexpected exit.
// Caller should ensure restart attempts are bounded.
func (m *EcaptureManager) restartCapture(proc *EcaptureProcess) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Ensure the process is still registered
	current, ok := m.processes[proc.ContainerID]
	if !ok || current != proc {
		return fmt.Errorf("cannot restart eCapture; process not registered for container %s", proc.ContainerID)
	}

	// Create fresh context
	ctx, cancel := context.WithCancel(context.Background())

	cmd := exec.CommandContext(ctx, "/ecapture", "tls",
		"--libssl="+proc.SSLPath,
		"-m", "text",
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("failed to create stdout pipe on restart for pod %s: %w", proc.PodName, err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("failed to create stderr pipe on restart for pod %s: %w", proc.PodName, err)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("failed to restart eCapture for pod %s: %w", proc.PodName, err)
	}

	textReader := pcap.NewEcaptureTextReader(stdout, proc.PodName)
	textReader.Start()

	// Update proc fields
	proc.TextReader = textReader
	proc.Cmd = cmd
	proc.Ctx = ctx
	proc.Cancel = cancel

	go m.monitorProcess(proc)
	go captureEcaptureStderr(proc.PodName, stderr)

	printer.Infof("eCapture restarted for pod %s (PID: %d)\n", proc.PodName, cmd.Process.Pid)
	return nil
}

// captureEcaptureStderr streams stderr lines from eCapture to agent logs.
func captureEcaptureStderr(podName string, r io.ReadCloser) {
	defer r.Close()
	scanner := bufio.NewScanner(r)
	// Limit log spam via scanner default token size; we rely on eCapture to output reasonable lines.
	for scanner.Scan() {
		printer.Errorf("eCapture stderr for pod %s: %s\n", podName, scanner.Text())
	}
}
