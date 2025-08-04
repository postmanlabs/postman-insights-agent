package daemonset

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestPodArgs_StateTransitions tests basic valid state transitions
func TestPodArgs_StateTransitions(t *testing.T) {
	tests := []struct {
		name          string
		initialState  PodTrafficMonitorState
		targetState   PodTrafficMonitorState
		allowedStates []PodTrafficMonitorState
		expectedError bool
		expectedState PodTrafficMonitorState
	}{
		{
			name:          "PodPending to PodRunning",
			initialState:  PodPending,
			targetState:   PodRunning,
			allowedStates: []PodTrafficMonitorState{PodPending},
			expectedError: false,
			expectedState: PodRunning,
		},
		{
			name:          "PodRunning to TrafficMonitoringRunning",
			initialState:  PodRunning,
			targetState:   TrafficMonitoringRunning,
			allowedStates: []PodTrafficMonitorState{PodRunning},
			expectedError: false,
			expectedState: TrafficMonitoringRunning,
		},
		{
			name:          "TrafficMonitoringRunning to TrafficMonitoringEnded",
			initialState:  TrafficMonitoringRunning,
			targetState:   TrafficMonitoringEnded,
			allowedStates: []PodTrafficMonitorState{TrafficMonitoringRunning, PodSucceeded, PodFailed, PodTerminated, DaemonSetShutdown},
			expectedError: false,
			expectedState: TrafficMonitoringEnded,
		},
		{
			name:          "TrafficMonitoringRunning to TrafficMonitoringFailed",
			initialState:  TrafficMonitoringRunning,
			targetState:   TrafficMonitoringFailed,
			allowedStates: []PodTrafficMonitorState{TrafficMonitoringRunning, PodSucceeded, PodFailed, PodTerminated, DaemonSetShutdown},
			expectedError: false,
			expectedState: TrafficMonitoringFailed,
		},
		{
			name:          "TrafficMonitoringEnded to RemovePodFromMap via markAsPruneReady",
			initialState:  TrafficMonitoringEnded,
			targetState:   RemovePodFromMap,
			expectedError: false,
			expectedState: RemovePodFromMap,
		},
		{
			name:          "TrafficMonitoringFailed to RemovePodFromMap via markAsPruneReady",
			initialState:  TrafficMonitoringFailed,
			targetState:   RemovePodFromMap,
			expectedError: false,
			expectedState: RemovePodFromMap,
		},
		{
			name:          "Any state to DaemonSetShutdown (no restrictions)",
			initialState:  PodRunning,
			targetState:   DaemonSetShutdown,
			expectedError: false,
			expectedState: DaemonSetShutdown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			podArgs := NewPodArgs("test-pod")
			podArgs.PodTrafficMonitorState = tt.initialState

			var err error
			if tt.targetState == RemovePodFromMap {
				err = podArgs.markAsPruneReady()
			} else {
				err = podArgs.changePodTrafficMonitorState(tt.targetState, tt.allowedStates...)
			}

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedState, podArgs.PodTrafficMonitorState)
			}
		})
	}
}

// TestPodArgs_InvalidTransitions tests invalid state transitions
func TestPodArgs_InvalidTransitions(t *testing.T) {
	tests := []struct {
		name          string
		initialState  PodTrafficMonitorState
		targetState   PodTrafficMonitorState
		allowedStates []PodTrafficMonitorState
		expectedError bool
		errorContains string
	}{
		{
			name:          "TrafficMonitoringEnded to any other state should fail",
			initialState:  TrafficMonitoringEnded,
			targetState:   PodRunning,
			allowedStates: []PodTrafficMonitorState{TrafficMonitoringEnded},
			expectedError: true,
			errorContains: "already in final state",
		},
		{
			name:          "TrafficMonitoringFailed to any other state should fail",
			initialState:  TrafficMonitoringFailed,
			targetState:   PodRunning,
			allowedStates: []PodTrafficMonitorState{TrafficMonitoringFailed},
			expectedError: true,
			errorContains: "already in final state",
		},
		{
			name:          "RemovePodFromMap to any other state should fail",
			initialState:  RemovePodFromMap,
			targetState:   PodRunning,
			allowedStates: []PodTrafficMonitorState{RemovePodFromMap},
			expectedError: true,
			errorContains: "already in final state",
		},
		{
			name:          "Transition to same state should fail",
			initialState:  PodRunning,
			targetState:   PodRunning,
			allowedStates: []PodTrafficMonitorState{PodRunning},
			expectedError: true,
			errorContains: "already in state",
		},
		{
			name:          "Invalid transition from PodPending to TrafficMonitoringRunning",
			initialState:  PodPending,
			targetState:   TrafficMonitoringRunning,
			allowedStates: []PodTrafficMonitorState{PodRunning}, // Only PodRunning allowed
			expectedError: true,
			errorContains: "Invalid current state",
		},
		{
			name:          "markAsPruneReady from non-final state should fail",
			initialState:  PodRunning,
			targetState:   RemovePodFromMap,
			expectedError: true,
			errorContains: "Invalid state",
		},
		{
			name:          "markAsPruneReady from RemovePodFromMap should fail",
			initialState:  RemovePodFromMap,
			targetState:   RemovePodFromMap,
			expectedError: true,
			errorContains: "already in final state",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			podArgs := NewPodArgs("test-pod")
			podArgs.PodTrafficMonitorState = tt.initialState

			var err error
			if tt.targetState == RemovePodFromMap && tt.initialState != RemovePodFromMap {
				err = podArgs.markAsPruneReady()
			} else {
				err = podArgs.changePodTrafficMonitorState(tt.targetState, tt.allowedStates...)
			}

			assert.Error(t, err)
			if tt.errorContains != "" {
				assert.Contains(t, err.Error(), tt.errorContains)
			}
			// State should remain unchanged
			assert.Equal(t, tt.initialState, podArgs.PodTrafficMonitorState)
		})
	}
}

// TestPodArgs_ConcurrentAccess tests concurrent access to PodArgs
func TestPodArgs_ConcurrentAccess(t *testing.T) {
	t.Run("Multiple goroutines changing state simultaneously", func(t *testing.T) {
		podArgs := NewPodArgs("test-pod")
		podArgs.PodTrafficMonitorState = PodPending

		var wg sync.WaitGroup
		errors := make(chan error, 10)
		successCount := 0
		var mu sync.Mutex

		// Start 10 goroutines trying to change state simultaneously
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := podArgs.changePodTrafficMonitorState(PodRunning, PodPending)
				if err == nil {
					mu.Lock()
					successCount++
					mu.Unlock()
				}
				errors <- err
			}()
		}

		wg.Wait()
		close(errors)

		// Only one should succeed, others should fail
		errorCount := 0
		for err := range errors {
			if err != nil {
				errorCount++
			}
		}

		assert.Equal(t, 1, successCount, "Only one state change should succeed")
		assert.Equal(t, 9, errorCount, "Nine state changes should fail")
		assert.Equal(t, PodRunning, podArgs.PodTrafficMonitorState, "Final state should be PodRunning")
	})

	t.Run("Race condition between state change and markAsPruneReady", func(t *testing.T) {
		podArgs := NewPodArgs("test-pod")
		podArgs.PodTrafficMonitorState = TrafficMonitoringEnded

		var wg sync.WaitGroup
		errors := make(chan error, 2)

		// Start two goroutines: one changing state, one marking as prune ready
		wg.Add(2)
		go func() {
			defer wg.Done()
			err := podArgs.changePodTrafficMonitorState(PodRunning)
			errors <- err
		}()

		go func() {
			defer wg.Done()
			err := podArgs.markAsPruneReady()
			errors <- err
		}()

		wg.Wait()
		close(errors)

		// One should succeed, one should fail
		errorCount := 0
		for err := range errors {
			if err != nil {
				errorCount++
			}
		}

		assert.Equal(t, 1, errorCount, "One operation should fail")
	})
}

// TestPodArgs_FinalStateProtection tests that pods in final states cannot be modified
func TestPodArgs_FinalStateProtection(t *testing.T) {
	finalStates := []PodTrafficMonitorState{
		TrafficMonitoringEnded,
		TrafficMonitoringFailed,
		RemovePodFromMap,
	}

	for _, finalState := range finalStates {
		t.Run("Cannot change state from "+string(finalState), func(t *testing.T) {
			podArgs := NewPodArgs("test-pod")
			podArgs.PodTrafficMonitorState = finalState

			// Try to change to various states
			testStates := []PodTrafficMonitorState{
				PodPending,
				PodRunning,
				TrafficMonitoringRunning,
				PodSucceeded,
				PodFailed,
				PodTerminated,
				DaemonSetShutdown,
			}

			for _, testState := range testStates {
				err := podArgs.changePodTrafficMonitorState(testState)
				assert.Error(t, err, "Should not be able to change from %s to %s", finalState, testState)
				assert.Contains(t, err.Error(), "already in final state")
				assert.Equal(t, finalState, podArgs.PodTrafficMonitorState, "State should remain unchanged")
			}
		})
	}

	t.Run("Cannot markAsPruneReady when already in RemovePodFromMap", func(t *testing.T) {
		podArgs := NewPodArgs("test-pod")
		podArgs.PodTrafficMonitorState = RemovePodFromMap

		err := podArgs.markAsPruneReady()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already in final state")
		assert.Equal(t, RemovePodFromMap, podArgs.PodTrafficMonitorState)
	})
}

// TestPodArgs_StopChannel tests the StopChan functionality
func TestPodArgs_StopChannel(t *testing.T) {
	t.Run("StopChan is properly initialized", func(t *testing.T) {
		podArgs := NewPodArgs("test-pod")
		assert.NotNil(t, podArgs.StopChan)
		assert.Equal(t, 2, cap(podArgs.StopChan), "StopChan should have capacity of 2")
	})

	t.Run("Can send stop signal", func(t *testing.T) {
		podArgs := NewPodArgs("test-pod")
		stopErr := assert.AnError

		// Send stop signal
		podArgs.StopChan <- stopErr

		// Verify signal was sent
		select {
		case receivedErr := <-podArgs.StopChan:
			assert.Equal(t, stopErr, receivedErr)
		case <-time.After(100 * time.Millisecond):
			t.Fatal("Timeout waiting for stop signal")
		}
	})

	t.Run("Multiple stop signals can be sent", func(t *testing.T) {
		podArgs := NewPodArgs("test-pod")
		err1 := assert.AnError
		err2 := assert.AnError

		// Send two stop signals
		podArgs.StopChan <- err1
		podArgs.StopChan <- err2

		// Verify both signals were sent
		select {
		case receivedErr := <-podArgs.StopChan:
			assert.Equal(t, err1, receivedErr)
		case <-time.After(100 * time.Millisecond):
			t.Fatal("Timeout waiting for first stop signal")
		}

		select {
		case receivedErr := <-podArgs.StopChan:
			assert.Equal(t, err2, receivedErr)
		case <-time.After(100 * time.Millisecond):
			t.Fatal("Timeout waiting for second stop signal")
		}
	})

	t.Run("Concurrent stop signal sending", func(t *testing.T) {
		podArgs := NewPodArgs("test-pod")
		var wg sync.WaitGroup
		signalsSent := make(chan struct{}, 10)

		// Start multiple goroutines sending stop signals
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				select {
				case podArgs.StopChan <- assert.AnError:
					signalsSent <- struct{}{}
				case <-time.After(100 * time.Millisecond):
					// Channel might be full, which is expected
				}
			}(i)
		}

		wg.Wait()
		close(signalsSent)

		// Count how many signals were successfully sent
		signalCount := 0
		for range signalsSent {
			signalCount++
		}

		assert.True(t, signalCount >= 1, "At least one signal should be sent")
		assert.True(t, signalCount <= 2, "No more than 2 signals should be sent (channel capacity)")
	})
}

// TestPodArgs_EdgeCases tests edge cases and error conditions
func TestPodArgs_EdgeCases(t *testing.T) {
	t.Run("State transition with empty allowed states list", func(t *testing.T) {
		podArgs := NewPodArgs("test-pod")
		podArgs.PodTrafficMonitorState = PodPending

		// Empty allowed states should allow any transition
		err := podArgs.changePodTrafficMonitorState(PodRunning)
		assert.NoError(t, err)
		assert.Equal(t, PodRunning, podArgs.PodTrafficMonitorState)
	})
}

// TestPodArgs_StateTransitionSequence tests complete state transition sequences
func TestPodArgs_StateTransitionSequence(t *testing.T) {
	t.Run("Complete lifecycle: PodPending -> PodRunning -> TrafficMonitoringRunning -> TrafficMonitoringEnded -> RemovePodFromMap", func(t *testing.T) {
		podArgs := NewPodArgs("test-pod")
		podArgs.PodTrafficMonitorState = PodPending

		// PodPending -> PodRunning
		err := podArgs.changePodTrafficMonitorState(PodRunning, PodPending)
		assert.NoError(t, err)
		assert.Equal(t, PodRunning, podArgs.PodTrafficMonitorState)

		// PodRunning -> TrafficMonitoringRunning
		err = podArgs.changePodTrafficMonitorState(TrafficMonitoringRunning, PodRunning)
		assert.NoError(t, err)
		assert.Equal(t, TrafficMonitoringRunning, podArgs.PodTrafficMonitorState)

		// TrafficMonitoringRunning -> TrafficMonitoringEnded
		err = podArgs.changePodTrafficMonitorState(TrafficMonitoringEnded, TrafficMonitoringRunning)
		assert.NoError(t, err)
		assert.Equal(t, TrafficMonitoringEnded, podArgs.PodTrafficMonitorState)

		// TrafficMonitoringEnded -> RemovePodFromMap
		err = podArgs.markAsPruneReady()
		assert.NoError(t, err)
		assert.Equal(t, RemovePodFromMap, podArgs.PodTrafficMonitorState)

		// Verify final state protection
		err = podArgs.changePodTrafficMonitorState(PodRunning)
		assert.Error(t, err)
		assert.Equal(t, RemovePodFromMap, podArgs.PodTrafficMonitorState)
	})

	t.Run("Failure path: PodPending -> PodRunning -> TrafficMonitoringRunning -> TrafficMonitoringFailed -> RemovePodFromMap", func(t *testing.T) {
		podArgs := NewPodArgs("test-pod")
		podArgs.PodTrafficMonitorState = PodPending

		// PodPending -> PodRunning
		err := podArgs.changePodTrafficMonitorState(PodRunning, PodPending)
		assert.NoError(t, err)

		// PodRunning -> TrafficMonitoringRunning
		err = podArgs.changePodTrafficMonitorState(TrafficMonitoringRunning, PodRunning)
		assert.NoError(t, err)

		// TrafficMonitoringRunning -> TrafficMonitoringFailed
		err = podArgs.changePodTrafficMonitorState(TrafficMonitoringFailed, TrafficMonitoringRunning)
		assert.NoError(t, err)
		assert.Equal(t, TrafficMonitoringFailed, podArgs.PodTrafficMonitorState)

		// TrafficMonitoringFailed -> RemovePodFromMap
		err = podArgs.markAsPruneReady()
		assert.NoError(t, err)
		assert.Equal(t, RemovePodFromMap, podArgs.PodTrafficMonitorState)
	})
}

// --- DaemonSet Shutdown and State Transition Tests ---

func TestPodArgs_DaemonShutdown(t *testing.T) {
	tests := []struct {
		name          string
		initialState  PodTrafficMonitorState
		expectedError bool
		expectedState PodTrafficMonitorState
	}{
		{"TrafficMonitoringRunning to DaemonSetShutdown", TrafficMonitoringRunning, false, DaemonSetShutdown},
		{"PodRunning to DaemonSetShutdown", PodRunning, false, DaemonSetShutdown},
		{"PodPending to DaemonSetShutdown", PodPending, false, DaemonSetShutdown},
		{"PodSucceeded to DaemonSetShutdown", PodSucceeded, false, DaemonSetShutdown},
		{"PodFailed to DaemonSetShutdown", PodFailed, false, DaemonSetShutdown},
		{"PodTerminated to DaemonSetShutdown", PodTerminated, false, DaemonSetShutdown},
		{"TrafficMonitoringEnded to DaemonSetShutdown", TrafficMonitoringEnded, true, TrafficMonitoringEnded},
		{"TrafficMonitoringFailed to DaemonSetShutdown", TrafficMonitoringFailed, true, TrafficMonitoringFailed},
		{"RemovePodFromMap to DaemonSetShutdown", RemovePodFromMap, true, RemovePodFromMap},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			podArgs := NewPodArgs("test-pod")
			podArgs.PodTrafficMonitorState = tt.initialState
			err := podArgs.changePodTrafficMonitorState(DaemonSetShutdown)
			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "already in final state")
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedState, podArgs.PodTrafficMonitorState)
			}
		})
	}
}

func TestPodArgs_DaemonShutdownConcurrency(t *testing.T) {
	t.Run("Multiple goroutines trying to change state during shutdown", func(t *testing.T) {
		podArgs := NewPodArgs("test-pod")
		podArgs.PodTrafficMonitorState = TrafficMonitoringRunning
		var wg sync.WaitGroup
		errors := make(chan error, 10)
		successCount := 0
		var mu sync.Mutex
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := podArgs.changePodTrafficMonitorState(DaemonSetShutdown)
				if err == nil {
					mu.Lock()
					successCount++
					mu.Unlock()
				}
				errors <- err
			}()
		}
		wg.Wait()
		close(errors)
		errorCount := 0
		for err := range errors {
			if err != nil {
				errorCount++
			}
		}
		assert.Equal(t, 1, successCount)
		assert.Equal(t, 9, errorCount)
		assert.Equal(t, DaemonSetShutdown, podArgs.PodTrafficMonitorState)
	})

	t.Run("Race condition between daemon shutdown and normal state transitions", func(t *testing.T) {
		podArgs := NewPodArgs("test-pod")
		podArgs.PodTrafficMonitorState = TrafficMonitoringRunning
		var wg sync.WaitGroup
		errors := make(chan error, 2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			err := podArgs.changePodTrafficMonitorState(TrafficMonitoringEnded, TrafficMonitoringRunning)
			errors <- err
		}()
		go func() {
			defer wg.Done()
			err := podArgs.changePodTrafficMonitorState(DaemonSetShutdown)
			errors <- err
		}()
		wg.Wait()
		close(errors)
		errorCount := 0
		for err := range errors {
			if err != nil {
				errorCount++
			}
		}
		assert.Equal(t, 1, errorCount)
	})
}
