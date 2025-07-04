package daemonset

import (
	"sync"
	"testing"
	"time"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/tags"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	t.Run("Concurrent reads while state is being changed", func(t *testing.T) {
		podArgs := NewPodArgs("test-pod")
		podArgs.PodTrafficMonitorState = PodPending

		var wg sync.WaitGroup
		readResults := make(chan PodTrafficMonitorState, 100)

		// Start a goroutine that continuously changes state
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				podArgs.changePodTrafficMonitorState(PodRunning, PodPending)
				time.Sleep(1 * time.Millisecond)
				podArgs.changePodTrafficMonitorState(PodPending, PodRunning)
				time.Sleep(1 * time.Millisecond)
			}
		}()

		// Start multiple goroutines reading state
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 20; j++ {
					readResults <- podArgs.PodTrafficMonitorState
					time.Sleep(1 * time.Millisecond)
				}
			}()
		}

		wg.Wait()
		close(readResults)

		// Verify all read results are valid states
		validStates := map[PodTrafficMonitorState]bool{
			PodPending: true,
			PodRunning: true,
		}

		for state := range readResults {
			assert.True(t, validStates[state], "Read state should be valid: %s", state)
		}
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

	t.Run("State transition with nil allowed states", func(t *testing.T) {
		podArgs := NewPodArgs("test-pod")
		podArgs.PodTrafficMonitorState = PodPending

		// Nil allowed states should allow any transition
		err := podArgs.changePodTrafficMonitorState(PodRunning)
		assert.NoError(t, err)
		assert.Equal(t, PodRunning, podArgs.PodTrafficMonitorState)
	})

	t.Run("NewPodArgs creates valid instance", func(t *testing.T) {
		podArgs := NewPodArgs("test-pod")

		assert.Equal(t, "test-pod", podArgs.PodName)
		assert.NotNil(t, podArgs.TraceTags)
		assert.NotNil(t, podArgs.StopChan)
		assert.Equal(t, 2, cap(podArgs.StopChan))
		assert.Equal(t, PodTrafficMonitorState(""), podArgs.PodTrafficMonitorState) // Zero value
	})

	t.Run("PodArgs fields are properly initialized", func(t *testing.T) {
		podArgs := NewPodArgs("test-pod")

		// Test that fields can be set and retrieved
		podArgs.InsightsProjectID = akid.ServiceID{}
		podArgs.ContainerUUID = "test-container-uuid"
		podArgs.ReproMode = true
		podArgs.DropNginxTraffic = true
		podArgs.AgentRateLimit = 100.0
		podArgs.PodCreds = PodCreds{
			InsightsAPIKey:      "test-key",
			InsightsEnvironment: "test-env",
		}
		podArgs.TraceTags = tags.SingletonTags{"test": "value"}

		assert.Equal(t, akid.ServiceID{}, podArgs.InsightsProjectID)
		assert.Equal(t, "test-container-uuid", podArgs.ContainerUUID)
		assert.True(t, podArgs.ReproMode)
		assert.True(t, podArgs.DropNginxTraffic)
		assert.Equal(t, 100.0, podArgs.AgentRateLimit)
		assert.Equal(t, "test-key", podArgs.PodCreds.InsightsAPIKey)
		assert.Equal(t, "test-env", podArgs.PodCreds.InsightsEnvironment)
		assert.Equal(t, tags.SingletonTags{"test": "value"}, podArgs.TraceTags)
	})

	t.Run("isTrafficMonitoringInFinalState function", func(t *testing.T) {
		finalStates := []PodTrafficMonitorState{
			TrafficMonitoringEnded,
			TrafficMonitoringFailed,
			RemovePodFromMap,
		}

		nonFinalStates := []PodTrafficMonitorState{
			PodPending,
			PodRunning,
			PodSucceeded,
			PodFailed,
			PodTerminated,
			TrafficMonitoringRunning,
			DaemonSetShutdown,
		}

		for _, state := range finalStates {
			podArgs := NewPodArgs("test-pod")
			podArgs.PodTrafficMonitorState = state
			assert.True(t, isTrafficMonitoringInFinalState(podArgs), "State %s should be final", state)
		}

		for _, state := range nonFinalStates {
			podArgs := NewPodArgs("test-pod")
			podArgs.PodTrafficMonitorState = state
			assert.False(t, isTrafficMonitoringInFinalState(podArgs), "State %s should not be final", state)
		}
	})
}

// TestPodArgs_ConcurrencyStress tests performance under concurrent load
func TestPodArgs_ConcurrencyStress(t *testing.T) {
	t.Run("High-frequency state transitions", func(t *testing.T) {
		podArgs := NewPodArgs("test-pod")
		podArgs.PodTrafficMonitorState = PodPending

		var wg sync.WaitGroup
		successCount := 0
		var mu sync.Mutex

		// Start 100 goroutines doing rapid state transitions
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 10; j++ {
					err := podArgs.changePodTrafficMonitorState(PodRunning, PodPending)
					if err == nil {
						mu.Lock()
						successCount++
						mu.Unlock()
						// Change back to allow others to succeed
						podArgs.changePodTrafficMonitorState(PodPending, PodRunning)
					}
				}
			}()
		}

		wg.Wait()

		// Should have many successful transitions
		assert.True(t, successCount > 0, "Should have successful transitions")
	})

	t.Run("Large number of concurrent PodArgs objects", func(t *testing.T) {
		const numPods = 100
		podArgsList := make([]*PodArgs, numPods)

		// Create many PodArgs objects
		for i := 0; i < numPods; i++ {
			podArgsList[i] = NewPodArgs("test-pod-" + string(rune(i)))
			podArgsList[i].PodTrafficMonitorState = PodPending
		}

		var wg sync.WaitGroup
		successCount := 0
		var mu sync.Mutex

		// Start goroutines for each PodArgs
		for i := 0; i < numPods; i++ {
			wg.Add(1)
			go func(podArgs *PodArgs) {
				defer wg.Done()
				err := podArgs.changePodTrafficMonitorState(PodRunning, PodPending)
				if err == nil {
					mu.Lock()
					successCount++
					mu.Unlock()
				}
			}(podArgsList[i])
		}

		wg.Wait()

		// All should succeed since they're different objects
		assert.Equal(t, numPods, successCount, "All PodArgs should transition successfully")
	})

	t.Run("Memory pressure scenarios", func(t *testing.T) {
		// Test that we can create many PodArgs without memory issues
		const numPods = 1000
		podArgsList := make([]*PodArgs, numPods)

		for i := 0; i < numPods; i++ {
			podArgsList[i] = NewPodArgs("test-pod-" + string(rune(i)))
			require.NotNil(t, podArgsList[i])
		}

		// Verify all are accessible
		for i := 0; i < numPods; i++ {
			assert.Equal(t, "test-pod-"+string(rune(i)), podArgsList[i].PodName)
		}
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
