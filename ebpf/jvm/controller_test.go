package jvm

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/postmanlabs/postman-insights-agent/ebpf/javatls"
)

type write struct {
	pid     uint32
	content string
	create  bool
}

// fakeFS records writes instead of touching containers.
type fakeFS struct {
	mu     sync.Mutex
	writes []write
	dead   map[uint32]bool
	err    error
	// failPID's writes fail, as for a process that has exited.
	failPID uint32
}

func (f *fakeFS) write(p *Process, content []byte, create bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, write{p.PID, string(content), create})
	if p.PID == f.failPID {
		return errors.New("no such process")
	}
	return f.err
}

func (f *fakeFS) alive(p *Process) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.dead[p.PID]
}

func (f *fakeFS) take() []write {
	f.mu.Lock()
	defer f.mu.Unlock()
	w := f.writes
	f.writes = nil
	return w
}

var (
	on  = javatls.Control{Enabled: true, CaptureCap: 4096}
	off = javatls.Control{Enabled: false}
)

func newTestController(settings *javatls.Control) (*Controller, *fakeFS) {
	fs := &fakeFS{dead: map[uint32]bool{}}
	c := NewController(func() javatls.Control { return *settings })
	c.write = fs.write
	c.alive = fs.alive
	return c, fs
}

func proc(pid uint32, mountNS uint64) *Process {
	return &Process{PID: pid, StartTime: uint64(pid) * 10, MountNS: mountNS, Kind: HotSpot}
}

func TestControllerWritesOnAdd(t *testing.T) {
	settings := on
	c, fs := newTestController(&settings)
	a := proc(1, 100)

	assert.True(t, c.Add(a))
	assert.Equal(t, []write{{1, string(on.Marshal()), true}}, fs.take())

	// A second subscription adding the same JVM writes nothing new.
	assert.False(t, c.Add(a))
	assert.Empty(t, fs.take())
	assert.Equal(t, 1, c.Len())
}

func TestControllerRefreshOncePerContainer(t *testing.T) {
	settings := on
	c, fs := newTestController(&settings)
	c.Add(proc(1, 100))
	c.Add(proc(2, 100)) // same container: shares /tmp
	c.Add(proc(3, 200))
	fs.take()

	c.Refresh()
	w := fs.take()
	assert.Len(t, w, 2)
	containers := map[bool]int{}
	for _, x := range w {
		containers[x.pid == 3]++
		assert.True(t, x.create)
	}
	assert.Equal(t, map[bool]int{false: 1, true: 1}, containers)

	// Changed settings reach the next refresh.
	settings = javatls.Control{Enabled: true, CaptureCap: 1024}
	c.Refresh()
	for _, x := range fs.take() {
		assert.Equal(t, string(settings.Marshal()), x.content)
	}
}

func TestControllerJavaOffNeverCreates(t *testing.T) {
	settings := off
	c, fs := newTestController(&settings)
	c.Add(proc(1, 100))
	c.Refresh()
	for _, x := range fs.take() {
		assert.False(t, x.create, "a control file was created with Java capture off")
		assert.Equal(t, string(off.Marshal()), x.content)
	}
}

func TestControllerRemove(t *testing.T) {
	settings := on
	c, fs := newTestController(&settings)
	a, b, other := proc(1, 100), proc(2, 100), proc(3, 200)
	c.Add(a)
	c.Add(a)
	c.Add(b)
	c.Add(other)
	fs.take()

	// Still added by another subscription.
	c.Remove(a.Key())
	assert.Empty(t, fs.take())
	// Gone, but b keeps the container's file fresh.
	c.Remove(a.Key())
	assert.Empty(t, fs.take())

	// The last JVM in the container, still running: its pod is no longer
	// monitored, so the agent is told to go dormant now.
	c.Remove(b.Key())
	assert.Equal(t, []write{{2, string(off.Marshal()), false}}, fs.take())

	// An exited JVM needs nothing.
	fs.dead[3] = true
	c.Remove(other.Key())
	assert.Empty(t, fs.take())
	assert.Equal(t, 0, c.Len())

	// Unknown keys are ignored.
	c.Remove(Key{PID: 9})
	c.Refresh()
	assert.Empty(t, fs.take())
}

func TestControllerDisablesAllWhenStopped(t *testing.T) {
	settings := on
	c, fs := newTestController(&settings)
	c.Add(proc(1, 100))
	c.Add(proc(2, 200))
	fs.dead[2] = true
	fs.take()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()
	cancel()
	<-done
	assert.Equal(t, []write{{1, string(off.Marshal()), false}}, fs.take())
}

// A JVM that exited before discovery reported it is skipped: the container is
// written through another JVM in it, and no failure is reported.
func TestControllerSkipsExitedJVMs(t *testing.T) {
	settings := on
	c, fs := newTestController(&settings)
	c.Add(proc(1, 100))
	c.Add(proc(2, 100))
	fs.take()

	fs.dead[1] = true
	fs.failPID = 1
	c.Refresh()
	w := fs.take()
	assert.Equal(t, uint32(2), w[len(w)-1].pid, "not written through the running JVM")

	fs.dead[2] = true
	fs.failPID = 0
	fs.err = errors.New("no such process")
	c.Refresh()
	assert.Len(t, fs.take(), 2, "both tried")
	c.mu.Lock()
	assert.Empty(t, c.failed, "an exited container reported as failing")
	assert.True(t, c.written[100])
	c.mu.Unlock()
}

func TestControllerKeepsGoingAfterErrors(t *testing.T) {
	settings := on
	c, fs := newTestController(&settings)
	fs.err = errors.New("read-only file system")
	c.Add(proc(1, 100))
	c.Refresh()
	assert.Len(t, fs.take(), 2, "a failed container is retried on every refresh")

	fs.err = errNoControlDir
	c.Refresh()
	assert.Len(t, fs.take(), 1)
}
