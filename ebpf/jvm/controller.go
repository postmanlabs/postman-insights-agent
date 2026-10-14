// SPDX-License-Identifier: Apache-2.0

package jvm

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/postmanlabs/postman-insights-agent/ebpf/javatls"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

// Controller keeps the Java agent's control file fresh in the container of
// every JVM it is given, refreshing it every javatls.ControlRefreshInterval.
// The agent captures only while the file is fresh and says enabled=1, so the
// agents go dormant on their own once the Controller stops: within one
// refresh when Java capture is turned off, and within
// javatls.ControlStaleAfter when the Insights agent goes away.
//
// JVMs that share a mount namespace share /tmp, so each container's file is
// written once per refresh. Safe for concurrent use.
type Controller struct {
	settings func() javatls.Control

	// For tests; writeControl and Alive in production.
	write func(p *Process, content []byte, create bool) error
	alive func(p *Process) bool

	// writeMu serializes writes, so a refresh cannot re-enable a container
	// that Remove has just disabled. Taken before mu.
	writeMu sync.Mutex

	mu    sync.Mutex
	procs map[Key]*entry
	// failed holds the last write error per mount namespace, so each
	// problem is logged once.
	failed map[uint64]string
	// written records the mount namespaces written successfully at least
	// once, for logging.
	written map[uint64]bool
}

type entry struct {
	p *Process
	// refs counts the callers that added p: two subscriptions can cover the
	// same pod while one replaces the other.
	refs int
}

// NewController returns a Controller that writes what settings returns.
// settings is called on every write, so a changed setting (Java capture
// switched off, a lower capture cap) reaches the agents within one refresh.
func NewController(settings func() javatls.Control) *Controller {
	return &Controller{
		settings: settings,
		write:    writeControl,
		alive:    Alive,
		procs:    make(map[Key]*entry),
		failed:   make(map[uint64]string),
		written:  make(map[uint64]bool),
	}
}

// Add starts keeping p's control file fresh, and writes it now so the agent
// in a monitored JVM captures from its first requests.
func (c *Controller) Add(p *Process) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.mu.Lock()
	e := c.procs[p.Key()]
	if e == nil {
		e = &entry{p: p}
		c.procs[p.Key()] = e
	}
	e.refs++
	first := e.refs == 1
	c.mu.Unlock()

	if first {
		c.writeContainer([]*Process{p}, c.settings())
	}
}

// Remove undoes one Add. When no added JVM is left in the container and the
// JVM is still running (its pod is no longer monitored, rather than gone), it
// tells the agent to go dormant now instead of when the file goes stale.
func (c *Controller) Remove(k Key) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.mu.Lock()
	e := c.procs[k]
	if e == nil {
		c.mu.Unlock()
		return
	}
	e.refs--
	if e.refs > 0 {
		c.mu.Unlock()
		return
	}
	delete(c.procs, k)
	lastInMount := true
	for _, other := range c.procs {
		if other.p.MountNS == e.p.MountNS {
			lastInMount = false
			break
		}
	}
	if lastInMount {
		delete(c.failed, e.p.MountNS)
		delete(c.written, e.p.MountNS)
	}
	c.mu.Unlock()

	if lastInMount && c.alive(e.p) {
		c.disable(e.p)
	}
}

// Run refreshes every javatls.ControlRefreshInterval until ctx ends, then
// tells every running agent to go dormant.
func (c *Controller) Run(ctx context.Context) {
	t := time.NewTicker(javatls.ControlRefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			c.disableAll()
			return
		case <-t.C:
			c.Refresh()
		}
	}
}

// Refresh rewrites every container's control file now.
func (c *Controller) Refresh() {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	settings := c.settings()
	for _, group := range c.byMount() {
		c.writeContainer(group, settings)
	}
}

// byMount groups the added JVMs by mount namespace: one group per container.
func (c *Controller) byMount() map[uint64][]*Process {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[uint64][]*Process)
	for _, e := range c.procs {
		out[e.p.MountNS] = append(out[e.p.MountNS], e.p)
	}
	return out
}

// writeContainer writes settings for the container of group, the JVMs that
// share one mount namespace, through the first of them still running. It
// logs the first success and each new problem once. Caller holds writeMu.
func (c *Controller) writeContainer(group []*Process, settings javatls.Control) {
	var p *Process
	var err error
	for _, candidate := range group {
		// With Java capture off, only existing control files are updated:
		// nothing new is added to containers.
		err = c.write(candidate, settings.Marshal(), settings.Enabled)
		// A JVM that just exited, before discovery reports it, is no
		// problem: try another in the same container.
		if err == nil || errors.Is(err, errNoControlDir) || c.alive(candidate) {
			p = candidate
			break
		}
	}
	// Every JVM exited, or there was nothing to update.
	if p == nil || errors.Is(err, errNoControlDir) {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		if c.failed[p.MountNS] != err.Error() {
			c.failed[p.MountNS] = err.Error()
			printer.Stderr.Warningf("ebpf: cannot write the Java agent's control file for JVM %s: %v\n", p, err)
		}
		return
	}
	delete(c.failed, p.MountNS)
	if !c.written[p.MountNS] {
		c.written[p.MountNS] = true
		state := "on"
		if !settings.Enabled {
			state = "off"
		}
		printer.Stderr.Infof("ebpf: Java HTTPS capture %s for JVM %s (control file %s)\n",
			state, p, javatls.ControlFilePath)
	}
}

// disable tells p's agent to go dormant now. Caller holds writeMu.
func (c *Controller) disable(p *Process) {
	err := c.write(p, javatls.Control{Enabled: false}.Marshal(), false)
	if err != nil && !errors.Is(err, errNoControlDir) {
		printer.Debugf("ebpf: Java control file for JVM %s: %v\n", p, err)
	}
}

// disableAll tells every running agent to go dormant, when the Insights agent
// stops.
func (c *Controller) disableAll() {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	for _, group := range c.byMount() {
		for _, p := range group {
			if c.alive(p) {
				c.disable(p)
				break
			}
		}
	}
}

// Len returns the number of JVMs added, for telemetry and tests.
func (c *Controller) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.procs)
}
