// SPDX-License-Identifier: Apache-2.0

package data_masks

import (
	"sync"
	"testing"
)

func TestCoverage_NilSafe(t *testing.T) {
	var c *CoverageCounters // nil
	c.IncSensitiveKey("authorization")
	c.IncSensitiveRegex("builtin[0]")
	c.IncUserRule("rule")
	c.IncBodyTruncation()
	c.IncRequestScanned()
	c.IncBodyDropped()
	c.IncHeaderDropped()
	snap := c.Snapshot()
	if len(snap.SensitiveKeyHits) != 0 {
		t.Errorf("nil snapshot must be empty, got %+v", snap)
	}
}

func TestCoverage_Counts(t *testing.T) {
	c := NewCoverageCounters()
	c.IncSensitiveKey("authorization")
	c.IncSensitiveKey("authorization")
	c.IncSensitiveKey("cookie")
	c.IncSensitiveRegex("builtin[5]")
	c.IncUserRule("custom-cc-rule")
	c.IncBodyTruncation()
	c.IncRequestScanned()
	c.IncBodyDropped()
	c.IncHeaderDropped()
	c.IncHeaderDropped()

	s := c.Snapshot()
	if s.SensitiveKeyHits["authorization"] != 2 {
		t.Errorf("authorization=%d, want 2", s.SensitiveKeyHits["authorization"])
	}
	if s.SensitiveKeyHits["cookie"] != 1 {
		t.Errorf("cookie=%d, want 1", s.SensitiveKeyHits["cookie"])
	}
	if s.SensitiveRegexHits["builtin[5]"] != 1 {
		t.Errorf("builtin[5]=%d, want 1", s.SensitiveRegexHits["builtin[5]"])
	}
	if s.UserRuleHits["custom-cc-rule"] != 1 {
		t.Errorf("custom-cc-rule=%d", s.UserRuleHits["custom-cc-rule"])
	}
	if s.BodyTruncations != 1 || s.TotalRequestsScanned != 1 || s.BodiesDropped != 1 || s.HeadersDropped != 2 {
		t.Errorf("scalar counters wrong: %+v", s)
	}
}

func TestCoverage_Concurrent(t *testing.T) {
	c := NewCoverageCounters()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				c.IncSensitiveKey("authorization")
				c.IncRequestScanned()
			}
		}()
	}
	wg.Wait()
	s := c.Snapshot()
	if s.SensitiveKeyHits["authorization"] != 100*1000 {
		t.Errorf("concurrent inc lost updates: got %d, want %d",
			s.SensitiveKeyHits["authorization"], 100*1000)
	}
	if s.TotalRequestsScanned != 100*1000 {
		t.Errorf("requests scanned lost updates: got %d", s.TotalRequestsScanned)
	}
}
