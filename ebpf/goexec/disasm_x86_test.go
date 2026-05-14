// SPDX-License-Identifier: Apache-2.0
//
// Architecture-independent tests for the x86_64 RET detector.
// Test runs on any host (we feed hand-crafted byte sequences); no
// cross-compilation needed.

package goexec

import "testing"

// TestFindRetAMD64_PlainRet: single 0xc3 anywhere returns its offset.
func TestFindRetAMD64_PlainRet(t *testing.T) {
	// `xor eax, eax; ret` — classic Go function epilogue
	code := []byte{0x31, 0xc0, 0xc3}
	got := findRetAMD64(code, 0x1000)
	if len(got) != 1 || got[0] != 0x1002 {
		t.Errorf("plain RET: got %v, want [0x1002]", got)
	}
}

// TestFindRetAMD64_RejectsByteMatchInOperand: 0xc3 inside an immediate
// operand must NOT be classified as a RET.
//
// `mov $0xc3, %al`  encodes as `b0 c3` — the 0xc3 is the IMMEDIATE
// value of a MOV, not a RET. The old byte-match scanner would
// falsely flag offset 1; the disassembler-based scanner skips it.
func TestFindRetAMD64_RejectsByteMatchInOperand(t *testing.T) {
	// `mov $0xc3, %al; xor eax, eax; ret`
	code := []byte{0xb0, 0xc3, 0x31, 0xc0, 0xc3}
	got := findRetAMD64(code, 0x2000)
	// Expect exactly one RET at offset 4 (the actual ret instruction),
	// NOT a false positive at offset 1 (the immediate inside MOV).
	if len(got) != 1 {
		t.Fatalf("got %d RETs %v, want exactly 1 at 0x2004", len(got), got)
	}
	if got[0] != 0x2004 {
		t.Errorf("RET offset = 0x%x, want 0x2004", got[0])
	}
}

// TestFindRetAMD64_MultipleRets: two RETs separated by a NOP slide.
func TestFindRetAMD64_MultipleRets(t *testing.T) {
	// ret; nop; nop; ret
	code := []byte{0xc3, 0x90, 0x90, 0xc3}
	got := findRetAMD64(code, 0x3000)
	if len(got) != 2 {
		t.Fatalf("got %v, want 2 RETs", got)
	}
	if got[0] != 0x3000 || got[1] != 0x3003 {
		t.Errorf("RET offsets = %v, want [0x3000, 0x3003]", got)
	}
}

// TestFindRetAMD64_RetImm16: RET with stack-pop immediate (0xc2 imm16)
// is also a return.
func TestFindRetAMD64_RetImm16(t *testing.T) {
	// `ret $0x0008` = c2 08 00
	code := []byte{0xc2, 0x08, 0x00}
	got := findRetAMD64(code, 0x4000)
	if len(got) != 1 || got[0] != 0x4000 {
		t.Errorf("RET imm16: got %v, want [0x4000]", got)
	}
}

// TestFindRetAMD64_TailCallJmpIsNotRet: a JMP <label> (tail call) is
// an outbound transfer, NOT a return. The disassembler must classify
// it as JMP, not RET, so we don't attach probes at tail-call sites.
func TestFindRetAMD64_TailCallJmpIsNotRet(t *testing.T) {
	// `jmp <rel8>` = eb XX. Not a RET; we must not flag it.
	code := []byte{0xeb, 0x10, 0xc3} // jmp +0x10; ret
	got := findRetAMD64(code, 0x5000)
	// Only the final c3 is a RET.
	if len(got) != 1 || got[0] != 0x5002 {
		t.Errorf("got %v, want only [0x5002]", got)
	}
}
