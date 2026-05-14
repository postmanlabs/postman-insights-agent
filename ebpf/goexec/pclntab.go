// SPDX-License-Identifier: Apache-2.0
//
// Pclntab fallback for stripped Go binaries.
//
// Production Go builds frequently use `go build -ldflags="-s -w"` which
// strips the ELF symbol table (.symtab). Without .symtab, the standard
// ELF symbol lookup in Inspect() / FunctionExtent() returns nothing and
// we can't compute file offsets for uprobe attach.
//
// The .gopclntab section (Go program counter line table) is preserved
// even in stripped builds because the Go runtime needs it for stack
// traces. It contains every function's name and entry/end PC. Go's
// stdlib `debug/gosym` parses it for us.
//
// Strategy:
//   1. If .symtab lookup yields nothing, try pclntab.
//   2. gosym.NewLineTable + gosym.NewTable(nil, lt) — the nil first arg
//      means "no .gosymtab, just use pclntab".
//   3. Iterate Funcs to find the named function; convert its virtual
//      address to a file offset via the same vaddrToFileOff helper used
//      by the ELF-symbol path.

package goexec

import (
	"debug/elf"
	"debug/gosym"
	"fmt"
)

// findFunctionViaPclntab returns (file offset, size) for a function by
// name, parsing .gopclntab. Used as a fallback when .symtab is absent
// (e.g. binaries built with `-ldflags="-s"` or `"-s -w"`).
//
// On success returns (fileOffset, sizeBytes, nil).
// On lookup failure returns (0, 0, error).
func findFunctionViaPclntab(f *elf.File, symbol string) (uint64, uint64, error) {
	tab, err := loadPclntab(f)
	if err != nil {
		return 0, 0, err
	}
	for _, fn := range tab.Funcs {
		if fn.Name != symbol {
			continue
		}
		off, err := vaddrToFileOff(f, fn.Entry)
		if err != nil {
			return 0, 0, fmt.Errorf("pclntab: vaddr 0x%x for %s: %w", fn.Entry, symbol, err)
		}
		return off, fn.End - fn.Entry, nil
	}
	return 0, 0, fmt.Errorf("pclntab: symbol %q not found among %d functions", symbol, len(tab.Funcs))
}

// listPclntabSymbols returns the file offsets of every symbol in
// wantSymbols that can be resolved via pclntab. Symbols not found are
// omitted. Returns an error only when pclntab itself cannot be parsed.
//
// Used to enrich Inspect() results when .symtab is stripped.
func listPclntabSymbols(f *elf.File, wantSymbols []string) (map[string]uint64, error) {
	tab, err := loadPclntab(f)
	if err != nil {
		return nil, err
	}
	want := make(map[string]struct{}, len(wantSymbols))
	for _, s := range wantSymbols {
		want[s] = struct{}{}
	}
	out := make(map[string]uint64, len(wantSymbols))
	for _, fn := range tab.Funcs {
		if _, ok := want[fn.Name]; !ok {
			continue
		}
		off, err := vaddrToFileOff(f, fn.Entry)
		if err != nil {
			continue
		}
		out[fn.Name] = off
	}
	return out, nil
}

// loadPclntab parses .gopclntab from a Go binary and returns the
// gosym.Table covering every function. Caller treats the result as
// read-only.
//
// Caveat: Go 1.18 changed the pclntab layout. debug/gosym.NewLineTable
// auto-detects the version from a magic header so we don't need to
// distinguish.
func loadPclntab(f *elf.File) (*gosym.Table, error) {
	sec := f.Section(".gopclntab")
	if sec == nil {
		return nil, fmt.Errorf("no .gopclntab section (not a Go binary or older Go version)")
	}
	pclntabBytes, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("read .gopclntab: %w", err)
	}

	// The line table needs the .text base address so it can map PCs back
	// to function entries. Use the section header's address.
	textSec := f.Section(".text")
	if textSec == nil {
		return nil, fmt.Errorf("no .text section")
	}

	lineTable := gosym.NewLineTable(pclntabBytes, textSec.Addr)
	// First arg nil = no .gosymtab (deprecated since Go 1.3 and absent in
	// modern binaries). gosym recovers everything it needs from pclntab.
	tab, err := gosym.NewTable(nil, lineTable)
	if err != nil {
		return nil, fmt.Errorf("gosym.NewTable: %w", err)
	}
	return tab, nil
}
