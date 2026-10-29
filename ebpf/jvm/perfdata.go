// SPDX-License-Identifier: Apache-2.0

package jvm

// perfDataAttach reports whether a JVM's attach mechanism is on, from the
// first character of its sun.rt.jvmCapabilities entry ("1" when on, "0" with
// -XX:+DisableAttachMechanism), as jps and VirtualMachine.list read it. known
// is false without the entry.
func perfDataAttach(entries map[string]string) (on, known bool) {
	c := entries["sun.rt.jvmCapabilities"]
	if c == "" {
		return false, false
	}
	return c[0] == '1', true
}
