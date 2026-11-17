// SPDX-License-Identifier: Apache-2.0

package events

import (
	"reflect"

	"github.com/akitasoftware/akita-libs/akinet"
)

// ReleaseBuffers returns c's body storage to its buffer pool. Call it once nothing reads c
// anymore; until then the storage stays out of the pool, and an empty pool stops bodies being read.
// Safe on HTTP messages that own no pool buffer, on which akinet's ReleaseBuffers panics.
func ReleaseBuffers(c akinet.ParsedNetworkContent) {
	switch c.(type) {
	case akinet.HTTPRequest, akinet.HTTPResponse:
		if reflect.ValueOf(c).FieldByName("buffer").IsNil() {
			return
		}
	}
	c.ReleaseBuffers()
}
