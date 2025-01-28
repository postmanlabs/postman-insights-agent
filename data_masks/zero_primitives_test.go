package data_masks

import "testing"

func BenchmarkZeroAllPrimitives(b *testing.B) {
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ZeroAllPrimitivesInMethod(testWitness.Method)
	}
}
