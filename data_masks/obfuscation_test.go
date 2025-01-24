package data_masks

import "testing"

func BenchmarkObfuscation(b *testing.B) {
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ObfuscateMethod(testWitness.Method)
	}
}
