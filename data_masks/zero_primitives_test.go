package data_masks

import (
	"path/filepath"
	"testing"

	"github.com/akitasoftware/akita-libs/test"
)

func BenchmarkZeroAllPrimitives(b *testing.B) {
	testWitness := test.LoadWitnessFromFileOrDie(filepath.Join("testdata", "001-witness.pb.txt"))

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ZeroAllPrimitivesInMethod(testWitness.Method)
	}
}
