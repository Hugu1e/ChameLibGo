package utils

import (
	"fmt"
)

type NativeMatrix struct {
	M [][]int16
}

func (matrix *NativeMatrix) Resize(n, m int) {
	matrix.M = make([][]int16, n)
	for i := range matrix.M {
		matrix.M[i] = make([]int16, m)
	}
}

func (m *NativeMatrix) Print() {
	fmt.Println("NativeMatrix:")
	for _, row := range m.M {
		fmt.Println(row)
	}
	fmt.Println()
}

func GenLSSSNativeMatrices(pl *PolicyList, booleanFormulas string) *NativeMatrix {
	// TOOD error handling
	bfParser, _ := NewBooleanFormulaParser(pl, booleanFormulas)
	return bfParser.SetToNativeMatrix()
}

