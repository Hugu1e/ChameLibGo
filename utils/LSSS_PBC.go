package utils

import (
	"fmt"

	"github.com/Nik-U/pbc"
)

type PBCMatrix struct {
	Pairing *pbc.Pairing
	G       pbc.Field

	M       [][]pbc.Element
	Policy  []string
	Formula string
}

func (m *PBCMatrix) PrintMatrix() {
	for _, row := range m.M {
		for _, ele := range row {
			fmt.Print(ele.String(), " ")
		}
		fmt.Println()
	}
}

func NewPBCMatrix(pairing *pbc.Pairing, G pbc.Field) *PBCMatrix {
	return &PBCMatrix{
		G: G,
		Pairing: pairing,
	}
}
func (m *PBCMatrix) GetNewElement() *pbc.Element {
	switch m.G {
	case pbc.G1:
		return m.Pairing.NewG1().Rand()
	case pbc.G2:
		return m.Pairing.NewG2().Rand()
	case pbc.GT:
		return m.Pairing.NewGT().Rand()
	case pbc.Zr:
		return m.Pairing.NewZr().Rand()
	default:
		return nil
	}
}
func (m *PBCMatrix) GetZeroElement() *pbc.Element {
	if ele := m.GetNewElement(); ele != nil {
		return ele.Set0()
	}
	return nil
}
func (m *PBCMatrix) GetOneElement() *pbc.Element {
	if ele := m.GetNewElement(); ele != nil {
		return ele.Set1()
	}
	return nil
}

type PBCVector struct {
	V []pbc.Element
}
func NewPBCVector(n int) *PBCVector {
	return &PBCVector{
		V: make([]pbc.Element, n),
	}
}

func (matrix *PBCMatrix) Resize(n, m int) {
	matrix.M = make([][]pbc.Element, n)
	for i := range matrix.M {
		matrix.M[i] = make([]pbc.Element, m)
	}
}

func (m *PBCMatrix) Prodith(y *PBCVector, i int) *pbc.Element {
	res := m.GetNewElement().Set0()
	for j := range m.M[i] {
		res.Add(res, MUL(&y.V[j], &m.M[i][j]))
	}
	return res
}

func (m *PBCMatrix) Solve(S *AttributeList) *PBCVector {
	b := &PBCVector{V: make([]pbc.Element, len(m.M[0]))}
	b.V[0] = *m.GetOneElement()
	for i := 1; i < len(m.M[0]); i++ {
		b.V[i] = *m.GetZeroElement()
	}
	return m.solve(b, S)
}

func (m *PBCMatrix) solve(b *PBCVector, S *AttributeList) *PBCVector {
	x := NewPBCVector(len(m.M))

	for i := range x.V {
		x.V[i] = *m.GetZeroElement()
	}
	if len(b.V) != len(m.M[0]) {
		return nil
	}
	tag := make([]bool, len(m.M))
	colRes := make([]int, len(m.M))
	colIndex := make([]int, len(m.M))
	for i := range colIndex {
		colIndex[i] = -1
	}
	rowCnt := 0
	for i := range m.Policy {
		if  _, ok := S.Attrs[m.Policy[i]]; ok {
			tag[i] = true
			colRes[rowCnt] = i
			rowCnt++
		} else {
			tag[i] = false
		}
	}
	mat := make([][]pbc.Element, len(m.M[0]))
	for i := range mat {
		mat[i] = make([]pbc.Element, rowCnt+1)
	}
	j := 0
	for i := range m.M {
		if tag[i] {
			for k := range m.M[i] {
				mat[k][j] = *COPY(&m.M[i][k])
			}
			j++
		}
	}
	for k := range m.M[0] {
		mat[k][j] = *COPY(&b.V[k])
	}
	mainCol, i := 0, 0
	for mainCol < rowCnt {
		if mat[i][mainCol].Is0() {
			for j = i + 1; j < len(mat); j++ {
				if !mat[j][mainCol].Is0() {
					mat[j], mat[i] = mat[i], mat[j]
					break
				}
			}
		}
		if mat[i][mainCol].Is0() {
			mainCol++
			continue
		}
		colIndex[mainCol] = i
		t := COPY(&mat[i][mainCol])
		for k := mainCol; k < len(mat[i]); k++ {
			mat[i][k].Div(&mat[i][k], t)
		}
		for j = 0; j < len(mat); j++ {
			if i == j || mat[j][mainCol].Is0() {
				continue
			}
			t = COPY(&mat[j][mainCol])
			for k := mainCol; k < len(mat[i]); k++ {
				mat[j][k].Sub(&mat[j][k], MUL(&mat[i][k], t))
			}
		}
		mainCol++
		i++
	}
	for i = 0; i < len(m.M); i++ {
		if colIndex[i] != -1 {
			x.V[colRes[i]] = *COPY(&mat[colIndex[i]][rowCnt])
		}
	}

	return x
}

func GenLSSSPBCMatrices(M *PBCMatrix, pl *PolicyList, BooleanFormulas string) {
	// TOOD error handling
	BFParser, _ := NewBooleanFormulaParser(pl, BooleanFormulas)
	M.Policy = make([]string, len(pl.Policy))
	copy(M.Policy, pl.Policy)
	BFParser.SetToPBCMatrix(M)
}