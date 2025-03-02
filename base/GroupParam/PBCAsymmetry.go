package GroupParam

import (
	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Nik-U/pbc"
)

type Asymmetry struct {
	Pairing			*pbc.Pairing
	SwapG1G2		bool

	Zr, G1, G2, GT	pbc.Field
}

func NewAsymmetry(curveName curve.Curve, swapG1G2 bool) *Asymmetry {
	a := new(Asymmetry)

	a.Pairing = curve.PairingGen(curveName)
	a.SwapG1G2 = swapG1G2

	if swapG1G2 {
		a.G1 = pbc.G2
		a.G2 = pbc.G1
	} else {
		a.G1 = pbc.G1
		a.G2 = pbc.G2
	}
	a.GT = pbc.GT
	a.Zr = pbc.Zr

	return a
}

func (a *Asymmetry) Pair(g1, g2 *pbc.Element) *pbc.Element {
	if a.SwapG1G2 {
		return a.Pairing.NewGT().Pair(g2, g1)
	}
	return a.Pairing.NewGT().Pair(g1, g2)
}

func (a *Asymmetry) GetG1Element() *pbc.Element {
	if a.SwapG1G2 {
		return a.Pairing.NewG2().Rand()
	} else {
		return a.Pairing.NewG1().Rand()
	}
}

func (a *Asymmetry) GetG2Element() *pbc.Element {
	if a.SwapG1G2 {
		return a.Pairing.NewG1().Rand()
	} else {
		return a.Pairing.NewG2().Rand()
	}
}

func (a *Asymmetry) GetGTElement() *pbc.Element {
	return a.Pairing.NewGT().Rand()
}

func (a *Asymmetry) GetZrElement() *pbc.Element {
	return a.Pairing.NewZr().Rand()
}