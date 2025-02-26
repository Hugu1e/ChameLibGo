package GroupParam

import (
	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Nik-U/pbc"
)

type Single struct {
	Pairing   *pbc.Pairing

	Zr, G pbc.Field
}
func (s *Single) CopyFrom(other *Single) *Single {
	s.Pairing = other.Pairing
	s.Zr = other.Zr
	s.G = other.G
	return s
}

func (s *Single) NewSingle(curveName curve.Curve, group pbc.Field) *Single {
	s.Pairing = curve.PairingGen(curveName)

	s.G = group
	s.Zr = pbc.Zr

	return s
}

func (s *Single) NewSingleFromPairing(pairing *pbc.Pairing, group pbc.Field) *Single {
	s.Pairing = pairing

	s.G = group
	s.Zr = pbc.Zr

	return s
}

func (s *Single) GetGElement() *pbc.Element{
	switch s.G{
	case pbc.G1:
		return s.Pairing.NewG1().Rand()
	case pbc.G2:
		return s.Pairing.NewG2().Rand()
	case pbc.GT:
		return s.Pairing.NewGT().Rand()
	default:
		return nil
	}
}

func (s *Single) GetZrElement() *pbc.Element {
	return s.Pairing.NewZr().Rand()
}