package BLS

import (
	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
	"github.com/Nik-U/pbc"
)

type PublicParam struct {
	Pairing   *pbc.Pairing
	Zr, G1, G2, GT pbc.Field

	SwapG1G2  bool

	G         pbc.Element
}

func (pp *PublicParam) pairing(g1, g2 *pbc.Element) *pbc.Element {
	if pp.SwapG1G2 {
		return pp.Pairing.NewGT().Pair(g2, g1)
	}
	return pp.Pairing.NewGT().Pair(g1, g2)
}

func (pp *PublicParam) H(m string) *pbc.Element {
	return utils.H_String_1_PBC_1(pp.Pairing ,pp.G1, m)
}

func (pp *PublicParam) GetG2Element() *pbc.Element {
	switch pp.G2{
	case pbc.G2:
		return pp.Pairing.NewG2().Rand()
	case pbc.G1:
		return pp.Pairing.NewG1().Rand()
	default:
		return nil
	}
}

func (pp *PublicParam) GetZrElement() *pbc.Element {
	return pp.Pairing.NewZr().Rand()
}

type SecretKey struct {
	Alpha pbc.Element
}

type PublicKey struct {
	H pbc.Element
}

type Signature struct {
	SigmaM pbc.Element
}

func (s *Signature) Equals(sign *Signature) bool {
	return s.SigmaM.Equals(&sign.SigmaM)
}

func SetUp(curveName curve.Curve, swapG1G2 bool) *PublicParam {
	pp := new(PublicParam)

	pp.SwapG1G2 = swapG1G2
	pp.Pairing = curve.PairingGen(curveName)
	if swapG1G2 {
		pp.G1 = pbc.G2
		pp.G2 = pbc.G1
	} else {
		pp.G1 = pbc.G1
		pp.G2 = pbc.G2
	}
	pp.GT = pbc.GT
	pp.Zr = pbc.Zr

	pp.G = *pp.GetG2Element()

	return pp
}

func KeyGen(pp *PublicParam) (*PublicKey, *SecretKey){
	pk := new(PublicKey)
	sk := new(SecretKey)

	sk.Alpha = *pp.GetZrElement()
	pk.H = *utils.POWZN(&pp.G, &sk.Alpha)

	return pk, sk
}

func Sign(sk *SecretKey, pp *PublicParam, m string) *Signature {
	sign := new(Signature)

	sign.SigmaM = *utils.POWZN(pp.H(m), &sk.Alpha)

	return sign
}

func Verify(pp *PublicParam, pk *PublicKey, sign *Signature, m string) bool {
	return pp.pairing(&sign.SigmaM, &pp.G).Equals(pp.pairing(pp.H(m), &pk.H))
}