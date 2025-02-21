package IB_CH_ZSS_S2_2003

import (
	"github.com/Nik-U/pbc"

	"github.com/Hugu1e/ChameLibGo/utils"
    "github.com/Hugu1e/ChameLibGo/curve"
)

type PublicParam struct {
	Pairing *pbc.Pairing
	Zr, G1, GT pbc.Field
	P, P_pub pbc.Element
}

func (sp *PublicParam) pairing(g1, g2 *pbc.Element) *pbc.Element {
	return sp.Pairing.NewGT().Pair(g1, g2)
}

func (sp *PublicParam) H1(m *pbc.Element) *pbc.Element {
	return utils.H_PBC_1_1(sp.Pairing, sp.Zr, m)
}

func (sp *PublicParam) GetGElement() *pbc.Element {
	return sp.Pairing.NewG1().Rand()
}

func (sp *PublicParam) GetZrElement() *pbc.Element {
	return sp.Pairing.NewZr().Rand()
}

type MasterSecretKey struct {
	S pbc.Element
}

type SecretKey struct {
	S_ID pbc.Element
}

type HashValue struct {
	H pbc.Element
}

type Randomness struct {
	R pbc.Element
}

func getHashValue(R *Randomness, sp *PublicParam, ID, m *pbc.Element) *pbc.Element {
	temp1 := sp.pairing(&sp.P, &sp.P)
	temp2 := sp.pairing(powZn(&sp.P, sp.H1(ID)).ThenMul(&sp.P_pub), &R.R)
	return temp1.ThenMul(temp2).ThenPowZn(sp.H1(m))
}

func SetUp(curveName curve.Curve) (*PublicParam, *MasterSecretKey) {
	sp := &PublicParam{
		Pairing: curve.PairingGen(curveName),
		G1:      pbc.G1,
		GT:      pbc.GT,
		Zr:      pbc.Zr,
	}
	sp.P = *sp.GetGElement()
	msk := &MasterSecretKey{
		S: *sp.GetZrElement(),
	}
	sp.P_pub = *powZn(&sp.P, &msk.S)
	return sp, msk
}

func KeyGen(sp *PublicParam, msk *MasterSecretKey, ID *pbc.Element) *SecretKey {
	return &SecretKey{
		S_ID: *powZn(&sp.P, invert(add(&msk.S, sp.H1(ID)))),
	}
}

func Hash(sp *PublicParam, ID, m *pbc.Element) (*HashValue, *Randomness) {
	R := &Randomness{
		R: *sp.GetGElement(),
	}
	H := &HashValue{
		H: *getHashValue(R, sp, ID, m),
	}
	return H, R
}

func Check(H *HashValue, R *Randomness, sp *PublicParam, ID, m *pbc.Element) bool {
	return H.H.Equals(getHashValue(R, sp, ID, m))
}

func Adapt(R *Randomness, sp *PublicParam, sk *SecretKey, m, m_p *pbc.Element) *Randomness {
	H1m := sp.H1(m)
	H1m_p := sp.H1(m_p)
	R_p := &Randomness{
		R: *powZn(&sk.S_ID, sub(H1m, H1m_p).ThenDiv(H1m_p)).ThenMul(powZn(&R.R, div(H1m, H1m_p))),
	}
	return R_p
}

func powZn(x, i *pbc.Element) *pbc.Element {
    return x.NewFieldElement().PowZn(x, i)
}
func mul(x, y *pbc.Element) *pbc.Element {
    return x.NewFieldElement().Mul(x, y)
}
func div(x, y *pbc.Element) *pbc.Element {
    return x.NewFieldElement().Div(x, y)
}
func add(x, y *pbc.Element) *pbc.Element {
    return x.NewFieldElement().Add(x, y)
}
func sub(x, y *pbc.Element) *pbc.Element {
    return x.NewFieldElement().Sub(x, y)
}
func invert(x *pbc.Element) *pbc.Element {
	return x.NewFieldElement().Invert(x)
}