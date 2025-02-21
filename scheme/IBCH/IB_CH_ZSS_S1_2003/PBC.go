package IB_CH_ZSS_S1_2003

import (
	"github.com/Nik-U/pbc"

	"github.com/Hugu1e/ChameLibGo/utils"
    "github.com/Hugu1e/ChameLibGo/curve"
)

type PublicParam struct {
	Pairing    *pbc.Pairing
	Zr, G1, G2, GT pbc.Field
	SwapG1G2   bool
	P, P_pub   pbc.Element
}

func (pp *PublicParam) pairing(g1, g2 *pbc.Element) *pbc.Element {
	if pp.SwapG1G2 {
		return pp.Pairing.NewGT().Pair(g2, g1)
	}
	return pp.Pairing.NewGT().Pair(g1, g2)
}

func (pp *PublicParam) H0(m *pbc.Element) *pbc.Element {
	return utils.H_PBC_1_1(pp.Pairing, pp.G1, m)
}

func (pp *PublicParam) H1(m *pbc.Element) *pbc.Element {
	return utils.H_PBC_1_1(pp.Pairing, pp.Zr, m)
}

func (pp *PublicParam) GetG1Element() *pbc.Element {
	switch pp.G1 {
    case pbc.G1:
        return pp.Pairing.NewG1().Rand()
    case pbc.G2:
        return pp.Pairing.NewG2().Rand()
    default:
        return nil
    }
}

func (pp *PublicParam) GetG2Element() *pbc.Element {
	switch pp.G2 {
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

func getHashValue(R *Randomness, SP *PublicParam, ID, m *pbc.Element) *pbc.Element {
	return SP.pairing(&R.R, &SP.P).ThenMul(SP.pairing(SP.H0(ID).ThenPowZn(SP.H1(m)), &SP.P_pub))
}

func SetUp(curveName curve.Curve, swapG1G2 bool) (*PublicParam, *MasterSecretKey) {
	SP := new(PublicParam)
	msk := new(MasterSecretKey)

	SP.SwapG1G2 = swapG1G2
	SP.Pairing = curve.PairingGen(curveName)
	if swapG1G2 {
		SP.G1 = pbc.G2
		SP.G2 = pbc.G1
	} else {
		SP.G1 = pbc.G1
		SP.G2 = pbc.G2
	}
	SP.GT = pbc.GT
	SP.Zr = pbc.Zr

	SP.P = *SP.GetG2Element()
	msk.S = *SP.GetZrElement()
	SP.P_pub = *powZn(&SP.P, &msk.S)

	return SP, msk
}

func KeyGen(SP *PublicParam, msk *MasterSecretKey, ID *pbc.Element) *SecretKey {
	sk := new(SecretKey)

	sk.S_ID = *SP.H0(ID).ThenPowZn(&msk.S)

	return sk
}

func Hash(SP *PublicParam, ID, m *pbc.Element) (*HashValue, *Randomness) {
	H := new(HashValue)
	R := new(Randomness)

	R.R = *SP.GetG1Element()
	H.H = *getHashValue(R, SP, ID, m)

	return H, R
}

func Check(H *HashValue, R *Randomness, SP *PublicParam, ID, m *pbc.Element) bool {
	return H.H.Equals(getHashValue(R, SP, ID, m))
}

func Adapt(R *Randomness, SP *PublicParam, sk *SecretKey, m, m_p *pbc.Element) *Randomness {
	R_p := new(Randomness)

	R_p.R = *mul(&R.R, powZn(&sk.S_ID, SP.H1(m).ThenSub(SP.H1(m_p))))

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