package CH_KEF_CZK_2004

import (
	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
	"github.com/Nik-U/pbc"
)

type PublicParam struct {
	Group pbc.Field
	Pairing *pbc.Pairing

	G *pbc.Element
}
func (pp *PublicParam) GetGroupElement() *pbc.Element {
	switch pp.Group {
	case pbc.G1:
		return pp.Pairing.NewG1().Rand()
	case pbc.G2:
		return pp.Pairing.NewG2().Rand()
	case pbc.GT:
		return pp.Pairing.NewGT().Rand()
	default:
		return nil
	}
}
func (pp *PublicParam) GetZrElement() *pbc.Element {
	return pp.Pairing.NewZr().Rand()
}
func (pp *PublicParam) H(m string) *pbc.Element {
	return utils.H_String_1_PBC_1(pp.Pairing, pp.Group, m)
}

type PublicKey struct {
	Y *pbc.Element
}

type SecretKey struct {
	X *pbc.Element
}

type HashValue struct {
	H *pbc.Element
}

type Randomness struct {
	G_a *pbc.Element
	Y_a *pbc.Element
}


func getHashValue(R *Randomness, SP *PublicParam, I, m *pbc.Element) *pbc.Element {
	return utils.MUL(SP.G, I).ThenPowZn(m).ThenMul(R.Y_a)
}


func SetUp(curveName curve.Curve, group pbc.Field) *PublicParam {
	pp := new(PublicParam)

	pp.Pairing = curve.PairingGen(curveName)
	pp.Group = group

	pp.G = pp.GetGroupElement()

	return pp
}

func KeyGen(pp *PublicParam) (*PublicKey, *SecretKey) {
	pk := new(PublicKey)
	sk := new(SecretKey)

	sk.X = pp.GetZrElement()
	pk.Y = utils.POWZN(pp.G, sk.X)

	return pk, sk
}

func Hash(pp *PublicParam, pk *PublicKey, I, m *pbc.Element) (*HashValue, *Randomness) {
	H := new(HashValue)
	R := new(Randomness)

	a := pp.GetZrElement()
	R.G_a = utils.POWZN(pp.G, a)
	R.Y_a = utils.POWZN(pk.Y, a)
	H.H = getHashValue(R, pp, I, m)

	return H, R
}

func Check(H *HashValue, R *Randomness, SP *PublicParam, I, m *pbc.Element) bool {
	return H.H.Equals(getHashValue(R, SP, I, m))
}

func Adapt(R *Randomness, SP *PublicParam, sk *SecretKey, I, m, m_p *pbc.Element) *Randomness {
	R_p := new(Randomness)

	gI := utils.MUL(SP.G, I)
	delta_m := utils.SUB(m ,m_p)
	R_p.Y_a = utils.POWZN(gI, delta_m).ThenMul(R.Y_a)
	R_p.G_a = utils.POWZN(gI, delta_m.ThenDiv(sk.X)).ThenMul(R.G_a)

	return R_p
}