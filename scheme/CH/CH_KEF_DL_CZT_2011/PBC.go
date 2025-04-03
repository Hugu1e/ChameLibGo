package CH_KEF_DL_CZT_2011

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
func (pp *PublicParam) H(m1, m2 *pbc.Element) *pbc.Element {
	return utils.H_PBC_2_1(pp.Pairing, pp.Group, m1, m2)
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

func getHashValue(R *Randomness, SP *PublicParam, pk *PublicKey, I, m *pbc.Element) *pbc.Element {
	return SP.H(pk.Y, I).ThenPowZn(m).ThenMul(R.G_a)
}

func SetUp(curveName curve.Curve, group pbc.Field) (*PublicParam) {
	SP := new(PublicParam)

	SP.Pairing = curve.PairingGen(curveName)
	SP.Group = group

	SP.G = SP.GetGroupElement()

	return SP
}

func KeyGen(SP *PublicParam) (*PublicKey, *SecretKey) {
	sk := new(SecretKey)
	pk := new(PublicKey)

	sk.X = SP.GetZrElement()
	pk.Y = utils.POWZN(SP.G, sk.X)

	return pk, sk
}

func Hash(SP *PublicParam, pk *PublicKey, I, m *pbc.Element) (*HashValue, *Randomness) {
	H := new(HashValue)
	R := new(Randomness)
	
	a := SP.GetZrElement()
	R.G_a = utils.POWZN(SP.G, a)
	R.Y_a = utils.POWZN(pk.Y, a)
	H.H = getHashValue(R, SP, pk, I, m)

	return H, R
}

func Check(H *HashValue, R *Randomness, SP *PublicParam, pk *PublicKey, I, m *pbc.Element) bool {
	return H.H.Equals(getHashValue(R, SP, pk, I, m))
}

func Adapt(R *Randomness, SP *PublicParam, pk *PublicKey, sk *SecretKey, I, m, m_p *pbc.Element) *Randomness {
	R_p := new(Randomness)

	h := SP.H(pk.Y, I)
	delta_m := utils.SUB(m, m_p)
	R_p.Y_a = utils.POWZN(h, utils.MUL(delta_m, sk.X)).ThenMul(R.Y_a)
	R_p.G_a = utils.POWZN(h, delta_m).ThenMul(R.G_a)

	return R_p
}