package CR_CH_DSS_2020

import (
	"fmt"

	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
	"github.com/Nik-U/pbc"
)

type PublicParam struct {
	Pairing *pbc.Pairing
	Group pbc.Field
	curveName curve.Curve

	G     *pbc.Element
}

func (pp *PublicParam) H(m string) *pbc.Element {
	return utils.H_String_1_PBC_1(pp.Pairing, pbc.Zr, m)
}

func (pp *PublicParam) H2(m1, m2, m3, m4, m5, m6, m7 *pbc.Element) *pbc.Element {
	ndonr := utils.GetNdonr(pp.Group, pp.curveName)
	return pp.H(fmt.Sprintf("(%s(%s|%s)%s)(%s|%s|%s)", m1, m2, m3, m4, utils.POWBIG(m5, ndonr).String(), utils.POWBIG(m6, ndonr).String(), utils.POWBIG(m7, ndonr).String()))
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

type PublicKey struct {
	Y *pbc.Element
}

type SecretKey struct {
	X *pbc.Element
}

type HashValue struct {
	C_1, C_2 *pbc.Element
}

type Randomness struct {
	E_1, E_2, S_1, S_2 *pbc.Element
}

func SetUp(curveName curve.Curve, group pbc.Field) (*PublicParam) {
	pp := new(PublicParam)

	pp.Pairing = curve.PairingGen(curveName)
	pp.Group = group
	pp.curveName = curveName

	pp.G = pp.GetGroupElement()

	return pp
}

func KeyGen(pp *PublicParam) (*PublicKey, *SecretKey) {
	sk := new(SecretKey)
	pk := new(PublicKey)

	sk.X = pp.GetZrElement()
	pk.Y = utils.POWZN(pp.G, sk.X)
	
	return pk, sk
}

func Hash(pp *PublicParam, pk *PublicKey, m *pbc.Element) (*HashValue, *Randomness) {
	H := new(HashValue)
	R := new(Randomness)

	xi := pp.GetZrElement()
	k1 := pp.GetZrElement()
	R.E_2 = pp.GetZrElement()
	R.S_2 = pp.GetZrElement()

	H.C_1 = utils.POWZN(pp.G, xi)
	H.C_2 = utils.MUL(m, utils.POWZN(pk.Y, xi))

	R.E_1 = utils.SUB(pp.H2(
		pk.Y, H.C_1, H.C_2, m,
		utils.POWZN(pp.G, k1), utils.POWZN(pk.Y, k1), utils.POWZN(pp.G, R.S_2).ThenMul(utils.POWZN(pk.Y, utils.NEG(R.E_2))),
	), R.E_2)
	R.S_1 = utils.MUL(R.E_1, xi).ThenAdd(k1)

	return H, R
}

func Check(H *HashValue, R *Randomness, pp *PublicParam, pk *PublicKey, m *pbc.Element) bool {
	tmp1 := utils.NEG(R.E_1)

	return utils.ADD(R.E_1, R.E_2).Equals(pp.H2(
		pk.Y, H.C_1, H.C_2, m,
		utils.POWZN(pp.G, R.S_1).ThenMul(utils.POWZN(H.C_1, tmp1)),
		utils.POWZN(pk.Y, R.S_1).ThenMul(utils.DIV(H.C_2, m).ThenPowZn(tmp1)),
		utils.POWZN(pp.G, R.S_2).ThenMul(utils.POWZN(pk.Y, utils.NEG(R.E_2))),
	))
}

func Adapt(H *HashValue, R *Randomness, pp *PublicParam, pk *PublicKey, sk *SecretKey, m, mp *pbc.Element) *Randomness {
	if !Check(H, R, pp, pk, m) {
		panic("wrong hash value")
	}
	Rp := new(Randomness)

	k2 := pp.GetZrElement()
	Rp.E_1 = pp.GetZrElement()
	Rp.S_1 = pp.GetZrElement()

	tmp1 := utils.NEG(Rp.E_1)

	Rp.E_2 = pp.H2(
		pk.Y, H.C_1, H.C_2, mp,
		utils.POWZN(pp.G, Rp.S_1).ThenMul(utils.POWZN(H.C_1, tmp1)),
		utils.POWZN(pk.Y, Rp.S_1).ThenMul(utils.DIV(H.C_2, mp).ThenPowZn(tmp1)),
		utils.POWZN(pp.G, k2),
	).ThenSub(Rp.E_1)

	Rp.S_2 = utils.MUL(Rp.E_2, sk.X).ThenAdd(k2)
	
	return Rp
}
