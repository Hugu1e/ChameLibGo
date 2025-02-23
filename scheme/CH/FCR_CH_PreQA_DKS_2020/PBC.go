package FCR_CH_PreQA_DKS_2020

import (
	"fmt"

	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
	"github.com/Nik-U/pbc"
)

type PublicParam struct {
	Pairing *pbc.Pairing
	Group pbc.Field

	G_1, G_2 pbc.Element
}

func (pp *PublicParam) H(m string) *pbc.Element {
	return utils.H_String_1_PBC_1(pp.Pairing, pbc.Zr, m)
}

func (pp *PublicParam) H2(m1, m2, m3, m4, m5 *pbc.Element) *pbc.Element {
	return pp.H(fmt.Sprintf("(%s|%s|%s)(%s|%s)", m1.String(), m2.String(), m3.String(), m4.String(), m5.String()))
}

func (pp *PublicParam) Hp(m *pbc.Element) *pbc.Element {
	return utils.H_PBC_1_1(pp.Pairing, pp.Group, m)
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
	Y pbc.Element
}

type SecretKey struct {
	X pbc.Element
}

type HashValue struct {
	O pbc.Element
}

type Randomness struct {
	E_1, E_2, S_1_1, S_1_2, S_2 pbc.Element
}

func SetUp(curveName curve.Curve, group pbc.Field) (*PublicParam) {
	pp := new(PublicParam)

	pp.Group = group
	pp.Pairing = curve.PairingGen(curveName)

	pp.G_1 = *pp.GetGroupElement()
	pp.G_2 = *pp.Hp(&pp.G_1)

	return pp
}

func KeyGen(pp *PublicParam) (*PublicKey, *SecretKey) {
	pk := new(PublicKey)
	sk := new(SecretKey)

	sk.X = *pp.GetZrElement()
	pk.Y = *utils.POWZN(&pp.G_1, &sk.X)

	return pk, sk
}

func Hash(pp *PublicParam, pk *PublicKey, m *pbc.Element) (*HashValue, *Randomness) {
	H := new(HashValue)
	R := new(Randomness)

	xi := pp.GetZrElement()
	k11 := pp.GetZrElement()
	k12 := pp.GetZrElement()
	R.E_2 = *pp.GetZrElement()
	R.S_2 = *pp.GetZrElement()

	H.O = *utils.POWZN(&pp.G_1, m).ThenMul(utils.POWZN(&pp.G_2, xi))

	R.E_1 = *utils.SUB(pp.H2(
		&pk.Y, &H.O, m,
		utils.MUL(utils.POWZN(&pp.G_1, k11), utils.POWZN(&pp.G_2, k12)),
		utils.MUL(utils.POWZN(&pp.G_1, &R.S_2), utils.POWZN(&pk.Y, utils.NEG(&R.E_2))),
	) , &R.E_2)
	R.S_1_1 = *utils.ADD(k11, utils.MUL(&R.E_1, m))
	R.S_1_2 = *utils.ADD(k12, utils.MUL(&R.E_1, xi))

	return H, R
}

func Check(H *HashValue, R *Randomness, pp *PublicParam, pk *PublicKey, m *pbc.Element) bool {
	return utils.ADD(&R.E_1, &R.E_2).Equals(pp.H2(
		&pk.Y, &H.O, m,
		utils.POWZN(&pp.G_1, &R.S_1_1).ThenMul(utils.POWZN(&pp.G_2, &R.S_1_2)).ThenMul(utils.POWZN(&H.O, utils.NEG(&R.E_1))),
		utils.POWZN(&pp.G_1, &R.S_2).ThenMul(utils.POWZN(&pk.Y, utils.NEG(&R.E_2))),
	))
}

func Adapt(H *HashValue, R *Randomness, pp *PublicParam, pk *PublicKey, sk *SecretKey, m, mp *pbc.Element) *Randomness {
	if !Check(H, R, pp, pk, m) {
		panic("wrong hash value")
	}
	Rp := new(Randomness)

	k2 := pp.GetZrElement()
	Rp.E_1 = *pp.GetZrElement()
	Rp.S_1_1 = *pp.GetZrElement()
	Rp.S_1_2 = *pp.GetZrElement()

	Rp.E_2 = *utils.SUB(pp.H2(
		&pk.Y, &H.O, mp,
		utils.POWZN(&pp.G_1, &Rp.S_1_1).ThenMul(utils.POWZN(&pp.G_2, &Rp.S_1_2)).ThenMul(utils.POWZN(&H.O, utils.NEG(&Rp.E_1))),
		utils.POWZN(&pp.G_1, k2),
	), &Rp.E_1)

	Rp.S_2 = *utils.ADD(k2, utils.MUL(&Rp.E_2, &sk.X))

	return Rp
}
