package CH_FS_ECC_CCT_2024

import (
	"fmt"

	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
	"github.com/Nik-U/pbc"
)

type PublicParam struct {
	Group pbc.Field
	Pairing *pbc.Pairing

	G     pbc.Element
}

func (pp *PublicParam) H(m *pbc.Element) *pbc.Element {
	return utils.H_PBC_1_1(pp.Pairing, pp.Group, m)
}

func (pp *PublicParam) H_p(m string) *pbc.Element {
	return utils.H_String_1_PBC_1(pp.Pairing, pbc.Zr, m)
}

func (pp *PublicParam) H_p_2(m1, m2, m3, m4 *pbc.Element) *pbc.Element {
	return pp.H_p(fmt.Sprintf("%s|%s|%s|%s", m1, m2, m3, m4))
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
	G_x pbc.Element
}

type SecretKey struct {
	X pbc.Element
}

type HashValue struct {
	H pbc.Element
}

type Randomness struct {
	Z_1, Z_2, C_1 pbc.Element
}

func SetUp(curveName curve.Curve, group pbc.Field) *PublicParam {
	pp := new(PublicParam)

	pp.Pairing = curve.PairingGen(curveName)
	pp.Group = group
	

	pp.G = *pp.GetGroupElement()
	return pp
}

func KeyGen(pp *PublicParam) (*PublicKey, *SecretKey) {
	sk := new(SecretKey)
	pk := new(PublicKey)

	sk.X = *pp.GetZrElement()
	pk.G_x = *utils.POWZN(&pp.G, &sk.X)

	return pk, sk
}

func Hash(pp *PublicParam, pk *PublicKey, m *pbc.Element) (*HashValue, *Randomness) {
	H := new(HashValue)
	R := new(Randomness)

	rho := pp.GetZrElement()

	H.H = *utils.POWZN(&pp.G, rho).ThenMul(pp.H(m))

	t_2 := pp.GetZrElement()
	R.Z_1 = *pp.GetZrElement()

	R.C_1 = *pp.H_p_2(utils.POWZN(&pp.G, t_2), &pk.G_x, utils.POWZN(&pp.G, rho), m)
	R.Z_2 = *utils.SUB(t_2, pp.H_p_2(utils.POWZN(&pp.G, &R.Z_1).ThenMul(utils.POWZN(&pk.G_x, &R.C_1)), &pk.G_x, utils.POWZN(&pp.G, rho), m).ThenMul(rho))
	return H, R
}

func Check(H *HashValue, R *Randomness, pp *PublicParam, pk *PublicKey, m *pbc.Element) bool {
	y_p := utils.DIV(&H.H, pp.H(m))

	tmp1 := pp.H_p_2(utils.POWZN(&pp.G, &R.Z_1).ThenMul(utils.POWZN(&pk.G_x, &R.C_1)), &pk.G_x, y_p, m)
	
	return R.C_1.Equals(pp.H_p_2(utils.POWZN(&pp.G, &R.Z_2).ThenMul(utils.POWZN(y_p, tmp1)), &pk.G_x, y_p, m))
}

func Adapt(H *HashValue, R *Randomness, pp *PublicParam, pk *PublicKey, sk *SecretKey, m, m_p *pbc.Element) *Randomness {
	if !Check(H, R, pp, pk, m) {
		panic("wrong hash value")
	}
	R_p := new(Randomness)

	y_p := utils.DIV(&H.H, pp.H(m_p))
	t_1_p := pp.GetZrElement()
	R_p.Z_2 = *pp.GetZrElement()

	R_p.C_1 = *pp.H_p_2(
		utils.POWZN(&pp.G, &R_p.Z_2).ThenMul(utils.POWZN(y_p, pp.H_p_2(
			utils.POWZN(&pp.G, t_1_p), &pk.G_x, y_p, m_p,
		))), &pk.G_x, y_p, m_p,
	)

	R_p.Z_1 = *utils.SUB(t_1_p, utils.MUL(&R_p.C_1, &sk.X))

	return R_p
}
