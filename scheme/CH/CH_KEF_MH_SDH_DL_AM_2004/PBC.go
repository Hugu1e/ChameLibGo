package CH_KEF_MH_SDH_DL_AM_2004

import (
	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
	"github.com/Nik-U/pbc"
)

type PublicParam struct {
	Pairing *pbc.Pairing
}
func (pp *PublicParam) GetGElement() *pbc.Element {
	return pp.Pairing.NewG1().Rand()
}
func (pp *PublicParam) GetZrElement() *pbc.Element {
	return pp.Pairing.NewZr().Rand()
}
func (pp *PublicParam) H(m *pbc.Element) *pbc.Element {
	return utils.H_PBC_1_1(pp.Pairing, pbc.Zr, m)
}

type PublicKey struct {
	H, G *pbc.Element
}

type SecretKey struct {
	X *pbc.Element
}

type HashValue struct {
	H *pbc.Element
}

type Randomness struct {
	G_r *pbc.Element
}

func SetUp(curveName curve.Curve) *PublicParam {
	pp := new(PublicParam)

	pp.Pairing = curve.PairingGen(curveName)

	return pp
}

func KeyGen(pp *PublicParam) (*PublicKey, *SecretKey) {
	sk := new(SecretKey)
	pk := new(PublicKey)

	sk.X = pp.GetZrElement()
	pk.G = pp.GetGElement()
	pk.H = utils.POWZN(pk.G, sk.X)

	return pk, sk
}

func Hash(pk *PublicKey, L, m *pbc.Element, pp *PublicParam) (*HashValue, *Randomness) {
	h := new(HashValue)
	r := new(Randomness)

	r_ := pp.GetZrElement()
	r.G_r = utils.POWZN(pk.G, r_)
	
	tmp1 := utils.POWZN(pk.G, pp.H(m))
	tmp2 := utils.POWZN(utils.MUL(utils.POWZN(pk.G, pp.H(L)), pk.H), r_)
	h.H = tmp1.ThenMul(tmp2)

	return h, r
}

func Check(h *HashValue, r *Randomness, pk *PublicKey, L, m *pbc.Element, pp *PublicParam) bool {
	tmp1 := pp.Pairing.NewGT().Pair(pk.G , utils.DIV(h.H, utils.POWZN(pk.G, pp.H(m))))
	tmp2 := pp.Pairing.NewGT().Pair(r.G_r, utils.MUL(pk.H, utils.POWZN(pk.G, pp.H(L))))
	return tmp1.Equals(tmp2)
}

func Adapt(r *Randomness, pk *PublicKey, sk *SecretKey, L, m, m_p *pbc.Element, pp *PublicParam) *Randomness {
	r_p := new(Randomness)

	tmp1 := utils.POWZN(pk.G, utils.SUB(pp.H(m), pp.H(m_p)).ThenDiv(utils.ADD(sk.X , pp.H(L))))
	r_p.G_r = tmp1.ThenMul(r.G_r)

	return r_p
}