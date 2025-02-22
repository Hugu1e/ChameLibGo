package CH_KEF_DLP_LLA_2012

import (
	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"

	"github.com/Nik-U/pbc"
)

type Label struct {
	L, R pbc.Element
}

type LabelGen struct {
	Y_1, Omega_1 pbc.Element
}

type LabelManager struct {
	Dict map[PublicKey]LabelGen
	Group pbc.Field
	Pairing *pbc.Pairing
}
func (lm *LabelManager) add(pk *PublicKey, lg *LabelGen) {
	lm.Dict[*pk] = *lg
}
func (lm *LabelManager) GetGroupElement() *pbc.Element {
	switch lm.Group {
	case pbc.G1:
		return lm.Pairing.NewG1().Rand()
	case pbc.G2:
		return lm.Pairing.NewG2().Rand()
	case pbc.GT:
		return lm.Pairing.NewGT().Rand()
	default:
		return nil
	}
}
func (lm *LabelManager) get(pk *PublicKey) *Label {
	L := new(Label)

	t := lm.GetGroupElement()
	H2_t := H2(lm.Pairing, pbc.Zr, t)
	lg := lm.Dict[*pk]
	L.L = *utils.POWZN(&lg.Y_1, H2_t)
	L.R = *utils.POWZN(&lg.Omega_1, H2_t).ThenMul(t)

	return L
}

type PublicParam struct {
	Pairing *pbc.Pairing
	Group pbc.Field
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
	G, Y_2 pbc.Element
}

type SecretKey struct {
	Alpha, X_1, X_2 pbc.Element
}

type HashValue struct {
	S pbc.Element
}

type Randomness struct {
	R pbc.Element
}

func H1(pairing *pbc.Pairing, group pbc.Field, m1, m2, m3 *pbc.Element) *pbc.Element {
	return utils.H_PBC_3_1(pairing, group, m1, m2, m3)
}

func H2(pairing *pbc.Pairing, group pbc.Field, m1 *pbc.Element) *pbc.Element {
	return utils.H_PBC_1_1(pairing, group, m1)
}

func getHashValue(r *Randomness, L *Label, pk *PublicKey, m *pbc.Element, pp *PublicParam) *pbc.Element {
	return utils.POWZN(&pk.G, m).ThenMul(utils.POWZN(&pk.Y_2, H1(pp.Pairing, pbc.Zr, &L.L, &L.R, &L.L)).ThenMul(&L.L).ThenPowZn(&r.R))
}

func SetUp(curveName curve.Curve, group pbc.Field) (*PublicParam, *LabelManager) {
	pp := new(PublicParam)
	lm := new(LabelManager)

	pp.Pairing = curve.PairingGen(curveName)
	pp.Group = group

	lm.Pairing = pp.Pairing
	lm.Group = group
	lm.Dict = make(map[PublicKey]LabelGen)
	
	return pp, lm
}

func KeyGen(lm *LabelManager, pp *PublicParam) (*PublicKey, *SecretKey) {
	pk := new(PublicKey)
	sk := new(SecretKey)

	pk.G = *pp.GetGroupElement()
	sk.Alpha = *pp.GetZrElement()
	sk.X_1 = *pp.GetZrElement()
	sk.X_2 = *pp.GetZrElement()

	lg := new(LabelGen)
	lg.Y_1 = *utils.POWZN(&pk.G, &sk.X_1)
	lg.Omega_1 = *utils.POWZN(&lg.Y_1, &sk.Alpha)
	
	pk.Y_2 = *utils.POWZN(&pk.G, &sk.X_2)
	lm.add(pk, lg)

	return pk, sk
}

func Hash(lm *LabelManager, pk *PublicKey, m *pbc.Element, pp *PublicParam) (*HashValue, *Randomness, *Label) {
	h := new(HashValue)
	r := new(Randomness)
	L := lm.get(pk)

	r.R = *pp.GetZrElement()
	h.S = *getHashValue(r, L, pk, m, pp)

	return h, r, L
}

func Check(h *HashValue, r *Randomness, pk *PublicKey, L *Label, m *pbc.Element, pp *PublicParam) bool {
	return h.S.Equals(getHashValue(r, L, pk, m, pp))
}

func UForge(h *HashValue, r *Randomness, L *Label, pk *PublicKey, sk *SecretKey, pp *PublicParam, m, m_p *pbc.Element) *Randomness {
	if !Check(h, r, pk, L, m, pp) {
		panic("illegal hash")
	}
	r_p := new(Randomness)

	t := utils.DIV(&L.R, utils.POWZN(&L.L, &sk.Alpha))
	H2_t := H2(pp.Pairing, pbc.Zr, t)
	c := H1(pp.Pairing, pbc.Zr, &L.L, &L.R, &L.L)
	if !utils.POWZN(&pk.G, utils.MUL(H2_t, &sk.X_1)).Equals(&L.L) {
		panic("illegal label")
	}
	r_p.R = *utils.SUB(m, m_p).ThenDiv(utils.MUL(&sk.X_1, H2_t).ThenAdd(utils.MUL(&sk.X_2, c))).ThenAdd(&r.R)

	return r_p
}

func IForge(r, r_p *Randomness, m, m_p, m_pp *pbc.Element) *Randomness {
	r_pp := new(Randomness)

	r_pp.R = *utils.SUB(&r_p.R, &r.R).ThenMul(utils.SUB(m_p, m_pp)).ThenDiv(utils.SUB(m, m_p)).ThenAdd(&r_p.R) 

	return r_pp
}