package IB_CH_KEF_CZS_2014

/*
 * Key exposure free chameleon hash schemes based on discrete logarithm problem
 * P6. 4.1. The proposed identity-based chameleon hash scheme
 */

import (

	"github.com/Nik-U/pbc"

	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
)

type PublicParam struct{
    Swap_G1G2 bool
    Pairing *pbc.Pairing
    G1, G2, GT, Zr pbc.Field

    P, P_pub pbc.Element
}

type MasterSecretKey struct{
    X pbc.Element
}

type SecretKey struct{
    S_ID pbc.Element
}

type HashValue struct{
    H pbc.Element
}

type Randomness struct{
    R_1, R_2 pbc.Element
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

func (pp *PublicParam) GetZrElement() *pbc.Element {
    return pp.Pairing.NewZr().Rand()
}

func SetUp(curveName curve.Curve, swap_G1G2 bool) (*PublicParam, *MasterSecretKey) {
    pp := new(PublicParam)
    msk := new(MasterSecretKey)

    pp.Pairing = curve.PairingGen(curveName)
    pp.Swap_G1G2 = swap_G1G2;
    if swap_G1G2 {
        pp.G1 = pbc.G2
        pp.G2 = pbc.G1
    } else {
        pp.G1 = pbc.G1
        pp.G2 = pbc.G2
    }
    pp.GT = pbc.GT
    pp.Zr = pbc.Zr

    pp.P = *pp.GetG1Element()
    msk.X = *pp.GetZrElement()
    pp.P_pub = *pp.P.NewFieldElement().PowZn(&pp.P, &msk.X)

    return pp, msk
}

func (pp *PublicParam) H_G1(m *pbc.Element) *pbc.Element {
    return utils.H_PBC_1_1(pp.Pairing, pp.G1, m)
}

func (pp *PublicParam) H_G2(m *pbc.Element) *pbc.Element {
    return utils.H_PBC_1_1(pp.Pairing, pp.G2, m)
}

func KeyGen(pp *PublicParam, msk *MasterSecretKey, ID *pbc.Element) *SecretKey {
    sk := new(SecretKey)

    sk.S_ID = *pp.H_G2(ID).ThenPowZn(&msk.X)
    return sk
}

func pairing(g1, g2 *pbc.Element, pp *PublicParam) *pbc.Element {
    gt := pp.Pairing.NewGT()
    if pp.Swap_G1G2 {
        gt.Pair(g2, g1)
    }else {
        gt.Pair(g1, g2)
    }
    return gt
}

func getHashValue(R *Randomness, pp *PublicParam, L, m *pbc.Element) *pbc.Element {
    return R.R_1.NewFieldElement().Mul(&R.R_1, pp.H_G1(L).ThenPowZn(m))
}


func Hash(pp *PublicParam, ID, L, m *pbc.Element) (*HashValue, *Randomness) {
    H := new(HashValue)
    R := new(Randomness)

    a := pp.GetZrElement()
    R.R_1 = *pp.P.NewFieldElement().PowZn(&pp.P, a)
    R.R_2 = *pairing(pp.P_pub.NewFieldElement().PowZn(&pp.P_pub, a), pp.H_G2(ID), pp)
    H.H = *getHashValue(R, pp, L, m)

    return H, R
}

func Check(H *HashValue, R *Randomness, pp *PublicParam, L, m *pbc.Element) bool {
    tmp_h := getHashValue(R, pp, L, m)
    return H.H.Equals(tmp_h)
}

func Adapt(R *Randomness, pp *PublicParam, sk *SecretKey, L, m, m_p *pbc.Element) *Randomness {
    R_p := new(Randomness)

    delta_m := m.NewFieldElement().Sub(m, m_p);
    R_p.R_1 = *R.R_1.NewFieldElement().Mul(&R.R_1, pp.H_G1(L).ThenPowZn(delta_m))
    tmp_gt := pairing(pp.H_G1(L), &sk.S_ID, pp)
    R_p.R_2 = *R.R_2.NewFieldElement().Mul(&R.R_2, tmp_gt.ThenPowZn(delta_m))

    return R_p
}

