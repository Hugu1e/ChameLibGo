package IB_CH_MD_LSX_2022

import (
    "github.com/Nik-U/pbc"

    "github.com/Hugu1e/ChameLibGo/utils"
    "github.com/Hugu1e/ChameLibGo/curve"
)

type PublicParam struct {
    Pairing *pbc.Pairing
    Zr, G1, GT pbc.Field
    G, G_1, G_2, Egg, Eg2g pbc.Element
}

type MasterSecretKey struct {
    Alpha, Beta pbc.Element
}

type SecretKey struct {
    Td_1, Td_2 pbc.Element
}

type HashValue struct {
    H pbc.Element
}

type Randomness struct {
    R_1, R_2 pbc.Element
}

func (pp *PublicParam) pairing(g1, g2 *pbc.Element) *pbc.Element {
    return pp.Pairing.NewGT().Pair(g1, g2)
}

func (pp *PublicParam) H(m *pbc.Element) *pbc.Element {
    return utils.H_PBC_1_1(pp.Pairing, pp.G1, m) 
}

func (pp *PublicParam) GetGElement() *pbc.Element {
    return pp.Pairing.NewG1().Rand()
}

func (pp *PublicParam) GetZrElement() *pbc.Element {
    return pp.Pairing.NewZr().Rand()
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

func getHashValue(R *Randomness, pp *PublicParam, ID, m *pbc.Element) *pbc.Element {
    temp1 := powZn(&pp.Eg2g, m)
    temp2 := powZn(&pp.Egg, &R.R_1)
    temp3 := pp.pairing(&R.R_2, div(&pp.G_1, powZn(&pp.G, ID)))
    return temp1.ThenMul(temp2).ThenMul(temp3)
}

func SetUp(curveName curve.Curve) (*PublicParam, *MasterSecretKey){
    pp := new(PublicParam)
    msk := new(MasterSecretKey)

    pp.Pairing = curve.PairingGen(curveName)
    pp.G1 = pbc.G1
    pp.GT = pbc.GT
    pp.Zr = pbc.Zr

    msk.Alpha = *pp.GetZrElement()
    msk.Beta = *pp.GetZrElement()
    pp.G = *pp.GetGElement()
    pp.G_1 = *powZn(&pp.G, &msk.Alpha)
    pp.G_2 = *powZn(&pp.G, &msk.Beta)
    pp.Egg = *pp.pairing(&pp.G, &pp.G)
    pp.Eg2g = *pp.pairing(&pp.G_2, &pp.G)

    return pp, msk
}

func KeyGen(pp *PublicParam, msk *MasterSecretKey, ID *pbc.Element) *SecretKey {
    sk := new(SecretKey)

    sk.Td_1 = *pp.GetZrElement()
    sk.Td_2 = *powZn(&pp.G, div(sub(&msk.Beta, &sk.Td_1), sub(&msk.Alpha, ID)))

    return sk
}

func Hash(pp *PublicParam, ID, m *pbc.Element) (*HashValue, *Randomness){
    H := new(HashValue)
    R := new(Randomness)

    R.R_1 = *pp.GetZrElement()
    R.R_2 = *pp.GetGElement()
    H.H = *getHashValue(R, pp, ID, m)

    return H, R
}

func Check(H *HashValue, R *Randomness, pp *PublicParam, ID, m *pbc.Element) bool {
    return H.H.Equals(getHashValue(R, pp, ID, m))
}

func Adapt(R *Randomness, sk *SecretKey, m, mp *pbc.Element) *Randomness{
    Rp := new(Randomness)

    deltaM := sub(m, mp)
    Rp.R_1 = *add(&R.R_1, mul(&sk.Td_1, deltaM))
    Rp.R_2 = *mul(&R.R_2, powZn(&sk.Td_2, deltaM))

    return Rp
}
