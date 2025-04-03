package ID_B_CollRes_XSL_2021

import (
	"math/rand"
	"time"

	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
	"github.com/Nik-U/pbc"
)

type PublicParam struct {
	Pairing    *pbc.Pairing
	Zr, G1, G2, GT pbc.Field
	SwapG1G2   bool

	G, G_1, G_2 *pbc.Element
	U          []*pbc.Element
	N          int
}

func (pp *PublicParam) pairing(g1, g2 *pbc.Element) *pbc.Element {
	if pp.SwapG1G2 {
		return pp.Pairing.NewGT().Pair(g2, g1)
	}
	return pp.Pairing.NewGT().Pair(g1, g2)
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

func (pp *PublicParam) GenIdentity() *Identity {
	id := new(Identity)
	id.I = make([]bool, pp.N)

	rand.Seed(time.Now().UnixNano())
	for i := 1; i <= pp.N; i++ {
		id.set(i, rand.Intn(2) == 1)
	}

	return id
}

type MasterSecretKey struct {
	G_2_alpha *pbc.Element
}

type SecretKey struct {
	Tk_1, Tk_2 *pbc.Element
}

type Identity struct {
	I []bool
}
func (I *Identity) at(i int) bool{
	return I.I[i-1]
}

func (I *Identity) set(i int, x bool){
	I.I[i-1] = x
}

type HashValue struct {
	H *pbc.Element
}

type Randomness struct {
	R_1, R_2 *pbc.Element
}


func getHashValue(R *Randomness, SP *PublicParam, ID *Identity, m *pbc.Element) *pbc.Element {
	tmp := SP.U[0].NewFieldElement().Set(SP.U[0])
	for i := 1; i <= SP.N; i++ {
		if ID.at(i) {
			tmp.ThenMul(SP.U[i])
		}
	}
	tmp1 := SP.pairing(SP.G_1, SP.G_2).ThenPowZn(m)
	tmp2 := SP.pairing(SP.G, R.R_1).ThenDiv(SP.pairing(R.R_2, tmp))
	return tmp1.ThenMul(tmp2)
}

func SetUp(curveName curve.Curve, n int, swapG1G2 bool) (*PublicParam, *MasterSecretKey) {
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
	SP.U = make([]*pbc.Element, n+1)
	SP.N = n

	alpha := SP.GetZrElement()
	SP.G = SP.GetG1Element()
	SP.G_2 = SP.GetG2Element()
	SP.G_1 = utils.POWZN(SP.G, alpha)
	for i := 0; i <= n; i++ {
		SP.U[i] = SP.GetG2Element()
	}
	msk.G_2_alpha = utils.POWZN(SP.G_2, alpha)

	return SP, msk
}

func KeyGen(SP *PublicParam, msk *MasterSecretKey, ID *Identity) *SecretKey {
	sk := new(SecretKey)

	t := SP.GetZrElement()
	tmp := SP.U[0].NewFieldElement().Set(SP.U[0])
	for i := 1; i <= SP.N; i++ {
		if ID.at(i) {
			tmp.ThenMul(SP.U[i])
		}
	}
	sk.Tk_1 = utils.MUL(msk.G_2_alpha, tmp.ThenPowZn(t))
	sk.Tk_2 = utils.POWZN(SP.G, t)

	return sk
}

func Hash(SP *PublicParam, ID *Identity, m *pbc.Element) (*HashValue, *Randomness) {
	H := new(HashValue)
	R := new(Randomness)

	R.R_1 = SP.GetG2Element()
	R.R_2 = SP.GetG1Element()
	H.H = getHashValue(R, SP, ID, m)

	return H, R
}

func Check(H *HashValue, R *Randomness, SP *PublicParam, ID *Identity, m *pbc.Element) bool {
	return H.H.Equals(getHashValue(R, SP, ID, m))
}

func Adapt(R *Randomness, sk *SecretKey, m, mp *pbc.Element) *Randomness {
	Rp := new(Randomness)

	deltaM := utils.SUB(m, mp)
	Rp.R_1 = utils.MUL(R.R_1, utils.POWZN(sk.Tk_1, deltaM))
	Rp.R_2 = utils.MUL(R.R_2, utils.POWZN(sk.Tk_2, deltaM))

	return Rp
}