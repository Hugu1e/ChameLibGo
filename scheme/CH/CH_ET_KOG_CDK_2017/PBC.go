package CH_ET_KOG_CDK_2017

import (
	"math/big"

	"github.com/Hugu1e/ChameLibGo/AE/RSA"
	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
	"github.com/Nik-U/pbc"
)

type NIZKPoK struct {
	Zr pbc.Field
	Pairing *pbc.Pairing
}
type Proof struct {
	Z, R pbc.Element
}
func (n *NIZKPoK) H(m1, m2 *pbc.Element) *pbc.Element {
	return utils.H_PBC_2_1(n.Pairing, n.Zr, m1, m2)
}
func (n *NIZKPoK) GenProof(g, pk, sk *pbc.Element) *Proof{
	pi := new(Proof)

	r := n.Pairing.NewZr().Rand()
	pi.R = *utils.POWZN(g, r)
	pi.Z = *utils.ADD(r, n.H(pk, &pi.R).ThenMul(sk))

	return pi
}
func (n *NIZKPoK) Verify(pi *Proof, g, pk *pbc.Element) bool {
	return utils.POWZN(g, &pi.Z).Equals(utils.MUL(&pi.R, utils.POWZN(pk, n.H(pk, &pi.R))))
}

type PublicParam struct {
	Group	pbc.Field
	Zr      pbc.Field
	Pairing *pbc.Pairing
	Nizkpok	NIZKPoK

	G      	pbc.Element
	Lambda 	int64
}
func (pp *PublicParam) H(m *pbc.Element) *pbc.Element {
	return utils.H_PBC_1_1(pp.Pairing, pp.Zr, m)
}
func (pp *PublicParam) GetZrElement() *pbc.Element {
	return pp.Pairing.NewZr().Rand()
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

type PublicKey struct {
	H      pbc.Element
	Pi_pk  Proof
	Pk_enc RSA.PublicKey
}

type SecretKey struct {
	X      pbc.Element
	Sk_enc RSA.SecretKey
}

type HashValue struct {
	B, H_p pbc.Element
	Pi_t   Proof
}

type Randomness struct {
	P    pbc.Element
	C    big.Int
	Pi_p Proof
}

type ETrapdoor struct {
	Etd pbc.Element
}


func SetUp(curveName curve.Curve, group pbc.Field,  lambda int64) *PublicParam {
	pp := new(PublicParam)

	pp.Pairing = curve.PairingGen(curveName)
	pp.Group = group
	pp.Zr = pbc.Zr

	pp.Nizkpok.Pairing = pp.Pairing
	pp.Nizkpok.Zr = pp.Zr

	pp.Lambda = lambda
	pp.G = *pp.GetGroupElement()

	return pp
}

func KeyGen(pp *PublicParam) (*PublicKey, *SecretKey){
	pk := new(PublicKey)
	sk := new(SecretKey)

	sk.X = *pp.GetZrElement()
	pk.H = *utils.POWZN(&pp.G, &sk.X)

	pk.Pi_pk = *pp.Nizkpok.GenProof(&pp.G, &pk.H, &sk.X)

	pk_RSA, sk_RSA := RSA.KeyGen_2(pp.Lambda, pp.Lambda)
	pk.Pk_enc = *pk_RSA
	sk.Sk_enc = *sk_RSA

	return pk, sk
}

func Hash(pp *PublicParam, pk *PublicKey, m *pbc.Element) (*HashValue, *Randomness, *ETrapdoor) {
	H := new(HashValue)
	R := new(Randomness)
	etd := new(ETrapdoor)

	if !pp.Nizkpok.Verify(&pk.Pi_pk, &pp.G, &pk.H) {
		panic("not valid proof")
	}
	r := pp.GetZrElement()
	etd.Etd = *pp.GetZrElement()
	H.H_p = *utils.POWZN(&pp.G, &etd.Etd)
	H.Pi_t = *pp.Nizkpok.GenProof(&pp.G, &H.H_p, &etd.Etd)
	R.C = *RSA.Encrypt(r.BigInt(), &pk.Pk_enc)
	a := pp.H(m)
	R.P = *utils.POWZN(&pk.H, r)
	R.Pi_p = *pp.Nizkpok.GenProof(&pk.H, &R.P, r)
	H.B = *utils.MUL(&R.P, utils.POWZN(&H.H_p, a))

	return H, R, etd
}

func Check(H *HashValue, R *Randomness, pp *PublicParam, pk *PublicKey, m *pbc.Element) bool {
	if !pp.Nizkpok.Verify(&R.Pi_p, &pk.H, &R.P) || !pp.Nizkpok.Verify(&H.Pi_t, &pp.G, &H.H_p) || !pp.Nizkpok.Verify(&pk.Pi_pk, &pp.G, &pk.H) {
		panic("not valid proof")
	}
	a := pp.H(m)
	return H.B.Equals(utils.MUL(&R.P, utils.POWZN(&H.H_p, a)))
}

func Adapt(H *HashValue, R *Randomness, etd *ETrapdoor, pp *PublicParam, pk *PublicKey, sk *SecretKey, m, m_p *pbc.Element) *Randomness{
	R_p := new(Randomness)

	if !Check(H, R, pp, pk, m) {
		panic("not valid hash")
	}
	r := pp.GetZrElement().SetBig(RSA.Decrypt(&R.C, &pk.Pk_enc, &sk.Sk_enc))
	if !H.H_p.Equals(utils.POWZN(&pp.G, &etd.Etd)) {
		panic("not valid hash")
	}
	a := pp.H(m)
	a_p := pp.H(m_p)
	if !R.P.Equals(utils.POWZN(&pp.G, utils.MUL(r, &sk.X))) {
		panic("not valid hash")
	}
	if a.Equals(a_p) {
		R_p.C = R.C
		R_p.P = R.P
		R_p.Pi_p = R.Pi_p
		return R_p
	}
	r_p := utils.ADD(r, utils.DIV(utils.MUL(utils.SUB(a, a_p), &etd.Etd), &sk.X))
	R_p.P = *utils.POWZN(&pk.H, r_p)
	R_p.C = *RSA.Encrypt(r_p.BigInt(), &pk.Pk_enc)
	R_p.Pi_p = *pp.Nizkpok.GenProof(&pk.H, &R_p.P, r_p)

	return R_p
}