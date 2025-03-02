package RPCH_TMM_2022

import (
	"github.com/Hugu1e/ChameLibGo/ABE/RABE"
	"github.com/Hugu1e/ChameLibGo/base/BinaryTree"
	"github.com/Hugu1e/ChameLibGo/base/GroupParam"
	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
	"github.com/Nik-U/pbc"
)

type PublicParam struct {
	GP      *GroupParam.Asymmetry

	GP_CHET *GroupParam.Single

	SP_RABE *RABE.PublicParam
}

func (pp *PublicParam) H(m string) *pbc.Element {
	return pp.SP_RABE.H(m)
}

type MasterPublicKey struct {
	G			*pbc.Element
	
	Mpk_RABE	*RABE.MasterPublicKey
}

type MasterSecretKey struct {
	Msk_RABE *RABE.MasterSecretKey
}

type PublicKey struct {
	Pk 	*pbc.Element
}

type SecretKey struct {
	X 	*pbc.Element

	Sk_RABE  *RABE.SecretKey
}

type UpdateKey struct {
	Ku_RABE *RABE.UpdateKey
}

type DecryptKey struct {
	X		*pbc.Element
	
	Dk_RABE	*RABE.DecryptKey
}

type HashValue struct {
	B, H 	*pbc.Element
	
	Ct_RABE *RABE.CipherText
}

type Randomness struct {
	R *pbc.Element
}

func SetUp(curveName curve.Curve, swap_G1G2 bool, group pbc.Field) (*PublicParam, *MasterPublicKey, *MasterSecretKey) {
	pp := new(PublicParam)
	mpk := new(MasterPublicKey)
	msk := new(MasterSecretKey)

	pp.GP = GroupParam.NewAsymmetry(curveName, swap_G1G2)

	pp.GP_CHET = GroupParam.NewSingleFromPairing(pp.GP.Pairing, group)

	pp_RABE, mpk_RABE, msk_RABE := RABE.SetUpWithGP(RABE.TMM_2022, pp.GP)
	pp.SP_RABE = pp_RABE
	mpk.Mpk_RABE = mpk_RABE
	msk.Msk_RABE = msk_RABE

	mpk.G = pp.GP_CHET.GetGElement()

	return pp, mpk, msk
}

func KeyGen(st *BinaryTree.BinaryTree, sp *PublicParam, mpk *MasterPublicKey, msk *MasterSecretKey, S *utils.AttributeList, id *pbc.Element) (*PublicKey, *SecretKey) {
	pk := new(PublicKey)
	sk := new(SecretKey)

	sk.X = sp.GP_CHET.GetZrElement()
	pk.Pk = utils.POWZN(mpk.G, sk.X)

	sk_RABE := RABE.KeyGen(st, sp.SP_RABE, mpk.Mpk_RABE, msk.Msk_RABE, S, id)
	sk.Sk_RABE= sk_RABE
	
	return pk, sk
}

func UpdateKeyGen(sp *PublicParam, mpk *MasterPublicKey, st *BinaryTree.BinaryTree, rl *BinaryTree.RevokeList, t int) *UpdateKey {
	ku := new(UpdateKey)

	ku_RABE := RABE.UpdateKeyGen(sp.SP_RABE, mpk.Mpk_RABE, st, rl, t)
	ku.Ku_RABE = ku_RABE

	return ku
}

func DecryptKeyGen(sp *PublicParam, mpk *MasterPublicKey, sk *SecretKey, ku *UpdateKey, st *BinaryTree.BinaryTree, rl *BinaryTree.RevokeList) *DecryptKey {
	dk := new(DecryptKey)

	dk.X = utils.COPY(sk.X)

	dk_RABE := RABE.DecryptKeyGen(sp.SP_RABE, mpk.Mpk_RABE, sk.Sk_RABE, ku.Ku_RABE, st, rl)
	dk.Dk_RABE = dk_RABE

	return dk
}

func Revoke(rl *BinaryTree.RevokeList, id *pbc.Element, t int) {
	RABE.Revoke(rl, id, t)
}

func Hash(sp *PublicParam, mpk *MasterPublicKey, pk * PublicKey, MSP *utils.PBCMatrix, m *pbc.Element, t int) (*HashValue, *Randomness){
	H := new(HashValue)
	R := new(Randomness)

	R_ := sp.GP_CHET.GetZrElement()
	R.R = sp.GP_CHET.GetZrElement()
	H.H = utils.POWZN(mpk.G, R_)
	H.B = utils.POWZN(pk.Pk, m).ThenMul(utils.POWZN(H.H, R.R))

	ct_RABE := RABE.Encrypt(sp.SP_RABE, mpk.Mpk_RABE, MSP, RABE.NewPlainText(R_), t)
	H.Ct_RABE = ct_RABE

	return H, R
}

func Check(H *HashValue, R *Randomness, pk *PublicKey, m *pbc.Element) bool {
	return H.B.Equals(utils.POWZN(pk.Pk, m).ThenMul(utils.POWZN(H.H, R.R)))
}

func Adapt(H *HashValue, R *Randomness, sp *PublicParam, pk *PublicKey, dk *DecryptKey, MSP *utils.PBCMatrix, m, m_p *pbc.Element) *Randomness {
	R_p := new(Randomness)

	if !Check(H, R, pk, m) {
		panic("wrong hash")
	}
	pt_RABE := RABE.Decrypt(sp.SP_RABE, dk.Dk_RABE, MSP, H.Ct_RABE)

	R_p.R = utils.ADD(R.R, utils.SUB(m, m_p).ThenMul(utils.DIV(dk.X, pt_RABE.M)))
	
	return R_p
}