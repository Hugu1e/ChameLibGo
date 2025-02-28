package RPCH_XNM_2021

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/Hugu1e/ChameLibGo/ABE/RABE"
	"github.com/Hugu1e/ChameLibGo/SE"
	"github.com/Hugu1e/ChameLibGo/base/BinaryTree"
	"github.com/Hugu1e/ChameLibGo/base/GroupParam"
	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/scheme/CH/CH_ET_BC_CDK_2017"
	"github.com/Hugu1e/ChameLibGo/utils"
	"github.com/Nik-U/pbc"
)

type PublicParam struct {
	GP		GroupParam.Asymmetry

	SP_RABE RABE.PublicParam
	lamuda	int64
}

func (pp *PublicParam) H(m string) *pbc.Element {
	return pp.SP_RABE.H(m)
}

type MasterPublicKey struct {
	Pk_CHET  CH_ET_BC_CDK_2017.PublicKey
	Mpk_RABE RABE.MasterPublicKey
}

type MasterSecretKey struct {
	Sk_CHET  CH_ET_BC_CDK_2017.SecretKey
	Msk_RABE RABE.MasterSecretKey
}

type SecretKey struct {
	Sk_CHET  CH_ET_BC_CDK_2017.SecretKey
	Sk_RABE  RABE.SecretKey
}

type UpdateKey struct {
	Ku_RABE RABE.UpdateKey
}

type DecryptKey struct {
	Sk_CHET  CH_ET_BC_CDK_2017.SecretKey
	Dk_RABE  RABE.DecryptKey
}

type HashValue struct {
	H_CHET  CH_ET_BC_CDK_2017.HashValue
	Ct_RABE RABE.CipherText
	Ct_SE   SE.CipherText
}

type Randomness struct {
	R_CHET CH_ET_BC_CDK_2017.Randomness
}

func SetUp(curveName curve.Curve, swap_G1G2 bool, lamuda int64) (*PublicParam, *MasterPublicKey, *MasterSecretKey) {
	pp := new(PublicParam)
	mpk := new(MasterPublicKey)
	msk := new(MasterSecretKey)

	pp.lamuda = lamuda

	pp.GP.NewAsymmetry(curveName, swap_G1G2)
	pp_RABE, mpk_RABE, msk_RABE := RABE.SetUpWithGP(RABE.XNM_2021, &pp.GP)
	pp.SP_RABE = *pp_RABE
	mpk.Mpk_RABE = *mpk_RABE
	msk.Msk_RABE = *msk_RABE

	pk_CHET, sk_CHET := CH_ET_BC_CDK_2017.KeyGen(lamuda)
	mpk.Pk_CHET = *pk_CHET
	msk.Sk_CHET = *sk_CHET

	return pp, mpk, msk
}

func KeyGen(st *BinaryTree.BinaryTree, sp *PublicParam, mpk *MasterPublicKey, msk *MasterSecretKey, S *utils.AttributeList, id *pbc.Element) *SecretKey {
	sk := new(SecretKey)

	sk.Sk_CHET = msk.Sk_CHET

	sk_RABE := RABE.KeyGen(st, &sp.SP_RABE, &mpk.Mpk_RABE, &msk.Msk_RABE, S, id)
	sk.Sk_RABE = *sk_RABE
	
	return sk
}

func UpdateKeyGen(sp *PublicParam, mpk *MasterPublicKey, st *BinaryTree.BinaryTree, rl *BinaryTree.RevokeList, t int) *UpdateKey {
	ku := new(UpdateKey)

	ku_RABE := RABE.UpdateKeyGen(&sp.SP_RABE, &mpk.Mpk_RABE, st, rl, t)
	ku.Ku_RABE = *ku_RABE

	return ku
}

func DecryptKeyGen(sp *PublicParam, mpk *MasterPublicKey, sk *SecretKey, ku *UpdateKey, st *BinaryTree.BinaryTree, rl *BinaryTree.RevokeList) *DecryptKey {
	dk := new(DecryptKey)

	dk.Sk_CHET = sk.Sk_CHET

	dk_RABE := RABE.DecryptKeyGen(&sp.SP_RABE, &mpk.Mpk_RABE, &sk.Sk_RABE, &ku.Ku_RABE, st, rl)
	dk.Dk_RABE = *dk_RABE

	return dk
}

func Revoke(rl *BinaryTree.RevokeList, id *pbc.Element, t int) {
	RABE.Revoke(rl, id, t)
}

func Hash(sp *PublicParam, mpk *MasterPublicKey, MSP *utils.PBCMatrix, m *big.Int, t int) (*HashValue, *Randomness){
	H := new(HashValue)
	R := new(Randomness)

	h_CHET, r_CHET, etd_CHET := CH_ET_BC_CDK_2017.Hash(&mpk.Pk_CHET, m, sp.lamuda)
	H.H_CHET = *h_CHET
	R.R_CHET = *r_CHET

	r := make([]byte, 16)
	k := make([]byte, 16)
	rand.Read(r)
	rand.Read(k)
	enc := utils.Encode(sp.GP.Pairing, sp.GP.GT, utils.NewPlaText(k, r))

	u := utils.H_2_element_String_3(sp.GP.Pairing, sp.GP.Zr, string(r), MSP.Formula, fmt.Sprintf("%d", t))
	ct_RABE := RABE.EncryptWithElements(&sp.SP_RABE, &mpk.Mpk_RABE, MSP, RABE.NewPlainText(enc.K), t, &u.U_1, &u.U_2)
	H.Ct_RABE = *ct_RABE

	ct_SE, _ := SE.Encrypt(SE.NewPlainText(etd_CHET.Sk_ch_2.D.Bytes()), k)
	H.Ct_SE.CopyFrom(ct_SE)

	return H, R
}

func Check(H *HashValue, R *Randomness, mpk *MasterPublicKey, m *big.Int) bool {
	return CH_ET_BC_CDK_2017.Check(&H.H_CHET, &R.R_CHET, &mpk.Pk_CHET, m)
}

func Adapt(H *HashValue, R *Randomness, sp *PublicParam, mpk *MasterPublicKey, dk *DecryptKey, MSP *utils.PBCMatrix, m, m_p *big.Int) *Randomness {
	R_p := new(Randomness)

	if !Check(H, R, mpk, m) {
		panic("wrong hash")
	}
	pt_RABE := RABE.Decrypt(&sp.SP_RABE, &dk.Dk_RABE, MSP, &H.Ct_RABE)

	pla := utils.Decode(utils.NewEncText(pt_RABE.M))

	u := utils.H_2_element_String_3(sp.GP.Pairing, sp.GP.Zr, string(pla.R), MSP.Formula, fmt.Sprintf("%d", dk.Dk_RABE.T))

	ct_RABE := RABE.EncryptWithElements(&sp.SP_RABE, &mpk.Mpk_RABE, MSP, pt_RABE, dk.Dk_RABE.T, &u.U_1, &u.U_2)

	if !ct_RABE.Equals(&H.Ct_RABE) {
		panic("wrong rabe ciphertext")
	}

	se_pt, _:= SE.Decrypt(&H.Ct_SE, pla.K)
	etd := new(CH_ET_BC_CDK_2017.ETrapdoor)
	etd.Sk_ch_2.D = new(big.Int).SetBytes(se_pt.Pt)

	r_CHET := CH_ET_BC_CDK_2017.Adapt(&H.H_CHET, &R.R_CHET, etd, &mpk.Pk_CHET, &dk.Sk_CHET, m, m_p)
	R_p.R_CHET = *r_CHET

	return R_p
}