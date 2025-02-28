package PCH_DSS_2019

import (
	"crypto/rand"
	"math/big"

	"github.com/Hugu1e/ChameLibGo/ABE/FAME"
	"github.com/Hugu1e/ChameLibGo/SE"
	"github.com/Hugu1e/ChameLibGo/base/GroupParam"
	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/scheme/CH/CH_ET_BC_CDK_2017"
	"github.com/Hugu1e/ChameLibGo/utils"
)

type PublicParam struct {
	GP     GroupParam.Asymmetry
	Pp_ABE FAME.PublicParam

	lamuda int64
}

type MasterPublicKey struct {
	Pk_CHET CH_ET_BC_CDK_2017.PublicKey
	Mpk_ABE FAME.MasterPublicKey
}

type MasterSecretKey struct {
	Sk_CHET CH_ET_BC_CDK_2017.SecretKey
	Msk_ABE FAME.MasterSecretKey
}

type SecretKey struct {
	Sk_CHET CH_ET_BC_CDK_2017.SecretKey
	Sk_ABE  FAME.SecretKey
}

type HashValue struct {
	H_CHET CH_ET_BC_CDK_2017.HashValue
	Ct_ABE FAME.CipherText
	Ct_SE  SE.CipherText
}

type Randomness struct {
	R_CHET CH_ET_BC_CDK_2017.Randomness
}

func SetUp(curveName curve.Curve, swap_G1G2 bool, lamuda int64) (*PublicParam, *MasterPublicKey, *MasterSecretKey) {
	pkPCH := new(MasterPublicKey)
	skPCH := new(MasterSecretKey)
	ppPCH := new(PublicParam)

	ppPCH.lamuda = lamuda

	ppPCH.GP.NewAsymmetry(curveName, swap_G1G2)
	pp_ABE, mpk_ABE, msk_ABE := FAME.SetUpWithGP(&ppPCH.GP)
	ppPCH.Pp_ABE.GP = pp_ABE.GP
	pkPCH.Mpk_ABE = *mpk_ABE
	skPCH.Msk_ABE = *msk_ABE
	
	pk_CHET, sk_CHET := CH_ET_BC_CDK_2017.KeyGen(lamuda)
	pkPCH.Pk_CHET = *pk_CHET
	skPCH.Sk_CHET = *sk_CHET

	return ppPCH, pkPCH, skPCH
}

func KeyGen(ppPCH *PublicParam, pkPCH *MasterPublicKey, skPCH *MasterSecretKey, S *utils.AttributeList) *SecretKey {
	sk := new(SecretKey)

	sk.Sk_CHET = skPCH.Sk_CHET
	sk_ABE := FAME.KeyGen(&ppPCH.Pp_ABE, &pkPCH.Mpk_ABE, &skPCH.Msk_ABE, S)
	sk.Sk_ABE = *sk_ABE

	return sk
}

func Hash(ppPCH *PublicParam, pkPCH *MasterPublicKey, MSP *utils.PBCMatrix, m *big.Int) (*HashValue, *Randomness){
	H := new(HashValue)
	R := new(Randomness)

	h_CHET, r_CHET, etd_CHET := CH_ET_BC_CDK_2017.Hash(&pkPCH.Pk_CHET, m, ppPCH.lamuda)
	H.H_CHET = *h_CHET
	R.R_CHET = *r_CHET

	r := make([]byte, 16)
	k := make([]byte, 16)
	rand.Read(r)
	rand.Read(k)

	u := utils.H_2_element_String_2(ppPCH.GP.Pairing, ppPCH.GP.Zr, string(r), MSP.Formula)

	pla := utils.NewPlaText(k, r)
	enc := utils.Encode(ppPCH.GP.Pairing, ppPCH.GP.GT, pla)

	ct_ABE := FAME.EncryptWithElements(&ppPCH.Pp_ABE, &pkPCH.Mpk_ABE, MSP, FAME.NewPlainText(enc.K), &u.U_1, &u.U_2)
	H.Ct_ABE = *ct_ABE

	ct_SE, err := SE.Encrypt(SE.NewPlainText(etd_CHET.Sk_ch_2.D.Bytes()), k)
	if err != nil {
		panic(err)
	}
	H.Ct_SE.CopyFrom(ct_SE)

	return H, R
}

func Check(H *HashValue, R *Randomness, pkPCH *MasterPublicKey, m *big.Int) bool {
	return CH_ET_BC_CDK_2017.Check(&H.H_CHET, &R.R_CHET, &pkPCH.Pk_CHET, m)
}

func  Adapt(H *HashValue, R *Randomness, ppPCH *PublicParam, pkPCH *MasterPublicKey, MSP *utils.PBCMatrix, sk *SecretKey, m, mp *big.Int) *Randomness {
	Rp := new(Randomness)

	ptABE := FAME.Decrypt(&ppPCH.Pp_ABE, MSP, &H.Ct_ABE, &sk.Sk_ABE)

	pla := utils.Decode(utils.NewEncText(ptABE.M))

	u := utils.H_2_element_String_2(ppPCH.GP.Pairing, ppPCH.GP.Zr, string(pla.R), MSP.Formula)

	ctP := FAME.EncryptWithElements(&ppPCH.Pp_ABE, &pkPCH.Mpk_ABE, MSP, ptABE, &u.U_1, &u.U_2)

	if !ctP.Equals(&H.Ct_ABE) {
		panic("wrong abe ciphertext")
	}

	// etd := CH_ET_BC_CDK_2017.NewETrapdoor()
	// sePT := se.NewAESPlainText()
	sePT, err := SE.Decrypt(&H.Ct_SE, pla.K)
	if err != nil {
		panic(err)
	}
	etd := new(CH_ET_BC_CDK_2017.ETrapdoor)
	etd.Sk_ch_2.D = new(big.Int).SetBytes(sePT.Pt)

	r_CHET := CH_ET_BC_CDK_2017.Adapt(&H.H_CHET, &R.R_CHET, etd, &pkPCH.Pk_CHET, &sk.Sk_CHET, m, mp)
	Rp.R_CHET = *r_CHET

	return Rp
}