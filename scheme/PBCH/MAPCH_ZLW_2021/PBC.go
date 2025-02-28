package MAPCH_ZLW_2021

import (
	"math/big"

	"github.com/Hugu1e/ChameLibGo/ABE/MA_ABE"
	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/scheme/CH/CH_ET_BC_CDK_2017"
	"github.com/Hugu1e/ChameLibGo/utils"
	"github.com/Nik-U/pbc"
)

type PublicParam struct {
	GP		MA_ABE.PublicParam
	hk		CH_ET_BC_CDK_2017.PublicKey
	tk		CH_ET_BC_CDK_2017.SecretKey
	lamuda	int64
}

type Authority struct {
	mtk			MasterSecretKey
	mhk			PublicKey
	MA_ABE_Auth MA_ABE.Authority
}

func NewAuthority(theta string, SP *PublicParam) *Authority {
	return &Authority{
		mtk: MasterSecretKey{tk: SP.tk},
		mhk: PublicKey{GP: SP.GP, hk: SP.hk},
		MA_ABE_Auth: *MA_ABE.NewAuthority(theta),
	}
}

type PublicKey struct {
	GP MA_ABE.PublicParam
	hk CH_ET_BC_CDK_2017.PublicKey
}

type MasterSecretKey struct {
	tk CH_ET_BC_CDK_2017.SecretKey
}

type SecretKey struct {
	MA_ABE_SK MA_ABE.SecretKey
	tk        CH_ET_BC_CDK_2017.SecretKey
}

type PublicKeyGroup struct {
	MA_ABE_PKG MA_ABE.PublicKeyGroup
	hk         CH_ET_BC_CDK_2017.PublicKey
	GP         MA_ABE.PublicParam
}

func (pkg *PublicKeyGroup) AddPK(auth *Authority) {
	pkg.hk = auth.mhk.hk
	pkg.GP = auth.mhk.GP
	pkg.MA_ABE_PKG.AddPK(&auth.MA_ABE_Auth)
}

type SecretKeyGroup struct {
	MA_ABE_SKG MA_ABE.SecretKeyGroup
	tk         CH_ET_BC_CDK_2017.SecretKey
}

func (skg *SecretKeyGroup) AddSK(sk *SecretKey) {
	skg.MA_ABE_SKG.AddSK(&sk.MA_ABE_SK)
	skg.tk = sk.tk
}

type HashValue struct {
	CHET_H CH_ET_BC_CDK_2017.HashValue
	MA_ABE_C MA_ABE.CipherText
}

type Randomness struct {
	CHET_R CH_ET_BC_CDK_2017.Randomness
}

func SetUp(curveName curve.Curve, lamuda int64) *PublicParam{
	SP := new(PublicParam)

	SP.GP = *MA_ABE.GlobalSetup(curveName)

	SP.lamuda = lamuda
	pk, sk := CH_ET_BC_CDK_2017.KeyGen(lamuda)
	SP.hk = *pk
	SP.tk = *sk

	return SP
}

func AuthSetup(auth *Authority) {
	MA_ABE.AuthSetup(&auth.MA_ABE_Auth, &auth.mhk.GP)
}

func KeyGen(auth *Authority, GID, i string) *SecretKey {
	msk_i := new(SecretKey)

	msk_i.MA_ABE_SK = *MA_ABE.KeyGen(&auth.MA_ABE_Auth, i, &auth.mhk.GP, GID)

	msk_i.tk = auth.mtk.tk

	return msk_i
}

func BigInteger2GT(pairing *pbc.Pairing, m *big.Int) *pbc.Element {
	tmp := make([]byte, len(m.Bytes())+2)
	tmp[1] = byte(len(m.Bytes()))
	copy(tmp[2:], m.Bytes())
	return pairing.NewGT().SetBytes(tmp)
}

func GT2BigInteger(t *pbc.Element) *big.Int {
	tmp := t.Bytes()
	l := int(tmp[1])
	if l <= 0 || l+2 >= len(tmp) {
		panic("decode error")
	}
	return new(big.Int).SetBytes(tmp[2 : 2+l])
}

func Hash(MHKS *PublicKeyGroup, MSP *utils.PBCMatrix, m *big.Int, SP *PublicParam) (*HashValue, *Randomness){
	H := new(HashValue)
	R := new(Randomness)

	h, r, e := CH_ET_BC_CDK_2017.Hash(&MHKS.hk, m, SP.lamuda)
	H.CHET_H = *h
	R.CHET_R = *r

	MA_ABE_PT := MA_ABE.SetPlainText(BigInteger2GT(SP.GP.Pairing, e.Sk_ch_2.D))
	H.MA_ABE_C = *MA_ABE.Encrypt(&MHKS.GP, &MHKS.MA_ABE_PKG, MSP, MA_ABE_PT)

	return H, R
}

func Check(H *HashValue, R *Randomness, MHKS *PublicKeyGroup, m *big.Int) bool {
	return CH_ET_BC_CDK_2017.Check(&H.CHET_H, &R.CHET_R, &MHKS.hk, m)
}

func Adapt(H *HashValue, R *Randomness, MHKS *PublicKeyGroup, MSKS *SecretKeyGroup, MSP *utils.PBCMatrix, m, m_p *big.Int) *Randomness{
	R_p := new(Randomness)

	if !Check(H, R, MHKS, m) {
		panic("Wrong Hash Value")
	}
	MA_ABE_PT := MA_ABE.Decrypt(&MHKS.GP, &MSKS.MA_ABE_SKG, MSP, &H.MA_ABE_C)

	etd := new(CH_ET_BC_CDK_2017.ETrapdoor)
	etd.Sk_ch_2.D = GT2BigInteger(MA_ABE_PT.M)
	R_p.CHET_R = *CH_ET_BC_CDK_2017.Adapt(&H.CHET_H, &R.CHET_R, etd, &MHKS.hk, &MSKS.tk, m, m_p)

	return R_p
}