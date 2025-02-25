package DPCH_MXN_2022

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/Hugu1e/ChameLibGo/ABE/MA_ABE"
	"github.com/Hugu1e/ChameLibGo/SE"
	"github.com/Hugu1e/ChameLibGo/Signature/BLS"
	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/scheme/CH/CH_ET_BC_CDK_2017"
	"github.com/Hugu1e/ChameLibGo/utils"
	"github.com/Nik-U/pbc"
)

type PublicParam struct {
	GP_MA_ABE MA_ABE.PublicParam
	pp_DS     BLS.PublicParam
	lamuda   int64
}

type MasterPublicKey struct {
	pk_CH CH_ET_BC_CDK_2017.PublicKey
	pk_DS BLS.PublicKey
}

type MasterSecretKey struct {
	sk_CH CH_ET_BC_CDK_2017.SecretKey
	sk_DS BLS.SecretKey
}

type Authority struct {
	MA_ABE_Auth MA_ABE.Authority
}

func NewAuthority(theta string) *Authority {
	return &Authority{
		MA_ABE_Auth: *MA_ABE.NewAuthority(theta),
	}
}

type Modifier struct {
	gid     string
	sk_gid  CH_ET_BC_CDK_2017.SecretKey
	sigma_gid BLS.Signature
	sk_gid_A MA_ABE.SecretKey
}

func NewModifier(gid string) *Modifier {
	return &Modifier{gid: gid}
}

type PublicKeyGroup struct {
	MA_ABE_PKG MA_ABE.PublicKeyGroup
}

func (pkg *PublicKeyGroup) AddPK(auth *Authority) {
	pkg.MA_ABE_PKG.AddPK(&auth.MA_ABE_Auth)
}

type SecretKeyGroup struct {
	MA_ABE_SKG MA_ABE.SecretKeyGroup
}

func (skg *SecretKeyGroup) AddSK(mod *Modifier) {
	skg.MA_ABE_SKG.AddSK(&mod.sk_gid_A)
}

type HashValue struct {
	H     CH_ET_BC_CDK_2017.HashValue
	C_SE  SE.CipherText
	C_MA_ABE MA_ABE.CipherText
}

type Randomness struct {
	R CH_ET_BC_CDK_2017.Randomness
}

type EncText struct {
	K pbc.Element
}

type PlaText struct {
	k []byte
	r []byte
}

func Encode(pairing *pbc.Pairing, P *PlaText) *EncText {
	K := new(EncText)

	tmp := make([]byte, pairing.GTLength())
	tmp[1] = byte(len(P.k))
	copy(tmp[2:], P.k)
	tmp[pairing.GTLength()/2+1] = byte(len(P.r))
	copy(tmp[pairing.GTLength()/2+2:], P.r)
	K.K = *pairing.NewGT().SetBytes(tmp)
	return K
}

func Decode(K *EncText) *PlaText {
	P := new(PlaText)

	tmp := K.K.Bytes()
	l1 := int(tmp[1])
	if l1 >= len(tmp) {
		panic("Decode Failed")
	}
	P.k = make([]byte, l1)
	copy(P.k, tmp[2:2+l1])
	l2 := int(tmp[K.K.BytesLen()/2+1])
	if l2+K.K.BytesLen()/2 >= len(tmp) {
		panic("Decode Failed")
	}
	P.r = make([]byte, l2)
	copy(P.r, tmp[K.K.BytesLen()/2+2:K.K.BytesLen()/2+2+l2])

	return P
}


func genEncMAABE(c_MA_ABE *MA_ABE.CipherText, pt_MA_ABE *MA_ABE.PlainText, PKG *PublicKeyGroup, MSP *utils.PBCMatrix, pp *PublicParam, r_t []byte) {
	l1 := len(MSP.M)
	l2 := len(MSP.M[0])

	t_x := utils.NewPBCVector(l1)
	for i := 1; i <= l1; i++ {
		t_x.V[i-1] = *pp.GP_MA_ABE.Ht(fmt.Sprintf("%s%s0%d", string(r_t), MSP.Formula, i))
	}

	v := utils.NewPBCVector(l2)
	v.V[0] = *pp.GP_MA_ABE.Ht(fmt.Sprintf("%s%s", string(r_t), MSP.Formula))
	for i := 2; i <= l2; i++ {
		v.V[i-1] = *pp.GP_MA_ABE.Ht(fmt.Sprintf("%s%s1%d", string(r_t), MSP.Formula, i))
	}

	w := utils.NewPBCVector(l2)
	w.V[0] = *pp.GP_MA_ABE.GetZrElement().Set0()
	for i := 2; i <= l2; i++ {
		w.V[i-1] = *pp.GP_MA_ABE.Ht(fmt.Sprintf("%s%s2%d", string(r_t), MSP.Formula, i))
	}

	ct := MA_ABE.Encrypt_2(&pp.GP_MA_ABE, &PKG.MA_ABE_PKG, MSP, pt_MA_ABE, v, w, t_x)
	c_MA_ABE.CopyFrom(ct)
}

func SetUp(curveName curve.Curve, lamuda int64) (*PublicParam, *MasterPublicKey, *MasterSecretKey) {
	pp := new(PublicParam)
	pk := new(MasterPublicKey)
	sk := new(MasterSecretKey)

	pp.lamuda = lamuda

	pp.GP_MA_ABE = *MA_ABE.GlobalSetup(curveName)

	pp.pp_DS = *BLS.SetUp(curveName, false)

	pk_CH, sk_CH := CH_ET_BC_CDK_2017.KeyGen(lamuda)
	pk.pk_CH, sk.sk_CH= *pk_CH, *sk_CH

	pk2, sk2 := BLS.KeyGen(&pp.pp_DS)
	pk.pk_DS, sk.sk_DS = *pk2, *sk2

	return pp, pk, sk
}

func ModSetup(mod *Modifier, pp *PublicParam, sk *MasterSecretKey) {
	mod.sigma_gid = *BLS.Sign(&sk.sk_DS, &pp.pp_DS, "1"+mod.gid)
	mod.sk_gid = sk.sk_CH
}

func AuthSetup(auth *Authority, pp *PublicParam) {
	MA_ABE.AuthSetup(&auth.MA_ABE_Auth, &pp.GP_MA_ABE)
}

func ModKeyGen(mod *Modifier, pp *PublicParam, pk *MasterPublicKey, auth *Authority, A string) {
	if !BLS.Verify(&pp.pp_DS, &pk.pk_DS, &mod.sigma_gid, "1"+mod.gid) {
		panic("illegal signature")
	}
	mod.sk_gid_A = *MA_ABE.KeyGen(&auth.MA_ABE_Auth, A, &pp.GP_MA_ABE, "0"+mod.gid)
}

func Hash(PKG *PublicKeyGroup, MSP *utils.PBCMatrix, pp *PublicParam, pk *MasterPublicKey, m *big.Int) (*HashValue, *Randomness){
	H := new(HashValue)
	R := new(Randomness)

	h, r, etd := CH_ET_BC_CDK_2017.Hash(&pk.pk_CH, m, pp.lamuda)
	H.H, R.R = *h, *r

	r_t := make([]byte, 16)
	rand.Read(r_t)
	k := make([]byte, 16)
	rand.Read(k)
	pt_SE := SE.PlainText{Pt: etd.Sk_ch_2.D.Bytes()}
	ct, _ := SE.Encrypt(&pt_SE, k)
	H.C_SE.Ct = make([]byte, len(ct.Ct))
	copy(H.C_SE.Ct, ct.Ct)

	pla := PlaText{k: k, r: r_t}
	enc := Encode(pp.GP_MA_ABE.Pairing, &pla)
	pt_MA_ABE := MA_ABE.PlainText{M: enc.K}
	genEncMAABE(&H.C_MA_ABE, &pt_MA_ABE, PKG, MSP, pp, r_t)

	return H, R
}

func Check(H *HashValue, R *Randomness, pk *MasterPublicKey, m *big.Int) bool {
	return CH_ET_BC_CDK_2017.Check(&H.H, &R.R, &pk.pk_CH, m)
}

func Adapt(H *HashValue, R *Randomness, PKG *PublicKeyGroup, SKG *SecretKeyGroup, MSP *utils.PBCMatrix, pp *PublicParam, pk *MasterPublicKey, sk *MasterSecretKey, m, m_p *big.Int) *Randomness{
	R_p := new(Randomness)
	
	if m.Cmp(m_p) == 0 {
		R_p.R = R.R
		return R_p
	}

	ct_MA_ABE := MA_ABE.CipherText{}

	pt_MA_ABE := MA_ABE.Decrypt(&pp.GP_MA_ABE, &SKG.MA_ABE_SKG, MSP, &H.C_MA_ABE)

	enc := EncText{K: pt_MA_ABE.M}
	pla := Decode(&enc)
	genEncMAABE(&ct_MA_ABE, pt_MA_ABE, PKG, MSP, pp, pla.r)
	if !ct_MA_ABE.IsEqual(&H.C_MA_ABE) {
		panic("illegal decrypt")
	}

	etd := CH_ET_BC_CDK_2017.ETrapdoor{}

	pt_SE, _ := SE.Decrypt(&H.C_SE, pla.k)
	etd.Sk_ch_2.D = *new(big.Int).SetBytes(pt_SE.Pt)

	R_p.R = *CH_ET_BC_CDK_2017.Adapt(&H.H, &R.R, &etd, &pk.pk_CH, &sk.sk_CH, m, m_p)

	return R_p
}