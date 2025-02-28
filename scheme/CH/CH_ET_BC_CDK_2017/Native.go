package CH_ET_BC_CDK_2017

import (
	"math/big"

	"github.com/Hugu1e/ChameLibGo/scheme/CH/MCH_CDK_2017"
)

type PublicKey struct {
	Pk_ch_1 MCH_CDK_2017.PublicKey
}

type SecretKey struct {
	Sk_Ch_1 MCH_CDK_2017.SecretKey
}

type HashValue struct {
	H_1, H_2 MCH_CDK_2017.HashValue
	Pk_ch_2 MCH_CDK_2017.PublicKey
}

type Randomness struct {
	R_1, R_2 MCH_CDK_2017.Randomness
}

type ETrapdoor struct {
	Sk_ch_2 MCH_CDK_2017.SecretKey
}

func KeyGen(lamuda int64) (*PublicKey, *SecretKey){
	pk := new(PublicKey)
	sk := new(SecretKey)
	
	pk_ch_1, sk_Ch_1 := MCH_CDK_2017.KeyGen(lamuda)
	pk.Pk_ch_1 = *pk_ch_1
	sk.Sk_Ch_1 = *sk_Ch_1

	return pk, sk
}

func Hash(pk *PublicKey, m *big.Int, lamuda int64) (*HashValue, *Randomness, *ETrapdoor) {
	h := new(HashValue)
	r := new(Randomness)
	etd := new(ETrapdoor)

	pk_ch_2, sk_ch_2 := MCH_CDK_2017.KeyGen(lamuda)
	h.Pk_ch_2 = *pk_ch_2
	etd.Sk_ch_2 = *sk_ch_2

	h_1, r_1 := MCH_CDK_2017.Hash(&pk.Pk_ch_1, m)
	h.H_1 = *h_1
	r.R_1 = *r_1

	h_2, r_2 := MCH_CDK_2017.Hash(pk_ch_2, m)
	h.H_2 = *h_2
	r.R_2 = *r_2

	return h, r, etd
}

func Check(h *HashValue, r *Randomness, pk *PublicKey, m *big.Int) bool {
	return MCH_CDK_2017.Check(&h.H_1, &r.R_1, &pk.Pk_ch_1, m) && MCH_CDK_2017.Check(&h.H_2, &r.R_2, &h.Pk_ch_2, m)
}

func Adapt(h *HashValue, r *Randomness, etd *ETrapdoor, pk *PublicKey, sk *SecretKey, m, m_p *big.Int) *Randomness {
	if !Check(h, r, pk, m) {
		panic("illegal hash")
	}
	r_p := new(Randomness)
	r_1 := MCH_CDK_2017.Adapt(&r.R_1, &pk.Pk_ch_1, &sk.Sk_Ch_1, m, m_p)
	r_2 := MCH_CDK_2017.Adapt(&r.R_2, &h.Pk_ch_2, &etd.Sk_ch_2, m, m_p)
	r_p.R_1 = *r_1
	r_p.R_2 = *r_2
	return r_p
}