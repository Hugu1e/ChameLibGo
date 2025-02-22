package CH_KEF_MH_RSA_F_AM_2004

import (
	"math/big"

	"github.com/Hugu1e/ChameLibGo/AE/RSA"
	"github.com/Hugu1e/ChameLibGo/utils"
)

type PublicParam struct {
	Tau, K int64
}

type PublicKey struct {
	N, E big.Int
}
func (pk *PublicKey) CopyFrom(rsa_Pk *RSA.PublicKey){
	pk.N = rsa_Pk.N
	pk.E = rsa_Pk.E
}

type SecretKey struct {
	P, Q, D big.Int
}
func (sk *SecretKey) CopyFrom(rsa_Sk *RSA.SecretKey){
	sk.P = rsa_Sk.P
	sk.Q = rsa_Sk.Q
	sk.D = rsa_Sk.D
}

type HashValue struct {
	H big.Int
}

type Randomness struct {
	R big.Int
}

func H(m *big.Int) *big.Int {
	return utils.H_native_1_1(m)
}

func C(m *big.Int, bitLen int64) *big.Int {
	return new(big.Int).Mod(H(m), utils.GenerateBigRange(bitLen))
}

func getHashValue(r *Randomness, pk *PublicKey, m, L *big.Int, pp *PublicParam) *big.Int {
	c := C(L, 2*pp.K - 1)
	h := C(m, pp.Tau)
	return new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(c, h, &pk.N), new(big.Int).Exp(&r.R, &pk.E, &pk.N)), &pk.N)
}

func SetUp(tau, k int64) (*PublicParam) {
	pp := new(PublicParam)
	pp.K = k
	pp.Tau = tau
	return pp
}

func KeyGen(pp *PublicParam) (*PublicKey, *SecretKey) {
	pk := new(PublicKey)
	sk := new(SecretKey)


	RSA_pk, RSA_sk := RSA.KeyGen_2(pp.Tau, pp.K)
	pk.CopyFrom(RSA_pk)
	sk.CopyFrom(RSA_sk)

	return pk, sk
}

func Hash(pk *PublicKey, L, m *big.Int, pp *PublicParam) (*HashValue, *Randomness) {
	h := new(HashValue)
	r := new(Randomness)

	r.R = *utils.GetZq(&pk.N)
	h.H = *getHashValue(r, pk, m, L, pp)

	return h, r
}

func Check(h *HashValue, r *Randomness, pk *PublicKey, L, m *big.Int, pp *PublicParam) bool {
	return h.H.Cmp(getHashValue(r, pk, m, L, pp)) == 0
}

func Adapt(r *Randomness, pk *PublicKey, sk *SecretKey, L, m, mp *big.Int, pp *PublicParam) *Randomness {
	rp := new(Randomness)

	c := C(L, 2*pp.K - 1)
	hm := C(m, pp.Tau)
	hmp := C(mp, pp.Tau)
	rp.R = *new(big.Int).Mod(new(big.Int).Mul(&r.R,  new(big.Int).Exp(new(big.Int).Exp(c, &sk.D, &pk.N), new(big.Int).Sub(hm, hmp), &pk.N)) , &pk.N)

	return rp
}
