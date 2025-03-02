package MCH_CDK_2017

import (
	"math/big"

	"github.com/Hugu1e/ChameLibGo/AE/RSA"
	"github.com/Hugu1e/ChameLibGo/utils"
)

type PublicKey struct {
	N, E *big.Int
}

type SecretKey struct {
	P, Q, D *big.Int
}

type HashValue struct {
	H *big.Int
}

type Randomness struct {
	R *big.Int
}

func H_n(n, m *big.Int) *big.Int {
	return new(big.Int).Mod(utils.H_native_1_1(m), n)
}

func getHashValue(r *Randomness, pk *PublicKey, m *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Mul(H_n(pk.N, m), new(big.Int).Exp(r.R, pk.E, pk.N)), pk.N)
}

func KeyGen(lamuda int64) (*PublicKey, *SecretKey){
	pk := new(PublicKey)
	sk := new(SecretKey)

	pk_RSA, sk_RSA := RSA.KeyGen_2(2*lamuda+1, lamuda)
	pk.N = pk_RSA.N
	pk.E = pk_RSA.E
	sk.P = sk_RSA.P
	sk.Q = sk_RSA.Q
	sk.D = sk_RSA.D

	return pk, sk
}

func Hash(pk *PublicKey, m *big.Int) (*HashValue, *Randomness){
	h := new(HashValue)
	r := new(Randomness)

	r.R = utils.GetZq(pk.N)
	h.H = getHashValue(r, pk, m)

	return h, r
}

func Check(h *HashValue, r *Randomness, pk *PublicKey, m *big.Int) bool {
	return h.H.Cmp(getHashValue(r, pk, m)) == 0
}

func Adapt(r *Randomness, pk *PublicKey, sk *SecretKey, m, m_p *big.Int) *Randomness {
	r_p := new(Randomness)
	r_p.R = new(big.Int).Exp(new(big.Int).Mul(getHashValue(r, pk, m), new(big.Int).ModInverse(H_n(pk.N, m_p), pk.N)), sk.D, pk.N)
	return r_p
}