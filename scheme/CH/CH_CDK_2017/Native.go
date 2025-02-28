package CH_CDK_2017

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

func H_n(n, m1, m2 *big.Int) *big.Int {
	return new(big.Int).Mod(utils.H_native_2_1(m1, m2), n)
}

func getHashValue(r *Randomness, pk *PublicKey, tau, m *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Mul(H_n(pk.N, tau, m), new(big.Int).Exp(r.R, pk.E, pk.N)), pk.N)
}

func KeyGen(lamuda int64) (*PublicKey, *SecretKey) {
	pk := new(PublicKey)
	sk := new(SecretKey)

	pk_RSA, sk_RSA := RSA.KeyGen_2(lamuda, lamuda)
	pk.E = pk_RSA.E
	pk.N = pk_RSA.N
	sk.D = sk_RSA.D
	sk.P = sk_RSA.P
	sk.Q = sk_RSA.Q

	return pk, sk
}

func Hash(pk *PublicKey, tau, m *big.Int) (*HashValue, *Randomness) {
	h := new(HashValue)
	r := new(Randomness)

	r.R = utils.GetZq(pk.N)
	h.H = getHashValue(r, pk, tau, m)

	return h, r
}

func Check(h *HashValue, r *Randomness, pk *PublicKey, tau, m *big.Int) bool {
	return h.H.Cmp(getHashValue(r, pk, tau, m)) == 0
}

func Adapt(r *Randomness, pk * PublicKey, sk *SecretKey, tau, m, tau_p, m_p *big.Int) *Randomness {
	r_p := new(Randomness)

	r_p.R = new(big.Int).Exp(new(big.Int).Mul(getHashValue(r, pk, tau, m), new(big.Int).ModInverse(H_n(pk.N, tau_p, m_p), pk.N)), sk.D, pk.N)

	return r_p
}