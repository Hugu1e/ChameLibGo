package CHET_RSA_CDK_2017

import (
	"math/big"

	"github.com/Hugu1e/ChameLibGo/AE/RSA"
	"github.com/Hugu1e/ChameLibGo/utils"
)

type PublicParam struct {
	Lambda int64
}

type PublicKey struct {
	N, E *big.Int
}

type SecretKey struct {
	P, Q *big.Int
}

type HashValue struct {
	H, N_p *big.Int
}

type Randomness struct {
	R *big.Int
}

type ETrapdoor struct {
	P_p, Q_p *big.Int
}

func H_n_n_p(n_n_p, m *big.Int) *big.Int {
	return new(big.Int).Mod(utils.H_native_1_1(m), n_n_p)
}

func SetUp(lamuda int64) *PublicParam {
	pp := new(PublicParam)
	pp.Lambda = lamuda
	return pp
}

func KeyGen(pp *PublicParam) (*PublicKey, *SecretKey) {
	pk := new(PublicKey)
	sk := new(SecretKey)


	pkRSA, skRSA := RSA.KeyGen_2(6*pp.Lambda + 1, pp.Lambda)
	pk.E = pkRSA.E
	pk.N = pkRSA.N
	sk.P = skRSA.P
	sk.Q = skRSA.Q
	sk.P = skRSA.P

	return pk, sk
}

func Hash(pk *PublicKey, m *big.Int, pp *PublicParam) (*HashValue, *Randomness, *ETrapdoor) {
	H := new(HashValue)
	R := new(Randomness)
	etd := new(ETrapdoor)

	pkRSA, skRSA := RSA.KeyGen_3(pk.N, pk.E, pp.Lambda)
	H.N_p = pkRSA.N
	etd.P_p = skRSA.P
	etd.Q_p = skRSA.Q
	n_n_p := new(big.Int).Mul(pk.N, H.N_p)
	R.R = utils.GetZq(n_n_p)
	H.H = new(big.Int).Mod(new(big.Int).Mul(H_n_n_p(n_n_p, m), new(big.Int).Exp(R.R, pk.E, n_n_p)), n_n_p)

	return H, R, etd
}

func Check(H *HashValue, R *Randomness, pk *PublicKey, m *big.Int) bool {
	n_n_p := new(big.Int).Mul(pk.N, H.N_p)
	if R.R.Cmp(big.NewInt(1)) < 0 || R.R.Cmp(n_n_p) >= 0 {
		panic("illegal R")
	}
	expected := new(big.Int).Mod(new(big.Int).Mul(H_n_n_p(n_n_p, m), new(big.Int).Exp(R.R, pk.E, n_n_p)), n_n_p)
	return H.H.Cmp(expected) == 0
}

func Adapt(h *HashValue, R *Randomness, etd *ETrapdoor, pk *PublicKey, sk *SecretKey, m, mp *big.Int) *Randomness {
	Rp := new(Randomness)

	if h.N_p.Cmp(new(big.Int).Mul(etd.P_p, etd.Q_p)) != 0 {
		panic("illegal etd")
	}
	if !Check(h, R, pk, m) {
		panic("illegal hash")
	}
	n_n_p := new(big.Int).Mul(pk.N, h.N_p)
	d := new(big.Int).ModInverse(pk.E, new(big.Int).Mul(phi(etd.P_p, etd.Q_p), phi(sk.P, sk.Q)))
	Rp.R = new(big.Int).Exp(new(big.Int).Mul(h.H, new(big.Int).ModInverse(H_n_n_p(n_n_p, mp), n_n_p)), d, n_n_p)
	
	return Rp
}

func phi(p,q *big.Int) *big.Int {
	return new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
}