package CH_KEF_NoMH_AM_2004

import (
	"math/big"

	"github.com/Hugu1e/ChameLibGo/utils"
)

type PublicKey struct {
	P, Q, G, Y big.Int
}

type SecretKey struct {
	X big.Int
}

type HashValue struct {
	H big.Int
}

type Randomness struct {
	R, S big.Int
}

func H(m1, m2 *big.Int) *big.Int {
	return utils.H_native_2_1(m1, m2)
}

func getHashValue(R *Randomness, pk *PublicKey, m *big.Int) *big.Int {
	tmp1 := new(big.Int).Exp(&pk.Y, H(m, &R.R), &pk.P)
	tmp2 := new(big.Int).Exp(&pk.G, &R.S, &pk.P)
	tmp3 := new(big.Int).Mod(new(big.Int).Mul(tmp1, tmp2) , &pk.P)
	
	return new(big.Int).Mod(new(big.Int).Sub(&R.R, tmp3), &pk.Q)
}

func KeyGen(k int64) (*PublicKey, *SecretKey) {
	pk := new(PublicKey)
	sk := new(SecretKey)

	for {
		pk.Q = *utils.GenerateBigPrime(k)
		pk.P = *new(big.Int).Add(new(big.Int).Mul(&pk.Q, big.NewInt(2)) , big.NewInt(1))
		if pk.P.ProbablyPrime(100) {
			break
		}
	}

	for {
		g := utils.GetZq(&pk.P)
		if new(big.Int).Exp(g, &pk.Q, &pk.P).Cmp(big.NewInt(1)) == 0 {
			pk.G = *g
			break
		}
	}

	sk.X = *utils.GetZq(&pk.Q)
	pk.Y = *new(big.Int).Exp(&pk.G, &sk.X, &pk.P)

	return pk, sk
}

func Hash(pk *PublicKey, m *big.Int) (*HashValue, *Randomness) {
	R := new(Randomness)
	H := new(HashValue)

	R.R = *utils.GetZq(&pk.Q)
	R.S = *utils.GetZq(&pk.Q)
	H.H = *getHashValue(R, pk, m)

	return H, R
}

func Check(H *HashValue, R *Randomness, pk *PublicKey, m *big.Int) bool {
	return H.H.Cmp(getHashValue(R, pk, m)) == 0
}

func Adapt(pk *PublicKey, sk *SecretKey, m_p *big.Int, h *HashValue) *Randomness {
	R_p := new(Randomness)

	k_p := utils.GetZq(&pk.Q)

	R_p.R = *new(big.Int).Add(&h.H, new(big.Int).Exp(&pk.G, k_p, &pk.P))
	R_p.R.Mod(&R_p.R, &pk.Q)

	R_p.S = *new(big.Int).Sub(k_p, new(big.Int).Mul(H(m_p, &R_p.R), &sk.X))
	R_p.S.Mod(&R_p.S, &pk.Q)

	return R_p
}