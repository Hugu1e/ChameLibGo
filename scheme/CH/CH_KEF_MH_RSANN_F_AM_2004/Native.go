package CH_KEF_MH_RSANN_F_AM_2004

import (
	"math/big"

	"github.com/Hugu1e/ChameLibGo/utils"
)
	
type PublicKey struct {
	N big.Int
}

type SecretKey struct {
	P, Q big.Int
}

type HashValue struct {
	H big.Int
}

type Randomness struct {
	R_1, R_2 big.Int
}

func H(m *big.Int) *big.Int {
	return utils.H_native_1_1(m)
}

func getHashValue(r *Randomness, pk *PublicKey, L, m *big.Int) *big.Int {
	mod_n2 := new(big.Int).Exp(&pk.N, big.NewInt(2), nil)
	
	tmp1 := new(big.Int).Add(new(big.Int).Mul(m, &pk.N), big.NewInt(1))
	tmp2 := new(big.Int).Mul(new(big.Int).Exp(H(L), &r.R_1, mod_n2) , new(big.Int).Exp(&r.R_2, &pk.N , mod_n2 ))

	return new(big.Int).Mod(new(big.Int).Mul(tmp1, tmp2), mod_n2)
}

func L(x, n *big.Int) *big.Int {
	return new(big.Int).Div(new(big.Int).Sub(x, big.NewInt(1)), n)
}


func KeyGen(bitLen int64) (*PublicKey, *SecretKey) {
	pk := new(PublicKey)
	sk := new(SecretKey)

	sk.P = *utils.GenerateBigPrime(bitLen)
	sk.Q = *utils.GenerateBigPrime(bitLen)
	pk.N = *new(big.Int).Mul(&sk.P, &sk.Q)
	
	return pk, sk
}

func Hash(pk *PublicKey, L, m *big.Int) (*HashValue, *Randomness) {
	r := new(Randomness)
	h := new(HashValue)

	r.R_1 = *utils.GetZq(&pk.N)
	r.R_2 = *utils.GetZq(&pk.N)
	h.H = *getHashValue(r, pk, L, m)
	
	return h, r
}

func Check(h *HashValue, r *Randomness, pk *PublicKey, L, m *big.Int) bool {
	return h.H.Cmp(getHashValue(r, pk, L, m)) == 0
}

func lcm(a, b *big.Int) *big.Int {
	gcd := new(big.Int).GCD(nil, nil, a, b)
	return new(big.Int).Div(new(big.Int).Mul(a, b), gcd)
}

func Adapt(h *HashValue, pk *PublicKey, sk *SecretKey, l, m_p *big.Int) *Randomness {
	r_p := new(Randomness)

	mod_n2 := new(big.Int).Exp(&pk.N, big.NewInt(2), nil)
	C_p := new(big.Int).Mod(new(big.Int).Mul(&h.H , new(big.Int).Sub(big.NewInt(1), new(big.Int).Mul(m_p, &pk.N))) , mod_n2)
	lamda := lcm(new(big.Int).Sub(&sk.P , big.NewInt(1)) , new(big.Int).Sub(&sk.Q , big.NewInt(1)))
	h_ := H(l)

	tmp1 := L(new(big.Int).Exp(C_p, lamda, mod_n2) , &pk.N)
	tmp2 := L(new(big.Int).Exp(h_, lamda, mod_n2) , &pk.N)
	tmp3 := new(big.Int).ModInverse(tmp2, &pk.N)
	r_p.R_1 = *new(big.Int).Mod(new(big.Int).Mul(tmp1, tmp3), &pk.N)

	tmp4 := new(big.Int).Exp(h_, new(big.Int).Neg(&r_p.R_1), &pk.N)
	tmp5 := new(big.Int).ModInverse(&pk.N, lamda)
	r_p.R_2 = *new(big.Int).Exp(new(big.Int).Mul(&h.H, tmp4) , tmp5, &pk.N)

	return r_p
}