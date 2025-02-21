package RSA

import (
	"math/big"

	"github.com/Hugu1e/ChameLibGo/utils"
)

type PublicKey struct {
	N, E big.Int
}

type SecretKey struct {
	P, Q, D big.Int
}

func KeyGen() (*PublicKey, *SecretKey) {
	pk := new(PublicKey)
	sk := new(SecretKey)

	pk.E.SetString("65537", 10)

	// Generate two large prime numbers p and q
	sk.P = *utils.GenerateBigPrime(1024)
	sk.Q = *utils.GenerateBigPrime(1024)

	one := big.NewInt(1)
	phi := computePhi(&sk.P, &sk.Q)
	gcd := new(big.Int).GCD(nil, nil, phi, &pk.E)
	for gcd.Cmp(one) != 0 {
		sk.P = *utils.GenerateBigPrime(1024)
		sk.Q = *utils.GenerateBigPrime(1024)
		phi = computePhi(&sk.P, &sk.Q)
		gcd.GCD(nil, nil, phi, &pk.E)
	}
	pk.N.Mul(&sk.P, &sk.Q);
	sk.D.ModInverse(&pk.E, phi);

	return pk, sk
}

func KeyGen_2(eBit int64, pBit int64) (*PublicKey, *SecretKey){
	pk := new(PublicKey)
	sk := new(SecretKey)

	pk.E = *utils.GenerateBigPrime(eBit)
	sk.P = *utils.GenerateBigPrime(pBit)
	sk.Q = *utils.GenerateBigPrime(pBit)

	phi := computePhi(&sk.P, &sk.Q)
	one := big.NewInt(1)
	gcd := new(big.Int).GCD(nil, nil, phi, &pk.E)
	for gcd.Cmp(one) != 0 {
		sk.P = *utils.GenerateBigPrime(pBit)
		sk.Q = *utils.GenerateBigPrime(pBit)
		phi = computePhi(&sk.P, &sk.Q)
		gcd.GCD(nil, nil, phi, &pk.E)
	}
	pk.N.Mul(&sk.P, &sk.Q)
	sk.D.ModInverse(&pk.E, phi)

	return pk, sk
}

func KeyGen_3(n, e *big.Int, pBit int64) (*PublicKey, *SecretKey) {
	pk := new(PublicKey)
	sk := new(SecretKey)

	pk.E.Set(e)
	sk.P = *utils.GenerateBigPrime(pBit)
	sk.Q = *utils.GenerateBigPrime(pBit)
	pk.N.Mul(&sk.P, &sk.Q)
	phi := computePhi(&sk.P, &sk.Q)
	one := big.NewInt(1)
	gcd1 := new(big.Int).GCD(nil, nil, phi, &pk.E)
	gcd2 := new(big.Int).GCD(nil, nil, n, &pk.N)
	for gcd1.Cmp(one) != 0 || gcd2.Cmp(one) != 0 {
		sk.P = *utils.GenerateBigPrime(pBit)
		sk.Q = *utils.GenerateBigPrime(pBit)
		pk.N.Mul(&sk.P, &sk.Q)
		phi = computePhi(&sk.P, &sk.Q)
		gcd1.GCD(nil, nil, phi, &pk.E)
		gcd2.GCD(nil, nil, n, &pk.N)
	}
	sk.D.ModInverse(&pk.E, phi)

	return pk, sk
}

func Encrypt(pt *big.Int, pk *PublicKey) *big.Int {
	return new(big.Int).Exp(pt, &pk.E, &pk.N);
}

func Decrypt(ct *big.Int, pk *PublicKey, sk *SecretKey) *big.Int {
	return new(big.Int).Exp(ct, &sk.D, &pk.N)
}

func computePhi(p, q *big.Int) *big.Int {
	one := big.NewInt(1)
	pMinus1 := new(big.Int).Sub(p, one)
	qMinus1 := new(big.Int).Sub(q, one)
	return new(big.Int).Mul(pMinus1, qMinus1)
}