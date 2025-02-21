package utils

import (
	"math/big"
	"math/rand"
	"time"
)

// generate a = 2^n
func GenerateBigRange(bitLen int64) *big.Int {
	return new(big.Int).Exp(big.NewInt(2), big.NewInt(bitLen), nil)
}

// generate a random number with bitLen
func GenerateBigNumber(bitLen int64) *big.Int {
	n := GenerateBigRange(bitLen)
	ran := rand.New(rand.NewSource(time.Now().UnixNano()))

	return new(big.Int).Rand(ran, n)
}

// generate a prime number with bitLen
func GenerateBigPrime(bitLen int64) *big.Int {
	n := GenerateBigRange(bitLen)
	ran := rand.New(rand.NewSource(time.Now().UnixNano()))

	p := new(big.Int).Rand(ran, n)
	for !p.ProbablyPrime(20) {
		p.Rand(ran, n)
	}

	return p
}

func GetZq(q *big.Int) *big.Int{
	ran := rand.New(rand.NewSource(time.Now().UnixNano()))
	return new(big.Int).Rand(ran, q)
}