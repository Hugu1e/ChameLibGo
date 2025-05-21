package CH_KEF_MH_RSANN_F_AM_2004

import (
	"flag"
	"fmt"
	"math/big"
	"testing"

	"github.com/Hugu1e/ChameLibGo/utils"
)

var (
	r = flag.Int("repeat", 100, "repeat times")
)

func run_scheme_benchmark(t *testing.T, bitLen int64) {
	repeat := *r
	timer := utils.NewTimer(t.Name(), repeat)

	pk := make([]*PublicKey, repeat)
	sk := make([]*SecretKey, repeat)

	timer.Start("KeyGen")
	for i := 0; i < repeat; i++ {
		pk[i], sk[i] = KeyGen(bitLen)
	}
	timer.End("KeyGen")

	m1 := make([]*big.Int, repeat)
	m2 := make([]*big.Int, repeat)
	L1 := make([]*big.Int, repeat)
	for i := 0; i < repeat; i++ {
		m1[i] = utils.GenerateBigNumber(bitLen/2)
		m2[i] = utils.GenerateBigNumber(bitLen/2)
		L1[i] = utils.GenerateBigNumber(bitLen)
	}

	h1 := make([]*HashValue, repeat)
	r1 := make([]*Randomness, repeat)

	timer.Start("Hash")
	for i := 0; i < repeat; i++ {
		h1[i], r1[i] = Hash(pk[i], L1[i], m1[i])
	}
	timer.End("Hash")

	checkRes := make([]bool, repeat)
	timer.Start("Check")
	for i := 0; i < repeat; i++ {
		checkRes[i] = Check(h1[i], r1[i], pk[i], L1[i], m1[i])
	}
	timer.End("Check")
	for i := 0; i < repeat; i++ {
		if !checkRes[i] {
			t.Fatal("H(L1, m1) invalid")
		}
	}

	r1_p := make([]*Randomness, repeat)
	timer.Start("Adapt")
	for i := 0; i < repeat; i++ {
		r1_p[i] = Adapt(h1[i], pk[i], sk[i], L1[i], m2[i])
	}
	timer.End("Adapt")

	for i := 0; i < repeat; i++ {
		if !Check(h1[i], r1_p[i], pk[i], L1[i], m2[i]) {
			t.Fatal("adapt m2 invalid")
		}
	}

	timer.AverageAndEnd()
}

func TestCH_KEF_MH_RSANN_F_AM_2004(t *testing.T) {
	cases := []struct {
		bitLen int64
	}{
		{256},
		{512},
		{1024},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("case %d bitLen %d", i+1, c.bitLen), func(t *testing.T) {
			run_scheme_benchmark(t, c.bitLen)
		})
	}
}


