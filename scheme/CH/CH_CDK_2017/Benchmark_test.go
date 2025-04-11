package CH_CDK_2017

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

func run_scheme_benchmark(t *testing.T, lamuda int64){
	repeat := *r
	timer := utils.NewTimer(t.Name(), repeat)

	pk := make([]*PublicKey, repeat)
	sk := make([]*SecretKey, repeat)

	timer.Start("KeyGen")
	for i:=0; i<repeat; i++{
		pk[i], sk[i] = KeyGen(lamuda)
	} 
	timer.End("KeyGen")

	m1 := make([]*big.Int, repeat)
	m2 := make([]*big.Int, repeat)
	l1 := make([]*big.Int, repeat)
	l2 := make([]*big.Int, repeat)
	for i:=0; i < repeat; i++ {
		m1[i] = utils.GenerateBigNumber(lamuda)
		m2[i] = utils.GenerateBigNumber(lamuda)
		l1[i] = utils.GenerateBigNumber(lamuda)
		l2[i] = utils.GenerateBigNumber(lamuda)
	}

	h1 := make([]*HashValue, repeat)
	r1 := make([]*Randomness, repeat)

	timer.Start("Hash")
	for i:=0; i<repeat; i++{
		h1[i], r1[i] = Hash(pk[i], l1[i], m1[i])
	}
	timer.End("Hash")

	checkRes := make([]bool, repeat)

	timer.Start("Check")
	for i:=0; i<repeat; i++{
		checkRes[i] = Check(h1[i], r1[i], pk[i], l1[i], m1[i])
	}
	timer.End("Check")

	for i:=0; i<repeat; i++{
		if !checkRes[i]{
			t.Fatal("H(l1, m1) invalid")
		}
	}
	
	r1_p := make([]*Randomness, repeat)
	timer.Start("Adapt")
	for i:=0; i<repeat; i++{
		timer.Start("Adapt")
		r1_p[i] = Adapt(r1[i], pk[i], sk[i], l1[i], m1[i], l2[i], m2[i])
		timer.End("Adapt")
	}

	for i:=0; i<repeat; i++{
		if !Check(h1[i], r1_p[i], pk[i], l2[i], m2[i]){
			t.Fatal("Adapt(l2, m2) invalid")
		}
	}

	timer.AverageAndEnd()
}

func TestCH_CDK_2017(t *testing.T) {	
	cases := []struct {
		lamuda int64
	}{
		{256},
		{512},
		{1024},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("case %d lamuda %d", i+1, c.lamuda), func(t *testing.T) {
			run_scheme_benchmark(t, c.lamuda)
		})
	}
}


