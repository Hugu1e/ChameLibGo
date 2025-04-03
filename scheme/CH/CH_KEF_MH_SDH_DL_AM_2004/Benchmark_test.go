package CH_KEF_MH_SDH_DL_AM_2004

import (
	"flag"
	"fmt"
	"testing"

	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
	"github.com/Nik-U/pbc"
)

var (
	r = flag.Int("repeat", 100, "repeat times")
)

func run_scheme_benchmark(t *testing.T, cur curve.Curve) {
	repeat := *r
	timer := utils.NewTimer(t.Name(), repeat)

	pp := make([]*PublicParam, repeat)
	timer.Start("SetUp")
	for i := 0; i < repeat; i++ {
		pp[i] = SetUp(cur)
	}
	timer.End("SetUp")

	pk := make([]*PublicKey, repeat)
	sk := make([]*SecretKey, repeat)

	timer.Start("KeyGen")
	for i := 0; i < repeat; i++ {
		pk[i], sk[i] = KeyGen(pp[i])
	}
	timer.End("KeyGen")

	m1 := make([]*pbc.Element, repeat)
	m2 := make([]*pbc.Element, repeat)
	for i := 0; i < repeat; i++ {
		m1[i] = pp[i].GetZrElement()
		m2[i] = pp[i].GetZrElement()
	}

	L1 := make([]*pbc.Element, repeat)
	for i := 0; i < repeat; i++ {
		L1[i] = pp[i].GetZrElement()
	}

	h1 := make([]*HashValue, repeat)
	r1 := make([]*Randomness, repeat)

	timer.Start("Hash")
	for i := 0; i < repeat; i++ {
		h1[i], r1[i] = Hash(pk[i], L1[i], m1[i], pp[i])
	}
	timer.End("Hash")

	checkRes := make([]bool, repeat)
	timer.Start("Check")
	for i := 0; i < repeat; i++ {
		checkRes[i] = Check(h1[i], r1[i], pk[i], L1[i], m1[i], pp[i])
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
		r1_p[i] = Adapt(r1[i], pk[i], sk[i], L1[i], m1[i], m2[i], pp[i])
	}
	timer.End("Adapt")

	for i := 0; i < repeat; i++ {
		if !Check(h1[i], r1_p[i], pk[i], L1[i], m2[i], pp[i]) {
			t.Fatal("Adapt(L1, m2) invalid")
		}
	}

	timer.AverageAndEnd()
}

func TestCH_KEF_MH_SDH_DL_AM_2004(t *testing.T) {
	cases := []struct {
		cur curve.Curve
	}{
		{curve.A},
		{curve.A1},
		{curve.E},
	}

	for i, c := range cases {
		curveName := curve.CurveName[c.cur]
		t.Run(fmt.Sprintf("case %d %s", i+1, curveName), func(t *testing.T) {
			run_scheme_benchmark(t, c.cur)
		})
	}

}