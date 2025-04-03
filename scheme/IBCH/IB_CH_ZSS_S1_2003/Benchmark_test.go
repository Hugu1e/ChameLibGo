package IB_CH_ZSS_S1_2003

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

func run_scheme_benchmark(t *testing.T, curve curve.Curve, swap bool) {
	repeat := *r
	timer := utils.NewTimer(t.Name(), repeat)

	pp := make([]*PublicParam, repeat)
	msk := make([]*MasterSecretKey, repeat)

	timer.Start("SetUp")
	for i := 0; i < repeat; i++ {
		pp[i], msk[i] = SetUp(curve, swap)
	}
	timer.End("SetUp")

	ID1 := make([]*pbc.Element, repeat)
	for i := 0; i < repeat; i++ {
		ID1[i] = pp[i].GetZrElement()
	}

	m1 := make([]*pbc.Element, repeat)
	m2 := make([]*pbc.Element, repeat)
	for i := 0; i < repeat; i++ {
		m1[i] = pp[i].GetZrElement()
		m2[i] = pp[i].GetZrElement()
	}

	sk1 := make([]*SecretKey, repeat)

	timer.Start("KeyGen")
	for i := 0; i < repeat; i++ {
		sk1[i] = KeyGen(pp[i], msk[i], ID1[i])
	}
	timer.End("KeyGen")

	h1 := make([]*HashValue, repeat)
	r1 := make([]*Randomness, repeat)

	timer.Start("Hash")
	for i := 0; i < repeat; i++ {
		h1[i], r1[i] = Hash(pp[i], ID1[i], m1[i])
	}
	timer.End("Hash")

	checkRes := make([]bool, repeat)
	timer.Start("Check")
	for i := 0; i < repeat; i++ {
		checkRes[i] = Check(h1[i], r1[i], pp[i], ID1[i], m1[i])
	}
	timer.End("Check")
	for i := 0; i < repeat; i++ {
		if !checkRes[i] {
			t.Fatal("H(ID1, m1) invalid")
		}
	}

	r1_p := make([]*Randomness, repeat)
	timer.Start("Adapt")
	for i := 0; i < repeat; i++ {
		r1_p[i] = Adapt(r1[i], pp[i], sk1[i], m1[i], m2[i])
	}
	timer.End("Adapt")

	for i := 0; i < repeat; i++ {
		if !Check(h1[i], r1_p[i], pp[i], ID1[i], m2[i]) {
			t.Fatal("Adapt(ID1, m2) invalid")
		}
	}

	timer.AverageAndEnd()
}

func TestIB_CH_ZSS_S1_2003(t *testing.T) {
	cases := []struct {
		cur curve.Curve
		swap bool
	}{
		{curve.A, false},
		{curve.A, true},
		{curve.A1, false},
		{curve.A1, true},
		{curve.D_159, false},
		{curve.D_159, true},
		{curve.D_201, false},
		{curve.D_201, true},
		{curve.D_224, false},
		{curve.D_224, true},
		{curve.D_105171_196_185, false},
		{curve.D_105171_196_185, true},
		{curve.D_277699_175_167, false},
		{curve.D_277699_175_167, true},
		{curve.D_278027_190_181, false},
		{curve.D_278027_190_181, true},
		{curve.E, false},
		{curve.E, true},
		{curve.F, false},
		{curve.F, true},
		{curve.SM_9, false},
		{curve.SM_9, true},
		{curve.G_149, false},
		{curve.G_149, true},
	}

	for i, c := range cases {
		curveName := curve.CurveName[c.cur]
		t.Run(fmt.Sprintf("case %d %s reverse %v", i+1, curveName, c.swap), func(t *testing.T) {
			run_scheme_benchmark(t, c.cur, c.swap)
		})
	}

}