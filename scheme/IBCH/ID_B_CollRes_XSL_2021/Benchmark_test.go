package ID_B_CollRes_XSL_2021

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

func run_scheme_benchmark(t *testing.T, curve curve.Curve, length int, swap bool) {
	repeat := *r
	timer := utils.NewTimer(t.Name(), repeat)

	pp := make([]*PublicParam, repeat)
	msk := make([]*MasterSecretKey, repeat)

	timer.Start("SetUp")
	for i := 0; i < repeat; i++ {
		pp[i], msk[i] = SetUp(curve, length, swap)
	}
	timer.End("SetUp")

	ID1 := make([]*Identity, repeat)
	for i := 0; i < repeat; i++ {
		ID1[i] = pp[i].GenIdentity()
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
		r1_p[i] = Adapt(r1[i], sk1[i], m1[i], m2[i])
	}
	timer.End("Adapt")

	for i := 0; i < repeat; i++ {
		if !Check(h1[i], r1_p[i], pp[i], ID1[i], m2[i]) {
			t.Fatal("Adapt(ID1, m2) invalid")
		}
	}

	timer.AverageAndEnd()
}

func TestID_B_CollRes_XSL_2021(t *testing.T) {
	curs := []curve.Curve{
		curve.A,
		curve.A1,
		curve.D_159,
		curve.D_201,
		curve.D_224,
		curve.D_105171_196_185,
		curve.D_277699_175_167,
		curve.D_278027_190_181,
		curve.E,
		curve.F,
		curve.SM_9,
		curve.G_149,
	}
	lens := []int{64, 128, 256}
	swaps := []bool{false, true}

	cases := []struct {
		cur curve.Curve
		len int
		swap bool
	}{}

	for _, c := range curs {
		for _, l := range lens {
			for _, s := range swaps {
				cases = append(cases, struct {
					cur  curve.Curve
					len  int
					swap bool
				}{
					cur:  c,
					len:  l,
					swap: s,
				})
			}
		}
	}

	for i, c := range cases {
		curveName := curve.CurveName[c.cur]
		t.Run(fmt.Sprintf("case %d %s length %d reverse %v", i+1, curveName,c.len, c.swap), func(t *testing.T) {
			run_scheme_benchmark(t, c.cur, c.len, c.swap)
		})
	}

}