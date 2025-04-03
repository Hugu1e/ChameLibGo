package CH_KEF_DLP_LLA_2012

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

func run_scheme_benchmark(t *testing.T, cur curve.Curve, group pbc.Field) {
	repeat := *r
	timer := utils.NewTimer(t.Name(), repeat)

	pp := make([]*PublicParam, repeat)
	lm := make([]*LabelManager, repeat)
	timer.Start("SetUp")
	for i := 0; i < repeat; i++ {
		pp[i], lm[i] = SetUp(cur, group)
	}
	timer.End("SetUp")

	pk := make([]*PublicKey, repeat)
	sk := make([]*SecretKey, repeat)
	timer.Start("KeyGen")
	for i := 0; i < repeat; i++ {
		pk[i], sk[i] = KeyGen(lm[i], pp[i])
	}
	timer.End("KeyGen")

	m1 := make([]*pbc.Element, repeat)
	m2 := make([]*pbc.Element, repeat)
	m3 := make([]*pbc.Element, repeat)
	for i := 0; i < repeat; i++ {
		m1[i] = pp[i].GetZrElement()
		m2[i] = pp[i].GetZrElement()
		m3[i] = pp[i].GetZrElement()
	}

	h1 := make([]*HashValue, repeat)
	r1 := make([]*Randomness, repeat)
	L1 := make([]*Label, repeat)
	timer.Start("Hash")
	for i := 0; i < repeat; i++ {
		h1[i], r1[i], L1[i] = Hash(lm[i], pk[i], m1[i], pp[i])
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
			t.Fatal("H(m1) invalid")
		}
	}

	r1_p := make([]*Randomness, repeat)
	timer.Start("UForge")
	for i := 0; i < repeat; i++ {
		r1_p[i] = UForge(h1[i], r1[i], L1[i], pk[i], sk[i], pp[i], m1[i], m2[i])
	}
	timer.End("UForge")

	for i := 0; i < repeat; i++ {
		if !Check(h1[i], r1_p[i], pk[i], L1[i], m2[i], pp[i]) {
			t.Fatal("Adapt(m2) invalid")
		}
	}

	r1_pp := make([]*Randomness, repeat)
	timer.Start("IForge")
	for i := 0; i < repeat; i++ {
		r1_pp[i] = IForge(r1[i], r1_p[i], m1[i], m2[i], m3[i])
	}
	timer.End("IForge")

	for i := 0; i < repeat; i++ {
		if !Check(h1[i], r1_pp[i], pk[i], L1[i], m3[i], pp[i]) {
			t.Fatal("Adapt(m3) invalid")
		}
	}

	timer.AverageAndEnd()
}

func TestCH_KEF_DLP_LLA_2012(t *testing.T) {
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
	groups := []pbc.Field{
        pbc.G1,
        pbc.G2,
        pbc.GT,
    }

	cases := []struct {
		cur curve.Curve
		group pbc.Field
	}{}

	for _, c := range curs {
		for _, g := range groups {
            cases = append(cases, struct {
                cur  curve.Curve
                group pbc.Field
            }{
                cur:  c,
                group:g,
            })
			
		}
	}

	for i, c := range cases {
		curveName := curve.CurveName[c.cur]
        groupName := curve.GroupName[c.group]
		t.Run(fmt.Sprintf("case %d %s %s", i+1, curveName, groupName), func(t *testing.T) {
			run_scheme_benchmark(t, c.cur, c.group)
		})
	}

}