package PCHBA_TLL_2020

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

func run_scheme_benchmark(t *testing.T, curve curve.Curve, swap bool, k int) {
	repeat := *r
	timer := utils.NewTimer(t.Name(), repeat)

	SP := make([]*PublicParam, repeat)
	MPK := make([]*MasterPublicKey, repeat)
	MSK := make([]*MasterSecretKey, repeat)

	timer.Start("SetUp")
	for i := 0; i < repeat; i++ {
		MPK[i], MSK[i], SP[i]= SetUp(curve, swap, k)
	}
	timer.End("SetUp")

	MSP := make([]*utils.PBCMatrix, repeat)
	pl := make([]*utils.PolicyList, repeat)
	for i := 0; i < repeat; i++ {
		MSP[i] = SP[i].PpFAME.NewPBCMatrix()
		pl[i] = SP[i].PpFAME.NewPolicyList()
		utils.GenLSSSPBCMatrices(MSP[i], pl[i], "A&(DDDD|(BB&CCC))")
	}

	S1 := utils.NewAttributeList()	
	S1.Add("A")
	S1.Add("DDDD")

	u1 := make([]*User, repeat)
	for i := 0; i < repeat; i++ {
		u1[i] = NewUserWithLen(SP[i], k/3)
		AssignUser(u1[i], MPK[i], MSK[i])
		timer.Start("KeyGen")
		KeyGen(u1[i], SP[i], MPK[i], MSK[i], S1)
		timer.End("KeyGen")
	}

	m1 := make([]*pbc.Element, repeat)
	m2 := make([]*pbc.Element, repeat)
	for i := 0; i < repeat; i++ {
		m1[i] = SP[i].GP.GetZrElement()
		m2[i] = SP[i].GP.GetZrElement()
	}

	h1 := make([]*HashValue, repeat)
	r1 := make([]*Randomness, repeat)
	timer.Start("Hash")
	for i := 0; i < repeat; i++ {
		h1[i], r1[i] = Hash(SP[i], MPK[i], u1[i], MSP[i], m1[i])
	}
	timer.End("Hash")

	checkRes := make([]bool, repeat)
	timer.Start("Check")
	for i := 0; i < repeat; i++ {
		checkRes[i] = Check(h1[i], r1[i], SP[i], MPK[i], m1[i])
	}
	timer.End("Check")
	for i := 0; i < repeat; i++ {
		if !checkRes[i] {
			t.Fatal("H(m1) invalid")
		}
	}

	r1_p := make([]*Randomness, repeat)
	timer.Start("Adapt")
	for i := 0; i < repeat; i++ {
		r1_p[i] = Adapt(h1[i], r1[i], SP[i], MPK[i], MSK[i], u1[i], MSP[i], m1[i], m2[i])
	}
	timer.End("Adapt")
	for i := 0; i < repeat; i++ {
		if !Check(h1[i], r1_p[i], SP[i], MPK[i], m2[i]) {
			t.Fatal("Adapt(m2) invalid")
		}
	}
	timer.AverageAndEnd()
}

func TestPCHBA_TLL_2020(t *testing.T) {
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
	swaps := []bool{false, true}
	ks := []int{
		8,
		16,
		24,
	}

	cases := []struct {
		cur   curve.Curve
		swap  bool
		k     int
	}{}

	for _, c := range curs {
		for _, s := range swaps {
			for _, k := range ks {
				cases = append(cases, struct {
					cur   curve.Curve
					swap  bool
					k     int
				}{
					cur:   c,
					swap:  s,
					k:	   k,
				})
			}
		}
	}

	for i, c := range cases {
		curveName := curve.CurveName[c.cur]
		t.Run(fmt.Sprintf("case %d %s swap %v k %d", i+1, curveName, c.swap, c.k), func(t *testing.T) {
			run_scheme_benchmark(t, c.cur, c.swap, c.k)
		})
	}

}
