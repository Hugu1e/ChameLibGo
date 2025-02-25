package PCH_DSS_2019

import (
	"fmt"
	"testing"

	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
)

func run_scheme(t *testing.T, cur curve.Curve, swap bool, lamuda int64) {
	pp_PCH, pk_PCH, sk_PCH := SetUp(cur, swap, lamuda)

	MSP := pp_PCH.Pp_ABE.NewPBCMatrix()
	pl := pp_PCH.Pp_ABE.NewPolicyList()
	utils.GenLSSSPBCMatrices(MSP, pl, "A&(DDDD|(BB&CCC))")
	
	S1 := utils.NewAttributeList()
	S2 := utils.NewAttributeList()
	S1.Add("A")
	S1.Add("DDDD")

	S2.Add("BB")
	S2.Add("CCC")
	
	sk1 := KeyGen(pp_PCH, pk_PCH, sk_PCH, S1)
	// sk2 := KeyGen(pp_PCH, pk_PCH, sk_PCH, S2)
	
	m1 := utils.GenerateBigNumber(lamuda)
	m2 := utils.GenerateBigNumber(lamuda)
	if m1.Cmp(m2) == 0 {
		t.Error("m1 == m2")
	}

	h1, r1 := Hash(pp_PCH, pk_PCH, MSP, m1)
	if !Check(h1, r1, pk_PCH, m1) {
		t.Error("H(m1) invalid")
	}
	if Check(h1, r1, pk_PCH, m2) {
		t.Error()
	}

	h2, r2 := Hash(pp_PCH, pk_PCH, MSP, m2)
	if !Check(h2, r2, pk_PCH, m2) {
		t.Error("H(m2) invalid")
	}
	if Check(h2, r2, pk_PCH, m1) {
		t.Error()
	}
	
	r1_p := Adapt(h1, r1, pp_PCH, pk_PCH, MSP, sk1, m1, m2)
	if !Check(h1, r1_p, pk_PCH, m2) {
		t.Error("Adapt(m2) invalid")
	}
	if Check(h1, r1_p, pk_PCH, m1) {
		t.Error()
	}
}

func Test_PBC(t *testing.T) {
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
	lamudas := []int64{
		256,
		512,
		1024,
	}

	cases := []struct {
		cur   curve.Curve
		swap  bool
		lamuda int64
	}{}

	for _, c := range curs {
		for _, s := range swaps {
			for _, l := range lamudas {
				cases = append(cases, struct {
					cur   curve.Curve
					swap  bool
					lamuda int64
				}{
					cur:   c,
					swap:  s,
					lamuda: l,
				})
			}
		}
	}

	for i, c := range cases {
		curveName := curve.CurveName[c.cur]
		t.Run(fmt.Sprintf("case %d %s swap %v lamuda %d", i+1, curveName, c.swap, c.lamuda), func(t *testing.T) {
			run_scheme(t, c.cur, c.swap, c.lamuda)
		})
	}

}
