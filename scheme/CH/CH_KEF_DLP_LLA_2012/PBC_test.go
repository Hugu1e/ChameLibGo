package CH_KEF_DLP_LLA_2012

import (
	"fmt"
	"testing"

	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Nik-U/pbc"
)

func run_scheme(t *testing.T, cur curve.Curve, group pbc.Field){
	if(group == pbc.GT && (cur == curve.SM_9 || cur == curve.G_149)){
		return
	}
	if(group == pbc.G2 && (cur == curve.G_149)){
		return
	}

	pp, lm := SetUp(cur, group)

	pk, sk := KeyGen(lm, pp)
	
	m1 := pp.GetZrElement()
	m2 := pp.GetZrElement()
	m3 := pp.GetZrElement()
	if m1.Equals(m2) {
		t.Errorf("m1 == m2")
	}
	if m1.Equals(m3) {
		t.Errorf("m1 == m3")
	}
	if m2.Equals(m3) {
		t.Errorf("m2 == m3")
	}
	
	h1, r1, L1 := Hash(lm, pk, m1, pp)
	t.Log("h1.S", h1.S.String())
	t.Log("r1.R", r1.R.String())
	t.Log("L1.L", L1.L.String())
	t.Log("L1.R", L1.R.String())
	h2, r2, L2 := Hash(lm, pk, m2, pp)

	if !Check(h1, r1, pk, L1, m1, pp) {
		t.Errorf("H(m1) invalid")
	}
	if Check(h1, r1, pk, L2, m1, pp) {
		t.Error()
	}
	
	if !Check(h2, r2, pk, L2, m2, pp) {
		t.Errorf("H(m2) invalid")
	}
	if Check(h2, r2, pk, L1, m2, pp) {
		t.Error()
	}
	
	if Check(h1, r1, pk, L2, m2, pp) {
		t.Error()
	}
	if Check(h2, r2, pk, L1, m1, pp) {
		t.Error()
	}
	
	r1_p := UForge(h1, r1, L1, pk, sk, pp, m1, m3)
	t.Log("r1_p.R", r1_p.R.String())
	if !Check(h1, r1_p, pk, L1, m3, pp) {
		t.Errorf("Adapt(m3) invalid")
	}
	
	r1_p = UForge(h1, r1, L1, pk, sk, pp, m1, m2)
	t.Log("r1_p.R", r1_p.R.String())
	if !Check(h1, r1_p, pk, L1, m2, pp) {
		t.Errorf("Adapt(m2) invalid")
	}
	
	r1_pp := IForge(r1, r1_p, m1, m2, m3)
	t.Log("r1_pp.R", r1_pp.R.String())
	if !Check(h1, r1_pp, pk, L1, m3, pp) {
		t.Errorf("Adapt(m3) valid")
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
			run_scheme(t, c.cur, c.group)
		})
	}

}