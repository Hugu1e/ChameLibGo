package CH_KEF_DL_CZT_2011

import (
	"fmt"
	"testing"

	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Nik-U/pbc"
)

func run_scheme(t *testing.T, cur curve.Curve, group pbc.Field){
	pp := SetUp(cur, group)
	
	pk, sk := KeyGen(pp)

	m1 := pp.GetZrElement()
	m2 := pp.GetZrElement()
	if m1.Equals(m2) {
		t.Errorf("m1 == m2")
	}
	
	L1 := pp.GetGroupElement()
	L2 := pp.GetGroupElement()
	if L1.Equals(L2) {
		t.Errorf("L1 == L2")
	}

	h1, r1 := Hash(pp, pk, L1, m1)
	t.Log("h1.H", h1.H.String())
	t.Log("r1.G_a", r1.G_a.String())
	t.Log("r1.Y_a", r1.Y_a.String())
	if !Check(h1, r1, pp, pk, L1, m1) {
		t.Errorf("H(L1, m1) invalid")
	}
	if Check(h1, r1, pp, pk, L2, m1) {
		t.Error()
	}
	
	h2, r2 := Hash(pp, pk, L2, m2)
	if !Check(h2, r2, pp, pk, L2, m2) {
		t.Errorf("H(L2, m2) invalid")
	}
	if Check(h2, r2, pp, pk, L1, m2) {
		t.Error()
	}
	
	if Check(h1, r1, pp, pk, L2, m2) {
		t.Error()
	}
	if Check(h2, r2, pp, pk, L1, m1) {
		t.Error()
	}
	
	r1_p := Adapt(r1, pp, pk, sk, L1, m1, m2)
	t.Log("r1_p.G_a", r1_p.G_a.String())
	t.Log("r1_p.Y_a", r1_p.Y_a.String())
	if !Check(h1, r1_p, pp, pk, L1, m2) {
		t.Errorf("Adapt(m2) invalid")
	}
	if Check(h1, r1_p, pp, pk, L1, m1) {
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