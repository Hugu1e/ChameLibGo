package CH_KEF_MH_SDH_DL_AM_2004

import (
	"fmt"
	"testing"

	"github.com/Hugu1e/ChameLibGo/curve"
)

func run_scheme(t *testing.T, curve curve.Curve){
	pp := SetUp(curve)

	pk, sk := KeyGen(pp)

	m1 := pp.GetZrElement()
	m2 := pp.GetZrElement()
	if m1.Equals(m2) {
		t.Errorf("m1 == m2")
	}
	L1 := pp.GetZrElement()
	L2 := pp.GetZrElement()
	if L1.Equals(L2) {
		t.Errorf("L1 == L2")
	}

	h1, r1 := Hash(pk, L1, m1, pp)
	t.Log("h1:", h1.H.String())
	t.Log("r1:", r1.G_r.String())
	if !Check(h1, r1, pk, L1, m1, pp) {
		t.Errorf("H(L1, m1) invalid")
	}
	if Check(h1, r1, pk, L2, m1, pp) {
		t.Error()
	}
	
	h2, r2 := Hash(pk, L2, m2, pp)
	if !Check(h2, r2, pk, L2, m2, pp) {
		t.Errorf("H(L2, m2) invalid")
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

	r1_p := Adapt(r1, pk, sk, L1, m1, m2, pp)
	t.Log("r1_p:", r1_p.G_r.String())
	if !Check(h1, r1_p, pk, L1, m2, pp) {
		t.Errorf("Adapt(L1, m2) invalid")
	}
	
	r1_p = Adapt(r1, pk, sk, L2, m1, m2, pp)
	if Check(h1, r1_p, pk, L2, m2, pp) {
		t.Error()
	}
}

func Test_PBC(t *testing.T) {
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
			run_scheme(t, c.cur)
		})
	}

}