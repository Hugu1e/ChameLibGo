package IB_CH_KEF_CZS_2014

import (
	"fmt"
	"testing"

	"github.com/Hugu1e/ChameLibGo/curve"
)

func run_scheme(t *testing.T, curve curve.Curve, swap bool){
	pp, msk := SetUp(curve, swap)

	ID1 := pp.GetZrElement()
	ID2 := pp.GetZrElement()
	if ID1.Equals(ID2) {
		t.Errorf("ID1 == ID2")
	}

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

	sk1 := KeyGen(pp, msk, ID1)
	sk2 := KeyGen(pp, msk, ID2)
	if sk1.S_ID.Equals(sk2.S_ID) {
		t.Errorf("sk1 == sk2")
	}

	h1, r1 := Hash(pp, ID1, L1, m1)
	if !Check(h1, r1, pp, L1, m1) {
		t.Errorf("H(L1, m1) invalid")
	}
	if Check(h1, r1, pp, L2, m1) {
		t.Errorf("H(L2, m1) valid")
	}
	if Check(h1, r1, pp, L1, m2) {
		t.Errorf("H(L1, m2) valid")
	}

	h2, r2 := Hash(pp, ID2, L2, m2)
	if !Check(h2, r2, pp, L2, m2) {
		t.Errorf("H(L2, m2) invalid")
	}
	if Check(h2, r2, pp, L1, m2) {
		t.Errorf("H(L1, m2) valid")
	}
	if Check(h2, r2, pp, L2, m1) {
		t.Errorf("H(L2, m1) valid")
	}

	r1_p := Adapt(r1, pp, sk1, L1, m1, m2)
	if !Check(h1, r1_p, pp, L1, m2) {
		t.Errorf("Adapt(L1, m2) invalid")
	}
	if Check(h1, r1_p, pp, L1, m1) {
		t.Errorf("Adapt(L1, m1) valid")
	}

	r1_p = Adapt(r1, pp, sk1, L2, m1, m2)
	if Check(h1, r1_p, pp, L2, m2) {
		t.Errorf("Adapt(L2, m2) valid")
	}
}

func Test_PBC(t *testing.T) {
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
			run_scheme(t, c.cur, c.swap)
		})
	}

}