package IB_CH_MD_LSX_2022

import (
	"fmt"
	"testing"

	"github.com/Hugu1e/ChameLibGo/curve"
)

func run_scheme(t *testing.T, curve curve.Curve){
	pp, msk := SetUp(curve)

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

	sk1 := KeyGen(pp, msk, ID1)

	h1, r1 := Hash(pp, ID1, m1)
	if !Check(h1, r1, pp, ID1, m1) {
		t.Errorf("H(ID1, m1) invalid")
	}
	if Check(h1, r1, pp, ID2, m1) {
		t.Errorf("H(ID2, m1) valid")
	}
	if Check(h1, r1, pp, ID1, m2) {
		t.Errorf("H(ID1, m2) valid")
	}

	h2, r2 := Hash(pp, ID2, m2)
	if !Check(h2, r2, pp, ID2, m2) {
		t.Errorf("H(ID2, m2) invalid")
	}
	if Check(h2, r2, pp, ID1, m2) {
		t.Errorf("H(ID1, m2) valid")
	}
	if Check(h2, r2, pp, ID2, m1) {
		t.Errorf("H(ID2, m1) valid")
	}

	r1_p := Adapt(r1, sk1, m1, m2)
	if !Check(h1, r1_p, pp, ID1, m2) {
		t.Errorf("Adapt(ID1, m2) invalid")
	}
	if Check(h1, r1_p, pp, ID1, m1) {
		t.Errorf("Adapt(ID1, m1) valid")
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