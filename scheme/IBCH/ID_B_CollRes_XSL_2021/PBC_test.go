package ID_B_CollRes_XSL_2021

import (
	"fmt"
	"testing"

	"github.com/Hugu1e/ChameLibGo/curve"
)

func run_scheme(t *testing.T, curve curve.Curve, len int, swap bool){
	pp, msk := SetUp(curve, len, swap)
	ID1 := pp.GenIdentity()
	ID2 := pp.GenIdentity()
	m1 := pp.GetZrElement()
	m2 := pp.GetZrElement()
	if m1.Equals(m2) {
		t.Errorf("m1 == m2")
	}

	sk1 := KeyGen(pp, msk, ID1)

	h1, r1 := Hash(pp, ID1, m1)
	t.Log("h1.h: ", h1.H.String())
	t.Log("r1.r1: ", r1.R_1.String())
	t.Log("r1.r2: ", r1.R_2.String())
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
	t.Log("r1_p.r1: ", r1_p.R_1.String())
	t.Log("r1_p.r2: ", r1_p.R_2.String())
	if !Check(h1, r1_p, pp, ID1, m2) {
		t.Errorf("Adapt(ID1, m2) invalid")
	}
	if Check(h1, r1_p, pp, ID1, m1) {
		t.Errorf("Adapt(ID1, m1) valid")
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
			run_scheme(t, c.cur, c.len, c.swap)
		})
	}

}