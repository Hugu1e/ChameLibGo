package BLS

import (
	"fmt"
	"testing"

	"github.com/Hugu1e/ChameLibGo/curve"
)

func run_scheme(t *testing.T, curve curve.Curve, swap bool){
	pp := SetUp(curve, swap)

	pk1, sk1 := KeyGen(pp)
	pk2, sk2 := KeyGen(pp)

	m1 := "WCjrCK"
	m2 := "123"

	s1 := Sign(sk1, pp, m1)
	s2 := Sign(sk2, pp, m2)
	if s1.Equals(s2) {
		t.Errorf("s1 == s2")
	}

	if !Verify(pp, pk1, s1, m1) {
		t.Errorf("valid sign(m1)")
	}
	if !Verify(pp, pk2, s2, m2) {
		t.Errorf("valid sign(m2)")
	}

	if Verify(pp, pk1, s2, m1) {
		t.Error()
	}
	if Verify(pp, pk2, s1, m1) {
		t.Error()
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