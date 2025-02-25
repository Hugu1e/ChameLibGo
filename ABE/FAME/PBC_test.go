package FAME

import (
	"fmt"
	"testing"

	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
)

func run_scheme(t *testing.T, curve curve.Curve, swap bool){
	pp, mpk, msk := SetUp(curve, swap)

	MSP := pp.NewPBCMatrix()
	pl := pp.NewPolicyList()
	utils.GenLSSSPBCMatrices(MSP, pl, "A&(DDDD|(BB&CCC))")

	S1 := utils.NewAttributeList()
	S1.Add("A")
	S1.Add("DDDD")

	S2 := utils.NewAttributeList()
	S2.Add("BB")
	S2.Add("CCC")

	sk1 := KeyGen(pp, mpk, msk, S1)
	sk2 := KeyGen(pp, mpk, msk, S2)

	m1 := NewRandomPlainText(pp)
	m2 := NewRandomPlainText(pp)
	if m1.Equals(m2) {
		t.Error("m1 == m2")
	}
	t.Log("m1:", m1.M.String())

	ct1 := Encrypt(pp, mpk, MSP, m1)
	m3 := Decrypt(pp, MSP, ct1, sk1)
	t.Log("m3:", m3.M.String())
	if !m3.Equals(m1) {
		t.Error("decrypt(sk1, ct1) != m1")
	}

	ct2 := Encrypt(pp, mpk, MSP, m2)
	m3 = Decrypt(pp, MSP, ct2, sk1)
	if !m3.Equals(m2) {
		t.Error("decrypt(sk1, ct2) != m2")
	}
	
	m3 = Decrypt(pp, MSP, ct1, sk2)
	if m3.Equals(m1) {
		t.Error("decrypt(sk2, ct1) == m1")
	}
	m3 = Decrypt(pp, MSP, ct1, sk2)
	if m3.Equals(m2) {
		t.Error("decrypt(sk2, ct1) == m2")
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