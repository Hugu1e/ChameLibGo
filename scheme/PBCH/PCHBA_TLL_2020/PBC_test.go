package PCHBA_TLL_2020

import (
	"fmt"
	"testing"

	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
)

func run_scheme(t *testing.T, cur curve.Curve, swap bool, k int) {
	mpk, msk, SP := SetUp(cur, swap, k)

	MSP := SP.PpFAME.NewPBCMatrix()
	pl := SP.PpFAME.NewPolicyList()
	utils.GenLSSSPBCMatrices(MSP, pl, "A&(DDDD|(BB&CCC))")

	S1 := utils.NewAttributeList()
	S2 := utils.NewAttributeList()
	
	S1.Add("A")
	S1.Add("DDDD")

	S2.Add("BB")
	S2.Add("CCC")

	u1 := NewUserWithLen(SP, k/3)
	AssignUser(u1, mpk, msk)
	KeyGen(u1, SP, mpk, msk, S1)

	u2 := NewUserFromUser(u1, SP, k/2)
	AssignUser(u2, mpk, msk)
	KeyGen(u2, SP, mpk, msk, S2)

	m1 := SP.GP.GetZrElement()
	m2 := SP.GP.GetZrElement()

	h1, r1 := Hash(SP, mpk, u1, MSP, m1)
	if !Check(h1, r1, SP, mpk, m1) {
		t.Errorf("H(m1) invalid")
	}
	if Check(h1, r1, SP, mpk, m2) {
		t.Error()
	}
	
	h2, r2 := Hash(SP, mpk, u2, MSP, m2)
	if !Check(h2, r2, SP, mpk, m2) {
		t.Errorf("H(m2) invalid")
	}
	if Check(h2, r2, SP, mpk, m1) {
		t.Error()
	}
	
	r1_p := Adapt(h1, r1, SP, mpk, msk, u1, MSP, m1, m2)
	if !Check(h1, r1_p, SP, mpk, m2) {
		t.Errorf("Adapt(m2) invalid")
	}
	if Check(h1, r1_p, SP, mpk, m1) {
		t.Error()
	}
	
	r1_p = Adapt(h2, r2, SP, mpk, msk, u1, MSP, m2, m1)
	if !Check(h2, r1_p, SP, mpk, m1) {
		t.Errorf("Adapt(m1) invalid")
	}
	if Check(h2, r1_p, SP, mpk, m2) {
		t.Error()
	}

	r1_p = Adapt(h2, r2, SP, mpk, msk, u2, MSP, m2, m1)
	if Check(h2, r1_p, SP, mpk, m1) {
		t.Error("policy false")
	}
	if Check(h2, r1_p, SP, mpk, m2) {
		t.Error("policy false")
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
			run_scheme(t, c.cur, c.swap, c.k)
		})
	}

}
