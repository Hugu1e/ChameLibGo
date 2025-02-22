package CHET_RSA_CDK_2017

import (
	"fmt"
	"testing"

	"github.com/Hugu1e/ChameLibGo/utils"
)

func run_scheme(t *testing.T, lamuda int64){
	pp := SetUp(lamuda)
	pk, sk := KeyGen(pp)

	m1 := utils.GenerateBigNumber(lamuda)
	m2 := utils.GenerateBigNumber(lamuda)
	if m1.Cmp(m2) == 0 {
		t.Errorf("m1 == m2")
	}
	
	h1, r1, etd1 := Hash(pk, m1, pp)
	t.Log("h1.h: ", h1.H.String())
	t.Log("r1.r: ", r1.R.String())
	t.Log("etd1.p: ", etd1.P_p.String())
	t.Log("etd1.q: ", etd1.Q_p.String())
	if !Check(h1, r1, pk, m1) {
		t.Errorf("H(m1) invalid")
	}
	
	h2, r2, _ := Hash(pk, m2, pp)
	if !Check(h2, r2, pk, m2) {
		t.Errorf("H(m2) invalid")
	}
	
	if Check(h1, r1, pk, m2) {
		t.Error()
	}
	if Check(h2, r2, pk, m1) {
		t.Error()
	}
	
	r1_p := Adapt(h1, r1, etd1, pk, sk, m1, m2);
	t.Log("r1_p.r: ", r1_p.R.String())
	if !Check(h1, r1_p, pk, m2) {
		t.Errorf("Adapt(m2) invalid")
	}
	if Check(h1, r1_p, pk, m1) {
		t.Error()
	}
}

func Test_Native(t *testing.T) {
	cases := []struct {
		lamuda int64
	}{
		{128},
		{256},
		{512},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("case %d lamuda %d", i+1, c.lamuda), func(t *testing.T) {
			run_scheme(t, c.lamuda)
		})
	}
}


