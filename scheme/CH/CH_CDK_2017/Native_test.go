package CH_CDK_2017

import (
	"fmt"
	"testing"

	"github.com/Hugu1e/ChameLibGo/utils"
)

func run_scheme(t *testing.T, lamuda int64){
	pk, sk := KeyGen(lamuda)

	m1 := utils.GenerateBigNumber(lamuda)
	m2 := utils.GenerateBigNumber(lamuda)
	if m1.Cmp(m2) == 0 {
		t.Errorf("m1 == m2")
	}
	l1 := utils.GenerateBigNumber(lamuda)
	l2 := utils.GenerateBigNumber(lamuda)
	if l1.Cmp(l2) == 0 {
		t.Errorf("l1 == l2")
	}

	h1, r1 := Hash(pk, l1, m1)
	t.Log("h1.h: ", h1.H.String())
	t.Log("r1.r: ", r1.R.String())
	if !Check(h1, r1, pk, l1, m1) {
		t.Errorf("H(l1, m1) invalid")
	}
	if Check(h1, r1, pk, l2, m1) {
		t.Errorf("H(l2, m1) valid")
	}

	h2, r2 := Hash(pk, l2, m2)
	if !Check(h2, r2, pk, l2, m2) {
		t.Errorf("H(l2, m2) invalid")
	}
	if Check(h2, r2, pk, l1, m2) {
		t.Errorf("H(l1, m2) = h2, r2")
	}
	if Check(h1, r1, pk, l1, m2) {
		t.Errorf("H(l1, m2) = h1, r1")
	}
	if Check(h2, r2, pk, l2, m1) {
		t.Errorf("H(l2, m1) = h2, r2")
	}
	
	r1_p := Adapt(r1, pk, sk, l1, m1, l2, m2)
	t.Log("r1_p.r: ", r1_p.R.String())
	if !Check(h1, r1_p, pk, l2, m2) {
		t.Errorf("Adapt(l2, m2) invalid")
	}
	if Check(h1, r1_p, pk, l2, m1) {
		t.Errorf("not adapt m1")
	}
	if Check(h1, r1_p, pk, l1, m2) {
		t.Errorf("not adapt l1")
	}
}

func Test_Native(t *testing.T) {
	cases := []struct {
		lamuda int64
	}{
		{256},
		{512},
		{1024},
		{2048},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("case %d lamuda %d", i+1, c.lamuda), func(t *testing.T) {
			run_scheme(t, c.lamuda)
		})
	}
}


