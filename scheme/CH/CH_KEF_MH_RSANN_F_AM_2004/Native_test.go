package CH_KEF_MH_RSANN_F_AM_2004

import (
	"fmt"
	"testing"

	"github.com/Hugu1e/ChameLibGo/utils"
)

func run_scheme(t *testing.T, bitLen int64){
	pk, sk := KeyGen(bitLen)
	m1 := utils.GenerateBigNumber(bitLen/2)
	m2 := utils.GenerateBigNumber(bitLen/2)
	if m1.Cmp(m2) == 0 {
		t.Errorf("m1 == m2")
	}
	L1 := utils.GenerateBigNumber(bitLen)
	L2 := utils.GenerateBigNumber(bitLen)
	if L1.Cmp(L2) == 0 {
		t.Errorf("L1 == L2")
	}
	
	h1, r1 := Hash(pk, L1, m1)
	t.Log("h1.h: ", h1.H.String())
	t.Log("r1.r1: ", r1.R_1.String())
	t.Log("r1.r2: ", r1.R_2.String())
	if !Check(h1, r1, pk, L1, m1) {
		t.Errorf("H(L1, m1) invalid")
	}
	if Check(h1, r1, pk, L2, m1) {
		t.Error()
	}
	
	h2, r2 := Hash(pk, L2, m2)
	if !Check(h2, r2, pk, L2, m2) {
		t.Errorf("H(L2, m2) invalid")
	}
	if Check(h2, r2, pk, L1, m2) {
		t.Error()
	}
	
	if Check(h1, r1, pk, L2, m2) {
		t.Error()
	}
	if Check(h2, r2, pk, L1, m1) {
		t.Error()
	}
	
	r1_p := Adapt(h1, pk, sk, L1, m2)
	t.Log("r1_p.r1: ", r1_p.R_1.String())
	t.Log("r1_p.r2: ", r1_p.R_2.String())
	if !Check(h1, r1_p, pk, L1, m2) {
		t.Errorf("adapt m2 invalid")
	}
}

func Test_Native(t *testing.T) {
	cases := []struct {
		bitLen int64
	}{
		{512},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("case %d bitLen %d", i+1, c.bitLen), func(t *testing.T) {
			run_scheme(t, c.bitLen)
		})
	}
}


