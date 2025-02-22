package CH_KEF_MH_RSA_F_AM_2004

import (
	"testing"

	"github.com/Hugu1e/ChameLibGo/utils"
)

func run_scheme(t *testing.T){
	pp := SetUp(512, 1024)

	pk, sk := KeyGen(pp)

	m1 := utils.GenerateBigNumber(256)
	m2 := utils.GenerateBigNumber(256)
	if m1.Cmp(m2) == 0 {
		t.Errorf("m1 == m2")
	}

	L1 := utils.GenerateBigNumber(512)
	L2 := utils.GenerateBigNumber(512)
	if L1.Cmp(L2) == 0 {
		t.Errorf("L1 == L2")
	}

	h1, r1 := Hash(pk, L1, m1, pp)
	t.Log("h1.h: ", h1.H.String())
	t.Log("r1.r: ", r1.R.String())
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
	t.Log("r1_p.r: ", r1_p.R.String())
	if !Check(h1, r1_p, pk, L1, m2, pp) {
		t.Errorf("adapt m2 invalid")
	}
	
	r1_p = Adapt(r1, pk, sk, L2, m1, m2, pp)
	if Check(h1, r1_p, pk, L2, m2, pp) {
		t.Error()
	}
}

func Test_Native(t *testing.T) {
	run_scheme(t)
}


