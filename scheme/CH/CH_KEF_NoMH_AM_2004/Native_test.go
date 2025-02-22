package CH_KEF_NoMH_AM_2004

import (
	"testing"

	"github.com/Hugu1e/ChameLibGo/utils"
)

func run_scheme(t *testing.T){
	pk, sk := KeyGen(512)

	m1 := utils.GenerateBigNumber(256)
	m2 := utils.GenerateBigNumber(256)
	if m1.Cmp(m2) == 0 {
		t.Errorf("m1 == m2")
	}
	
	h1, r1 := Hash(pk, m1)
	if !Check(h1, r1, pk, m1) {
		t.Errorf("H(m1) invalid")
	}

	h2, r2 := Hash(pk, m2)
	if !Check(h2, r2, pk, m2) {
		t.Errorf("H(m2) invalid")
	}
	
	if Check(h1, r1, pk, m2) {
		t.Error()
	}
	if Check(h2, r2, pk, m1) {
		t.Error()
	}
	
	r1_p := Adapt(pk, sk, m2, h1)
	if !Check(h1, r1_p, pk, m2) {
		t.Errorf("Adapt(m2) invalid")
	}
}

func Test_Native(t *testing.T) {
	run_scheme(t)
}


