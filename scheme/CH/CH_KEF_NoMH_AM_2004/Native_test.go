package CH_KEF_NoMH_AM_2004

import (
	"fmt"
	"testing"

	"github.com/Hugu1e/ChameLibGo/utils"
)

func run_scheme(t *testing.T, k int64) {
	pk, sk := KeyGen(k)

	m1 := utils.GenerateBigNumber(k/2)
	m2 := utils.GenerateBigNumber(k/2)
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
	cases := []struct {
		k int64
	}{
		{512},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("case %d k %d", i+1, c.k), func(t *testing.T) {
			run_scheme(t, c.k)
		})
	}
}


