package RSA

import (
	"testing"

	"github.com/Hugu1e/ChameLibGo/utils"
)

func TestRSA(t *testing.T) {
	pk, sk := KeyGen()

	m1 := utils.GenerateBigNumber(1024)
	m2 := utils.GenerateBigNumber(1024)
	if m1.Cmp(m2) == 0 {
		t.Errorf("m1 == m2")
	}

	c1 := Encrypt(m1, pk)
	c2 := Encrypt(m2, pk)
	if c1.Cmp(c2) == 0 {
		t.Errorf("c1 == c2")
	}

	m1p := Decrypt(c1, pk, sk)
	m2p := Decrypt(c2, pk, sk)
	if m1p.Cmp(m2p) == 0 {
		t.Errorf("m1p == m2p")
	}
	if m1.Cmp(m1p) != 0 {
		t.Errorf("m1 != m1p")
	}
	if m2.Cmp(m2p) != 0 {
		t.Errorf("m2 != m2p")
	}
}