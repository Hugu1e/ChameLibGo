package MA_ABE

import (
	"fmt"
	"testing"

	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
)

func run_scheme(t *testing.T, curve curve.Curve, auth_nums int){
	GP := GlobalSetup(curve)

	MSP := GP.NewPBCMatrix()
	pl := GP.NewPolicyList()
	utils.GenLSSSPBCMatrices(MSP, pl, "(A|FF)&(DDDD|(BB&CCC))")
	t.Log("PolicyList:", pl.Policy)
	t.Log("MSP.Policy:", MSP.Policy)
	t.Log("MSP.Formula:", MSP.Formula)
	MSP.PrintMatrix()
	
	GID1 := "WCjrCK"
	GID2 := "Hugu1e"

	PKG := new(PublicKeyGroup)

	auths := make([]*Authority, auth_nums)
	for i := 0; i < auth_nums; i++ {
		auths[i] = NewAuthority(fmt.Sprintf("theta_a_%d", i))
	}
	auths[0].ControlAttr = append(auths[0].ControlAttr, "A")
	auths[1].ControlAttr = append(auths[1].ControlAttr, "BB")
	auths[2].ControlAttr = append(auths[2].ControlAttr, "CCC")
	auths[3].ControlAttr = append(auths[3].ControlAttr, "DDDD")
	auths[4].ControlAttr = append(auths[4].ControlAttr, "E")
	auths[5].ControlAttr = append(auths[5].ControlAttr, "FF")

	for i := 0; i < auth_nums; i++ {
		AuthSetup(auths[i], GP)
	}

	for i := 0; i < auth_nums; i++ {
		PKG.AddPK(auths[i])
	}

	SKG1 := new(SecretKeyGroup)
	SKG3 := new(SecretKeyGroup)
	SK1 := KeyGen(auths[0], "A", GP, GID1)
	SKG1.AddSK(SK1);
	SKG3.AddSK(SK1);
	SK1 = KeyGen(auths[3], "DDDD", GP, GID1)
	SKG1.AddSK(SK1);
	SK1 = KeyGen(auths[4], "E", GP, GID1)
	SKG1.AddSK(SK1);
	
	SKG2 := new(SecretKeyGroup)
	SK2 := KeyGen(auths[1], "BB", GP, GID2)
	SKG2.AddSK(SK2);
	SKG3.AddSK(SK2);
	SK2 = KeyGen(auths[2], "CCC", GP, GID2)
	SKG2.AddSK(SK2);
	SKG3.AddSK(SK2);
	SK2 = KeyGen(auths[5], "FF", GP, GID2)
	SKG2.AddSK(SK2);

	m1 := NewPlainText(GP)
	m2 := NewPlainText(GP)
	if m1.Equals(m2) {
		t.Error("m1 == m2")
	}

	c1 := Encrypt(GP, PKG, MSP, m1)
	t.Log("c1.C_0:", c1.C_0.String())
	// for i := range c1.C {
	// 	for j := range c1.C[i] {
	// 		t.Log("c1.C[", i, "][", j, "]:", c1.C[i][j].String())
	// 	}
	// }
	c2 := Encrypt(GP, PKG, MSP, m2)

	m3 := Decrypt(GP, SKG1, MSP, c1)
	if !m3.Equals(m1) {
		t.Error("decrypt(c1) != m1")
	}
	if m3.Equals(m2) {
		t.Error()
	}
	
	m3 = Decrypt(GP, SKG2, MSP, c2)
	if !m3.Equals(m2) {
		t.Error("decrypt(c2) != m2")
	}
	
	m3 = Decrypt(GP, SKG3, MSP, c1)
	if m3.Equals(m1) {
		t.Error()
	}
	if m3.Equals(m2) {
		t.Error()
	}
}

func Test_PBC(t *testing.T) {
	curs := []curve.Curve{
		curve.A,
		curve.A1,
		curve.E,
	}
	auth_nums := []int{16, 32, 64}

	cases := []struct {
		cur curve.Curve
		auth_num int
	}{}

	for _, c := range curs {
		for _, l := range auth_nums {
			cases = append(cases, struct {
				cur  curve.Curve
				auth_num  int
			}{
				cur:  c,
				auth_num:  l,
			})
		}
	}

	for i, c := range cases {
		curveName := curve.CurveName[c.cur]
		t.Run(fmt.Sprintf("case %d %s auth_num %d", i+1, curveName,c.auth_num), func(t *testing.T) {
			run_scheme(t, c.cur, c.auth_num)
		})
	}

}