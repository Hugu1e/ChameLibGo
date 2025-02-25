package DPCH_MXN_2022

import (
	"fmt"
	"testing"

	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
)

func run_scheme(t *testing.T, curve curve.Curve, auth_nums int, lamuda int64){
	SP, MPK, MSK := SetUp(curve, lamuda)

	MSP := SP.GP_MA_ABE.NewPBCMatrix()
	pl := SP.GP_MA_ABE.NewPolicyList()
	utils.GenLSSSPBCMatrices(MSP, pl, "(A|FF)&(DDDD|(BB&CCC))")

	GID1 := "WCjrCK"
	GID2 := "Hugu1e"

	mod1 := NewModifier(GID1)
	mod2 := NewModifier(GID2)
	
	ModSetup(mod1, SP, MSK)
	ModSetup(mod2, SP, MSK)

	auths := make([]*Authority, auth_nums)
	for i := 0; i < auth_nums; i++ {
		auths[i] = NewAuthority(fmt.Sprintf("auth_%d", i))
	}
	auths[0].MA_ABE_Auth.ControlAttr = append(auths[0].MA_ABE_Auth.ControlAttr, "A")
	auths[1].MA_ABE_Auth.ControlAttr = append(auths[1].MA_ABE_Auth.ControlAttr, "BB")
	auths[2].MA_ABE_Auth.ControlAttr = append(auths[2].MA_ABE_Auth.ControlAttr, "CCC")
	auths[3].MA_ABE_Auth.ControlAttr = append(auths[3].MA_ABE_Auth.ControlAttr, "DDDD")
	auths[4].MA_ABE_Auth.ControlAttr = append(auths[4].MA_ABE_Auth.ControlAttr, "E")
	auths[5].MA_ABE_Auth.ControlAttr = append(auths[5].MA_ABE_Auth.ControlAttr, "FF")

	for i := 0; i < auth_nums; i++ {
		AuthSetup(auths[i], SP)
	}

	PKG := new(PublicKeyGroup)
	for i := 0; i < auth_nums; i++ {
		PKG.AddPK(auths[i])
	}

	SKG1 := new(SecretKeyGroup)
	SKG3 := new(SecretKeyGroup)
	ModKeyGen(mod1, SP, MPK, auths[0], "A")
	SKG1.AddSK(mod1)
	SKG3.AddSK(mod1)
	ModKeyGen(mod1, SP, MPK, auths[3], "DDDD")
	SKG1.AddSK(mod1)
	ModKeyGen(mod1, SP, MPK, auths[4], "E")
	SKG1.AddSK(mod1)

	SKG2 := new(SecretKeyGroup)
	ModKeyGen(mod2, SP, MPK, auths[1], "BB")
	SKG2.AddSK(mod2)
	SKG3.AddSK(mod2)
	ModKeyGen(mod2, SP, MPK, auths[2], "CCC")
	SKG2.AddSK(mod2)
	SKG3.AddSK(mod2)
	ModKeyGen(mod2, SP, MPK, auths[5], "FF")
	SKG2.AddSK(mod2)

	m1 := utils.GenerateBigNumber(lamuda)
	m2 := utils.GenerateBigNumber(lamuda)
	if m1.Cmp(m2) == 0 {
		t.Error("m1 == m2")
	}
	
	h1, r1 := Hash(PKG, MSP, SP, MPK, m1)
	t.Log("h1.H.H_1.H:", h1.H.H_1.H.String())
	t.Log("h1.H.H_2.H:", h1.H.H_2.H.String())
	t.Log("h1.H.Pk_ch_2.N:", h1.H.Pk_ch_2.N.String())
	t.Log("h1.H.Pk_ch_2.E:", h1.H.Pk_ch_2.E.String())
	t.Log("h1.C_SE.Ct:", fmt.Sprintf("%x", h1.C_SE.Ct))
	t.Log("h1.C_MA_ABE.C_0:", h1.C_MA_ABE.C_0.String())
	// for i := range h1.C_MA_ABE.C{
	// 	for j := range h1.C_MA_ABE.C[i]{
	// 		t.Log(fmt.Sprintf("h1.C_MA_ABE.C[%d][%d]:", i, j), h1.C_MA_ABE.C[i][j].String())
	// 	}
	// }
	t.Log("r1.R.R_1.R:", r1.R.R_1.R.String())
	t.Log("r1.R.R_2.R:", r1.R.R_2.R.String())
	if !Check(h1, r1, MPK, m1){
		t.Error("H(m1) invalid")
	}
	if Check(h1, r1, MPK, m2){
		t.Error()
	}

	h2, r2 := Hash(PKG, MSP, SP, MPK, m2)
	if !Check(h2, r2, MPK, m2){
		t.Error("H(m2) invalid")
	}
	if Check(h2, r2, MPK, m1){
		t.Error()
	}

	r1_p := Adapt(h1, r1, PKG, SKG1, MSP, SP, MPK, MSK, m1, m2)
	t.Log("r1_p.R.R_1.R:", r1_p.R.R_1.R.String())
	t.Log("r1_p.R.R_2.R:", r1_p.R.R_2.R.String())
	if !Check(h1, r1_p, MPK, m2){
		t.Error("adapt m2 invalid")
	}
	if Check(h1, r1_p, MPK, m1){
		t.Error()
	}
	
	r1_p = Adapt(h1, r1, PKG, SKG2, MSP, SP, MPK, MSK, m1, m2)
	t.Log("r1_p.R.R_1.R:", r1_p.R.R_1.R.String())
	t.Log("r1_p.R.R_2.R:", r1_p.R.R_2.R.String())
	if !Check(h1, r1_p, MPK, m2){
		t.Error("adapt m2 invalid")
	}
	if Check(h1, r1_p, MPK, m1){
		t.Error()
	}
}

func TestPBC(t *testing.T) {
	curs := []curve.Curve{
		curve.A,
		curve.A1,
		curve.E,
	}
	auth_nums := []int{16, 32, 64}
	lamudas := []int64{256, 512, 1024}

	cases := []struct {
		cur curve.Curve
		auth_num int
		lamuda int64
	}{}

	for _, c := range curs {
		for _, l := range auth_nums {
			for _, lam := range lamudas {
				cases = append(cases, struct {
					cur  curve.Curve
					auth_num  int
					lamuda int64
				}{
					cur:  c,
					auth_num:  l,
					lamuda: lam,
				})
			}
		}
	}

	for i, c := range cases {
		curveName := curve.CurveName[c.cur]
		t.Run(fmt.Sprintf("case %d %s auth_num %d lamuda %d", i+1, curveName, c.auth_num, c.lamuda), func(t *testing.T) {
			run_scheme(t, c.cur, c.auth_num, c.lamuda)
		})
	}

}