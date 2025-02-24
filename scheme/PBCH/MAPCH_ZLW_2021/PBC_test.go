package MAPCH_ZLW_2021

import (
	"fmt"
	"testing"

	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
)

func run_scheme(t *testing.T, curve curve.Curve, auth_nums int, lamuda int64){
	GP := SetUp(curve, lamuda)

	// TODO 封装
	MSP := GP.GP.NewPBCMatrix()
	pl := GP.GP.NewPolicyList()
	utils.GenLSSSPBCMatrices(MSP, pl, "(A|FF)&(DDDD|(BB&CCC))")

	GID1 := "WCjrCK"
	GID2 := "Hugu1e"

	PKG := new(PublicKeyGroup)

	auths := make([]*Authority, auth_nums)
	for i := 0; i < auth_nums; i++ {
		auths[i] = NewAuthority(fmt.Sprintf("auth_%d", i), GP)
	}
	auths[0].MA_ABE_Auth.ControlAttr = append(auths[0].MA_ABE_Auth.ControlAttr, "A")
	auths[1].MA_ABE_Auth.ControlAttr = append(auths[1].MA_ABE_Auth.ControlAttr, "BB")
	auths[2].MA_ABE_Auth.ControlAttr = append(auths[2].MA_ABE_Auth.ControlAttr, "CCC")
	auths[3].MA_ABE_Auth.ControlAttr = append(auths[3].MA_ABE_Auth.ControlAttr, "DDDD")
	auths[4].MA_ABE_Auth.ControlAttr = append(auths[4].MA_ABE_Auth.ControlAttr, "E")
	auths[5].MA_ABE_Auth.ControlAttr = append(auths[5].MA_ABE_Auth.ControlAttr, "FF")

	for i := 0; i < auth_nums; i++ {
		AuthSetup(auths[i])
	}
	
	for i := 0; i < auth_nums; i++ {
		PKG.AddPK(auths[i])
	}

	SKG1 := new(SecretKeyGroup)
	SKG3 := new(SecretKeyGroup)
	
	SK1 := KeyGen(auths[0], GID1, "A")
	SKG1.AddSK(SK1)
	SKG3.AddSK(SK1)
	SK1 = KeyGen(auths[3], GID1, "DDDD")
	SKG1.AddSK(SK1)
	SK1 = KeyGen(auths[4], GID1, "E")
	SKG1.AddSK(SK1)

	SKG2 := new(SecretKeyGroup)
	SK2 := KeyGen(auths[1], GID2, "BB")
	SKG2.AddSK(SK2)
	SKG3.AddSK(SK2)
	SK2 = KeyGen(auths[2], GID2, "CCC")
	SKG2.AddSK(SK2)
	SKG3.AddSK(SK2)
	SK2 = KeyGen(auths[5], GID2, "FF")
	SKG2.AddSK(SK2)

	m1 := utils.GenerateBigNumber(lamuda)
	m2 := utils.GenerateBigNumber(lamuda)
	if m1.Cmp(m2) == 0 {
		t.Error("m1 == m2")
	}

	h1, r1 := Hash(PKG, MSP, m1, GP)
	t.Log("h1.CHET_H.H_1.H:", h1.CHET_H.H_1.H.String())
	t.Log("h1.CHET_H.H_2.H:", h1.CHET_H.H_2.H.String())
	t.Log("h1.CHET_H.Pk_ch_2.N:", h1.CHET_H.Pk_ch_2.N.String())
	t.Log("h1.CHET_H.Pk_ch_2.E:", h1.CHET_H.Pk_ch_2.E.String())
	t.Log("r1.CHET_R.R_1.R:", r1.CHET_R.R_1.R.String())
	t.Log("r1.CHET_R.R_2.R:", r1.CHET_R.R_2.R.String())

	h2, r2 := Hash(PKG, MSP, m2, GP)

	if !Check(h1, r1, PKG, m1) {
		t.Error("H(m1) invalid")
	}
	if Check(h1, r1, PKG, m2) {
		t.Error()
	}
	if !Check(h2, r2, PKG, m2) {
		t.Error("H(m2) invalid")
	}
	if Check(h2, r2, PKG, m1) {
		t.Error()
	}
	
	r1_p := Adapt(h1, r1, PKG, SKG1, MSP, m1, m2)
	t.Log("r1_p.CHET_R.R_1.R:", r1_p.CHET_R.R_1.R.String())
	t.Log("r1_p.CHET_R.R_2.R:", r1_p.CHET_R.R_2.R.String())
	if !Check(h1, r1_p, PKG, m2) {
		t.Error("adapt m2 invalid")
	}
	if Check(h1, r1_p, PKG, m1) {
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
	lamudas := []int64{32, 64,128}

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