package DPCH_MXN_2022

import (
	"flag"
	"fmt"
	"math/big"
	"testing"

	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
)

var (
	r = flag.Int("repeat", 100, "repeat times")
)

func run_scheme_benchmark(t *testing.T, curve curve.Curve, auth_nums int, lamuda int64){
	repeat := *r
	timer := utils.NewTimer(t.Name(), repeat)

	SP := make([]*PublicParam, repeat)
	MPK := make([]*MasterPublicKey, repeat)
	MSK := make([]*MasterSecretKey, repeat)

	timer.Start("SetUp")
	for i := 0; i < repeat; i++ {
		SP[i], MPK[i], MSK[i] = SetUp(curve, lamuda)
	}
	timer.End("SetUp")

	MSP := make([]*utils.PBCMatrix, repeat)
	pl := make([]*utils.PolicyList, repeat)
	for i := 0; i < repeat; i++ {
		MSP[i] = SP[i].GP_MA_ABE.NewPBCMatrix()
		pl[i] = SP[i].GP_MA_ABE.NewPolicyList()
		utils.GenLSSSPBCMatrices(MSP[i], pl[i], "(A|FF)&(DDDD|(BB&CCC))")
	}

	GID1 := "WCjrCK"

	mod1 := make([]*Modifier, repeat)
	for i := 0; i < repeat; i++ {
		mod1[i] = NewModifier(GID1)
	}
	timer.Start("ModSetup")
	for i := 0; i < repeat; i++ {
		ModSetup(mod1[i], SP[i], MSK[i])
	}
	timer.End("ModSetup")

	auths := make([][]*Authority, repeat)
	for i := 0; i < repeat; i++ {
		auths[i] = make([]*Authority, auth_nums)
		for j := 0; j < auth_nums; j++ {
			auths[i][j] = NewAuthority(fmt.Sprintf("auth_%d", j))
		}
		auths[i][0].MA_ABE_Auth.ControlAttr = append(auths[i][0].MA_ABE_Auth.ControlAttr, "A")
		auths[i][1].MA_ABE_Auth.ControlAttr = append(auths[i][1].MA_ABE_Auth.ControlAttr, "BB")
		auths[i][2].MA_ABE_Auth.ControlAttr = append(auths[i][2].MA_ABE_Auth.ControlAttr, "CCC")
		auths[i][3].MA_ABE_Auth.ControlAttr = append(auths[i][3].MA_ABE_Auth.ControlAttr, "DDDD")
		auths[i][4].MA_ABE_Auth.ControlAttr = append(auths[i][4].MA_ABE_Auth.ControlAttr, "E")
		auths[i][5].MA_ABE_Auth.ControlAttr = append(auths[i][5].MA_ABE_Auth.ControlAttr, "FF")

		timer.Start("AuthSetup")
		for j := 0; j < auth_nums; j++ {
			AuthSetup(auths[i][j], SP[i])
		}
		timer.End("AuthSetup")
	}
	timer.AverageN("AuthSetup", auth_nums)

	PKG := make([]*PublicKeyGroup, repeat)
	for i := 0; i < repeat; i++ {
		PKG[i] = new(PublicKeyGroup)
		for j := 0; j < auth_nums; j++ {
			PKG[i].AddPK(auths[i][j])
		}
	}

	SKG1 := make([]*SecretKeyGroup, repeat)
	for i := 0; i < repeat; i++ {
		SKG1[i] = new(SecretKeyGroup)
		timer.Start("ModKeyGen")
		ModKeyGen(mod1[i], SP[i], MPK[i], auths[i][0], "A")
		timer.End("ModKeyGen")
		SKG1[i].AddSK(mod1[i])
		ModKeyGen(mod1[i], SP[i], MPK[i], auths[i][3], "DDDD")
		SKG1[i].AddSK(mod1[i])
		ModKeyGen(mod1[i], SP[i], MPK[i], auths[i][4], "E")
		SKG1[i].AddSK(mod1[i])
	}

	m1 := make([]*big.Int, repeat)
	m2 := make([]*big.Int, repeat)
	for i := 0; i < repeat; i++ {
		m1[i] = utils.GenerateBigNumber(lamuda)
		m2[i] = utils.GenerateBigNumber(lamuda)
	}

	h1 := make([]*HashValue, repeat)
	r1 := make([]*Randomness, repeat)
	timer.Start("Hash")
	for i := 0; i < repeat; i++ {
		h1[i], r1[i] = Hash(PKG[i], MSP[i], SP[i], MPK[i], m1[i])
	}
	timer.End("Hash")

	checkRes := make([]bool, repeat)
	timer.Start("Check")
	for i := 0; i < repeat; i++ {
		checkRes[i] = Check(h1[i], r1[i], MPK[i], m1[i])
	}
	timer.End("Check")
	for i := 0; i < repeat; i++ {
		if !checkRes[i] {
			t.Fatal("H(m1) invalid")
		}
	}
	
	r1_p := make([]*Randomness, repeat)
	timer.Start("Adapt")
	for i := 0; i < repeat; i++ {
		r1_p[i] = Adapt(h1[i], r1[i], PKG[i], SKG1[i], MSP[i], SP[i], MPK[i], MSK[i], m1[i], m2[i])
	}
	timer.End("Adapt")
	for i := 0; i < repeat; i++ {
		if !Check(h1[i], r1_p[i], MPK[i], m2[i]) {
			t.Fatal("adapt m2 invalid")
		}
	}

	timer.AverageAndEnd()
}

func TestDPCH_MXN_2022(t *testing.T) {
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
			run_scheme_benchmark(t, c.cur, c.auth_num, c.lamuda)
		})
	}

}