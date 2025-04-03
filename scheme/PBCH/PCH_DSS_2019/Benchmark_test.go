package PCH_DSS_2019

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

func run_scheme_benchmark(t *testing.T, cur curve.Curve, swap bool, lamuda int64) {
	repeat := *r
	timer := utils.NewTimer(t.Name(), repeat)

	pp_PCH := make([]*PublicParam, repeat)
	pk_PCH := make([]*MasterPublicKey, repeat)
	sk_PCH := make([]*MasterSecretKey, repeat)

	timer.Start("SetUp")
	for i := 0; i < repeat; i++ {
		pp_PCH[i], pk_PCH[i], sk_PCH[i] = SetUp(cur, swap, lamuda)
	}
	timer.End("SetUp")

	MSP := make([]*utils.PBCMatrix, repeat)
	pl := make([]*utils.PolicyList, repeat)
	for i := 0; i < repeat; i++ {
		MSP[i] = pp_PCH[i].Pp_ABE.NewPBCMatrix()
		pl[i] = pp_PCH[i].Pp_ABE.NewPolicyList()
		utils.GenLSSSPBCMatrices(MSP[i], pl[i], "A&(DDDD|(BB&CCC))")
	}

	S1 := utils.NewAttributeList()
	S1.Add("A")
	S1.Add("DDDD")

	sk1 := make([]*SecretKey, repeat)
	timer.Start("KeyGen")
	for i := 0; i < repeat; i++ {
		sk1[i] = KeyGen(pp_PCH[i], pk_PCH[i], sk_PCH[i], S1)
	}
	timer.End("KeyGen")

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
		h1[i], r1[i] = Hash(pp_PCH[i], pk_PCH[i], MSP[i], m1[i])
	}
	timer.End("Hash")

	checkRes := make([]bool, repeat)
	timer.Start("Check")
	for i := 0; i < repeat; i++ {
		checkRes[i] = Check(h1[i], r1[i], pk_PCH[i], m1[i])
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
		r1_p[i] = Adapt(h1[i], r1[i], pp_PCH[i], pk_PCH[i], MSP[i], sk1[i], m1[i], m2[i])
	}
	timer.End("Adapt")

	for i := 0; i < repeat; i++ {
		if !Check(h1[i], r1_p[i], pk_PCH[i], m2[i]) {
			t.Fatal("Adapt(m2) invalid")
		}
	}

	timer.AverageAndEnd()
}

func TestPCH_DSS_2019(t *testing.T) {
	curs := []curve.Curve{
		curve.A,
		curve.A1,
		curve.D_159,
		curve.D_201,
		curve.D_224,
		curve.D_105171_196_185,
		curve.D_277699_175_167,
		curve.D_278027_190_181,
		curve.E,
		curve.F,
		curve.SM_9,
		curve.G_149,
	}
	swaps := []bool{false, true}
	lamudas := []int64{
		256,
		512,
		1024,
	}

	cases := []struct {
		cur   curve.Curve
		swap  bool
		lamuda int64
	}{}

	for _, c := range curs {
		for _, s := range swaps {
			for _, l := range lamudas {
				cases = append(cases, struct {
					cur   curve.Curve
					swap  bool
					lamuda int64
				}{
					cur:   c,
					swap:  s,
					lamuda: l,
				})
			}
		}
	}

	for i, c := range cases {
		curveName := curve.CurveName[c.cur]
		t.Run(fmt.Sprintf("case %d %s swap %v lamuda %d", i+1, curveName, c.swap, c.lamuda), func(t *testing.T) {
			run_scheme_benchmark(t, c.cur, c.swap, c.lamuda)
		})
	}

}
