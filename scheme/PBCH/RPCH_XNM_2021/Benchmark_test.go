package RPCH_XNM_2021

import (
	"flag"
	"fmt"
	"math/big"
	"testing"

	"github.com/Hugu1e/ChameLibGo/base/BinaryTree"
	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
	"github.com/Nik-U/pbc"
)

var (
	r = flag.Int("repeat", 100, "repeat times")
)

func run_scheme_benchmark(t *testing.T, cur curve.Curve, swap bool, k int64, n int) {
	repeat := *r
	timer := utils.NewTimer(t.Name(), repeat)

	SP := make([]*PublicParam, repeat)
	MPK := make([]*MasterPublicKey, repeat)
	MSK := make([]*MasterSecretKey, repeat)

	timer.Start("SetUp")
	for i := 0; i < repeat; i++ {
		SP[i], MPK[i], MSK[i] = SetUp(cur, swap, k)
	}
	timer.End("SetUp")

	BT := make([]*BinaryTree.BinaryTree, repeat)
	rl := make([]*BinaryTree.RevokeList, repeat)
	for i := 0; i < repeat; i++ {
		BT[i] = BinaryTree.NewBinaryTree(n)
		rl[i] = BinaryTree.NewRevokeList()
	}

	MSP := make([]*utils.PBCMatrix, repeat)
	pl := make([]*utils.PolicyList, repeat)
	for i := 0; i < repeat; i++ {
		MSP[i] = SP[i].SP_RABE.Pp_FAME.NewPBCMatrix()
		pl[i] = SP[i].SP_RABE.Pp_FAME.NewPolicyList()
		utils.GenLSSSPBCMatrices(MSP[i], pl[i], "A&(DDDD|(BB&CCC))")
	}

	S1 := utils.NewAttributeList()
	S1.Add("A")
	S1.Add("DDDD")

	id1 := make([]*pbc.Element, repeat)
	sk1 := make([]*SecretKey, repeat)

	for i := 0; i < repeat; i++ {
		id1[i] = SP[i].GP.GetZrElement()
	}

	timer.Start("KeyGen")
	for i := 0; i < repeat; i++ {
		sk1[i] = KeyGen(BT[i], SP[i], MPK[i], MSK[i], S1, id1[i])
	}
	timer.End("KeyGen")

	timer.Start("Revoke")
	for i := 0; i < repeat; i++ {
		Revoke(rl[i], id1[i], 10)
	}
	timer.End("Revoke")

	ku1 := make([]*UpdateKey, repeat)
	timer.Start("UpdateKeyGen")
	for i := 0; i < repeat; i++ {
		ku1[i] = UpdateKeyGen(SP[i], MPK[i], BT[i], rl[i], 5)
	}
	timer.End("UpdateKeyGen")

	dk_1_1 := make([]*DecryptKey, repeat)
	timer.Start("DecryptKeyGen")
	for i := 0; i < repeat; i++ {
		dk_1_1[i] = DecryptKeyGen(SP[i], MPK[i], sk1[i], ku1[i], BT[i], rl[i])
	}
	timer.End("DecryptKeyGen")

	m1 := make([]*big.Int, repeat)
	m2 := make([]*big.Int, repeat)
	for i := 0; i < repeat; i++ {
		m1[i] = utils.GenerateBigNumber(k)
		m2[i] = utils.GenerateBigNumber(k)
	}

	h1 := make([]*HashValue, repeat)
	r1 := make([]*Randomness, repeat)
	timer.Start("Hash")
	for i := 0; i < repeat; i++ {
		h1[i], r1[i] = Hash(SP[i], MPK[i], MSP[i], m1[i], 5)
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
		r1_p[i] = Adapt(h1[i], r1[i], SP[i], MPK[i], dk_1_1[i], MSP[i], m1[i], m2[i])
	}
	timer.End("Adapt")

	for i := 0; i < repeat; i++ {
		if !Check(h1[i], r1_p[i], MPK[i], m2[i]) {
			t.Fatal("Adapt(m2) invalid")
		}
	}

	timer.AverageAndEnd()
}

func TestRPCH_XNM_2021(t *testing.T) {
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
	ks := []int64{
		128,
		256,
		512,
	}
	nodes := []int{
		16,
		32,
		64,
	}

	cases := []struct {
		cur   curve.Curve
		swap  bool
		k     int64
		node  int
	}{}

	for _, c := range curs {
		for _, s := range swaps {
			for _, k := range ks {
				for _, n := range nodes {
					cases = append(cases, struct {
						cur   curve.Curve
						swap  bool
						k     int64
						node  int
					}{
						cur:   c,
						swap:  s,
						k:	   k,
						node:  n,
					})
				}
			}
		}
	}

	for i, c := range cases {
		curveName := curve.CurveName[c.cur]
		t.Run(fmt.Sprintf("case %d %s swap %v k %d leafnodes %d", i+1, curveName, c.swap, c.k, c.node), func(t *testing.T) {
			run_scheme_benchmark(t, c.cur, c.swap, c.k, c.node)
		})
	}

}
