package RPCH_TMM_2022

import (
	"flag"
	"fmt"
	"testing"

	"github.com/Hugu1e/ChameLibGo/base/BinaryTree"
	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
	"github.com/Nik-U/pbc"
)

var (
	r = flag.Int("repeat", 100, "repeat times")
)

func run_scheme_benchmark(t *testing.T, curve curve.Curve, swap bool, g pbc.Field, n int) {
	repeat := *r
	timer := utils.NewTimer(t.Name(), repeat)

	SP := make([]*PublicParam, repeat)
	MPK := make([]*MasterPublicKey, repeat)
	MSK := make([]*MasterSecretKey, repeat)

	timer.Start("SetUp")
	for i := 0; i < repeat; i++ {
		SP[i], MPK[i], MSK[i] = SetUp(curve, swap, g)
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
	pk1 := make([]*PublicKey, repeat)
	sk1 := make([]*SecretKey, repeat)

	for i := 0; i < repeat; i++ {
		id1[i] = SP[i].GP.GetZrElement()
	}

	timer.Start("KeyGen")
	for i := 0; i < repeat; i++ {
		pk1[i], sk1[i] = KeyGen(BT[i], SP[i], MPK[i], MSK[i], S1, id1[i])
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

	m1 := make([]*pbc.Element, repeat)
	m2 := make([]*pbc.Element, repeat)
	for i := 0; i < repeat; i++ {
		m1[i] = SP[i].GP_CHET.GetZrElement()
		m2[i] = SP[i].GP_CHET.GetZrElement()
	}

	h1 := make([]*HashValue, repeat)
	r1 := make([]*Randomness, repeat)
	timer.Start("Hash")
	for i := 0; i < repeat; i++ {
		h1[i], r1[i] = Hash(SP[i], MPK[i], pk1[i], MSP[i], m1[i], 5)
	}
	timer.End("Hash")

	checkRes := make([]bool, repeat)
	timer.Start("Check")
	for i := 0; i < repeat; i++ {
		checkRes[i] = Check(h1[i], r1[i], pk1[i], m1[i]) 
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
		r1_p[i] = Adapt(h1[i], r1[i], SP[i], pk1[i], dk_1_1[i], MSP[i], m1[i], m2[i])
	}
	timer.End("Adapt")

	for i := 0; i < repeat; i++ {
		if !Check(h1[i], r1_p[i], pk1[i], m2[i]) {
			t.Fatal("Adapt(m2) invalid")
		}
	}

	timer.AverageAndEnd()
}

func TestRPCH_TMM_2022(t *testing.T) {
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
	groups := []pbc.Field{
		pbc.G1,
		pbc.G2,
		pbc.GT,
	}
	nodes := []int{
		16,
		32,
		64,
	}

	cases := []struct {
		cur   curve.Curve
		swap  bool
		g     pbc.Field
		node  int
	}{}

	for _, c := range curs {
		for _, s := range swaps {
			for _, g := range groups {
				for _, n := range nodes {
					cases = append(cases, struct {
						cur   curve.Curve
						swap  bool
						g     pbc.Field
						node  int
					}{
						cur:   c,
						swap:  s,
						g:	   g,
						node:  n,
					})
				}
			}
		}
	}

	for i, c := range cases {
		curveName := curve.CurveName[c.cur]
		groupName := ""
		switch c.g {
		case pbc.G1:
			groupName = "G1"
		case pbc.G2:
			groupName = "G2"
		case pbc.GT:
			groupName = "GT"
		}
		t.Run(fmt.Sprintf("case %d %s swap %v gropu %s leafnodes %d", i+1, curveName, c.swap, groupName, c.node), func(t *testing.T) {
			run_scheme_benchmark(t, c.cur, c.swap, c.g, c.node)
		})
	}

}
