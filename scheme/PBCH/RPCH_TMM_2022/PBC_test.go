package RPCH_TMM_2022

import (
	"fmt"
	"testing"

	"github.com/Hugu1e/ChameLibGo/base/BinaryTree"
	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
	"github.com/Nik-U/pbc"
)

func run_scheme(t *testing.T, cur curve.Curve, swap bool, g pbc.Field, n int) {
	SP, mpk, msk := SetUp(cur, swap, g)

	BT := BinaryTree.NewBinaryTree(n)
	rl := BinaryTree.NewRevokeList()

	MSP := SP.SP_RABE.Pp_FAME.NewPBCMatrix()
	pl := SP.SP_RABE.Pp_FAME.NewPolicyList()
	utils.GenLSSSPBCMatrices(MSP, pl, "A&(DDDD|(BB&CCC))")
	
	S1 := utils.NewAttributeList()
	S1.Add("A")
	S1.Add("DDDD")
	
	S2 := utils.NewAttributeList()
	S2.Add("BB")
	S2.Add("CCC")
	
	S3 := utils.NewAttributeList()
	S3.Add("A")
	S3.Add("BB")
	S3.Add("CCC")

	id1 := SP.GP.GetZrElement()
	pk1, sk1:= KeyGen(BT, SP, mpk, msk, S1, id1)
	
	id2 := SP.GP.GetZrElement()
	pk2, _ := KeyGen(BT, SP, mpk, msk, S2, id2)
	
	// pk3, sk3 := KeyGen(BT, SP, mpk, msk, S3, id1)
	
	Revoke(rl, id1, 10)
	Revoke(rl, id2, 100)
	
	ku1 := UpdateKeyGen(SP, mpk, BT, rl, 5)
	// ku2 := UpdateKeyGen(SP, mpk, BT, rl, 50)

	dk_1_1 := DecryptKeyGen(SP, mpk, sk1, ku1, BT, rl)
	// dk_1_2 := DecryptKeyGen(SP, mpk, sk1, ku2, BT, rl)
	// dk_2_1 := DecryptKeyGen(SP, mpk, sk2, ku1, BT, rl)
	// dk_2_2 := DecryptKeyGen(SP, mpk, sk2, ku2, BT, rl)
	// dk_3_1 := DecryptKeyGen(SP, mpk, sk3, ku1, BT, rl)
	// dk_3_2 := DecryptKeyGen(SP, mpk, sk3, ku2, BT, rl)
	
	m1 := SP.GP_CHET.GetZrElement()
	m2 := SP.GP_CHET.GetZrElement()
	
	h1, r1 := Hash(SP, mpk, pk1, MSP, m1, 5)
	if !Check(h1, r1, pk1, m1) {
		t.Errorf("H(m1) invalid")
	}
	if Check(h1, r1, pk1, m2) {
		t.Error()
	}
	if Check(h1, r1, pk2, m1) {
		t.Error()
	}
	if Check(h1, r1, pk1, m2) {
		t.Error()
	}

	
	h2, r2 := Hash(SP, mpk, pk2, MSP, m2, 50)
	if !Check(h2, r2, pk2, m2) {
		t.Errorf("H(m2) invalid")
	}
	if Check(h2, r2, pk2, m1) {
		t.Error()
	}
	
	r1_p := Adapt(h1, r1, SP, pk1, dk_1_1, MSP, m1, m2)
	if !Check(h1, r1_p, pk1, m2) {
		t.Errorf("Adapt(m2) invalid")
	}
	if Check(h1, r1_p, pk1, m1) {
		t.Error()
	}
}

func Test_PBC(t *testing.T) {
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
			run_scheme(t, c.cur, c.swap, c.g, c.node)
		})
	}

}
