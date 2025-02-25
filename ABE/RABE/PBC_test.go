package RABE

import (
	"fmt"
	"testing"

	"github.com/Hugu1e/ChameLibGo/base/BinaryTree"
	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
)

func run_scheme(t *testing.T, cur curve.Curve, swap bool, num int) {
	SP, mpk, msk := SetUp(XNM_2021, cur, swap)

	BT := BinaryTree.NewBinaryTree(num)
	rl := BinaryTree.NewRevokeList()

	MSP := SP.Pp_FAME.NewPBCMatrix()
	pl := SP.Pp_FAME.NewPolicyList()
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
	sk1 := KeyGen(BT, SP, mpk, msk, S1, id1)
	
	id2 := SP.GP.GetZrElement()
	sk2 := KeyGen(BT, SP, mpk, msk, S2, id2)

	sk3 := KeyGen(BT, SP, mpk, msk, S3, id1)

	Revoke(rl, id1, 10)
	Revoke(rl, id2, 100)

	m1 := NewPlainText(SP.GP.GetGTElement())
	t.Log("m1:", m1.M.String())
	m2 := NewPlainText(SP.GP.GetGTElement())

	ct1 := Encrypt(SP, mpk, MSP, m1, 5)
	ct2 := Encrypt(SP, mpk, MSP, m2, 50)

	ku1 := UpdateKeyGen(SP, mpk, BT, rl, 5)
	// ku2 := UpdateKeyGen(SP, mpk, BT, rl, 50)
	
	dk_1_1 := DecryptKeyGen(SP, mpk, sk1, ku1, BT, rl)
	// dk_1_2 := DecryptKeyGen(SP, mpk, sk1, ku2, BT, rl)
	dk_2_1 := DecryptKeyGen(SP, mpk, sk2, ku1, BT, rl)
	// dk_2_2 := DecryptKeyGen(SP, mpk, sk2, ku2, BT, rl)
	dk_3_1 := DecryptKeyGen(SP, mpk, sk3, ku1, BT, rl)
	// dk_3_2 := DecryptKeyGen(SP, mpk, sk3, ku2, BT, rl)
	

	m3 := Decrypt(SP, dk_1_1, MSP, ct1)
	t.Log("m3:", m3.M.String())
	if !m3.Equals(m1) {
		t.Errorf("decrypt(dk_1_1, ct1) != m1")
	}

	m3 = Decrypt(SP, dk_2_1, MSP, ct1)
	if m3.Equals(m1) {
		t.Errorf("policy false")
	}
	
	m3 = Decrypt(SP, dk_3_1, MSP, ct1)
	if !m3.Equals(m1) {
		t.Errorf("decrypt(dk_3_1, ct1) != m1")
	}

	m3 = Decrypt(SP, dk_1_1, MSP, ct2)
	if m3.Equals(m2) {
		t.Errorf("different time")
	}

	// m3 = Decrypt(SP, dk_1_2, MSP, ct2);

	// assertThrows(NullPointerException.class, () -> {
	// 	scheme.Decrypt(m3, SP, dk_1_2, MSP, ct2);
	// 	assertFalse(m3.isEqual(m1), "decrypt(dk_1_2, ct1) != m1");
	// }, "id1 expired");
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
	nums := []int{
		16,
		32,
		64,
	}

	cases := []struct {
		cur   curve.Curve
		swap  bool
		num int
	}{}

	for _, c := range curs {
		for _, s := range swaps {
			for _, n := range nums {
				cases = append(cases, struct {
					cur   curve.Curve
					swap  bool
					num int
				}{
					cur:   c,
					swap:  s,
					num: n,
				})
			}
		}
	}

	for i, c := range cases {
		curveName := curve.CurveName[c.cur]
		t.Run(fmt.Sprintf("case %d %s swap %v num %d", i+1, curveName, c.swap, c.num), func(t *testing.T) {
			run_scheme(t, c.cur, c.swap, c.num)
		})
	}

}
