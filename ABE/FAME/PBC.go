package FAME

import (
	"fmt"

	"github.com/Hugu1e/ChameLibGo/base/GroupParam"
	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
	"github.com/Nik-U/pbc"
)

type PublicParam struct {
	GP	GroupParam.Asymmetry
}

func (pp *PublicParam) h(m string) *pbc.Element {
	return utils.H_String_1_PBC_1(pp.GP.Pairing, pp.GP.G1, m)
}
func (pp *PublicParam) NewPBCMatrix() *utils.PBCMatrix {
	return utils.NewPBCMatrix(pp.GP.Pairing, pp.GP.Zr)
}
func (pp *PublicParam) NewPolicyList() *utils.PolicyList{
	return new(utils.PolicyList)
}

type MasterPublicKey struct {
	G, H, H_1, H_2, T_1, T_2 pbc.Element
}

type MasterSecretKey struct {
	B_1, B_2, A_1, A_2, G_d1, G_d2, G_d3 pbc.Element
}

type SecretKey struct {
	Attr2id map[string]int
	S       utils.AttributeList
	Sk_y    [][]pbc.Element
	Sk_0    [3]pbc.Element
	Sk_p    [3]pbc.Element
}

type CipherText struct {
	Ct_0 [3]pbc.Element
	Ct   [][]pbc.Element
	Ct_p pbc.Element
}

func (ct *CipherText) Equals(ct2 *CipherText) bool {
	if len(ct.Ct_0) != len(ct2.Ct_0) {	
		return false
	}
	if len(ct.Ct) != len(ct2.Ct) {
		return false
	}
	if len(ct.Ct[0]) != len(ct2.Ct[0]) {
		return false
	}

	for i := 0; i < len(ct.Ct_0); i++ {
		if !ct.Ct_0[i].Equals(&ct2.Ct_0[i]) {
			return false
		}
	}

	for i := 0; i < len(ct.Ct); i++ {
		for j := 0; j < len(ct.Ct[i]); j++ {
			if !ct.Ct[i][j].Equals(&ct2.Ct[i][j]) {
				return false
			}
		}
	}

	return ct.Ct_p.Equals(&ct2.Ct_p)
}

type PlainText struct {
	M pbc.Element
}
func NewPlainText(pp *PublicParam) *PlainText {
	pt := new(PlainText)
	pt.M = *pp.GP.GetGTElement()
	return pt
}

func (pt *PlainText) PlainText(m *pbc.Element) *PlainText {
	pt.M = *utils.COPY(m)
	return pt
}

func (pt *PlainText) Equals(pt2 *PlainText) bool {
	return pt.M.Equals(&pt2.M)
}


func SetUp(curveName curve.Curve, swap_G1G2 bool) (*PublicParam, *MasterPublicKey, *MasterSecretKey) {
	SP := new(PublicParam)

	SP.GP.Asymmetry(curveName, swap_G1G2)

	d1 := SP.GP.GetZrElement()
	d2 := SP.GP.GetZrElement()
	d3 := SP.GP.GetZrElement()

	mpk, msk := setUp(SP, d1, d2, d3, SP.GP.GetZrElement().Set1())
	return SP, mpk, msk
}

func setUp(SP *PublicParam, d1,d2,d3,alpha *pbc.Element) (*MasterPublicKey, *MasterSecretKey) {
	mpk := new(MasterPublicKey)
	msk := new(MasterSecretKey)

	mpk.H = *SP.GP.GetG2Element()
	mpk.G = *SP.GP.GetG1Element()
	egh := SP.GP.Pair(&mpk.G, &mpk.H)

	msk.A_1 = *SP.GP.GetZrElement()
	msk.A_2 = *SP.GP.GetZrElement()
	msk.B_1 = *SP.GP.GetZrElement()
	msk.B_2 = *SP.GP.GetZrElement()

	mpk.H_1 = *utils.POWZN(&mpk.H, &msk.A_1)
	mpk.H_2 = *utils.POWZN(&mpk.H, &msk.A_2)
	mpk.T_1 = *utils.POWZN(egh, utils.MUL(d1, &msk.A_1).ThenAdd(utils.DIV(d3, alpha)))
	mpk.T_2 = *utils.POWZN(egh, utils.MUL(d2, &msk.A_2).ThenAdd(utils.DIV(d3, alpha)))

	msk.G_d1 = *utils.POWZN(&mpk.G, d1)
	msk.G_d2 = *utils.POWZN(&mpk.G, d2)
	msk.G_d3 = *utils.POWZN(&mpk.G, d3)

	return mpk, msk
}

func KeyGen(SP *PublicParam, mpk *MasterPublicKey, msk *MasterSecretKey, S *utils.AttributeList) *SecretKey {
	sk := new(SecretKey)

	sk.S = *utils.NewAttributeList()
	sk.S.Copy(S)

	r1 := SP.GP.GetZrElement()
	r2 := SP.GP.GetZrElement()
	sk.Sk_0[0] = *utils.POWZN(&mpk.H, utils.MUL(&msk.B_1, r1))
	sk.Sk_0[1] = *utils.POWZN(&mpk.H, utils.MUL(&msk.B_2, r2))
	sk.Sk_0[2] = *utils.POWZN(&mpk.H, utils.ADD(r1, r2))

	sk.Attr2id = make(map[string]int)
	sk.Sk_y = make([][]pbc.Element, len(S.Attrs))
	i := 0
	for y:= range S.Attrs {
		sk.Attr2id[y] = i

		sk.Sk_y[i] = make([]pbc.Element, 3)

		sigma_y := SP.GP.GetZrElement()
		sk.Sk_y[i][0] = *utils.POWZN(SP.h(y+"11"), utils.MUL(&msk.B_1, r1).ThenDiv(&msk.A_1)).
			ThenMul(utils.POWZN(SP.h(y+"21"), utils.MUL(&msk.B_2, r2).ThenDiv(&msk.A_1))).
			ThenMul(utils.POWZN(SP.h(y+"31"), utils.ADD(r1, r2).ThenDiv(&msk.A_1))).
			ThenMul(utils.POWZN(&mpk.G, utils.DIV(sigma_y, &msk.A_1)))

		sk.Sk_y[i][1] = *utils.POWZN(SP.h(y+"12"), utils.MUL(&msk.B_1, r1).ThenDiv(&msk.A_2)).
			ThenMul(utils.POWZN(SP.h(y+"22"), utils.MUL(&msk.B_2, r2).ThenDiv(&msk.A_2))).
			ThenMul(utils.POWZN(SP.h(y+"32"), utils.ADD(r1, r2).ThenDiv(&msk.A_2))).
			ThenMul(utils.POWZN(&mpk.G, utils.DIV(sigma_y, &msk.A_2)))

		sk.Sk_y[i][2] = *utils.POWZN(&mpk.G, utils.NEG(sigma_y))

		i++
	}

	sigma_p := SP.GP.GetZrElement()
	sk.Sk_p[0] = *utils.MUL(&msk.G_d1, SP.h("0111").ThenPowZn(utils.MUL(&msk.B_1, r1).ThenDiv(&msk.A_1))).
		ThenMul(SP.h("0121").ThenPowZn(utils.MUL(&msk.B_2, r2).ThenDiv(&msk.A_1))).
		ThenMul(SP.h("0131").ThenPowZn(utils.ADD(r1, r2).ThenDiv(&msk.A_1))).
		ThenMul(utils.POWZN(&mpk.G, utils.DIV(sigma_p, &msk.A_1)))

	sk.Sk_p[1] = *utils.MUL(&msk.G_d2, SP.h("0112").ThenPowZn(utils.MUL(&msk.B_1, r1).ThenDiv(&msk.A_2))).
		ThenMul(SP.h("0122").ThenPowZn(utils.MUL(&msk.B_2, r2).ThenDiv(&msk.A_2))).
		ThenMul(SP.h("0132").ThenPowZn(utils.ADD(r1, r2).ThenDiv(&msk.A_2))).
		ThenMul(utils.POWZN(&mpk.G, utils.DIV(sigma_p, &msk.A_2)))

	sk.Sk_p[2] = *utils.MUL(&msk.G_d3, utils.POWZN(&mpk.G, utils.NEG(sigma_p)))

	return sk
}

func Encrypt(SP *PublicParam, mpk *MasterPublicKey, MSP *utils.PBCMatrix, PT *PlainText) *CipherText{
	s1 := SP.GP.GetZrElement()
	s2 := SP.GP.GetZrElement()
	return EncryptWithElements(SP, mpk, MSP, PT, s1, s2)
}

func EncryptWithElements(SP *PublicParam, mpk *MasterPublicKey, MSP *utils.PBCMatrix, PT *PlainText, s1, s2 *pbc.Element) *CipherText  {
	CT := new(CipherText)

	CT.Ct_0[0] = *utils.POWZN(&mpk.H_1, s1)
	CT.Ct_0[1] = *utils.POWZN(&mpk.H_2, s2)
	CT.Ct_0[2] = *utils.POWZN(&mpk.H, utils.ADD(s1, s2))

	CT.Ct_p = *utils.POWZN(&mpk.T_1, s1).ThenMul(utils.POWZN(&mpk.T_2, s2)).ThenMul(&PT.M)

	n1 := len(MSP.M)
	n2 := len(MSP.M[0])
	CT.Ct = make([][]pbc.Element, n1)
	for i := 0; i < n1; i++ {
		CT.Ct[i] = make([]pbc.Element, 3)
		for l := 1; l <= 3; l++ {
			tmp := SP.h(fmt.Sprintf("%s%d1", MSP.Policy[i], l)).ThenPowZn(s1).
				ThenMul(SP.h(fmt.Sprintf("%s%d2", MSP.Policy[i], l)).ThenPowZn(s2))
			for j := 1; j <= n2; j++ {
				tmp.ThenMul(SP.h(fmt.Sprintf("0%d%d1", j, l)).ThenPowZn(s1).
					ThenMul(SP.h(fmt.Sprintf("0%d%d2", j, l)).ThenPowZn(s2)).ThenPowZn(&MSP.M[i][j-1]))
			}
			CT.Ct[i][l-1] = *tmp
		}
	}
	return CT
}

func Decrypt(SP *PublicParam, MSP *utils.PBCMatrix, CT *CipherText, sk *SecretKey) *PlainText {
	PT := new(PlainText)

	gamma := MSP.Solve(&sk.S)
	num := utils.COPY(&CT.Ct_p)
	for t := 0; t < 3; t++ {
		tmp := SP.GP.GetG1Element().Set1()
		for i := 0; i < len(CT.Ct); i++ {
			tmp.ThenMul(utils.POWZN(&CT.Ct[i][t], &gamma.V[i]))
		}
		num.ThenMul(SP.GP.Pair(tmp, &sk.Sk_0[t]))
	}
	den := SP.GP.GetGTElement().Set1()
	for t := 0; t < 3; t++ {
		tmp := utils.COPY(&sk.Sk_p[t])
		for i := 0; i < len(CT.Ct); i++ {
			if id, ok := sk.Attr2id[MSP.Policy[i]]; ok {
				tmp.ThenMul(utils.POWZN(&sk.Sk_y[id][t], &gamma.V[i]))
			}
		}
		den.ThenMul(SP.GP.Pair(tmp, &CT.Ct_0[t]))
	}
	PT.M = *utils.DIV(num, den)

	return PT
}

