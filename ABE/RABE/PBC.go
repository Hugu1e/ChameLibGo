package RABE

import (
	"fmt"

	"github.com/Hugu1e/ChameLibGo/ABE/FAME"
	"github.com/Hugu1e/ChameLibGo/base/BinaryTree"
	"github.com/Hugu1e/ChameLibGo/base/GroupParam"
	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
	"github.com/Nik-U/pbc"
)

type TYPE int16
const (
    XNM_2021 TYPE = iota
    TMM_2022
)

type PublicParam struct {
    GP      GroupParam.Asymmetry

    Pp_FAME FAME.PublicParam
    Type    TYPE
}

func (pp *PublicParam) CopyFrom(other *PublicParam) {
    pp.GP.CopyFrom(&other.GP)
    pp.Pp_FAME.CopyFrom(&other.Pp_FAME)
    pp.Type = other.Type
}

func (pp *PublicParam) H(m string) *pbc.Element {
    if pp.Type == XNM_2021 {
        return pp.Pp_FAME.H("1" + m)
    }
    return pp.Pp_FAME.H(m)
}

type MasterPublicKey struct {
    Mpk_FAME FAME.MasterPublicKey
}
func (mpk *MasterPublicKey) CopyFrom(other *MasterPublicKey) {
    mpk.Mpk_FAME.CopyFrom(&other.Mpk_FAME)
}

type MasterSecretKey struct {
    Msk_FAME FAME.MasterSecretKey
}
func (msk *MasterSecretKey) CopyFrom(other *MasterSecretKey) {
    msk.Msk_FAME.CopyFrom(&other.Msk_FAME)
}

type SecretKey struct {
    Sk_FAME  FAME.SecretKey
    Sk_theta map[int]pbc.Element
    Node_id  int
}

func (sk *SecretKey) CopyFrom(other *SecretKey) {
    sk.Sk_FAME.CopyFrom(&other.Sk_FAME)

    sk.Node_id = other.Node_id
    
    sk.Sk_theta = make(map[int]pbc.Element)
    for k, v := range other.Sk_theta {
        sk.Sk_theta[k] = *utils.COPY(&v)
    }
}

type UpdateKey struct {
    T        int
    Ku_theta map[int][2]pbc.Element
}

func (ku *UpdateKey) CopyFrom(other *UpdateKey) {
    ku.T = other.T

    ku.Ku_theta = make(map[int][2]pbc.Element)
    for k, v := range other.Ku_theta {
        ku.Ku_theta[k] = [2]pbc.Element{*utils.COPY(&v[0]), *utils.COPY(&v[1])}
    }
}

func (ku *UpdateKey) AddKey(theta int, k_u_theta_0, k_u_theta_1 *pbc.Element) {
    if ku.Ku_theta == nil {
        ku.Ku_theta = make(map[int][2]pbc.Element)
    }

    ku.Ku_theta[theta] = [2]pbc.Element{*utils.COPY(k_u_theta_0), *utils.COPY(k_u_theta_1)}
}

type DecryptKey struct {
    Node_id int
    T       int
    Sk_FAME FAME.SecretKey
    Sk_0_4  pbc.Element
}

func (dk *DecryptKey) CopyFrom(other *DecryptKey) {
    dk.Node_id = other.Node_id
    dk.T = other.T
    dk.Sk_FAME.CopyFrom(&other.Sk_FAME)
    dk.Sk_0_4 = *utils.COPY(&other.Sk_0_4)
}

type CipherText struct {
    Ct_FAME   FAME.CipherText
    Ct_TMM_2022 []byte
    Ct_0_4   pbc.Element
}
func (ct *CipherText) CopyFrom(CT_p *CipherText) {
    ct.Ct_FAME.CopyFrom(&CT_p.Ct_FAME)

    ct.Ct_0_4 = *utils.COPY(&CT_p.Ct_0_4)
    
    ct.Ct_TMM_2022 = make([]byte, len(CT_p.Ct_TMM_2022))
    copy(ct.Ct_TMM_2022, CT_p.Ct_TMM_2022)
}

func (ct *CipherText) Equals(CT_p *CipherText) bool {
    return ct.Ct_FAME.Equals(&CT_p.Ct_FAME) && ct.Ct_0_4.Equals(&CT_p.Ct_0_4)
}

type PlainText struct {
    M pbc.Element
}
func NewPlainText(m *pbc.Element) *PlainText {
    pt := new(PlainText)
    pt.M = *utils.COPY(m)
    return pt
}

func (pt *PlainText) Equals(p *PlainText) bool {
    return pt.M.Equals(&p.M)
}


func SetUp(t TYPE, curveName curve.Curve, swap_G1G2 bool) (*PublicParam, *MasterPublicKey, *MasterSecretKey){
    mpk := new(MasterPublicKey)
    msk := new(MasterSecretKey)
    SP := new(PublicParam)

    SP.GP.Asymmetry(curveName, swap_G1G2)
    SP.Type = t

    pp_FAME, mpk_FAME, msk_FAME := FAME.SetUpWithGP(&SP.GP)
    SP.Pp_FAME.CopyFrom(pp_FAME)
    mpk.Mpk_FAME.CopyFrom(mpk_FAME)
    msk.Msk_FAME.CopyFrom(msk_FAME)

    return SP, mpk, msk
}

func SetUpWithGP(t TYPE, gp *GroupParam.Asymmetry) (*PublicParam, *MasterPublicKey, *MasterSecretKey){
    mpk := new(MasterPublicKey)
    msk := new(MasterSecretKey)
    SP := new(PublicParam)

    SP.GP.CopyFrom(gp)
    SP.Type = t

    pp_FAME, mpk_FAME, msk_FAME := FAME.SetUpWithGP(&SP.GP)
    SP.Pp_FAME.CopyFrom(pp_FAME)
    mpk.Mpk_FAME.CopyFrom(mpk_FAME)
    msk.Msk_FAME.CopyFrom(msk_FAME)

    return SP, mpk, msk
}

func KeyGen(st *BinaryTree.BinaryTree, SP *PublicParam, mpk *MasterPublicKey, msk *MasterSecretKey, S *utils.AttributeList, id *pbc.Element) *SecretKey {
    sk := new(SecretKey)

    sk_FAME := FAME.KeyGen(&SP.Pp_FAME, &mpk.Mpk_FAME, &msk.Msk_FAME, S)
    sk.Sk_FAME.CopyFrom(sk_FAME)

    theta := st.Pick(id)
    sk.Node_id = theta
    if !st.TagG[theta] {
        st.Setg(theta, SP.GP.GetG1Element())
    }
    sk.Sk_theta = make(map[int]pbc.Element)
    sk.Sk_theta[theta] = *utils.DIV(&sk.Sk_FAME.Sk_p[2], &st.GTheta[theta])
    for theta != 0 {
        theta = st.GetFNodeId(theta)
        if !st.TagG[theta] {
            st.Setg(theta, SP.GP.GetG1Element())
        }
        sk.Sk_theta[theta] = *utils.DIV(&sk.Sk_FAME.Sk_p[2], &st.GTheta[theta])
    }
    sk.Sk_FAME.Sk_p[2] = *SP.GP.GetG1Element()

    return sk
}

func UpdateKeyGen(SP *PublicParam, mpk *MasterPublicKey, st *BinaryTree.BinaryTree, rl *BinaryTree.RevokeList, t int) *UpdateKey {
    ku := new(UpdateKey)

    st.GetUpdateKeyNode(rl, t)
    ku.T = t
    for theta := 0; theta < len(st.GTheta); theta++ {
        if st.Tag[theta] && st.TagG[theta] {
            r_theta := SP.GP.GetZrElement()
            ku.AddKey(theta,
                utils.MUL(&st.GTheta[theta], SP.H(fmt.Sprintf("%d", t)).ThenPowZn(r_theta)),
                utils.POWZN(&mpk.Mpk_FAME.H, r_theta),
            )
        }
    }

    return ku
}

func DecryptKeyGen(SP *PublicParam, mpk *MasterPublicKey, sk *SecretKey, ku *UpdateKey, st *BinaryTree.BinaryTree, rl *BinaryTree.RevokeList) *DecryptKey {
    dk := new(DecryptKey)

    st.GetUpdateKeyNode(rl, ku.T)

    node_id := sk.Node_id
    theta := -1
    if st.Tag[node_id] {
        theta = node_id
    }
    for node_id != 0 && theta == -1 {
        node_id = st.GetFNodeId(node_id)
        if st.Tag[node_id] {
            theta = node_id
        }
    }

    if theta != -1 {
        dk.Sk_FAME.CopyFrom(&sk.Sk_FAME)
        dk.T = ku.T
        dk.Node_id = sk.Node_id

        ku_theta := ku.Ku_theta[theta]
        if SP.Type == XNM_2021 {
            r_theta_p := SP.GP.GetZrElement()
            sk_theta_value := sk.Sk_theta[theta]
            dk.Sk_FAME.Sk_p[2] = *utils.MUL(&sk_theta_value, &ku_theta[0]).ThenMul(SP.H(fmt.Sprintf("%d", dk.T)).ThenPowZn(r_theta_p))
            dk.Sk_0_4 = *utils.MUL(&ku_theta[1], utils.POWZN(&mpk.Mpk_FAME.H, r_theta_p))
        } else if SP.Type == TMM_2022 {
            sk_theta_value := sk.Sk_theta[theta]
            dk.Sk_FAME.Sk_p[2] = *utils.MUL(&sk_theta_value, &ku_theta[0])
            dk.Sk_0_4 = *utils.COPY(&ku_theta[1])
        }
    }

    return dk
}

func Encrypt(SP *PublicParam, mpk *MasterPublicKey, MSP *utils.PBCMatrix, PT *PlainText, t int) *CipherText {
    s_1 := SP.GP.GetZrElement()
    s_2 := SP.GP.GetZrElement()
    return EncryptWithElements(SP, mpk, MSP, PT, t, s_1, s_2)
}

func EncryptWithElements(SP *PublicParam, mpk *MasterPublicKey, MSP *utils.PBCMatrix, PT *PlainText, t int, s_1, s_2 *pbc.Element) *CipherText {
    CT := new(CipherText)

    CT.Ct_0_4 = *SP.H(fmt.Sprintf("%d", t)).ThenPowZn(utils.ADD(s_1, s_2))
    if SP.Type == XNM_2021 {
        ct_FAME := FAME.EncryptWithElements(&SP.Pp_FAME, &mpk.Mpk_FAME, MSP, FAME.NewPlainText(&PT.M), s_1, s_2)
        CT.Ct_FAME.CopyFrom(ct_FAME)
    } else if SP.Type == TMM_2022 {
        ct_FAME := FAME.EncryptWithElements(&SP.Pp_FAME, &mpk.Mpk_FAME, MSP, FAME.NewPlainText(SP.GP.GetGTElement().Set1()), s_1, s_2)
        CT.Ct_FAME.CopyFrom(ct_FAME)

        b := CT.Ct_FAME.Ct_p.Bytes()
        CT.Ct_TMM_2022 = make([]byte, len(b))
        copy(CT.Ct_TMM_2022, b)

        CT.Ct_FAME.Ct_p = *SP.GP.GetGTElement().Set1()

        tmp := PT.M.Bytes()
        for i := 0; i < len(tmp); i++ {
            CT.Ct_TMM_2022[i] ^= tmp[i]
        }
    }

    return CT
}

func Decrypt(SP *PublicParam, dk *DecryptKey, MSP *utils.PBCMatrix, CT *CipherText) *PlainText {
    PT := new(PlainText)

    pt_FAME := FAME.Decrypt(&SP.Pp_FAME, MSP, &CT.Ct_FAME, &dk.Sk_FAME)
    PT.M = *utils.MUL(&pt_FAME.M, SP.GP.Pair(&CT.Ct_0_4, &dk.Sk_0_4))
    if SP.Type == TMM_2022 {
        tmp := utils.INVERT(&PT.M).Bytes()
        for i := 0; i < len(tmp); i++ {
            tmp[i] ^= CT.Ct_TMM_2022[i]
        }
        PT.M = *SP.GP.GetZrElement().SetBytes(tmp[:SP.GP.Pairing.ZrLength()])
    }

    return PT
}

func Revoke(rl *BinaryTree.RevokeList, id *pbc.Element, t int) {
    rl.Add(id, t)
}