package PCHBA_TLL_2020

import (
	"crypto/rand"
	"fmt"

	"github.com/Hugu1e/ChameLibGo/ABE/FAME"
	"github.com/Hugu1e/ChameLibGo/base/GroupParam"
	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
	"github.com/Nik-U/pbc"
)

type PublicParam struct {
	GP      *GroupParam.Asymmetry
	PpFAME  *FAME.PublicParam
}

func (pp *PublicParam) H2(m string) *pbc.Element {
	return utils.H_String_1_PBC_1(pp.GP.Pairing, pp.GP.Zr, m)
}

type MasterPublicKey struct {
	MpkFAME			*FAME.MasterPublicKey
	G_alpha			*pbc.Element
	H_d_alpha		*pbc.Element
	H_1_alpha		*pbc.Element
	H_beta_alpha	*pbc.Element
	Pk_Ch			*pbc.Element
	G_i				[]*pbc.Element
	G_alpha_i		[]*pbc.Element
	H_i				[]*pbc.Element
}

type MasterSecretKey struct {
	MskFAME	*FAME.MasterSecretKey
	Alpha   *pbc.Element
	Beta    *pbc.Element
	Sk_ch   *pbc.Element
	Z_i		[]*pbc.Element
}

type SecretKey struct {
	SkFAME	*FAME.SecretKey
	Sk_0_g	[3]*pbc.Element
	Sk_1    *pbc.Element
	Sk_ch   *pbc.Element
	Sk_2    []*pbc.Element
}

func (sk *SecretKey) delegate(SP *PublicParam, mpk *MasterPublicKey, msk *MasterSecretKey, ID_i_1, I_i_1 *pbc.Element) bool {
	if len(sk.Sk_2) == 0 {
		return false
	}
	z1 := SP.GP.GetZrElement()
	z2 := SP.GP.GetZrElement()
	z := utils.ADD(z1, z2)

	sk.SkFAME.Sk_0[0] = utils.MUL(sk.SkFAME.Sk_0[0], utils.POWZN(mpk.MpkFAME.H, utils.MUL(msk.MskFAME.B_1, z1)))
	sk.SkFAME.Sk_0[1] = utils.MUL(sk.SkFAME.Sk_0[1], utils.POWZN(mpk.MpkFAME.H, utils.MUL(msk.MskFAME.B_2, z2)))
	sk.SkFAME.Sk_0[2] = utils.MUL(sk.SkFAME.Sk_0[2], utils.POWZN(mpk.H_1_alpha, z))
	sk.Sk_0_g[1] = utils.MUL(sk.Sk_0_g[1], utils.POWZN(sk.Sk_0_g[0], z))

	alphaA1 := utils.MUL(msk.Alpha, msk.MskFAME.A_1)
	alphaA2 := utils.MUL(msk.Alpha, msk.MskFAME.A_2)

	for key, value := range sk.SkFAME.Attr2id {
		sk.SkFAME.Sk_y[value][0] = utils.MUL(sk.SkFAME.Sk_y[value][0], SP.PpFAME.H(key+"11").ThenPowZn(utils.MUL(msk.MskFAME.B_1, z1).ThenDiv(msk.MskFAME.A_1)).
			ThenMul(SP.PpFAME.H(key+"21").ThenPowZn(utils.MUL(msk.MskFAME.B_2, z2).ThenDiv(msk.MskFAME.A_1))).
			ThenMul(SP.PpFAME.H(key+"31").ThenPowZn(utils.DIV(z, alphaA1))))

		sk.SkFAME.Sk_y[value][1] = utils.MUL(sk.SkFAME.Sk_y[value][1], SP.PpFAME.H(key+"12").ThenPowZn(utils.MUL(msk.MskFAME.B_1, z1).ThenDiv(msk.MskFAME.A_2)).
			ThenMul(SP.PpFAME.H(key+"22").ThenPowZn(utils.MUL(msk.MskFAME.B_2, z2).ThenDiv(msk.MskFAME.A_2))).
			ThenMul(SP.PpFAME.H(key+"32").ThenPowZn(utils.DIV(z, alphaA2))))
	}

	sk.SkFAME.Sk_p[0] = utils.MUL(sk.SkFAME.Sk_p[0], SP.PpFAME.H("0111").ThenPowZn(utils.MUL(msk.MskFAME.B_1, z1).ThenDiv(msk.MskFAME.A_1)).
		ThenMul(SP.PpFAME.H("0121").ThenPowZn(utils.MUL(msk.MskFAME.B_2, z2).ThenDiv(msk.MskFAME.A_1))).
		ThenMul(SP.PpFAME.H("0131").ThenPowZn(utils.DIV(z, alphaA1))))

	sk.SkFAME.Sk_p[1] = utils.MUL(sk.SkFAME.Sk_p[1], SP.PpFAME.H("0112").ThenPowZn(utils.MUL(msk.MskFAME.B_1, z1).ThenDiv(msk.MskFAME.A_2)).
		ThenMul(SP.PpFAME.H("0122").ThenPowZn(utils.MUL(msk.MskFAME.B_2, z2).ThenDiv(msk.MskFAME.A_2))).
		ThenMul(SP.PpFAME.H("0132").ThenPowZn(utils.DIV(z, alphaA2))))

	sk.Sk_1 = utils.MUL(sk.Sk_1, utils.POWZN(sk.Sk_2[0], I_i_1)).ThenMul(utils.POWZN(ID_i_1, z))
	sk.Sk_2 = sk.Sk_2[1:]
	for i := range sk.Sk_2 {
		sk.Sk_2[i] = utils.MUL(sk.Sk_2[i], utils.POWZN(mpk.G_alpha_i[len(sk.Sk_2)-i-1], z))
	}

	return true
}

type HashValue struct {
	B		*pbc.Element
	H_p		*pbc.Element
	OwnerID []*pbc.Element
}

type Randomness struct {
	CtFAME	*FAME.CipherText
	Epk		*pbc.Element
	P       *pbc.Element
	Sigma   *pbc.Element
	C       *pbc.Element
	Ct_0_4	*pbc.Element
	Ct_1    *pbc.Element
	Ct_2    *pbc.Element
	Ct_3    *pbc.Element
	Ct      []byte
	Ct_p	[]byte
}

type User struct {
	Ssk				*SecretKey
	ID_hat_alpha	*pbc.Element
	ID_hat			*pbc.Element
	ID_hat_h		*pbc.Element
	ID				[]*pbc.Element
}

func NewUserWithLen(SP *PublicParam, len int) *User {
	usr := new(User)

	usr.ID = make([]*pbc.Element, len)
	for i := 0; i < len; i++ {
		usr.ID[i] = SP.GP.GetZrElement()
	}

	return usr
}

// func NewUserFromUser(f *User, SP *PublicParam, len int) *User {
// 	ID := make([]*pbc.Element, len)
// 	copy(ID, f.ID)
// 	for i := len(f.ID); i < len; i++ {
// 		ID[i] = SP.GP.GetZrElement()
// 	}
// 	return &User{
// 		Ssk: f.Ssk,
// 		ID:  ID,
// 	}
// }

func NewUser(u *User) *User {
	return &User{
		Ssk:        u.Ssk,
		ID_hat_alpha: u.ID_hat_alpha,
		ID_hat:      u.ID_hat,
		ID_hat_h:     u.ID_hat_h,
		ID:         append([]*pbc.Element(nil), u.ID...),
	}
}

func (u *User) delegate(SP *PublicParam, mpk *MasterPublicKey, msk *MasterSecretKey, I_i_1 *pbc.Element) bool {
	u.ID = append(u.ID, I_i_1)
	u.ID_hat = utils.MUL(u.ID_hat, utils.POWZN(mpk.G_i[len(mpk.G_i)-len(u.ID)], I_i_1))
	u.ID_hat_h = utils.MUL(u.ID_hat_h, utils.POWZN(mpk.H_i[len(mpk.H_i)-len(u.ID)], I_i_1))
	u.ID_hat_alpha = utils.MUL(u.ID_hat_alpha, utils.POWZN(mpk.H_i[len(mpk.H_i)-len(u.ID)], utils.MUL(I_i_1, msk.Alpha)))
	return u.Ssk.delegate(SP, mpk, msk, utils.POWZN(u.ID_hat, msk.Alpha), I_i_1)
}

func SetUp(curveName curve.Curve, swap_G1G2 bool, k int) (*MasterPublicKey, *MasterSecretKey, *PublicParam) {
	mpk := new(MasterPublicKey)
	msk := new(MasterSecretKey)
	SP := new(PublicParam)

	SP.GP = GroupParam.NewAsymmetry(curveName, swap_G1G2)
	SP.PpFAME = new(FAME.PublicParam)
	SP.PpFAME.GP = SP.GP

	d1 := SP.GP.GetZrElement()
	d2 := SP.GP.GetZrElement()
	d3 := SP.GP.GetZrElement()

	msk.Alpha = SP.GP.GetZrElement()
	msk.Beta = SP.GP.GetZrElement()
	msk.Z_i = make([]*pbc.Element, k)

	for i := 0; i < k; i++ {
		msk.Z_i[i] = SP.GP.GetZrElement()
	}
	mpkFAME, mskFAME := FAME.SetUp_d(SP.PpFAME, d1, d2, d3, msk.Alpha)
	mpk.MpkFAME = mpkFAME
	msk.MskFAME = mskFAME

	mpk.G_i = make([]*pbc.Element, k)
	for i := 0; i < k; i++ {
		mpk.G_i[i] = utils.POWZN(mpk.MpkFAME.G, msk.Z_i[i])
	}
	mpk.G_alpha_i = make([]*pbc.Element, k)
	for i := 0; i < k; i++ {
		mpk.G_alpha_i[i] = utils.POWZN(mpk.G_i[i], msk.Alpha)
	}
	mpk.H_i = make([]*pbc.Element, k)
	for i := 0; i < k; i++ {
		mpk.H_i[i] = utils.POWZN(mpk.MpkFAME.H, msk.Z_i[i])
	}

	mpk.G_alpha = utils.POWZN(mpk.MpkFAME.G, msk.Alpha)
	mpk.H_d_alpha = utils.POWZN(mpk.MpkFAME.H, utils.ADD(d1, d2).ThenAdd(d3).ThenDiv(msk.Alpha))
	mpk.H_1_alpha = utils.POWZN(mpk.MpkFAME.H, utils.INVERT(msk.Alpha))
	mpk.H_beta_alpha = utils.POWZN(mpk.MpkFAME.H, utils.DIV(msk.Beta, msk.Alpha))

	msk.Sk_ch = SP.GP.GetZrElement()
	mpk.Pk_Ch = utils.POWZN(mpk.MpkFAME.H, msk.Sk_ch)

	return mpk, msk, SP
}

func AssignUser(usr *User, mpk *MasterPublicKey, msk *MasterSecretKey) {
	usr.ID_hat = mpk.MpkFAME.G
	usr.ID_hat_h = mpk.MpkFAME.H
	for i := 0; i < len(usr.ID); i++ {
		usr.ID_hat = utils.MUL(usr.ID_hat, utils.POWZN(mpk.G_i[len(mpk.G_i)-i-1], usr.ID[i]))
		usr.ID_hat_h = utils.MUL(usr.ID_hat_h, utils.POWZN(mpk.H_i[len(mpk.G_i)-i-1], usr.ID[i]))
	}
	usr.ID_hat_alpha = utils.POWZN(usr.ID_hat_h, msk.Alpha)
}

func KeyGen(mod *User, SP *PublicParam, mpk *MasterPublicKey, msk *MasterSecretKey, S *utils.AttributeList) {
	r1 := SP.GP.GetZrElement()
	r2 := SP.GP.GetZrElement()
	r := utils.ADD(r1, r2)
	R := SP.GP.GetZrElement()
	skFAME := FAME.KeyGenWithElements(SP.PpFAME, mpk.MpkFAME, msk.MskFAME, S, r1, r2, msk.Alpha)
	mod.Ssk = new(SecretKey)
	mod.Ssk.SkFAME = skFAME

	mod.Ssk.SkFAME.Sk_0[2] = utils.POWZN(mpk.MpkFAME.H, utils.DIV(r, msk.Alpha))
	mod.Ssk.Sk_0_g[0] = utils.POWZN(mpk.MpkFAME.G, utils.INVERT(msk.Alpha))
	mod.Ssk.Sk_0_g[1] = utils.POWZN(mpk.MpkFAME.G, utils.DIV(r, msk.Alpha))
	mod.Ssk.Sk_0_g[2] = utils.POWZN(mpk.MpkFAME.G, R)

	mod.Ssk.Sk_1 = utils.MUL(msk.MskFAME.G_d1, msk.MskFAME.G_d2).
		ThenMul(msk.MskFAME.G_d3).
		ThenMul(utils.POWZN(mod.ID_hat, utils.MUL(msk.Alpha, r))).
		ThenMul(utils.POWZN(mpk.MpkFAME.G, utils.MUL(msk.Beta, R)))
	r = utils.MUL(r, msk.Alpha)
	mod.Ssk.Sk_2 = make([]*pbc.Element, len(mpk.G_i)-len(mod.ID))
	for i := 0; i < len(mod.Ssk.Sk_2); i++ {
		mod.Ssk.Sk_2[i] = utils.POWZN(mpk.G_i[len(mod.Ssk.Sk_2)-i-1], r)
	}
	mod.Ssk.Sk_ch = msk.Sk_ch
}

func GenCipher(R *Randomness, SP *PublicParam, mpk *MasterPublicKey, owner *User, MSP *utils.PBCMatrix, r *pbc.Element, R_ []byte) {
	s1 := SP.GP.GetZrElement()
	s2 := SP.GP.GetZrElement()
	s := utils.ADD(s1, s2)
	R.P = utils.POWZN(mpk.Pk_Ch, r)

	ctFAME := FAME.EncryptWithElements(SP.PpFAME, mpk.MpkFAME, MSP, &FAME.PlainText{M : SP.GP.GetGTElement().Set1()}, s1, s2)
	R.CtFAME = ctFAME

	R.CtFAME.Ct_0[2] = utils.POWZN(mpk.H_1_alpha, s)
	R.Ct_0_4 = utils.POWZN(mpk.H_beta_alpha, s)

	// R.Ct = make([]byte, len(R.CtFAME.Ct_p.Bytes()))
	R.Ct = R.CtFAME.Ct_p.Bytes()
	R.CtFAME.Ct_p = SP.GP.GetGTElement().Set1()
	tmp := r.Bytes()
	for i := 0; i < len(tmp); i++ {
		R.Ct[i] ^= tmp[i]
	}

	R.Ct_p = SP.H2(SP.GP.Pair(mpk.MpkFAME.G, mpk.H_d_alpha).ThenPowZn(s).String()).Bytes()
	for i := 0; i < len(R_); i++ {
		R.Ct_p[i] ^= R_[i]
	}

	R.Ct_1 = utils.POWZN(owner.ID_hat_alpha, s)
	R.Ct_2 = utils.POWZN(owner.ID_hat_h, s)
	R.Ct_3 = utils.POWZN(R.Ct_1, s)

	esk := SP.GP.GetZrElement()
	R.Epk = utils.POWZN(mpk.MpkFAME.G, esk)

	originalR_ := make([]byte, len(R_))
	copy(originalR_, R_)
	R_ = make([]byte, SP.GP.Pairing.ZrLength())
	copy(R_, originalR_)


	R.C = utils.POWZN(mpk.MpkFAME.H, utils.ADD(s, SP.H2(string(R_))))
	R.Sigma = utils.ADD(esk, utils.MUL(s, SP.H2(fmt.Sprintf("%s|%s", R.Epk, R.C))))
}

func Hash(SP *PublicParam, mpk *MasterPublicKey, owner *User, MSP *utils.PBCMatrix, m *pbc.Element) (*HashValue, *Randomness){
	H := new(HashValue)
	R := new(Randomness)

	H.OwnerID = append([]*pbc.Element(nil), owner.ID...)

	r := SP.GP.GetZrElement()

	R_ := make([]byte, SP.GP.Pairing.ZrLength()/2)
	rand.Read(R_)

	GenCipher(R, SP, mpk, owner, MSP, r, R_)

	H.H_p = utils.POWZN(mpk.MpkFAME.H, SP.H2(string(R_)))

	H.B = utils.MUL(R.P, utils.POWZN(H.H_p, m))

	return H, R
}

func Check(H *HashValue, R *Randomness, SP *PublicParam, mpk *MasterPublicKey, m *pbc.Element) bool {
	return H.B.Equals(utils.MUL(R.P, utils.POWZN(H.H_p, m))) &&
		SP.GP.Pair(mpk.G_alpha, R.Ct_2).ThenPowZn(R.Sigma).Equals(SP.GP.Pair(R.Epk, R.Ct_1).ThenMul(SP.GP.Pair(mpk.MpkFAME.G, R.Ct_3).ThenPowZn(SP.H2(fmt.Sprintf("%s|%s", R.Epk, R.C)))))
}

func Adapt(H *HashValue, R *Randomness, SP *PublicParam, mpk *MasterPublicKey, msk *MasterSecretKey, moder *User, MSP *utils.PBCMatrix, m, m_p *pbc.Element) *Randomness{
	R_p := new(Randomness)

	moder_p := NewUser(moder)

	for i := len(moder_p.ID); i < len(H.OwnerID); i++ {
		if !moder_p.delegate(SP, mpk, msk, H.OwnerID[i]) {
			panic("delegate failed")
		}
	}

	R_ := SP.H2(SP.GP.Pair(moder_p.Ssk.Sk_1, R.CtFAME.Ct_0[2]).ThenDiv(SP.GP.Pair(moder_p.Ssk.Sk_0_g[1], R.Ct_1).ThenMul(SP.GP.Pair(moder_p.Ssk.Sk_0_g[2], R.Ct_0_4))).String()).Bytes()
	for i := 0; i < len(R_); i++ {
		R_[i] ^= R.Ct_p[i]
	}

	tag := true
	for i := len(R_)/2; i < len(R_); i++ {
		if R_[i] != 0 {
			tag = false
			break
		}
	}
	if !tag {
		panic("unable to adapt")
	}

	R_ = R_[:len(R_)/2]

	pt_RABE := FAME.Decrypt(SP.PpFAME, MSP, R.CtFAME, moder_p.Ssk.SkFAME)

	r_ := utils.INVERT(pt_RABE.M).Bytes()
	for i := 0; i < len(r_); i++ {
		r_[i] ^= R.Ct[i]
	}

	tmp := SP.GP.Pairing.NewZr().SetBytes(r_)
	r_p := tmp.ThenAdd(utils.SUB(m, m_p).ThenMul(SP.H2(string(R_)).ThenDiv(moder_p.Ssk.Sk_ch)))
	GenCipher(R_p, SP, mpk, moder_p, MSP, r_p, R_)

	return R_p
}
