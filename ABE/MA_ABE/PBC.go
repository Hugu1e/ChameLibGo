package MA_ABE

import (
	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
	"github.com/Nik-U/pbc"
)

type Authority struct {
	Msk         MasterSecretKey
	Pk          PublicKey
	ControlAttr []string
	Theta       string
}

func NewAuthority(theta string) *Authority {
	auth := new(Authority)
	auth.Theta = theta
	return auth
}

type PublicParam struct {
	Pairing   *pbc.Pairing
	Zr pbc.Field

	G, Egg    pbc.Element
}
func (pp *PublicParam) Copy() *PublicParam {
	newPP := new(PublicParam)
	newPP.Pairing = pp.Pairing
	newPP.Zr = pp.Zr
	newPP.G = *utils.COPY(&pp.G)
	newPP.Egg = *utils.COPY(&pp.Egg)
	return newPP
}
func (pp *PublicParam) pairing(g1, g2 *pbc.Element) *pbc.Element {
	return pp.Pairing.NewGT().Pair(g1, g2)
}
func (pp *PublicParam) H(m string) *pbc.Element {
	return utils.H_String_1_PBC_1(pp.Pairing, pbc.G1, m)
}
func (pp *PublicParam) Ht(m string) *pbc.Element {
	return utils.H_String_1_PBC_1(pp.Pairing, pbc.Zr, m)
}
func (pp *PublicParam) F(m string) *pbc.Element {
	return utils.H_String_1_PBC_1(pp.Pairing, pbc.G1, m)
}
func (pp *PublicParam) GetGElement() *pbc.Element {
	return pp.Pairing.NewG1().Rand()
}
func (pp *PublicParam) GetGTElement() *pbc.Element {
	return pp.Pairing.NewGT().Rand()
}
func (pp *PublicParam) GetZrElement() *pbc.Element {
	return pp.Pairing.NewZr().Rand()
}
func (pp *PublicParam) NewPBCMatrix() *utils.PBCMatrix {
	return utils.NewPBCMatrix(pp.Pairing, pp.Zr)
}
func (pp *PublicParam) NewPolicyList() *utils.PolicyList{
	return new(utils.PolicyList)
}

type PublicKey struct {
	Egg_alpha, G_y pbc.Element
}

type PublicKeyGroup struct {
	PK  []PublicKey
	Rho map[string]int
}
func (pkg *PublicKeyGroup) AddPK(auth *Authority) {
	if pkg.Rho == nil {
		pkg.Rho = make(map[string]int)
	}
	for _, attr := range auth.ControlAttr {
		pkg.Rho[attr] = len(pkg.PK)
	}
	pkg.PK = append(pkg.PK, auth.Pk)
}

type SecretKeyGroup struct {
	SK  []SecretKey
	Rho map[string]int
}

func (skg *SecretKeyGroup) AddSK(sk *SecretKey) {
	if skg.Rho == nil {
		skg.Rho = make(map[string]int)
	}
	skg.Rho[sk.U] = len(skg.SK)
	skg.SK = append(skg.SK, *sk)
}

type MasterSecretKey struct {
	Alpha, Y pbc.Element
}

type SecretKey struct {
	K, K_P   pbc.Element
	GID, U  string
}

type CipherText struct {
	C_0 pbc.Element
	C  [][]pbc.Element
}
func (ct *CipherText) CopyFrom(other *CipherText) {
	ct.C_0 = *utils.COPY(&other.C_0)
	ct.C = make([][]pbc.Element, len(other.C))
	for i := range ct.C {
		ct.C[i] = make([]pbc.Element, len(other.C[i]))
		for j := range ct.C[i] {
			ct.C[i][j] = *utils.COPY(&other.C[i][j])
		}
	}
}

func (ct *CipherText) IsEqual(other *CipherText) bool {
	if len(ct.C) != len(other.C) || len(ct.C[0]) != len(other.C[0]) {
		return false
	}
	for i := range ct.C {
		for j := range ct.C[i] {
			if !ct.C[i][j].Equals(&other.C[i][j]) {
				return false
			}
		}
	}
	return ct.C_0.Equals(&other.C_0)
}

type PlainText struct {
	M pbc.Element
}
func NewPlainText(pp *PublicParam) *PlainText {
	pt := new(PlainText)
	pt.M = *pp.GetGTElement()
	return pt
}
func SetPlainText(m *pbc.Element) *PlainText {
	pt := new(PlainText)
	pt.M = *utils.COPY(m)
	return pt
}
func (pt *PlainText) Equals(other *PlainText) bool {
	return pt.M.Equals(&other.M)
}

func GlobalSetup(curveName curve.Curve) *PublicParam {
	pp := new(PublicParam)

	pp.Pairing = curve.PairingGen(curveName)
	pp.Zr = pbc.Zr
	
	pp.G = *pp.GetGElement()
	pp.Egg = *pp.pairing(&pp.G, &pp.G)

	return pp
}

func AuthSetup(auth *Authority, pp *PublicParam) {
	auth.Msk.Alpha = *pp.GetZrElement()
	auth.Msk.Y = *pp.GetZrElement()
	auth.Pk.Egg_alpha = *utils.POWZN(&pp.Egg, &auth.Msk.Alpha)
	auth.Pk.G_y = *utils.POWZN(&pp.G, &auth.Msk.Y)
}

func KeyGen(auth *Authority, u string, pp *PublicParam, GID string) *SecretKey {
	sk := new(SecretKey)

	if !contains(auth.ControlAttr, u) {
		panic("authority not control this attr")
	}
	t := pp.GetZrElement()
	sk.K_P = *utils.POWZN(&pp.G, t)
	sk.K = *utils.POWZN(&pp.G, &auth.Msk.Alpha).ThenMul(utils.POWZN(pp.H(GID), &auth.Msk.Y)).ThenMul(utils.POWZN(pp.F(u), t))
	sk.GID = GID
	sk.U = u

	return sk
}

func Encrypt(pp *PublicParam, pkg *PublicKeyGroup, msp *utils.PBCMatrix, pt *PlainText) *CipherText {
	l := len(msp.M)
	n := len(msp.M[0])
	
	v := utils.NewPBCVector(n)
	for i := range v.V {
		v.V[i] = *pp.GetZrElement()
	}
	t_x := utils.NewPBCVector(l)
	for i := range t_x.V {
		t_x.V[i] = *pp.GetZrElement()
	}
	w := utils.NewPBCVector(n)
	w.V[0] = *pp.GetZrElement().Set0()
	for i := 1; i < n; i++ {
		w.V[i] = *pp.GetZrElement()
	}
	return Encrypt_2(pp, pkg, msp, pt, v, w, t_x)
}

func Encrypt_2(pp *PublicParam, pkg *PublicKeyGroup, msp *utils.PBCMatrix, pt *PlainText, v, w, t_x *utils.PBCVector) *CipherText {
	ct := new(CipherText)

	l := len(msp.M)

	ct.C = make([][]pbc.Element, 4)
	for i := range ct.C {
		ct.C[i] = make([]pbc.Element, l)
	}
	ct.C_0 = *utils.POWZN(&pp.Egg, &v.V[0]).ThenMul(&pt.M)

	for i := 0; i < l; i++ {
		rho_x, ok := pkg.Rho[msp.Policy[i]]
		if !ok {
			panic("invalid attribute")
		}
		ct.C[0][i] = *utils.POWZN(&pkg.PK[rho_x].Egg_alpha, &t_x.V[i]).ThenMul(utils.POWZN(&pp.Egg, msp.Prodith(v, i)))
		ct.C[1][i] = *utils.POWZN(&pp.G, utils.NEG(&t_x.V[i]))
		ct.C[2][i] = *utils.POWZN(&pkg.PK[rho_x].G_y, &t_x.V[i]).ThenMul(utils.POWZN(&pp.G, msp.Prodith(w, i)))
		ct.C[3][i] = *utils.POWZN(pp.F(msp.Policy[i]), &t_x.V[i])
	}

	return ct
}

func Decrypt(pp *PublicParam, skg *SecretKeyGroup, msp *utils.PBCMatrix, ct *CipherText) *PlainText {
	pt := new(PlainText)

	S := utils.NewAttributeList()
	for attr := range skg.Rho {
		S.Attrs[attr] = struct{}{}
	}
	c := msp.Solve(S)
	tmp := pp.GetGTElement().Set1()
	for i := range msp.Policy {
		if !c.V[i].Is0() {
			skID := skg.Rho[msp.Policy[i]]
			tmp.ThenMul(
				utils.MUL(&ct.C[0][i], pp.pairing(&skg.SK[skID].K, &ct.C[1][i])).
					ThenMul(pp.pairing(pp.H(skg.SK[skID].GID), &ct.C[2][i])).
					ThenMul(pp.pairing(&skg.SK[skID].K_P, &ct.C[3][i])).
					ThenPowZn(&c.V[i]),
			)
		}
	}
	pt.M = *utils.DIV(&ct.C_0, tmp)

	return pt
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}