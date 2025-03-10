package CH_FS_ECC_CCT_2024

import (
	"fmt"
	"testing"

	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Nik-U/pbc"
)

func run_scheme(t *testing.T, cur curve.Curve, group pbc.Field) {
	if(group == pbc.G2) {
		switch (cur) {
			case curve.A:
				break
			case curve.A1:
				break
			case curve.E:
				break

			default:
				// non-symmetric group there may be different element in string that isEqual returns true.
				return
		}
	}

	pp := SetUp(cur, group)

	pk, sk := KeyGen(pp)

	m1 := pp.GetGroupElement()
	m2 := pp.GetGroupElement()
	if m1.Equals(m2) {
		t.Errorf("m1 == m2")
	}
	
	h1, r1 := Hash(pp, pk, m1)
	t.Log("h1.H", h1.H.String())
	t.Log("r1.Z_1", r1.Z_1.String())
	t.Log("r1.Z_2", r1.Z_2.String())
	t.Log("r1.C_1", r1.C_1.String())
	if !Check(h1, r1, pp, pk, m1) {
		t.Errorf("H(m1) invalid")
	}
	if Check(h1, r1, pp, pk, m2) {
		t.Error()
	}
	
	h2, r2 := Hash(pp, pk, m2)
	if !Check(h2, r2, pp, pk, m2) {
		t.Errorf("H(m2) invalid")
	}
	if Check(h2, r2, pp, pk, m1) {
		t.Error()
	}
	
	r1_p := Adapt(h1, r1, pp, pk, sk, m1, m2)
	t.Log("r1_p.Z_1", r1_p.Z_1.String())
	t.Log("r1_p.Z_2", r1_p.Z_2.String())
	t.Log("r1_p.C_1", r1_p.C_1.String())
	if !Check(h1, r1_p, pp, pk, m2) {
		t.Errorf("Adapt(m2) invalid")
	}
	if Check(h1, r1_p, pp, pk, m1) {
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
	groups := []pbc.Field{
		pbc.G1,
		pbc.G2,
		pbc.GT,
	}

	cases := []struct {
		cur   curve.Curve
		group pbc.Field
	}{}

	for _, c := range curs {
		for _, g := range groups {
			cases = append(cases, struct {
				cur   curve.Curve
				group pbc.Field
			}{
				cur:   c,
				group: g,
			})

		}
	}

	for i, c := range cases {
		curveName := curve.CurveName[c.cur]
		groupName := curve.GroupName[c.group]
		t.Run(fmt.Sprintf("case %d %s %s", i+1, curveName, groupName), func(t *testing.T) {
			run_scheme(t, c.cur, c.group)
		})
	}

}
