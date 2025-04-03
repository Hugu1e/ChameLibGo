package CH_ET_KOG_CDK_2017

import (
	"flag"
	"fmt"
	"testing"

	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Hugu1e/ChameLibGo/utils"
	"github.com/Nik-U/pbc"
)

var (
    r = flag.Int("repeat", 100, "repeat times")
)
func run_scheme_benchmark(t *testing.T, cur curve.Curve, group pbc.Field) {
    repeat := *r
    timer := utils.NewTimer(t.Name(), repeat)

    pp := make([]*PublicParam, repeat)
    timer.Start("SetUp")
    for i := 0; i < repeat; i++ {
        pp[i] = SetUp(cur, group, 1024)
    }
    timer.End("SetUp")

    pk := make([]*PublicKey, repeat)
    sk := make([]*SecretKey, repeat)

    timer.Start("KeyGen")
    for i := 0; i < repeat; i++ {
        pk[i], sk[i] = KeyGen(pp[i])
    }
    timer.End("KeyGen")

    m1 := make([]*pbc.Element, repeat)
    m2 := make([]*pbc.Element, repeat)
    for i := 0; i < repeat; i++ {
        m1[i] = pp[i].GetZrElement()
        m2[i] = pp[i].GetZrElement()
    }

    h1 := make([]*HashValue, repeat)
    r1 := make([]*Randomness, repeat)
    etd1 := make([]*ETrapdoor, repeat)

    timer.Start("Hash")
    for i := 0; i < repeat; i++ {
        h1[i], r1[i], etd1[i] = Hash(pp[i], pk[i], m1[i])
    }
    timer.End("Hash")

    checkRes := make([]bool, repeat)
    timer.Start("Check")
    for i := 0; i < repeat; i++ {
        checkRes[i] = Check(h1[i], r1[i], pp[i], pk[i], m1[i])
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
        r1_p[i] = Adapt(h1[i], r1[i], etd1[i], pp[i], pk[i], sk[i], m1[i], m2[i])
    }
    timer.End("Adapt")

    for i := 0; i < repeat; i++ {
        if !Check(h1[i], r1_p[i], pp[i], pk[i], m2[i]) {
            t.Fatal("Adapt(m2) invalid")
        }
    }

    timer.AverageAndEnd()
}

func TestCH_ET_KOG_CDK_2017(t *testing.T) {
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
		cur curve.Curve
		group pbc.Field
	}{}

	for _, c := range curs {
		for _, g := range groups {
            cases = append(cases, struct {
                cur  curve.Curve
                group pbc.Field
            }{
                cur:  c,
                group:g,
            })
			
		}
	}

	for i, c := range cases {
		curveName := curve.CurveName[c.cur]
        groupName := curve.GroupName[c.group]
		t.Run(fmt.Sprintf("case %d %s %s", i+1, curveName, groupName), func(t *testing.T) {
			run_scheme_benchmark(t, c.cur, c.group)
		})
	}

}