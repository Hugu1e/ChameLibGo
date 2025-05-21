package BaseTest

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

func run_scheme_benchmark(t *testing.T, cur curve.Curve) {
	repeat := *r
	timer := utils.NewTimer(t.Name(), repeat)
	Pairing := curve.PairingGen(cur)

	// var Glist [4][repeat]pbc.Element;
	var Glist = make([][]*pbc.Element, 4)
	for i := range Glist {
		Glist[i] = make([]*pbc.Element, repeat + 1)
	}

	names := []string{
		"G1",
		"G2",
		"GT",
		"Zr",
	}

	groups := []pbc.Field{
		pbc.G1,
		pbc.G2,
		pbc.GT,
		pbc.Zr,
	}

	var iii = 0;
	{
		timer.Start(names[iii] + "_Rand")
		for j := 0; j < repeat; j++ {
			Glist[iii][j] = Pairing.NewG1().Rand()
		}
		timer.End(names[iii] + "_Rand")
		iii += 1
	}
	{
		timer.Start(names[iii] + "_Rand")
		for j := 0; j < repeat; j++ {
			Glist[iii][j] = Pairing.NewG2().Rand()
		}
		timer.End(names[iii] + "_Rand")
		iii += 1
	}
	{
		timer.Start(names[iii] + "_Rand")
		for j := 0; j < repeat; j++ {
			Glist[iii][j] = Pairing.NewGT().Rand()
		}
		timer.End(names[iii] + "_Rand")
		iii += 1
	}
	{
		timer.Start(names[iii] + "_Rand")
		for j := 0; j < repeat; j++ {
			Glist[iii][j] = Pairing.NewZr().Rand()
		}
		timer.End(names[iii] + "_Rand")
		iii += 1
	}

	Glist[0][repeat] = Pairing.NewG1().Rand()
	Glist[1][repeat] = Pairing.NewG2().Rand()
	Glist[2][repeat] = Pairing.NewGT().Rand()
	Glist[3][repeat] = Pairing.NewZr().Rand()

	for i := range Glist {
		timer.Start(names[i] + "_Hash")
		for j := 0; j < repeat; j++ {
			Glist[i][j] = utils.H_PBC_1_1(Pairing, groups[i], Glist[i][j])
		}
		timer.End(names[i] + "_Hash")
	}

	for i := range Glist {
		timer.Start(names[i] + "_Add")
		for j := 0; j < repeat; j++ {
			Glist[i][j] = utils.ADD(Glist[i][j], Glist[i][j + 1])
		}
		timer.End(names[i] + "_Add")
	}

	for i := range Glist {
		timer.Start(names[i] + "_Mul")
		for j := 0; j < repeat; j++ {
			Glist[i][j] = utils.MUL(Glist[i][j], Glist[i][j + 1])
		}
		timer.End(names[i] + "_Mul")
	}

	for i := range Glist {
		timer.Start(names[i] + "_Pow")
		for j := 0; j < repeat; j++ {
			Glist[i][j] = utils.POWZN(Glist[i][j], Glist[3][j])
		}
		timer.End(names[i] + "_Pow")
	}

	timer.Start("Pairing")
	for j := 0; j < repeat; j++ {
		Glist[2][j].Pair(Glist[0][j], Glist[1][j])
	}
	timer.End("Pairing")

	timer.AverageAndEnd()
}

func TestBaseTest(t *testing.T) {
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

	for i, c := range curs {
		curveName := curve.CurveName[c]
		t.Run(fmt.Sprintf("case %d %s", i+1, curveName), func(t *testing.T) {
			run_scheme_benchmark(t, c)
		})
	}
}

