package curve

import (
	"testing"
	"github.com/Nik-U/pbc"
)

func baseRun(t *testing.T, pairing *pbc.Pairing) {
    // Initialize group elements. pbc automatically handles garbage collection.
	g := pairing.NewG1()
	h := pairing.NewG2()
	x := pairing.NewGT()

	// Generate random group elements and pair them
	g.Rand()
	h.Rand()
	// fmt.Printf("g = %s\n", g)
	// fmt.Printf("h = %s\n", h)
	x.Pair(g, h)
	// fmt.Printf("e(g,h) = %s\n", x)
	if(x.Is1()) {
		t.Errorf("pairing failed")
	}
}

func TestRandomTypeACurve(t *testing.T) {
	params := pbc.GenerateA(160, 512)
	pairing := params.NewPairing()
    baseRun(t, pairing)
}

func TestTypeACurve(t *testing.T) {
    baseRun(t, PairingGen(A))
}

// func TestTypeA_80Curve(t *testing.T) {
// 	baseRun(t, PairingGen(A_80))
// }

// func TestTypeA_112Curve(t *testing.T) {
// 	baseRun(t, PairingGen(A_112))
// }

// func TestTypeA_128Curve(t *testing.T) {
// 	baseRun(t, PairingGen(A_128))
// }

// func TestTypeA_160Curve(t *testing.T) {
// 	baseRun(t, PairingGen(A_160))
// }

func TestTypeA1Curve(t *testing.T) {
	baseRun(t, PairingGen(A1))
}

func TestTypeD_159Curve(t *testing.T) {
	baseRun(t, PairingGen(D_159))
}

func TestTypeD_201Curve(t *testing.T) {
	baseRun(t, PairingGen(D_201))
}

func TestTypeD_224Curve(t *testing.T) {
	baseRun(t, PairingGen(D_224))
}

func TestTypeD_105171_196_185Curve(t *testing.T) {
	baseRun(t, PairingGen(D_105171_196_185))
}

func TestTypeD_277699_175_167Curve(t *testing.T) {
	baseRun(t, PairingGen(D_277699_175_167))
}

func TestTypeD_278027_190_181Curve(t *testing.T) {
	baseRun(t, PairingGen(D_278027_190_181))
}

func TestTypeECurve(t *testing.T) {
	baseRun(t, PairingGen(E))
}

func TestTypeFCurve(t *testing.T) {
	baseRun(t, PairingGen(F))
}

func TestTypeSM_9Curve(t *testing.T) {
	baseRun(t, PairingGen(SM_9))
}

func TestTypeG_149Curve(t *testing.T) {
	baseRun(t, PairingGen(G_149))
}