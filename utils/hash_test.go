package utils

import (
	"math/big"
	"testing"

	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Nik-U/pbc"
)

func Test_H_String_PBC(t *testing.T){
	str := "test string"

	pbc_G1 := H_String_1_PBC_1(curve.PairingGen(curve.A), pbc.G1, str)
	pbc_G2 := H_String_1_PBC_1(curve.PairingGen(curve.A), pbc.G2, str)
	pbc_GT := H_String_1_PBC_1(curve.PairingGen(curve.A), pbc.GT, str)
	pbc_Zr := H_String_1_PBC_1(curve.PairingGen(curve.A), pbc.Zr, str)

	if pbc_G1 == nil || pbc_G2 == nil || pbc_GT == nil || pbc_Zr == nil {
		t.Error("H_String_1_PBC_1 failed")
	}
}

func Test_H_PBC(t *testing.T){
	pbc_G1 := curve.PairingGen(curve.A).NewG1().Rand()
	pbc_G2 := curve.PairingGen(curve.A).NewG2().Rand()
	pbc_GT := curve.PairingGen(curve.A).NewGT().Rand()

	pbc_Zr_1 := H_PBC_1_1(curve.PairingGen(curve.A), pbc.Zr, pbc_G1)
	if pbc_Zr_1 == nil {
		t.Error("H_PBC_1_1 failed")
	}
	pbc_Zr_2 := H_PBC_2_1(curve.PairingGen(curve.A), pbc.Zr, pbc_G1, pbc_G2)
	if pbc_Zr_2 == nil {
		t.Error("H_PBC_2_1 failed")
	}
	pbc_Zr_3 := H_PBC_3_1(curve.PairingGen(curve.A), pbc.Zr, pbc_G1, pbc_G2, pbc_GT)
	if pbc_Zr_3 == nil {
		t.Error("H_PBC_3_1 failed")
	}
}

func Test_H_native(t *testing.T){
	bigInt_1 := new(big.Int).SetInt64(1)
	bigInt_2 := new(big.Int).SetInt64(2)

	native_1 := H_native_1_1(bigInt_1)
	if native_1 == nil {
		t.Error("H_native_1_1 failed")
	}
	native_2 := H_native_2_1(bigInt_1, bigInt_2)
	if native_2 == nil {
		t.Error("H_native_2_1 failed")
	}
}

func Test_H_PBC_native(t *testing.T){
	pbc_G1 := curve.PairingGen(curve.A).NewG1().Rand()
	pbc_G2 := curve.PairingGen(curve.A).NewG2().Rand()
	pbc_GT := curve.PairingGen(curve.A).NewGT().Rand()

	native_1 := H_PBC_1_native_1(pbc_G1)
	if native_1 == nil {
		t.Error("H_PBC_1_native_1 failed")
	}
	native_2 := H_PBC_3_native_1(pbc_G1, pbc_G2, pbc_GT)
	if native_2 == nil {
		t.Error("H_PBC_3_native_1 failed")
	}
}