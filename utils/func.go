package utils

import (
	"github.com/Nik-U/pbc"
	"github.com/Hugu1e/ChameLibGo/curve"
)

func PairingGen(cur int) *pbc.Pairing {
	var param *pbc.Params
	var err error
	switch cur {
	// case curve.A_80: 
	// 	param, err = pbc.NewParamsFromString(curve.A_param_80)
	// case curve.A_112:
	// 	param, err = pbc.NewParamsFromString(curve.A_param_112)
	// case curve.A_128:
	// 	param, err = pbc.NewParamsFromString(curve.A_param_128)
	// case curve.A_160:
	// 	param, err = pbc.NewParamsFromString(curve.A_param_160)
	case curve.A:
		param, err = pbc.NewParamsFromString(curve.A_param)
	case curve.A1:
		param, err = pbc.NewParamsFromString(curve.A1_param)
	case curve.D_159:
		param, err = pbc.NewParamsFromString(curve.D159_param)
	case curve.D_201:
		param, err = pbc.NewParamsFromString(curve.D201_param)
	case curve.D_224:
		param, err = pbc.NewParamsFromString(curve.D224_param)
	case curve.D_105171_196_185:
		param, err = pbc.NewParamsFromString(curve.D105171_196_185_param)
	case curve.D_277699_175_167:
		param, err = pbc.NewParamsFromString(curve.D277699_175_167_param)
	case curve.D_278027_190_181:
		param, err = pbc.NewParamsFromString(curve.D278027_190_181_param)
	case curve.E:
		param, err = pbc.NewParamsFromString(curve.E_param)
	case curve.F:
		param, err = pbc.NewParamsFromString(curve.F_param)
	case curve.SM_9:
		param, err = pbc.NewParamsFromString(curve.Sm9_param)
	case curve.G_149:
		param, err = pbc.NewParamsFromString(curve.G149_param)
	default:
		param, err = pbc.NewParamsFromString(curve.A_param)
	}
	if err != nil {
		panic(err)
	}
	return param.NewPairing()
}