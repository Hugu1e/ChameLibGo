package curve

import (
	"github.com/Nik-U/pbc"
)

func PairingGen(cur int) *pbc.Pairing {
	var param *pbc.Params
	var err error
	switch cur {
	// case A_80: 
	// 	param, err = pbc.NewParamsFromString(a_param_80)
	// case A_112:
	// 	param, err = pbc.NewParamsFromString(a_param_112)
	// case A_128:
	// 	param, err = pbc.NewParamsFromString(a_param_128)
	// case A_160:
	// 	param, err = pbc.NewParamsFromString(a_param_160)
	case A:
		param, err = pbc.NewParamsFromString(a_param)
	case A1:
		param, err = pbc.NewParamsFromString(a1_param)
	case D_159:
		param, err = pbc.NewParamsFromString(d159_param)
	case D_201:
		param, err = pbc.NewParamsFromString(d201_param)
	case D_224:
		param, err = pbc.NewParamsFromString(d224_param)
	case D_105171_196_185:
		param, err = pbc.NewParamsFromString(d105171_196_185_param)
	case D_277699_175_167:
		param, err = pbc.NewParamsFromString(d277699_175_167_param)
	case D_278027_190_181:
		param, err = pbc.NewParamsFromString(d278027_190_181_param)
	case E:
		param, err = pbc.NewParamsFromString(e_param)
	case F:
		param, err = pbc.NewParamsFromString(f_param)
	case SM_9:
		param, err = pbc.NewParamsFromString(sm9_param)
	case G_149:
		param, err = pbc.NewParamsFromString(g149_param)
	default:
		param, err = pbc.NewParamsFromString(a_param)
	}
	if err != nil {
		panic(err)
	}
	return param.NewPairing()
}