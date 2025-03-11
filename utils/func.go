package utils

import (
	"math/big"

	"github.com/Hugu1e/ChameLibGo/curve"
	"github.com/Nik-U/pbc"
)

func POWZN(x, i *pbc.Element) *pbc.Element {
    return x.NewFieldElement().PowZn(x, i)
}
func POWBIG(x *pbc.Element, i *big.Int) *pbc.Element {
    return x.NewFieldElement().PowBig(x, i)
}
func MUL(x, y *pbc.Element) *pbc.Element {
    return x.NewFieldElement().Mul(x, y)
}
func DIV(x, y *pbc.Element) *pbc.Element {
    return x.NewFieldElement().Div(x, y)
}
func ADD(x, y *pbc.Element) *pbc.Element {
    return x.NewFieldElement().Add(x, y)
}
func SUB(x, y *pbc.Element) *pbc.Element {
    return x.NewFieldElement().Sub(x, y)
}
func INVERT(x *pbc.Element) *pbc.Element {
	return x.NewFieldElement().Invert(x)
}
func NEG(x *pbc.Element) *pbc.Element {
    return x.NewFieldElement().Neg(x)
}
func COPY(x *pbc.Element) *pbc.Element {
    return x.NewFieldElement().Set(x)
}

func pbc_mpz_trace_n(q, trace *big.Int, n int) *big.Int {
    c2 := big.NewInt(2)
    c1 := new(big.Int).Set(trace)

    for i := 2; i <= n; i++ {
        c0 := new(big.Int).Mul(trace, c1)
        t0 := new(big.Int).Mul(q, c2)
        c0.Sub(c0, t0)
        c2.Set(c1)
        c1.Set(c0)
    }

    return c1
}

func pbc_mpz_curve_order_extn(q, t *big.Int, k int) *big.Int {
    kBig := big.NewInt(int64(k))
    qPowK := new(big.Int).Exp(q, kBig, nil)

    return new(big.Int).Sub(qPowK.Add(qPowK, big.NewInt(1)), pbc_mpz_trace_n(q, t, k))
}

func GetNdonr(group pbc.Field, curveName curve.Curve) *big.Int {
    res := big.NewInt(1)
    switch group {
    case pbc.G1:
        return res
    case pbc.GT:
        return res
    case pbc.G2:
        switch curveName {
        case curve.A, curve.A1, curve.E:
            return res
        case curve.D_159, curve.D_201, curve.D_224, curve.D_105171_196_185, curve.D_277699_175_167, curve.D_278027_190_181:
            q := curveName.GetBigInt("q")
            t := new(big.Int).Neg(new(big.Int).Add(new(big.Int).Sub(q, curveName.GetBigInt("n")), big.NewInt(1)))
            k := int(new(big.Int).Div(curveName.GetBigInt("k"), big.NewInt(2)).Int64())
            return new(big.Int).Div(pbc_mpz_curve_order_extn(q, t, k), curveName.GetBigInt("r"))
        case curve.F, curve.SM_9:
            q := curveName.GetBigInt("q")
            t := new(big.Int).Add(new(big.Int).Sub(q, curveName.GetBigInt("r")), big.NewInt(1))
            r := curveName.GetBigInt("r")
            return new(big.Int).Div(new(big.Int).Div(pbc_mpz_curve_order_extn(q, t, 12), r), r)
        case curve.G_149:
            q := curveName.GetBigInt("q")
            t := new(big.Int).Neg(new(big.Int).Add(new(big.Int).Sub(q, curveName.GetBigInt("n")), big.NewInt(1)))
            return new(big.Int).Div(pbc_mpz_curve_order_extn(q, t, 5), curveName.GetBigInt("r"))
        default:
            panic("Unknown curve")
        }
    default:
        panic("Unknown group")
    }
}