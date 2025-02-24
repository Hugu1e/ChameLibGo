package utils

import (
	"github.com/Nik-U/pbc"
)

func POWZN(x, i *pbc.Element) *pbc.Element {
    return x.NewFieldElement().PowZn(x, i)
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