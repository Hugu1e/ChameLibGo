package utils

import (
	"crypto/sha256"
	"math/big"

	"github.com/Nik-U/pbc"
)

func H_String_1_PBC_1(pairing *pbc.Pairing, field pbc.Field, m string) *pbc.Element{
    switch field {
    case pbc.G1:
        return pairing.NewG1().SetFromStringHash(m, sha256.New())
    case pbc.G2:
        return pairing.NewG2().SetFromStringHash(m, sha256.New())
    case pbc.GT:
        return pairing.NewGT().SetFromStringHash(m, sha256.New())
    case pbc.Zr:
        return pairing.NewZr().SetFromStringHash(m, sha256.New())
    default:
        return nil
    }
}

func H_PBC_1_1(pairing *pbc.Pairing, field pbc.Field, m *pbc.Element) *pbc.Element{
    return H_String_1_PBC_1(pairing, field, m.String())
}

func H_PBC_2_1(pairing *pbc.Pairing, field pbc.Field, m1, m2 *pbc.Element) *pbc.Element{
    return H_String_1_PBC_1(pairing, field, m1.String() + "|" + m2.String())
}

func H_PBC_3_1(pairing *pbc.Pairing, field pbc.Field, m1, m2, m3 *pbc.Element) *pbc.Element{
    return H_String_1_PBC_1(pairing, field, m1.String() + "|" + m2.String() + "|" + m3.String())
}

func H_native_1_1(m *big.Int) *big.Int {
    h := sha256.New()
    h.Write(m.Bytes())
    return new(big.Int).SetBytes(h.Sum(nil))
}

func H_native_2_1(m1, m2 *big.Int) *big.Int {
    h := sha256.New()
    h.Write([]byte(m1.String() + "|" + m2.String()))
    return new(big.Int).SetBytes(h.Sum(nil))
}

func H_PBC_1_native_1(m *pbc.Element) *big.Int {
    h := sha256.New()
    h.Write(m.Bytes())
    return new(big.Int).SetBytes(h.Sum(nil))
}

func H_PBC_3_native_1(m1, m2, m3 *pbc.Element) *big.Int {
    h := sha256.New()
    h.Write([]byte(m1.String() + "|" + m2.String() + "|" + m3.String()))
    return new(big.Int).SetBytes(h.Sum(nil))
}

type H_2_element struct{
    U_1, U_2 *pbc.Element
}

func H_2_element_String_2(pairing *pbc.Pairing, G pbc.Field, m1, m2 string) *H_2_element {
    u := new(H_2_element)
    u.U_1 = H_String_1_PBC_1(pairing, G, m1 + "|" + m2)
    u.U_2 = H_String_1_PBC_1(pairing, G, m2 + "|" + m1)
    return u
}

func H_2_element_String_3(pairing *pbc.Pairing, G pbc.Field, m1, m2, m3 string) *H_2_element{
    u := new(H_2_element)
    u.U_1 = H_String_1_PBC_1(pairing, G, m1 + "|" + m2 + "|" + m3)
    u.U_2 = H_String_1_PBC_1(pairing, G, m3 + "|" + m2 + "|" + m1)
    return u
}
