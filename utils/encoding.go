package utils

import "github.com/Nik-U/pbc"

type EncText struct {
	K pbc.Element
}
func NewEncText(m *pbc.Element) *EncText {
	et := new(EncText)
	et.K = *COPY(m)
	return et
}

type PlaText struct {
	K []byte
	R []byte
}

func NewPlaText(k, r []byte) *PlaText {
	pla := new(PlaText)
	pla.K = make([]byte, len(k))
	pla.R = make([]byte, len(r))
	copy(pla.K, k)
	copy(pla.R, r)
	return pla
}

func Encode(pairing *pbc.Pairing, G pbc.Field, P *PlaText) *EncText {
	K := new(EncText)

	tmp := make([]byte, pairing.GTLength())
	tmp[1] = byte(len(P.K))
	copy(tmp[2:], P.K)
	tmp[pairing.GTLength()/2+1] = byte(len(P.R))
	copy(tmp[pairing.GTLength()/2+2:], P.R)

	switch G {
	case pbc.G1:
		K.K = *pairing.NewG1().SetBytes(tmp)
	case pbc.G2:
		K.K = *pairing.NewG2().SetBytes(tmp)
	case pbc.GT:
		K.K = *pairing.NewGT().SetBytes(tmp)
	case pbc.Zr:
		K.K = *pairing.NewZr().SetBytes(tmp)
	default:
		panic("Encode Failed: Unknown Field G")
	}
	return K
}

func Decode(K *EncText) *PlaText {
	P := new(PlaText)

	tmp := K.K.Bytes()
	l1 := int(tmp[1])
	if l1 >= len(tmp) {
		panic("Decode Failed")
	}
	P.K = make([]byte, l1)
	copy(P.K, tmp[2:2+l1])
	l2 := int(tmp[K.K.BytesLen()/2+1])
	if l2+K.K.BytesLen()/2 >= len(tmp) {
		panic("Decode Failed")
	}
	P.R = make([]byte, l2)
	copy(P.R, tmp[K.K.BytesLen()/2+2:K.K.BytesLen()/2+2+l2])

	return P
}