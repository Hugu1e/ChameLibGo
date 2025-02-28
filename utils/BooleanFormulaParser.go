package utils

import (
	"errors"
	"fmt"
	"github.com/Nik-U/pbc"
)

type TokenType int
const (
	AND TokenType = iota
	OR
	LEFT_BRACKET
	RIGHT_BRACKET
	TOKEN
	POLICY
)

type Node struct {
	x   int
	tag []int16
}

type NodePBC struct {
	x   int
	tag []*pbc.Element
}

type AttributeList struct {
	Attrs map[string]struct{}
}
func (al *AttributeList) CopyFrom(other *AttributeList) {
	if al.Attrs == nil {
		al.Attrs = make(map[string]struct{})
	}
	for attr := range other.Attrs {
		al.Attrs[attr] = struct{}{}
	}
}
func NewAttributeList() *AttributeList {
	return &AttributeList{Attrs: make(map[string]struct{})}
}
func (al *AttributeList) Add(attr string) {
	al.Attrs[attr] = struct{}{}
}
func (al *AttributeList) Print() {
	fmt.Println("AttributeList:")
	for attr := range al.Attrs {
		fmt.Println(attr)
	}
	fmt.Println()
}

type PolicyList struct {
	Policy []string
}
func (pl *PolicyList) Resize(n int) {
	pl.Policy = make([]string, n)
}
func (pl *PolicyList) Print() {
	fmt.Println("PolicyList:")
	for _, pol := range pl.Policy{
		fmt.Println(pol)
	}
	fmt.Println()
}

type BooleanFormulaParser struct {
	tokens []TokenType
	range_ [][]int
	n, m, x int
	formula string
}

func NewBooleanFormulaParser(pl *PolicyList, BooleanFormulas string) (*BooleanFormulaParser, error) {
	bfp := &BooleanFormulaParser{
		formula: BooleanFormulas,
		n:       0,
		m:       1,
		range_:  make([][]int, len(BooleanFormulas)),
		tokens:  make([]TokenType, len(BooleanFormulas)),
	}
	for i := range bfp.range_ {
		bfp.range_[i] = make([]int, 2)
	}

	gates := []int{}
	for i := 0; i < len(BooleanFormulas); i++ {
		bfp.range_[i][0] = i
		bfp.range_[i][1] = i
		switch BooleanFormulas[i] {
		case '&':
			bfp.tokens[i] = AND
			gates = append(gates, i)
			bfp.m++
		case '|':
			bfp.tokens[i] = OR
			gates = append(gates, i)
		case '(':
			bfp.tokens[i] = LEFT_BRACKET
		case ')':
			bfp.tokens[i] = RIGHT_BRACKET
		default:
			bfp.tokens[i] = POLICY
			if i == 0 || bfp.tokens[i-1] != POLICY {
				bfp.n++
			} else {
				bfp.range_[i][0] = bfp.range_[i-1][0]
				bfp.range_[bfp.range_[i][0]][1] = i
			}
		}
	}

	pl.Resize(bfp.n)
	L, R, loopCnt, rowCnt := 0, 0, 0, 0
	for len(gates) > 0 {
		if loopCnt >= len(gates) {
			return nil, errors.New("wrong boolean formulas")
		}
		bfp.x = gates[0]
		gates = gates[1:]
		if (bfp.tokens[bfp.x-1] != TOKEN && bfp.tokens[bfp.x-1] != POLICY) || (bfp.tokens[bfp.x+1] != TOKEN && bfp.tokens[bfp.x+1] != POLICY) {
			gates = append(gates, bfp.x)
			loopCnt++
			continue
		}
		loopCnt = 0
		L = bfp.range_[bfp.x-1][0]
		if bfp.tokens[L] == POLICY && bfp.tokens[bfp.x-1] == POLICY {
			pl.Policy[rowCnt] = BooleanFormulas[L:bfp.x]
			bfp.range_[bfp.x][0] = -rowCnt
			rowCnt++
			bfp.tokens[L] = TOKEN
			bfp.tokens[bfp.x-1] = TOKEN
		} else {
			bfp.range_[bfp.x][0] = bfp.range_[bfp.x-1][1]
		}
		R = bfp.range_[bfp.x+1][1]
		if bfp.tokens[R] == POLICY && bfp.tokens[bfp.x+1] == POLICY {
			pl.Policy[rowCnt] = BooleanFormulas[bfp.x+1 : R+1]
			bfp.range_[bfp.x][1] = -rowCnt
			rowCnt++
			bfp.tokens[R] = TOKEN
			bfp.tokens[bfp.x+1] = TOKEN
		} else {
			bfp.range_[bfp.x][1] = bfp.range_[bfp.x+1][0]
		}
		if L > 0 && bfp.tokens[L-1] == LEFT_BRACKET {
			L--
			bfp.tokens[L] = TOKEN
			if R < len(BooleanFormulas)-1 && bfp.tokens[R+1] == RIGHT_BRACKET {
				R++
				bfp.tokens[R] = TOKEN
			} else {
				return nil, errors.New("wrong boolean formulas")
			}
		}
		bfp.range_[L][0] = bfp.x
		bfp.range_[L][1] = R
		bfp.range_[R][0] = L
		bfp.range_[R][1] = bfp.x
	}
	if bfp.range_[0][1] != len(BooleanFormulas)-1 || bfp.range_[len(BooleanFormulas)-1][0] != 0 {
		return nil, errors.New("wrong boolean formulas")
	}
	if bfp.x == -1 {
		pl.Policy[0] = bfp.formula
	}
	return bfp, nil
}

func (bfp *BooleanFormulaParser) SetToNativeMatrix() *NativeMatrix {
	M := new(NativeMatrix)

	M.Resize(bfp.n, bfp.m)
	if bfp.x == -1 {
		M.M[0][0] = 1
	} else {
		rt := []Node{{x: bfp.x, tag: make([]int16, bfp.m)}}
		rt[0].tag[0] = 1
		colCnt := 1
		for len(rt) > 0 {
			tmp := rt[0]
			rt = rt[1:]
			if bfp.tokens[tmp.x] == AND {
				if bfp.range_[tmp.x][0] < 1 {
					if colCnt >= 0{
						copy(M.M[-bfp.range_[tmp.x][0]], tmp.tag[:colCnt])
					}	
					M.M[-bfp.range_[tmp.x][0]][colCnt] = 1
				} else {
					tmpL := Node{x: bfp.range_[tmp.x][0], tag: make([]int16, bfp.m)}
					if colCnt >= 0{
						copy(tmpL.tag, tmp.tag[:colCnt])
					}
					tmpL.tag[colCnt] = 1
					rt = append(rt, tmpL)
				}
				if bfp.range_[tmp.x][1] < 1 {
					M.M[-bfp.range_[tmp.x][1]][colCnt] = -1
				} else {
					tmpR := Node{x: bfp.range_[tmp.x][1], tag: make([]int16, bfp.m)}
					tmpR.tag[colCnt] = -1
					rt = append(rt, tmpR)
				}
				colCnt++
			} else if bfp.tokens[tmp.x] == OR {
				if bfp.range_[tmp.x][0] < 1 {
					if colCnt>=0{
						copy(M.M[-bfp.range_[tmp.x][0]], tmp.tag[:colCnt])
					}
				} else {
					tmpL := Node{x: bfp.range_[tmp.x][0], tag: tmp.tag}
					rt = append(rt, tmpL)
				}
				if bfp.range_[tmp.x][1] < 1 {
					if colCnt>=0{
						copy(M.M[-bfp.range_[tmp.x][1]], tmp.tag[:colCnt])
					}
					
				} else {
					tmpR := Node{x: bfp.range_[tmp.x][1], tag: tmp.tag}
					rt = append(rt, tmpR)
				}
			}
		}
	}

	return M
}

func (bfp *BooleanFormulaParser) SetToPBCMatrix(M *PBCMatrix){
	M.Formula = bfp.formula
	M.Resize(bfp.n, bfp.m)
	zeroList := make([]*pbc.Element, bfp.m)
	for i := range zeroList {
		zeroList[i] = M.GetZeroElement()
	}
	if bfp.x == -1 {
		M.M[0][0] = M.GetOneElement()
	} else {
		rt := []NodePBC{{x: bfp.x, tag: make([]*pbc.Element, bfp.m)}}
		copy(rt[0].tag, zeroList)
		rt[0].tag[0] = M.GetOneElement()
		colCnt := 1
		for len(rt) > 0 {
			tmp := rt[0]
			rt = rt[1:]
			if bfp.tokens[tmp.x] == AND {
				if bfp.range_[tmp.x][0] < 1 {
					copy(M.M[-bfp.range_[tmp.x][0]], tmp.tag)
					M.M[-bfp.range_[tmp.x][0]][colCnt] = M.GetOneElement()
				} else {
					tmpL := NodePBC{x: bfp.range_[tmp.x][0], tag: make([]*pbc.Element, bfp.m)}
					copy(tmpL.tag, tmp.tag)
					tmpL.tag[colCnt] = M.GetOneElement()
					rt = append(rt, tmpL)
				}
				if bfp.range_[tmp.x][1] < 1 {
					copy(M.M[-bfp.range_[tmp.x][1]], zeroList)
					M.M[-bfp.range_[tmp.x][1]][colCnt] = M.GetOneElement().ThenNeg()
				} else {
					tmpR := NodePBC{x: bfp.range_[tmp.x][1], tag: make([]*pbc.Element, bfp.m)}
					copy(tmpR.tag, zeroList)
					tmpR.tag[colCnt] = M.GetOneElement().ThenNeg()
					rt = append(rt, tmpR)
				}
				colCnt++
			} else if bfp.tokens[tmp.x] == OR {
				if bfp.range_[tmp.x][0] < 1 {
					copy(M.M[-bfp.range_[tmp.x][0]], tmp.tag)
				} else {
					tmpL := NodePBC{x: bfp.range_[tmp.x][0], tag: tmp.tag}
					rt = append(rt, tmpL)
				}
				if bfp.range_[tmp.x][1] < 1 {
					copy(M.M[-bfp.range_[tmp.x][1]], tmp.tag)
				} else {
					tmpR := NodePBC{x: bfp.range_[tmp.x][1], tag: tmp.tag}
					rt = append(rt, tmpR)
				}
			}
		}
	}
}