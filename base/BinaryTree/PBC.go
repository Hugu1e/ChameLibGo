package BinaryTree

import (
	"fmt"
	"strings"

	"github.com/Hugu1e/ChameLibGo/utils"
	"github.com/Nik-U/pbc"
)

type RevokeList struct {
	Rl map[string]int
}

func NewRevokeList() *RevokeList {
	return &RevokeList{Rl: make(map[string]int)}
}

func (rl *RevokeList) Add(id *pbc.Element, expireTime int) {
	str_id := id.String()
	if _, exists := rl.Rl[str_id]; !exists || (exists && rl.Rl[str_id] >= expireTime) {
		rl.Rl[str_id] = expireTime
	}
}

type BinaryTree struct {
	EmptyLeafID int
	Id2Node     map[string]int
	GTheta      []*pbc.Element
	TagG        []bool
	Tag         []bool
}

func NewBinaryTree(n int) *BinaryTree {
	return &BinaryTree{
		EmptyLeafID: n - 1,
		Id2Node:     make(map[string]int),
		GTheta:      make([]*pbc.Element, 2*n-1),
		TagG:        make([]bool, 2*n-1),
		Tag:         make([]bool, 2*n-1),
	}
}

func (p *BinaryTree) GetFNodeId(id int) int {
	return (id - 1) >> 1
}

func (p *BinaryTree) Pick(id *pbc.Element) int {
	str_id := id.String()
	if _, exists := p.Id2Node[str_id]; !exists {
		if p.EmptyLeafID == len(p.GTheta) {
			panic("binary tree is full")
		}
		p.Id2Node[str_id] = p.EmptyLeafID
		p.EmptyLeafID++
	}
	return p.Id2Node[str_id]
}

func (p *BinaryTree) Setg(nodeID int, g *pbc.Element) {
	p.TagG[nodeID] = true
	p.GTheta[nodeID] = utils.COPY(g)
}

func (p *BinaryTree) GetUpdateKeyNode(rl *RevokeList, time int) {
	for i := range p.GTheta {
		p.Tag[i] = true
	}
	for id, expireTime := range rl.Rl {
		if expireTime <= time {
			if nodeID, exists := p.Id2Node[id]; exists {
				p.Tag[nodeID] = false
				for nodeID != 0 {
					nodeID = p.GetFNodeId(nodeID)
					p.Tag[nodeID] = false
				}
			}
		}
	}
	for i := len(p.GTheta) - 1; i > 0; i-- {
		if p.Tag[p.GetFNodeId(i)] {
			p.Tag[i] = false
		}
	}
}

func (p *BinaryTree) Print() {
	h := 1
	for len(p.GTheta) > h {
		h <<= 1
	}
	fmt.Println(h)
	id, i := 0, 1
	for id < len(p.GTheta) {
		fmt.Print(strings.Repeat(" ", (h>>1)-1))
		for j := 0; j < i; j++ {
			if id == len(p.GTheta) {
				break
			}
			if p.Tag[id] {
				fmt.Print("1")
			} else {
				fmt.Print("0")
			}
			fmt.Print(strings.Repeat(" ", h-1))
			id++
		}
		fmt.Println()
		i <<= 1
		h >>= 1
	}
	fmt.Println("done print BT")
}

func (p *BinaryTree) PrintTheta() {
	h := 1
	for len(p.GTheta) > h {
		h <<= 1
	}
	fmt.Println(h)
	id, i := 0, 1
	for id < len(p.GTheta) {
		fmt.Print(strings.Repeat(" ", (h>>1)-1))
		for j := 0; j < i; j++ {
			if id == len(p.GTheta) {
				break
			}
			if p.TagG[id] {
				fmt.Print("1")
			} else {
				fmt.Print("0")
			}
			fmt.Print(strings.Repeat(" ", h-1))
			id++
		}
		fmt.Println()
		i <<= 1
		h >>= 1
	}
	fmt.Println("done print BT")
}