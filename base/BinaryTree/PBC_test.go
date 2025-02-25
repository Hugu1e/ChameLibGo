package BinaryTree

import (
	"testing"

	"github.com/Hugu1e/ChameLibGo/utils"
	"github.com/Nik-U/pbc"
)

func TestBinaryTree(t *testing.T) {
	binaryTree := NewBinaryTree(8)
	binaryTree.Print()
	binaryTree.PrintTheta()

	params := pbc.GenerateA(160, 512)
	pairing := params.NewPairing()

	id7 := pairing.NewZr().SetInt32(7)
	id7_ := utils.COPY(id7)
	id8 := pairing.NewZr().SetInt32(8)
	id9 := pairing.NewZr().SetInt32(9)
	id10 := pairing.NewZr().SetInt32(10)
	id11 := pairing.NewZr().SetInt32(11)
	id12 := pairing.NewZr().SetInt32(12)

	rl := NewRevokeList()
	rl.Add(id7, 100)
	rl.Add(id7_, 90)
	rl.Add(id8, 50)
	rl.Add(id9, 100)
	rl.Add(id10, 100)
	rl.Add(id11, 50)
	rl.Add(id12, 50)
	
	binaryTree.GetUpdateKeyNode(rl, 80)

	binaryTree.Print()
	binaryTree.PrintTheta()
}