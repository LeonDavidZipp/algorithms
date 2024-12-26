package cryptography

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var tree *MerkleTree
var vals = [][]byte{}

func TestMain(m *testing.M) {
	vals = [][]byte{
		[]byte("hello"),
		[]byte("world"),
		[]byte("this"),
		[]byte("is"),
		[]byte("a"),
		[]byte("test"),
	}

	var err error
	tree, err = NewMerkleTree(vals)
	if err != nil {
		panic(err)
	}
}

func TestNewMerkleTree(t *testing.T) {
	assert.NotNil(t, tree)
	assert.Equal(t, uint32(6), tree.Size())
	assert.Equal(t, uint32(4), tree.Depth())
}

func TestCalcSizeAndDepth(t *testing.T) {
	tree.calcSize()
	tree.calcDepth()

	assert.Equal(t, uint32(6), tree.Size())
	assert.Equal(t, uint32(4), tree.Depth())
}

func TestSiseDepth(t *testing.T) {
	assert.Equal(t, uint32(6), tree.Size())
	assert.Equal(t, uint32(4), tree.Depth())
}

func TestLeaves(t *testing.T) {
	// get all leaves
	leaves := tree.Leaves()
	assert.Len(t, leaves, 6)
	for i := 0; i < 6; i++ {
		res, _ := Sha256(vals[i])
		assert.Equal(t, res, leaves[i].Value())
	}
}

func TestLeaf(t *testing.T) {
	// get all leaves
	for i := 0; i < 6; i++ {
		leaf, err := tree.Leaf(uint32(i))
		assert.Nil(t, err)
		res, _ := Sha256(vals[i])
		assert.Equal(t, res, leaf.Value())
	}

	// check error for out of bounds
	_, err := tree.Leaf(uint32(6))
	assert.NotNil(t, err)
}

func TestPushBackLeaf(t *testing.T) {
	// append a new leaf
	val := []byte("new")
	node, err := tree.PushBackLeaf(val)
	assert.Nil(t, err)
	assert.Equal(t, uint32(7), tree.Size())
	res, _ := Sha256(val)
	assert.Equal(t, res, node.Value())

	leaf, err := tree.Leaf(uint32(6))
	assert.Nil(t, err)
	res, _ = Sha256(val)
	assert.Equal(t, res, leaf.Value())

	// append another new leaf
	val = []byte("new2")
	node, err = tree.PushBackLeaf(val)
	assert.Nil(t, err)
	assert.Equal(t, uint32(8), tree.Size())
	res, _ = Sha256(val)
	assert.Equal(t, res, node.Value())

	leaf, err = tree.Leaf(uint32(7))
	assert.Nil(t, err)
	res, _ = Sha256(val)
	assert.Equal(t, res, leaf.Value())
}

func TestPrevNextPow2(t *testing.T) {
	// prev
	assert.Equal(t, uint32(0), prevPow2(0))
	assert.Equal(t, uint32(1), prevPow2(1))
	assert.Equal(t, uint32(2), prevPow2(2))
	assert.Equal(t, uint32(2), prevPow2(3))
	assert.Equal(t, uint32(4), prevPow2(4))
	assert.Equal(t, uint32(4), prevPow2(5))
	assert.Equal(t, uint32(4), prevPow2(6))
	assert.Equal(t, uint32(4), prevPow2(7))
	assert.Equal(t, uint32(8), prevPow2(8))
	assert.Equal(t, uint32(8), prevPow2(9))
	assert.Equal(t, uint32(16), prevPow2(16))
	assert.Equal(t, uint32(16), prevPow2(23))
	assert.Equal(t, uint32(32), prevPow2(32))
	assert.Equal(t, uint32(32), prevPow2(33))
	assert.Equal(t, uint32(32), prevPow2(63))

	// next
	assert.Equal(t, uint32(0), nextPow2(0))
	assert.Equal(t, uint32(1), nextPow2(1))
	assert.Equal(t, uint32(2), nextPow2(2))
	assert.Equal(t, uint32(4), nextPow2(3))
	assert.Equal(t, uint32(4), nextPow2(4))
	assert.Equal(t, uint32(8), nextPow2(5))
	assert.Equal(t, uint32(8), nextPow2(6))
	assert.Equal(t, uint32(8), nextPow2(7))
	assert.Equal(t, uint32(8), nextPow2(8))
	assert.Equal(t, uint32(16), nextPow2(9))
	assert.Equal(t, uint32(16), nextPow2(16))
	assert.Equal(t, uint32(32), nextPow2(17))
	assert.Equal(t, uint32(32), nextPow2(32))
	assert.Equal(t, uint32(64), nextPow2(33))
	assert.Equal(t, uint32(64), nextPow2(63))
}
