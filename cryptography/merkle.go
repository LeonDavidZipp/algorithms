package cryptography

import (
	"fmt"
	"math/bits"
)

type pos struct {
	// row index
	row uint32
	// column index
	col uint32
}

/* --------------------------------------------------------------------------------- */
/* Merkle Node                                                                       */
/* --------------------------------------------------------------------------------- */
// single node of the merkle tree
type MerkleNode struct {
	// parent node
	par *MerkleNode
	// next node in row
	next *MerkleNode
	// position in tree; if nil, pos has not been set yet
	pos *pos
	// hashed data
	val [32]byte
}

func NewMerkleNode(val [32]byte) *MerkleNode {
	return &MerkleNode{
		par:  nil,
		next: nil,
		pos:  nil,
		val:  val,
	}
}

// returns the parent node or nil
func (n *MerkleNode) Parent() *MerkleNode {
	return n.par
}

// returns the row index of node
func (n *MerkleNode) Position() *pos {
	return n.pos
}

// returns hash stored in node
func (n *MerkleNode) Value() [32]byte {
	return n.val
}

// returns next node after this one or nil
func (n *MerkleNode) Next() *MerkleNode {
	return n.next
}

/* --------------------------------------------------------------------------------- */
/* Optimized Merkle Tree                                                             */
/* Leaves that exceed 2^n are moved up the tree to minimize recalculations           */
/* This removes the need to store and hash palceholder nodes                         */
/* --------------------------------------------------------------------------------- */
// dimensions struct
type dim struct {
	// number of levels of the tree
	depth uint32
	// number of leaf nodes
	size uint32
}

// optimized merkle tree struct
type MerkleTree struct {
	// leaf nodes; simply holds the leaves
	leaves []*MerkleNode
	// tree; holds all nodes of the tree, including leaves
	tree [][]*MerkleNode
	//dimensions of the tree
	dim dim
}

// TODO: adjust for optimized tree
// creates a new merkle tree
func NewMerkleTree(leaves []*MerkleNode) *MerkleTree {
	tree := &MerkleTree{
		leaves: leaves,
		tree:   [][]*MerkleNode{},
	}

	tree.calcDim()

	// TODO: calculations to create tree

	return tree
}

// counts the number of leavf nodes
func (t *MerkleTree) calcSize() {
	t.dim.size = uint32(len((*t).leaves))
}

// returns count of leaf nodes of tree
func (t *MerkleTree) Size() uint32 {
	return t.dim.size
}

// calculates the next greater power of 2 to an uint32 variable
func nextPow2(n uint32) uint32 {
	switch n {
	case 0:
		return 0
	case 1:
		return 1
	default:
		return 1 << bits.Len32(n-1)
	}
}

// calculates the next smaller power of 2 to an uint32 variable
func prevPow2(n uint32) uint32 {
	switch n {
	case 0:
		return 0
	case 1:
		return 1
	default:
		return 1 << (bits.Len32(n) - 1)
	}
}

// returns the base-2 logarithm of n
func log2(n uint32) uint32 {
	return uint32(bits.Len32(n) - 1)
}

// returns count of rows of tree
func (t *MerkleTree) calcDepth() {
	if t.Size() == 0 {
		t.dim.depth = 0
	} else {
		t.dim.depth = log2(nextPow2(t.Size())) + 1
	}
}

// calculates the dimensions of the tree
func (t *MerkleTree) calcDim() {
	t.calcSize()
	t.calcDepth()
}

// returns depth of the tree
func (t *MerkleTree) Depth() uint32 {
	return t.dim.depth
}

// returns leaf nodes of tree
func (t *MerkleTree) Leaves() []*MerkleNode {
	return t.leaves
}

// returns leaf node at index i
func (t *MerkleTree) Leaf(i uint32) (*MerkleNode, error) {
	if i >= t.Size() {
		return nil, fmt.Errorf("out of bounds")
	}
	return t.leaves[i], nil
}

// calculates the least-calculations-optimized position of a leaf node in the tree
func (t *MerkleTree) calcPos(i uint32) *pos {
	return &pos{}
}

// TODO: adjust for optimized tree
// adds a new leaf node to the merkle tree leaves array
func (t *MerkleTree) PushBackLeaf(value []byte) (*MerkleNode, error) {
	val, err := Sha256(value)
	if err != nil {
		return nil, err
	}

	// TODO: fix, not correct for optimized tree yet
	node := NewMerkleNode(val)

	// add node to leaves
	t.leaves = append(t.leaves, node)
	if t.Size() > 0 {
		(*t).leaves[t.Size()-1].next = node
	}

	// recalculate dimensions
	t.calcDim()

	return node, nil
}

// PushFrontLeaf leads to whole tree needing to be recalculated!!!
// adds a new leaf node to the merkle tree leaves array
func (t *MerkleTree) PushFrontLeaf(value []byte) (*MerkleNode, error) {
	val, err := Sha256(value)
	if err != nil {
		return nil, err
	}

	// TODO: fix, not correct for optimized tree yet
	node := NewMerkleNode(val)

	// add node to leaves
	t.leaves = append([]*MerkleNode{node}, t.Leaves()...)
	if t.Size() > 1 {
		node.next = t.leaves[1]
	}

	// recalculate dimensions
	t.calcDim()

	return node, nil
}

// inserts a new leaf node at position i
func (t *MerkleTree) InsertLeaf(value []byte, i uint32) (*MerkleNode, error) {
	if i >= t.Size() {
		return nil, fmt.Errorf("out of bounds")
	}

	val, err := Sha256(value)
	if err != nil {
		return nil, err
	}

	node := NewMerkleNode(val)

	// more than 1 leaf node
	if t.Size() > 1 {
		// i is not first element
		if i > 0 {
			// i is not last element
			if i < t.Size()-1 {
				node.next = (*t).leaves[i]
				(*t).leaves[i-1].next = node
				newLeaves := append((*t).leaves[:i], node)
				(*t).leaves = append(newLeaves, (*t).leaves[i:]...)
			} else {
				(*t).leaves[i-1].next = node
				(*t).leaves = append((*t).leaves, node)
			}
		} else {
			(*t).leaves = append([]*MerkleNode{node}, (*t).leaves...)
		}
	} else {
		t.leaves = []*MerkleNode{node}
		t.tree = [][]*MerkleNode{[]*MerkleNode{node}}
	}

	t.calcDim()

	return node, nil
}

// deletes leaf node at index i
func (t *MerkleTree) DeleteLeaf(i uint32) error {
	if i >= t.Size() {
		return fmt.Errorf("out of bounds")
	}

	// more than 1 leaf node
	if t.Size() > 1 {
		// i is not first element
		if i > 0 {
			// i is not last element
			if i < t.Size()-1 {
				(*t).leaves[i-1].next = (*t).leaves[i+1]
				newLeaves := append((*t).leaves[:i], (*t).leaves[i+1:]...)
				(*t).leaves = newLeaves
			} else {
				(*t).leaves[i-1].next = nil
				(*t).leaves = (*t).leaves[:i]
			}
		} else {
			(*t).leaves = (*t).leaves[1:]
		}
	} else {
		t.leaves = []*MerkleNode{}
		t.tree = [][]*MerkleNode{}
	}

	t.calcDim()

	return nil
}

// returns a pos of which nodes with smaller or equal values can be skipped
func (t *MerkleTree) skippableNodes() pos {

}

// calculates the tree completely with no regard for indexing
func (t *MerkleTree) CalculateTree() {

}

// hashes two nodes & returns resulting parent node
func HashNodes(node1 *MerkleNode, node2 *MerkleNode) (*MerkleNode, error) {
	// generate parent node
	val1 := node1.Value()
	val2 := node2.Value()
	val, err := Sha256(append(val1[:], val2[:]...))
	if err != nil {
		return nil, err
	}
	parent := NewMerkleNode(val)

	// set parent of both nodes to parent
	node1.par = parent
	node2.par = parent

	return parent, nil
}
