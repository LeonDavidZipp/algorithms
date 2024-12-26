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
	t.dim.size = uint32(len(t.leaves))
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
		t.leaves[t.Size()-1].next = node
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
				node.next = t.leaves[i]
				t.leaves[i-1].next = node
				newLeaves := append(t.leaves[:i], node)
				t.leaves = append(newLeaves, t.leaves[i:]...)
			} else {
				t.leaves[i-1].next = node
				t.leaves = append(t.leaves, node)
			}
		} else {
			t.leaves = append([]*MerkleNode{node}, t.leaves...)
		}
	} else {
		t.leaves = []*MerkleNode{node}
		t.tree = [][]*MerkleNode{{node}}
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
				t.leaves[i-1].next = t.leaves[i+1]
				newLeaves := append(t.leaves[:i], t.leaves[i+1:]...)
				t.leaves = newLeaves
			} else {
				t.leaves[i-1].next = nil
				t.leaves = t.leaves[:i]
			}
		} else {
			t.leaves = t.leaves[1:]
		}
	} else {
		t.leaves = []*MerkleNode{}
		t.tree = [][]*MerkleNode{}
	}

	t.calcDim()

	return nil
}

// calculates the first row where insertion should start
func (t *MerkleTree) calcFirstInsertableRow(leftover uint32) uint32 {
	s := nextPow2(t.Size())
	var i uint32
	for i = 1; i < t.Depth()-1; i++ {
		missing := (s >> i) - uint32(len(t.tree[i]))
		if leftover > missing {
			return i - 1
		}
	}

	return i - 1
}

func (t *MerkleTree) cleanupTree(start uint32) {
	// cleanup tree
	for i := uint32(1); i < t.Depth(); i++ {
		t.tree[i] = t.tree[i][:start>>i]
	}
}

// calculates the least-calculations-optimized position of all leaf nodes in the tree
func (t *MerkleTree) calcOptimizedPos() {
	s := t.Size()
	// all nodes left of start are in the correct position
	start := prevPow2(s)
	leftover := s - start

	for i := t.calcFirstInsertableRow(leftover); i < t.Depth()-2; i++ {
		// always insert as many nodes nc as possible so complete subtree is inserted (2^n leaf nodes)
		insertCount := prevPow2(leftover)
		offset := uint32(0) // 0 for first insertion, half of previous insertion for all following
		for j := uint32(0); j < insertCount; j++ {
			// row start will always be half of previous row's start
			rowStart := start >> i
			t.leaves[start+j].pos = &pos{
				row: i,
				col: rowStart + offset + j,
			}
		}

		leftover -= insertCount
		offset = insertCount >> 1

		// if there are less leftover nodes than the next smaller insertCount, skip rows until there's not
		for k := leftover; k < (insertCount >> 1); k++ {
			i++
			offset >>= 1
		}
	}
}

// moves the leaves to their optimized positions
func (t *MerkleTree) moveLeaves() {
	s := t.Size()

	// iterate over every node
	for i := prevPow2(s); i < s; i++ {
		for missing := t.leaves[i].pos.col - uint32(len(t.tree[t.leaves[i].pos.row])); missing > 0; missing-- {
			t.tree[t.leaves[i].pos.row] = append(t.tree[t.leaves[i].pos.row], nil)
		}
		t.tree[t.leaves[i].pos.row] = append(t.tree[t.leaves[i].pos.row], t.leaves[i])
	}
}

// calculates the tree starting from start index; leaves everything left of index untouched
func (t *MerkleTree) calcTree(start uint32) (*MerkleNode, error) {
	if start >= t.Size() {
		return nil, fmt.Errorf("out of bounds")
	}

	// if the start element is the 2nd of a pairing, the first element also needs to be moved
	if start%2 == 1 {
		start--
	}

	t.cleanupTree(start)
	t.calcOptimizedPos()
	t.moveLeaves()

	// hash all entries
	maxRow := t.Depth() - 1
	for i := uint32(0); i < maxRow; i++ {
		rowStart := int(start >> i)
		for j := rowStart; j < len(t.tree[i]); j += 2 {
			parent, err := hashNodes(t.tree[i][j], t.tree[i][j+1])
			if err != nil {
				return nil, err
			}
			t.tree[i+1][j] = parent
		}
	}

	return t.tree[maxRow][0], nil
}

// hashes two nodes & returns resulting parent node
func hashNodes(node1 *MerkleNode, node2 *MerkleNode) (*MerkleNode, error) {
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
