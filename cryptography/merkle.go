package cryptography

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
	// position in tree
	pos pos
	// hashed data
	val [32]byte
}

// returns the parent node or nil
func (n *MerkleNode) Parent() *MerkleNode {
	return n.par
}

// returns the row index of node
func (n *MerkleNode) Position() pos {
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
/* --------------------------------------------------------------------------------- */
// optimized merkle tree struct
type MerkleTree struct {
	// leaf nodes
	leaves []*MerkleNode
	// branch nodes
	branches [][]*MerkleNode
	// whether tree gets recalculated automatically when leaf node is added or removed
	autoRecalc bool
}

// creates a new merkle tree
func NewMerkleTree(leaves []*MerkleNode, autoRecalc bool) *MerkleTree {
	return &MerkleTree{
		leaves:     leaves,
		branches:   [][]*MerkleNode{},
		autoRecalc: autoRecalc,
	}
}

// TODO: adjust for optimized tree
// returns count of leaf nodes of tree
func (t *MerkleTree) Size() uint32 {
	return uint32(len((*t).leaves))
}

// TODO: adjust for optimized tree
// returns count of rows of tree
func (t *MerkleTree) Depth() uint32 {
	if t.Size() == 0 {
		return 0
	} else {
		return uint32(len((*t).branches) + 1)
	}
}

// TODO: adjust for optimized tree
// adds a new leaf node to the merkle tree
func (t *MerkleTree) NewLeaf(value []byte) (*MerkleNode, error) {
	val, err := Sha256(value)
	if err != nil {
		return nil, err
	}

	// TODO: fix, not correct for optimized tree yet
	node := &MerkleNode{
		par: nil,
		pos: pos{
			row: t.Depth(),
			col: t.Size(),
		},
		val:  val,
		next: nil,
	}

	if t.Size() > 0 {
		(*t).leaves[t.Size()-1].next = node
	}

	if t.autoRecalc {
	}

	return node, nil
}
