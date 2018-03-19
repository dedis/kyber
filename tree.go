package onet

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"math/rand"

	"gopkg.in/dedis/kyber.v2"
	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/onet.v2/network"
	"gopkg.in/satori/go.uuid.v1"
)

// In this file we define the main structures used for a running protocol
// instance. First there is the ServerIdentity struct: it represents the ServerIdentity of
// someone, a server over the internet, mainly tied by its public key.
// The tree contains the peerId which is the ID given to a an ServerIdentity / server
// during one protocol instance. A server can have many peerId in one tree.
//
// ProtocolInstance needs to know:
//   - which Roster we are using ( a selection of proper servers )
//   - which Tree we are using
//   - The overlay network: a mapping from PeerId
//
// It contains the PeerId of the parent and the sub tree of the children.

func init() {
	network.RegisterMessage(Tree{})
	network.RegisterMessage(tbmStruct{})
}

// Tree is a topology to be used by any network layer/host layer.
// It contains the peer list we use, and the tree we use
type Tree struct {
	ID     TreeID
	Roster *Roster
	Root   *TreeNode
}

// TreeID uniquely identifies a Tree struct in the onet framework.
type TreeID uuid.UUID

// Equal returns true if and only if tID2 equals this TreeID.
func (tId TreeID) Equal(tID2 TreeID) bool {
	return uuid.Equal(uuid.UUID(tId), uuid.UUID(tID2))
}

// Equals will be removed!
func (tId TreeID) Equals(tID2 TreeID) bool {
	log.Warn("Deprecated: TreeID.Equals will be removed in onet.v2")
	return tId.Equal(tID2)
}

// String returns a canonical representation of the TreeID.
func (tId TreeID) String() string {
	return uuid.UUID(tId).String()
}

// IsNil returns true iff the TreeID is Nil
func (tId TreeID) IsNil() bool {
	return tId.Equal(TreeID(uuid.Nil))
}

// NewTree creates a new tree using the given roster and root. It
// also generates the id.
func NewTree(roster *Roster, root *TreeNode) *Tree {
	// walk the tree with DFS to build a unique hash
	h := sha256.New()
	root.Visit(0, func(d int, tn *TreeNode) {
		_, err := tn.ServerIdentity.Public.MarshalTo(h)
		if err != nil {
			log.Error(err)
		}
		if tn.IsLeaf() {
			// to prevent generating the same hash for tree with
			// the same nodes but with a different structure
			_, err = h.Write([]byte{1})
			if err != nil {
				log.Error(err)
			}
		}
	})

	url := network.NamespaceURL + "tree/" + roster.ID.String() + hex.EncodeToString(h.Sum(nil))
	t := &Tree{
		Roster: roster,
		Root:   root,
		ID:     TreeID(uuid.NewV5(uuid.NamespaceURL, url)),
	}
	t.computeSubtreeAggregate(root)
	return t
}

// NewTreeFromMarshal takes a slice of bytes and an Roster to re-create
// the original tree
func NewTreeFromMarshal(s network.Suite, buf []byte, el *Roster) (*Tree, error) {
	tp, pm, err := network.Unmarshal(buf, s)
	if err != nil {
		return nil, err
	}
	if !tp.Equal(TreeMarshalTypeID) {
		return nil, errors.New("Didn't receive TreeMarshal-struct")
	}
	t, err := pm.(*TreeMarshal).MakeTree(el)
	t.computeSubtreeAggregate(t.Root)
	return t, err
}

// MakeTreeMarshal creates a replacement-tree that is safe to send: no
// parent (creates loops), only sends ids (not send the roster again)
func (t *Tree) MakeTreeMarshal() *TreeMarshal {
	if t.Roster == nil {
		return &TreeMarshal{}
	}
	treeM := &TreeMarshal{
		TreeID:   t.ID,
		RosterID: t.Roster.ID,
	}
	treeM.Children = append(treeM.Children, TreeMarshalCopyTree(t.Root))
	return treeM
}

// Marshal creates a simple binary-representation of the tree containing only
// the ids of the elements. Use NewTreeFromMarshal to get back the original
// tree
func (t *Tree) Marshal() ([]byte, error) {
	buf, err := network.Marshal(t.MakeTreeMarshal())
	return buf, err
}

type tbmStruct struct {
	T  []byte
	Ro *Roster
}

// BinaryMarshaler does the same as Marshal
func (t *Tree) BinaryMarshaler() ([]byte, error) {
	bt, err := t.Marshal()
	if err != nil {
		return nil, err
	}
	tbm := &tbmStruct{
		T:  bt,
		Ro: t.Roster,
	}
	b, err := network.Marshal(tbm)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// BinaryUnmarshaler takes a TreeMarshal and stores it in the tree
func (t *Tree) BinaryUnmarshaler(s network.Suite, b []byte) error {
	_, m, err := network.Unmarshal(b, s)
	tbm, ok := m.(*tbmStruct)
	if !ok {
		return errors.New("Didn't find TBMstruct")
	}
	tree, err := NewTreeFromMarshal(s, tbm.T, tbm.Ro)
	if err != nil {
		return err
	}
	t.Roster = tbm.Ro
	t.ID = tree.ID
	t.Root = tree.Root
	return nil
}

// Equal verifies if the given tree is equal
func (t *Tree) Equal(t2 *Tree) bool {
	if !t.ID.Equal(t2.ID) || !t.Roster.ID.Equal(t2.Roster.ID) {
		log.Lvl4("Ids of trees don't match")
		return false
	}
	return t.Root.Equal(t2.Root)
}

// String writes the definition of the tree
func (t *Tree) String() string {
	return fmt.Sprintf("TreeId:%s - RosterId:%s - RootId:%s",
		t.ID, t.Roster.ID, t.Root.ID)
}

// Dump returns string about the tree
func (t *Tree) Dump() string {
	ret := "Tree " + t.ID.String() + " is:"
	t.Root.Visit(0, func(d int, tn *TreeNode) {
		if tn.Parent != nil {
			ret += fmt.Sprintf("\n%d - %s/%s has parent %s/%s", d,
				tn.ServerIdentity.Public, tn.ServerIdentity.Address,
				tn.Parent.ServerIdentity.Public, tn.Parent.ServerIdentity.Address)
		} else {
			ret += fmt.Sprintf("\n%s/%s is root", tn.ServerIdentity.Public, tn.ServerIdentity.Address)
		}
	})
	return ret
}

// Search searches the Tree for the given TreeNodeID and returns the corresponding TreeNode
func (t *Tree) Search(tn TreeNodeID) (ret *TreeNode) {
	found := func(d int, tns *TreeNode) {
		if tns.ID.Equal(tn) {
			ret = tns
		}
	}
	t.Root.Visit(0, found)
	return ret
}

// List returns a list of TreeNodes generated by DFS-iterating the Tree
func (t *Tree) List() (ret []*TreeNode) {
	ret = make([]*TreeNode, 0)
	add := func(d int, tns *TreeNode) {
		ret = append(ret, tns)
	}
	t.Root.Visit(0, add)
	return ret
}

// IsBinary returns true if every node has two or no children
func (t *Tree) IsBinary(root *TreeNode) bool {
	return t.IsNary(root, 2)
}

// IsNary returns true if every node has two or no children
func (t *Tree) IsNary(root *TreeNode, N int) bool {
	nChild := len(root.Children)
	if nChild != N && nChild != 0 {
		log.Lvl3("Only", nChild, "children for", root.ID)
		return false
	}
	for _, c := range root.Children {
		if !t.IsNary(c, N) {
			return false
		}
	}
	return true
}

// Size returns the number of all TreeNodes
func (t *Tree) Size() int {
	size := 0
	t.Root.Visit(0, func(d int, tn *TreeNode) {
		size++
	})
	return size
}

// UsesList returns true if all ServerIdentities of the list are used at least once
// in the tree
func (t *Tree) UsesList() bool {
	nodes := t.List()
	for _, p := range t.Roster.List {
		found := false
		for _, n := range nodes {
			if n.ServerIdentity.ID.Equal(p.ID) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// computeSubtreeAggregate will compute the aggregate subtree public key for
// each node of the tree.
// root is the root of the subtree we want to compute the aggregate for
// recursive function so it will go down to the leaves then go up to the root
// Return the aggregate sub tree public key for this root (and compute each sub
// aggregate public key for each of the children).
func (t *Tree) computeSubtreeAggregate(root *TreeNode) kyber.Point {
	// Cloning the root public key does two things for us. First, it
	// gets agg set to the right kind of kyber.Group for this tree.
	// Second, it is the first component of the aggregate. The rest
	// of the subtree aggregates are added via the DFS.
	agg := root.ServerIdentity.Public.Clone()

	// DFS search
	for _, ch := range root.Children {
		agg = agg.Add(agg, t.computeSubtreeAggregate(ch))
	}
	root.PublicAggregateSubTree = agg
	return agg
}

// TreeMarshal is used to send and receive a tree-structure without having
// to copy the whole nodelist
type TreeMarshal struct {
	// This is the UUID of the corresponding TreeNode
	TreeNodeID TreeNodeID
	// TreeId identifies the Tree for the top-node
	TreeID TreeID
	// This is the UUID of the ServerIdentity, except
	ServerIdentityID network.ServerIdentityID
	// for the top-node this contains the Roster's ID
	RosterID RosterID
	// All children from this tree. The top-node only has one child, which is
	// the root
	Children []*TreeMarshal
}

func (tm *TreeMarshal) String() string {
	s := fmt.Sprintf("%v", tm.ServerIdentityID)
	s += "\n"
	for i := range tm.Children {
		s += tm.Children[i].String()
	}
	return s
}

// TreeMarshalTypeID of TreeMarshal message as registered in network
var TreeMarshalTypeID = network.RegisterMessage(TreeMarshal{})

// TreeMarshalCopyTree takes a TreeNode and returns a corresponding
// TreeMarshal
func TreeMarshalCopyTree(tr *TreeNode) *TreeMarshal {
	tm := &TreeMarshal{
		TreeNodeID:       tr.ID,
		ServerIdentityID: tr.ServerIdentity.ID,
	}
	for i := range tr.Children {
		tm.Children = append(tm.Children,
			TreeMarshalCopyTree(tr.Children[i]))
	}
	return tm
}

// MakeTree creates a tree given an Roster
func (tm TreeMarshal) MakeTree(ro *Roster) (*Tree, error) {
	if !ro.ID.Equal(tm.RosterID) {
		return nil, errors.New("Not correct Roster-Id")
	}
	tree := &Tree{
		ID:     tm.TreeID,
		Roster: ro,
	}
	tree.Root = tm.Children[0].MakeTreeFromList(nil, ro)
	tree.computeSubtreeAggregate(tree.Root)
	return tree, nil
}

// MakeTreeFromList creates a sub-tree given an Roster
func (tm *TreeMarshal) MakeTreeFromList(parent *TreeNode, ro *Roster) *TreeNode {
	idx, ent := ro.Search(tm.ServerIdentityID)
	tn := &TreeNode{

		Parent:         parent,
		ID:             tm.TreeNodeID,
		ServerIdentity: ent,
		RosterIndex:    idx,
	}
	for _, c := range tm.Children {
		tn.Children = append(tn.Children, c.MakeTreeFromList(tn, ro))
	}
	return tn
}

// A Roster is a list of ServerIdentity we choose to run some tree on it ( and
// therefor some protocols). Access is not safe from multiple goroutines.
type Roster struct {
	ID RosterID
	// List is the list of actual entities.
	List      []*network.ServerIdentity
	Aggregate kyber.Point
}

// RosterID uniquely identifies an Roster
type RosterID uuid.UUID

// String returns the default representation of the ID (wrapper around
// uuid.UUID.String()
func (roID RosterID) String() string {
	return uuid.UUID(roID).String()
}

// Equal returns true if and only if roID2 equals this RosterID.
func (roID RosterID) Equal(roID2 RosterID) bool {
	return uuid.Equal(uuid.UUID(roID), uuid.UUID(roID2))
}

// IsNil returns true iff the RosterID is Nil
func (roID RosterID) IsNil() bool {
	return roID.Equal(RosterID(uuid.Nil))
}

// RosterTypeID of Roster message as registered in network
var RosterTypeID = network.RegisterMessage(Roster{})

// NewRoster creates a new roster from a list of entities. It also
// adds a UUID which is randomly chosen.
func NewRoster(ids []*network.ServerIdentity) *Roster {
	// Don't allow a crash if things are not as expected.
	if len(ids) < 1 || ids[0].Public == nil {
		return nil
	}

	h := sha256.New()
	for _, id := range ids {
		_, err := id.Public.MarshalTo(h)
		if err != nil {
			log.Error(err)
		}
	}

	r := &Roster{
		ID: RosterID(uuid.NewV5(uuid.NamespaceURL, hex.EncodeToString(h.Sum(nil)))),
	}

	// Take a copy of ids, in case the caller tries to change it later.
	r.List = append(r.List, ids...)

	if len(ids) != 0 {
		// compute the aggregate key, using the first server's
		// public key to discover which kyber.Group we should be
		// using.
		agg := ids[0].Public.Clone()
		agg.Null()
		for _, e := range ids {
			if e.Public != nil {
				agg = agg.Add(agg, e.Public)
			}
		}
		r.Aggregate = agg
	}
	return r
}

// Search searches the Roster for the given ServerIdentityID and returns the
// corresponding ServerIdentity.
func (ro *Roster) Search(eID network.ServerIdentityID) (int, *network.ServerIdentity) {
	for i, e := range ro.List {
		if e.ID.Equal(eID) {
			return i, e
		}
	}
	return -1, nil
}

// Get simply returns the entity that is stored at that index in the entitylist
// returns nil if index error
func (ro *Roster) Get(idx int) *network.ServerIdentity {
	if idx < 0 || idx > len(ro.List) {
		return nil
	}
	return ro.List[idx]
}

// Publics returns the public-keys of the underlying Roster. It won't modify
// the underlying list.
func (ro *Roster) Publics() []kyber.Point {
	res := make([]kyber.Point, len(ro.List))
	for i, p := range ro.List {
		res[i] = p.Public
	}
	return res
}

// GenerateBigNaryTree creates a tree where each node has N children.
// It will make a tree with exactly 'nodes' elements, regardless of the
// size of the Roster. If 'nodes' is bigger than the number of elements
// in the Roster, it will add some or all elements in the Roster
// more than once.
// If the length of the Roster is equal to 'nodes', it is guaranteed that
// all ServerIdentities from the Roster will be used in the tree.
// However, for some configurations it is impossible to use all ServerIdentities from
// the Roster and still avoid having a parent and a child from the same
// host. In this case use-all has preference over not-the-same-host.
func (ro *Roster) GenerateBigNaryTree(N, nodes int) *Tree {
	if len(ro.List) == 0 {
		panic("empty roster")
	}

	// list of which hosts are already used
	used := make([]bool, len(ro.List))
	ilLen := len(ro.List)
	// only use all ServerIdentities if we have the same number of nodes and hosts
	useAll := ilLen == nodes
	root := NewTreeNode(0, ro.List[0])
	used[0] = true
	levelNodes := []*TreeNode{root}
	totalNodes := 1
	roIndex := 1 % ilLen
	for totalNodes < nodes {
		newLevelNodes := make([]*TreeNode, len(levelNodes)*N)
		newLevelNodesCounter := 0
		for i, parent := range levelNodes {
			children := (nodes - totalNodes) * (i + 1) / len(levelNodes)
			if children > N {
				children = N
			}
			parent.Children = make([]*TreeNode, children)
			parentHost := parent.ServerIdentity.Address.Host()
			for n := 0; n < children; n++ {
				// Check on host-address, so that no child is
				// on the same host as the parent.
				childHost := ro.List[roIndex].Address.Host()
				roIndexFirst := roIndex
				notSameHost := true
				for (notSameHost && childHost == parentHost && ilLen > 1) ||
					(useAll && used[roIndex]) {
					roIndex = (roIndex + 1) % ilLen
					if useAll && used[roIndex] {
						// In case we searched all ServerIdentities,
						// give up on finding another host, but
						// keep using all ServerIdentities
						if roIndex == roIndexFirst {
							notSameHost = false
						}
						continue
					}
					// If we tried all hosts, it means we're using
					// just one hostname, as we didn't find any
					// other name
					if roIndex == roIndexFirst {
						break
					}
					childHost = ro.List[roIndex].Address.Host()
				}
				child := NewTreeNode(roIndex, ro.List[roIndex])
				used[roIndex] = true
				roIndex = (roIndex + 1) % ilLen
				totalNodes++
				parent.Children[n] = child
				child.Parent = parent
				newLevelNodes[newLevelNodesCounter] = child
				newLevelNodesCounter++
			}
		}
		levelNodes = newLevelNodes[:newLevelNodesCounter]
	}
	return NewTree(ro, root)
}

// NewRosterWithRoot returns a copy of the roster but with the given ServerIdentity
// at the first entry in the roster.
func (ro *Roster) NewRosterWithRoot(root *network.ServerIdentity) *Roster {
	list := make([]*network.ServerIdentity, len(ro.List))
	copy(list, ro.List)
	rootIndex, _ := ro.Search(root.ID)
	if rootIndex < 0 {
		return nil
	}
	list[0], list[rootIndex] = list[rootIndex], list[0]
	return NewRoster(list)
}

// GenerateNaryTreeWithRoot creates a tree where each node has N children.
// The root is given as an ServerIdentity. If root doesn't exist in the
// roster, `nil` will be returned.
// The generation of the tree is done in a simple for-loop, so that the
// original roster can be used for tree creation, even if the root is not
// at position 0.
// If root == nil, the first element of the roster will be taken as root.
//
// If you need the root node to be at the first position of the roster, then
// you need to create a new roster using roster.NewRosterWithRoot. Else this method
// does not change the underlying roster or create a new one.
func (ro *Roster) GenerateNaryTreeWithRoot(N int, root *network.ServerIdentity) *Tree {
	// Fetch the root node, set to the first element of the roster if
	// root == nil.
	rootIndex := 0
	if root != nil {
		rootIndex, _ = ro.Search(root.ID)
		if rootIndex < 0 {
			log.Lvl2("Asked for non-existing root:", root, ro.List)
			return nil
		}
	} else {
		root = ro.List[0]
	}
	rootNode := NewTreeNode(rootIndex, root)
	parents := []*TreeNode{rootNode}
	children := []*TreeNode{}
	for i := 1; i < len(ro.List); i++ {
		index := (i + rootIndex) % len(ro.List)
		// If a parent is full, remove it from the list.
		if parents[0].SubtreeCount() == N {
			parents = parents[1:]
		}
		// If there are no parents, pass all children to the parents, and
		// continue
		if len(parents) == 0 {
			parents = children
			children = []*TreeNode{}
		}
		// Create the new child and add it to the parent node.
		newChild := NewTreeNode(index, ro.List[index])
		children = append(children, newChild)
		parents[0].AddChild(newChild)
	}
	return NewTree(ro, rootNode)
}

// GenerateNaryTree creates a tree where each node has N children.
// The first element of the Roster will be the root element.
func (ro *Roster) GenerateNaryTree(N int) *Tree {
	return ro.GenerateNaryTreeWithRoot(N, nil)
}

// GenerateBinaryTree creates a binary tree out of the Roster
// out of it. The first element of the Roster will be the root element.
func (ro *Roster) GenerateBinaryTree() *Tree {
	return ro.GenerateNaryTree(2)
}

// GenerateStar creates a star topology with the first element
// of Roster as root, and all other elements as children of the root.
func (ro *Roster) GenerateStar() *Tree {
	return ro.GenerateNaryTree(len(ro.List) - 1)
}

// RandomServerIdentity returns a random element of the Roster.
func (ro *Roster) RandomServerIdentity() *network.ServerIdentity {
	if ro.List == nil || len(ro.List) == 0 {
		return nil
	}
	return ro.List[rand.Int()%len(ro.List)]
}

// RandomSubset returns a new Roster which starts with root and is
// followed by a random subset of n elements of ro, not including root.
func (ro *Roster) RandomSubset(root *network.ServerIdentity, n int) *Roster {
	if n > len(ro.List) {
		n = len(ro.List)
	}
	out := make([]*network.ServerIdentity, 1, n+1)
	out[0] = root

	perm := rand.Perm(len(ro.List))
	for _, p := range perm {
		if !ro.List[p].ID.Equal(root.ID) {
			out = append(out, ro.List[p])
			if len(out) == n+1 {
				break
			}
		}
	}
	return NewRoster(out)
}

// addNary is a recursive function to create the binary tree.
func (ro *Roster) addNary(parent *TreeNode, N, start, end int) *TreeNode {
	if !(start <= end && end < len(ro.List)) {
		return nil
	}
	node := NewTreeNode(start, ro.List[start])
	if parent != nil {
		node.Parent = parent
		parent.Children = append(parent.Children, node)
	}
	diff := end - start
	for n := 0; n < N; n++ {
		s := diff * n / N
		e := diff * (n + 1) / N
		ro.addNary(node, N, start+s+1, start+e)
	}
	return node
}

// TreeNode is one node in the tree
type TreeNode struct {
	// The Id represents that node of the tree
	ID TreeNodeID
	// The ServerIdentity points to the corresponding host. One given host
	// can be used more than once in a tree.
	ServerIdentity *network.ServerIdentity
	// RosterIndex is the index in the Roster where the `ServerIdentity` is located
	RosterIndex int
	// Parent link
	Parent *TreeNode
	// Children links
	Children []*TreeNode
	// Aggregate public key for *this* subtree,i.e. this node's public key + the
	// aggregate of all its children's aggregate public key
	PublicAggregateSubTree kyber.Point
}

// TreeNodeID identifies a given TreeNode struct in the onet framework.
type TreeNodeID uuid.UUID

// String returns a canonical representation of the TreeNodeID.
func (tId TreeNodeID) String() string {
	return uuid.UUID(tId).String()
}

// Equal returns true if and only if the given TreeNodeID equals tId.
func (tId TreeNodeID) Equal(tID2 TreeNodeID) bool {
	return uuid.Equal(uuid.UUID(tId), uuid.UUID(tID2))
}

// IsNil returns true iff the TreeNodID is Nil
func (tId TreeNodeID) IsNil() bool {
	return tId.Equal(TreeNodeID(uuid.Nil))
}

// Name returns a human readable representation of the TreeNode (IP address).
func (t *TreeNode) Name() string {
	return t.ServerIdentity.Address.String()
}

var _ = network.RegisterMessage(TreeNode{})

// NewTreeNode creates a new TreeNode with the proper Id
func NewTreeNode(entityIdx int, ni *network.ServerIdentity) *TreeNode {
	tn := &TreeNode{
		ServerIdentity: ni,
		RosterIndex:    entityIdx,
		Parent:         nil,
		Children:       make([]*TreeNode, 0),
		ID:             TreeNodeID(uuid.NewV5(uuid.NamespaceURL, ni.Public.String())),
	}
	return tn
}

// IsConnectedTo checks if the TreeNode can communicate with its parent or
// children.
func (t *TreeNode) IsConnectedTo(si *network.ServerIdentity) bool {
	if t.Parent != nil && t.Parent.ServerIdentity.Equal(si) {
		return true
	}

	for i := range t.Children {
		if t.Children[i].ServerIdentity.Equal(si) {
			return true
		}
	}
	return false
}

// IsLeaf returns true for a node without children
func (t *TreeNode) IsLeaf() bool {
	return len(t.Children) == 0
}

// IsRoot returns true for a node without a parent
func (t *TreeNode) IsRoot() bool {
	return t.Parent == nil
}

// IsInTree - verifies if the TreeNode is in the given Tree
func (t *TreeNode) IsInTree(tree *Tree) bool {
	root := *t
	for root.Parent != nil {
		root = *root.Parent
	}
	return tree.Root.ID.Equal(root.ID)
}

// AddChild adds a child to this tree-node.
func (t *TreeNode) AddChild(c *TreeNode) {
	t.Children = append(t.Children, c)
	c.Parent = t
}

// Equal tests if that node is equal to the given node
func (t *TreeNode) Equal(t2 *TreeNode) bool {
	if !t.ID.Equal(t2.ID) || !t.ServerIdentity.ID.Equal(t2.ServerIdentity.ID) {
		log.Lvl4("TreeNode: ids are not equal")
		return false
	}
	if len(t.Children) != len(t2.Children) {
		log.Lvl4("TreeNode: number of children are not equal")
		return false
	}
	for i, c := range t.Children {
		if !c.Equal(t2.Children[i]) {
			log.Lvl4("TreeNode: children are not equal")
			return false
		}
	}
	return true
}

// String returns the current treenode's Id as a string.
func (t *TreeNode) String() string {
	return string(t.ID.String())
}

// Visit is a recursive function that allows for depth-first calling on all
// nodes
func (t *TreeNode) Visit(firstDepth int, fn func(depth int, n *TreeNode)) {
	fn(firstDepth, t)
	for _, c := range t.Children {
		c.Visit(firstDepth+1, fn)
	}
}

// SubtreeCount returns how many children are attached to that
// TreeNode.
func (t *TreeNode) SubtreeCount() int {
	ret := -1
	t.Visit(0, func(int, *TreeNode) { ret++ })
	return ret
}

// AggregatePublic will return the aggregate public key of the TreeNode
// and all it's children
func (t *TreeNode) AggregatePublic(s network.Suite) kyber.Point {
	agg := s.Point().Null()
	t.Visit(0, func(i int, tn *TreeNode) {
		agg.Add(agg, tn.ServerIdentity.Public)
	})
	return agg
}

// RosterToml is the struct can can embedded ServerIdentityToml to be written in a
// toml file
type RosterToml struct {
	ID   RosterID
	List []*network.ServerIdentityToml
}

// Toml returns the toml-writable version of this roster.
func (ro *Roster) Toml(suite network.Suite) *RosterToml {
	ids := make([]*network.ServerIdentityToml, len(ro.List))
	for i := range ro.List {
		ids[i] = ro.List[i].Toml(suite)
	}
	return &RosterToml{
		ID:   ro.ID,
		List: ids,
	}
}

// Roster returns the Id list from this toml read struct
func (rot *RosterToml) Roster(suite network.Suite) *Roster {
	ids := make([]*network.ServerIdentity, len(rot.List))
	for i := range rot.List {
		ids[i] = rot.List[i].ServerIdentity(suite)
	}
	return &Roster{
		ID:   rot.ID,
		List: ids,
	}
}
