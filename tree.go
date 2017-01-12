package onet

import (
	"errors"
	"fmt"

	"math/rand"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/satori/go.uuid"
)

// In this file we define the main structures used for a running protocol
// instance. First there is the ServerIdentity struct: it represents the ServerIdentity of
// someone, a server over the internet, mainly tied by its public key.
// The tree contains the peerId which is the ID given to a an ServerIdentity / server
// during one protocol instance. A server can have many peerId in one tree.
// ProtocolInstance needs to know:
// - which Roster we are using ( a selection of proper servers )
// - which Tree we are using.
// - The overlay network: a mapping from PeerId
// It contains the PeerId of the parent and the sub tree of the children.

func init() {
	network.RegisterMessage(Tree{})
	network.RegisterMessage(tbmStruct{})
}

// Tree is a topology to be used by any network layer/host layer
// It contains the peer list we use, and the tree we use
type Tree struct {
	ID     TreeID
	Roster *Roster
	Root   *TreeNode
}

// TreeID uniquely identifies a Tree struct in the onet framework.
type TreeID uuid.UUID

// Equals returns true if and only if the given TreeID equals the current one.
func (tId TreeID) Equals(tID2 TreeID) bool {
	return uuid.Equal(uuid.UUID(tId), uuid.UUID(tID2))
}

// String returns a canonical representation of the TreeID.
func (tId TreeID) String() string {
	return uuid.UUID(tId).String()
}

// NewTree creates a new tree using the entityList and the root-node. It
// also generates the id.
func NewTree(el *Roster, r *TreeNode) *Tree {
	url := network.NamespaceURL + "tree/" + el.ID.String() + r.ID.String()
	t := &Tree{
		Roster: el,
		Root:   r,
		ID:     TreeID(uuid.NewV5(uuid.NamespaceURL, url)),
	}
	// network.Suite used for the moment => explicit mark that something is
	// wrong and that needs to be changed !
	t.computeSubtreeAggregate(network.Suite, r)
	return t
}

// NewTreeFromMarshal takes a slice of bytes and an Roster to re-create
// the original tree
func NewTreeFromMarshal(buf []byte, el *Roster) (*Tree, error) {
	tp, pm, err := network.Unmarshal(buf)
	if err != nil {
		return nil, err
	}
	if tp != TreeMarshalTypeID {
		return nil, errors.New("Didn't receive TreeMarshal-struct")
	}
	t, err := pm.(*TreeMarshal).MakeTree(el)
	t.computeSubtreeAggregate(network.Suite, t.Root)
	return t, err
}

// MakeTreeMarshal creates a replacement-tree that is safe to send: no
// parent (creates loops), only sends ids (not send the entityList again)
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
	EL *Roster
}

// BinaryMarshaler does the same as Marshal
func (t *Tree) BinaryMarshaler() ([]byte, error) {
	bt, err := t.Marshal()
	if err != nil {
		return nil, err
	}
	tbm := &tbmStruct{
		T:  bt,
		EL: t.Roster,
	}
	b, err := network.Marshal(tbm)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// BinaryUnmarshaler takes a TreeMarshal and stores it in the tree
func (t *Tree) BinaryUnmarshaler(b []byte) error {
	_, m, err := network.Unmarshal(b)
	tbm, ok := m.(*tbmStruct)
	if !ok {
		return errors.New("Didn't find TBMstruct")
	}
	tree, err := NewTreeFromMarshal(tbm.T, tbm.EL)
	if err != nil {
		return err
	}
	t.Roster = tbm.EL
	t.ID = tree.ID
	t.Root = tree.Root
	return nil
}

// Equal verifies if the given tree is equal
func (t *Tree) Equal(t2 *Tree) bool {
	if t.ID != t2.ID || t.Roster.ID != t2.Roster.ID {
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
		if tns.ID == tn {
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
			if n.ServerIdentity.ID == p.ID {
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
func (t *Tree) computeSubtreeAggregate(suite abstract.Suite, root *TreeNode) abstract.Point {
	aggregate := suite.Point().Add(suite.Point().Null(), root.ServerIdentity.Public)
	// DFS search
	for _, ch := range root.Children {
		aggregate = aggregate.Add(aggregate, t.computeSubtreeAggregate(suite, ch))
	}

	// sets the field
	root.PublicAggregateSubTree = aggregate
	return aggregate
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
func (tm TreeMarshal) MakeTree(el *Roster) (*Tree, error) {
	if el.ID != tm.RosterID {
		return nil, errors.New("Not correct Roster-Id")
	}
	tree := &Tree{
		ID:     tm.TreeID,
		Roster: el,
	}
	tree.Root = tm.Children[0].MakeTreeFromList(nil, el)
	tree.computeSubtreeAggregate(network.Suite, tree.Root)
	return tree, nil
}

// MakeTreeFromList creates a sub-tree given an Roster
func (tm *TreeMarshal) MakeTreeFromList(parent *TreeNode, el *Roster) *TreeNode {
	idx, ent := el.Search(tm.ServerIdentityID)
	tn := &TreeNode{
		Parent:         parent,
		ID:             tm.TreeNodeID,
		ServerIdentity: ent,
		RosterIndex:    idx,
	}
	for _, c := range tm.Children {
		tn.Children = append(tn.Children, c.MakeTreeFromList(tn, el))
	}
	return tn
}

// An Roster is a list of ServerIdentity we choose to run  some tree on it ( and
// therefor some protocols)
type Roster struct {
	ID RosterID
	// TODO make that a map so search is O(1)
	// List is the List of actual "entities"
	// Be careful if you access it in go-routines (not safe by default)
	List []*network.ServerIdentity
	// Aggregate public key
	Aggregate abstract.Point
}

// RosterID uniquely identifies an Roster
type RosterID uuid.UUID

// String returns the default representation of the ID (wrapper around
// uuid.UUID.String()
func (elId RosterID) String() string {
	return uuid.UUID(elId).String()
}

// RosterTypeID of Roster message as registered in network
var RosterTypeID = network.RegisterMessage(Roster{})

// NewRoster creates a new ServerIdentity from a list of entities. It also
// adds a UUID which is randomly chosen.
func NewRoster(ids []*network.ServerIdentity) *Roster {
	// compute the aggregate key already
	agg := network.Suite.Point().Null()
	for _, e := range ids {
		agg = agg.Add(agg, e.Public)
	}
	return &Roster{
		List:      ids,
		Aggregate: agg,
		ID:        RosterID(uuid.NewV4()),
	}
}

// Search searches the Roster for the given ServerIdentityID and returns the
// corresponding ServerIdentity.
func (el *Roster) Search(eID network.ServerIdentityID) (int, *network.ServerIdentity) {
	for i, e := range el.List {
		if e.ID == eID {
			return i, e
		}
	}
	return -1, nil
}

// Get simply returns the entity that is stored at that index in the entitylist
// returns nil if index error
func (el *Roster) Get(idx int) *network.ServerIdentity {
	if idx < 0 || idx > len(el.List) {
		return nil
	}
	return el.List[idx]
}

// Publics returns the public-keys of the underlying Roster. It won't modify
// the underlying list.
func (el *Roster) Publics() []abstract.Point {
	res := make([]abstract.Point, len(el.List))
	for i, p := range el.List {
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
func (el *Roster) GenerateBigNaryTree(N, nodes int) *Tree {
	// list of which hosts are already used
	used := make([]bool, len(el.List))
	ilLen := len(el.List)
	// only use all ServerIdentities if we have the same number of nodes and hosts
	useAll := ilLen == nodes
	root := NewTreeNode(0, el.List[0])
	used[0] = true
	levelNodes := []*TreeNode{root}
	totalNodes := 1
	elIndex := 1 % ilLen
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
				childHost := el.List[elIndex].Address.Host()
				elIndexFirst := elIndex
				notSameHost := true
				for (notSameHost && childHost == parentHost && ilLen > 1) ||
					(useAll && used[elIndex]) {
					elIndex = (elIndex + 1) % ilLen
					if useAll && used[elIndex] {
						// In case we searched all ServerIdentities,
						// give up on finding another host, but
						// keep using all ServerIdentities
						if elIndex == elIndexFirst {
							notSameHost = false
						}
						continue
					}
					// If we tried all hosts, it means we're using
					// just one hostname, as we didn't find any
					// other name
					if elIndex == elIndexFirst {
						break
					}
					childHost = el.List[elIndex].Address.Host()
				}
				child := NewTreeNode(elIndex, el.List[elIndex])
				used[elIndex] = true
				elIndex = (elIndex + 1) % ilLen
				totalNodes++
				parent.Children[n] = child
				child.Parent = parent
				newLevelNodes[newLevelNodesCounter] = child
				newLevelNodesCounter++
			}
		}
		levelNodes = newLevelNodes[:newLevelNodesCounter]
	}
	return NewTree(el, root)
}

// GenerateNaryTreeWithRoot creates a tree where each node has N children.
// The root is given as an ServerIdentity.
func (el *Roster) GenerateNaryTreeWithRoot(N int, rootServerIdentity *network.ServerIdentity) *Tree {
	rootIndex, _ := el.Search(rootServerIdentity.ID)
	if rootIndex < 0 {
		log.Fatal(rootServerIdentity, el.List, log.Stack())
		return nil
	}
	cList := el.List
	onlyRoot := []*network.ServerIdentity{cList[rootIndex]}
	uptoRoot := cList[:rootIndex]
	afterRoot := cList[rootIndex+1:]
	list := append(onlyRoot, uptoRoot...)
	list = append(list, afterRoot...)
	return NewRoster(list).GenerateNaryTree(N)
}

// GenerateNaryTree creates a tree where each node has N children.
// The first element of the Roster will be the root element.
func (el *Roster) GenerateNaryTree(N int) *Tree {
	root := el.addNary(nil, N, 0, len(el.List)-1)
	return NewTree(el, root)
}

// GenerateBinaryTree creates a binary tree out of the Roster
// out of it. The first element of the Roster will be the root element.
func (el *Roster) GenerateBinaryTree() *Tree {
	return el.GenerateNaryTree(2)
}

// RandomServerIdentity returns a random element of the Roster.
func (el *Roster) RandomServerIdentity() *network.ServerIdentity {
	if el.List == nil || len(el.List) == 0 {
		return nil
	}
	return el.List[rand.Int()%len(el.List)]
}

// addNary is a recursive function to create the binary tree.
func (el *Roster) addNary(parent *TreeNode, N, start, end int) *TreeNode {
	if !(start <= end && end < len(el.List)) {
		return nil
	}
	node := NewTreeNode(start, el.List[start])
	if parent != nil {
		node.Parent = parent
		parent.Children = append(parent.Children, node)
	}
	diff := end - start
	for n := 0; n < N; n++ {
		s := diff * n / N
		e := diff * (n + 1) / N
		el.addNary(node, N, start+s+1, start+e)
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
	PublicAggregateSubTree abstract.Point
}

// TreeNodeID identifies a given TreeNode struct in the onet framework.
type TreeNodeID uuid.UUID

// String returns a canonical representation of the TreeNodeID.
func (tId TreeNodeID) String() string {
	return uuid.UUID(tId).String()
}

// Equal returns true if and only if the given TreeNodeID equals the current
// one.
func (tId TreeNodeID) Equal(tID2 TreeNodeID) bool {
	return uuid.Equal(uuid.UUID(tId), uuid.UUID(tID2))
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
		ID:             TreeNodeID(uuid.NewV4()),
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
	return tree.Root.ID == root.ID
}

// AddChild adds a child to this tree-node.
func (t *TreeNode) AddChild(c *TreeNode) {
	t.Children = append(t.Children, c)
	c.Parent = t
}

// Equal tests if that node is equal to the given node
func (t *TreeNode) Equal(t2 *TreeNode) bool {
	if t.ID != t2.ID || t.ServerIdentity.ID != t2.ServerIdentity.ID {
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
func (t *TreeNode) AggregatePublic() abstract.Point {
	agg := network.Suite.Point().Null()
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

// Toml returns the toml-writable version of this entityList
func (el *Roster) Toml(suite abstract.Suite) *RosterToml {
	ids := make([]*network.ServerIdentityToml, len(el.List))
	for i := range el.List {
		ids[i] = el.List[i].Toml(suite)
	}
	return &RosterToml{
		ID:   el.ID,
		List: ids,
	}
}

// Roster returns the Id list from this toml read struct
func (elt *RosterToml) Roster(suite abstract.Suite) *Roster {
	ids := make([]*network.ServerIdentity, len(elt.List))
	for i := range elt.List {
		ids[i] = elt.List[i].ServerIdentity(suite)
	}
	return &Roster{
		ID:   elt.ID,
		List: ids,
	}
}
