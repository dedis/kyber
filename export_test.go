package onet

func (c *Conode) CreateProtocol(name string, t *Tree) (ProtocolInstance, error) {
	return c.overlay.CreateProtocolOnet(name, t)
}

func (c *Conode) StartProtocol(name string, t *Tree) (ProtocolInstance, error) {
	return c.overlay.StartProtocol(t, name)
}

func (c *Conode) Roster(id RosterID) (*Roster, bool) {
	el := c.overlay.Roster(id)
	return el, el != nil
}

func (c *Conode) GetTree(id TreeID) (*Tree, bool) {
	t := c.overlay.Tree(id)
	return t, t != nil
}

func (c *Conode) Overlay() *Overlay {
	return c.overlay
}

func (o *Overlay) TokenToNode(tok *Token) (*TreeNodeInstance, bool) {
	tni, ok := o.instances[tok.ID()]
	return tni, ok
}

// AddTree registers the given Tree struct in the underlying overlay.
// Useful for unit-testing only.
func (c *Conode) AddTree(t *Tree) {
	c.overlay.RegisterTree(t)
}

// AddRoster registers the given Roster in the underlying overlay.
// Useful for unit-testing only.
func (c *Conode) AddRoster(el *Roster) {
	c.overlay.RegisterRoster(el)
}
