package app

import (
	"bytes"
	"io"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/onet"
	"github.com/dedis/onet/crypto"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
)

// CothorityConfig is the configuration structure of the cothority daemon.
type CothorityConfig struct {
	Public      string
	Private     string
	Address     network.Address
	Description string
}

// Save will save this CothorityConfig to the given file name. It
// will return an error if the file couldn't be created or if
// there is an error in the encoding.
func (hc *CothorityConfig) Save(file string) error {
	fd, err := os.Create(file)
	if err != nil {
		return err
	}
	err = toml.NewEncoder(fd).Encode(hc)
	if err != nil {
		return err
	}
	return nil
}

// ParseCothority parses the config file into a CothorityConfig.
// It returns the CothorityConfig, the Host so we can already use it, and an error if
// the file is inaccessible or has wrong values in it.
func ParseCothority(file string) (*CothorityConfig, *onet.Conode, error) {
	hc := &CothorityConfig{}
	_, err := toml.DecodeFile(file, hc)
	if err != nil {
		return nil, nil, err
	}
	// Try to decode the Hex values
	secret, err := crypto.ReadScalarHex(network.Suite, hc.Private)
	if err != nil {
		return nil, nil, err
	}
	point, err := crypto.ReadPubHex(network.Suite, hc.Public)
	if err != nil {
		return nil, nil, err
	}
	si := network.NewServerIdentity(point, hc.Address)
	si.Description = hc.Description
	conode := onet.NewConodeTCP(si, secret)
	return hc, conode, nil
}

// GroupToml holds the data of the group.toml file.
type GroupToml struct {
	Description string
	Servers     []*ServerToml `toml:"servers"`
}

// NewGroupToml creates a new GroupToml struct from the given ServerTomls.
// Currently used together with calling String() on the GroupToml to output
// a snippet which can be used to create a CoSi group.
func NewGroupToml(servers ...*ServerToml) *GroupToml {
	return &GroupToml{
		Servers: servers,
	}
}

// ServerToml is one entry in the group.toml file describing one server to use for
// the cothority.
type ServerToml struct {
	Address     network.Address
	Public      string
	Description string
}

// Group holds the Roster and the server-description.
type Group struct {
	Roster      *onet.Roster
	description map[*network.ServerIdentity]string
}

// GetDescription returns the description of a ServerIdentity.
func (g *Group) GetDescription(e *network.ServerIdentity) string {
	return g.description[e]
}

// ReadGroupDescToml reads a group.toml file and returns the list of ServerIdentities
// and descriptions in the file.
// If the file couldn't be decoded or doesn't hold valid ServerIdentities,
// an error is returned.
func ReadGroupDescToml(f io.Reader) (*Group, error) {
	group := &GroupToml{}
	_, err := toml.DecodeReader(f, group)
	if err != nil {
		return nil, err
	}
	// convert from ServerTomls to entities
	var entities = make([]*network.ServerIdentity, len(group.Servers))
	var descs = make(map[*network.ServerIdentity]string)
	for i, s := range group.Servers {
		en, err := s.toServerIdentity(network.Suite)
		if err != nil {
			return nil, err
		}
		entities[i] = en
		descs[en] = s.Description
	}
	el := onet.NewRoster(entities)
	return &Group{el, descs}, nil
}

// ReadGroupToml reads a group.toml file and returns the list of ServerIdentity
// described in the file.
// If the file holds an invalid ServerIdentity-description, an error is returned.
func ReadGroupToml(f io.Reader) (*onet.Roster, error) {
	group, err := ReadGroupDescToml(f)
	if err != nil {
		return nil, err
	}
	return group.Roster, nil
}

// Save writes the GroupToml definition into the file given by its name.
// It will return an error if the file couldn't be created or if writing
// to it failed.
func (gt *GroupToml) Save(fname string) error {
	file, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(gt.String())
	return err
}

// String returns the TOML representation of this GroupToml.
func (gt *GroupToml) String() string {
	var buff bytes.Buffer
	if gt.Description == "" {
		gt.Description = "Description of your cothority roster"
	}
	for _, s := range gt.Servers {
		if s.Description == "" {
			s.Description = "Description of your server"
		}
	}
	enc := toml.NewEncoder(&buff)
	if err := enc.Encode(gt); err != nil {
		return "Error encoding grouptoml" + err.Error()
	}
	return buff.String()
}

// toServerIdentity converts this ServerToml struct to a ServerIdentity.
func (s *ServerToml) toServerIdentity(suite abstract.Suite) (*network.ServerIdentity, error) {
	pubR := strings.NewReader(s.Public)
	public, err := crypto.ReadPub64(suite, pubR)
	if err != nil {
		return nil, err
	}
	return network.NewServerIdentity(public, s.Address), nil
}

// NewServerToml takes a public key and an address and returns
// the corresponding ServerToml.
// If an error occurs, it will be printed to StdErr and nil
// is returned.
func NewServerToml(suite abstract.Suite, public abstract.Point, addr network.Address,
	desc string) *ServerToml {
	var buff bytes.Buffer
	if err := crypto.WritePub64(suite, &buff, public); err != nil {
		log.Error("Error writing public key")
		return nil
	}
	return &ServerToml{
		Address:     addr,
		Public:      buff.String(),
		Description: desc,
	}
}

// String returns the TOML representation of the ServerToml.
func (s *ServerToml) String() string {
	var buff bytes.Buffer
	if s.Description == "" {
		s.Description = "## Put your description here for convenience ##"
	}
	enc := toml.NewEncoder(&buff)
	if err := enc.Encode(s); err != nil {
		return "## Error encoding server informations ##" + err.Error()
	}
	return buff.String()
}
