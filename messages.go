package onet

import (
	"sync"

	"github.com/dedis/onet/network"
	"github.com/satori/go.uuid"
)

// ProtocolMsgID is to be embedded in every message that is made for a
// ID of ProtocolMsg message as registered in network
var ProtocolMsgID = network.RegisterPacketType(ProtocolMsg{})

// RequestTreeMessageID of RequestTree message as registered in network
var RequestTreeMessageID = network.RegisterPacketType(RequestTree{})

// RequestRosterMessageID of RequestRoster message as registered in network
var RequestRosterMessageID = network.RegisterPacketType(RequestRoster{})

// SendTreeMessageID of TreeMarshal message as registered in network
var SendTreeMessageID = TreeMarshalTypeID

// SendRosterMessageID of Roster message as registered in network
var SendRosterMessageID = RosterTypeID

// ConfigMessageID of the generic config message
var ConfigMessageID = network.RegisterPacketType(ConfigMessage{})

// ProtocolMsg is to be embedded in every message that is made for a
// ProtocolInstance
type ProtocolMsg struct {
	// Token uniquely identify the protocol instance this msg is made for
	From *Token
	// The TreeNodeId Where the message goes to
	To *Token
	// NOTE: this is taken from network.NetworkMessage
	ServerIdentity *network.ServerIdentity
	// MsgType of the underlying data
	MsgType network.PacketTypeID
	// The interface to the actual Data
	Msg network.Body
	// The actual data as binary blob
	MsgSlice []byte
}

// ConfigMessage is sent by the overlay containing a generic slice of bytes to
// give to service in the `NewProtocol` method.
type ConfigMessage struct {
	Config GenericConfig
	Dest   TokenID
}

// RoundID uniquely identifies a round of a protocol run
type RoundID uuid.UUID

// String returns the canonical representation of the rounds ID (wrapper around // uuid.UUID.String())
func (rId RoundID) String() string {
	return uuid.UUID(rId).String()
}

// TokenID uniquely identifies the start and end-point of a message by an ID
// (see Token struct)
type TokenID uuid.UUID

func (t *TokenID) String() string {
	return uuid.UUID(*t).String()
}

// A Token contains all identifiers needed to uniquely identify one protocol
// instance. It gets passed when a new protocol instance is created and get used
// by every protocol instance when they want to send a message. That way, the
// host knows how to create the ProtocolMsg message around the protocol's message
// with the right fields set.
type Token struct {
	RosterID RosterID
	TreeID   TreeID
	// TO BE REMOVED
	ProtoID   ProtocolID
	ServiceID ServiceID
	RoundID   RoundID
	// TreeNodeID is defined by the
	TreeNodeID TreeNodeID
	cacheID    TokenID
}

// Global mutex when we're working on Tokens. Needed because we
// copy Tokens in ChangeTreeNodeID.
var tokenMutex sync.Mutex

// ID returns the TokenID which can be used to identify by token in map
func (t *Token) ID() TokenID {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()
	if t.cacheID == TokenID(uuid.Nil) {
		url := network.NamespaceURL + "token/" + t.RosterID.String() +
			t.RoundID.String() + t.ServiceID.String() + t.ProtoID.String() + t.TreeID.String() +
			t.TreeNodeID.String()
		t.cacheID = TokenID(uuid.NewV5(uuid.NamespaceURL, url))
	}
	return t.cacheID
}

// Clone returns a new token out of this one
func (t *Token) Clone() *Token {
	t2 := *t
	return &t2
}

// ChangeTreeNodeID return a new Token containing a reference to the given
// TreeNode
func (t *Token) ChangeTreeNodeID(newid TreeNodeID) *Token {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()
	tOther := *t
	tOther.TreeNodeID = newid
	tOther.cacheID = TokenID(uuid.Nil)
	return &tOther
}

// TreeNodeInfo holds the sender and the destination of the message.
type TreeNodeInfo struct {
	To   *Token
	From *Token
}

// OverlayMessage contains all routing-information about the tree and the
// roster.
type OverlayMessage struct {
	TreeNodeInfo *TreeNodeInfo

	RequestTree   *RequestTree
	TreeMarshal   *TreeMarshal
	RequestRoster *RequestRoster
	Roster        *Roster
}

// RequestTree is used to ask the parent for a given Tree
type RequestTree struct {
	// The treeID of the tree we want
	TreeID TreeID
}

// RequestRoster is used to ask the parent for a given Roster
type RequestRoster struct {
	RosterID RosterID
}

// RosterUnknown is used in case the entity list is unknown
type RosterUnknown struct {
}

// SendServerIdentity is the first message we send on creation of a link
type SendServerIdentity struct {
	Name string
}
