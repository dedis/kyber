package network

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"sync"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/ed25519"
	"github.com/dedis/onet/log"
	"github.com/dedis/protobuf"
	"github.com/satori/go.uuid"
)

/// Encoding part ///

// Suite used globally by this network library.
// For the moment, this will stay,as our focus is not on having the possibility
// to use any suite we want (the decoding stuff is much harder then, because we
// don't want to send the suite in the wire).
// It will surely change in futur releases so we can permit this behavior.
var Suite = ed25519.NewAES128SHA256Ed25519(false)

// Body is a type for any message that the user wants to send
type Body interface{}

// PacketTypeID is the ID used to uniquely identify different registered messages
type PacketTypeID uuid.UUID

// ErrorType is reserved by the network library. When you receive a message of
// ErrorType, it is generally because an error happened, then you can call
// Error() on it.
var ErrorType = PacketTypeID(uuid.Nil)

// String returns the name of the structure if it is known, else it returns
// the hexadecimal value of the Id.
func (pId PacketTypeID) String() string {
	t, ok := registry.get(pId)
	if ok {
		return fmt.Sprintf("PTID(%s:%x)", t.String(), uuid.UUID(pId).Bytes())
	}
	return uuid.UUID(pId).String()
}

// Equal returns true if pId is equal to t
func (pId PacketTypeID) Equal(t PacketTypeID) bool {
	return bytes.Compare(uuid.UUID(pId).Bytes(), uuid.UUID(t).Bytes()) == 0
}

// NamespaceURL is the basic namespace used for uuid
// XXX should move that to external of the library as not every
// cothority/packages should be expected to use that.
const NamespaceURL = "https://dedis.epfl.ch/"

// NamespaceBodyType is the namespace used for PacketTypeID
const NamespaceBodyType = NamespaceURL + "/protocolType/"

// RegisterPacketType registers a custom "struct" / "packet" and returns the
// corresponding PacketTypeID.
// Simply pass your non-initialized struct.
func RegisterPacketType(msg Body) PacketTypeID {
	msgType := TypeToPacketTypeID(msg)
	val := reflect.ValueOf(msg)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	t := val.Type()
	return RegisterPacketUUID(msgType, t)
}

// RegisterPacketUUID can be used if the uuid and the type is already known
// NOTE: be sure to only registers VALUE message and not POINTERS to message.
func RegisterPacketUUID(mt PacketTypeID, rt reflect.Type) PacketTypeID {
	if _, typeRegistered := registry.get(mt); typeRegistered {
		return mt
	}
	registry.put(mt, rt)
	return mt
}

// TypeFromData returns the PacketTypeID corresponding to the given structure.
// It returns 'ErrorType' if the type wasn't found or an error occurred.
func TypeFromData(msg Body) PacketTypeID {
	msgType := TypeToPacketTypeID(msg)
	_, ok := registry.get(msgType)
	if !ok {
		return ErrorType
	}
	return msgType
}

// TypeToPacketTypeID converts a Body to a PacketTypeID
func TypeToPacketTypeID(msg Body) PacketTypeID {
	val := reflect.ValueOf(msg)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	url := NamespaceBodyType + val.Type().String()
	u := uuid.NewV5(uuid.NamespaceURL, url)
	log.Lvl5("Reflecting", reflect.TypeOf(msg), "to", u)
	return PacketTypeID(u)
}

// RTypeToPacketTypeID converts a reflect.Type to a PacketTypeID
func RTypeToPacketTypeID(msg reflect.Type) PacketTypeID {
	url := NamespaceBodyType + msg.String()
	return PacketTypeID(uuid.NewV5(uuid.NamespaceURL, url))
}

// DumpTypes is used for debugging - it prints out all known types
func DumpTypes() {
	for t, m := range registry.types {
		log.Print("Type", t, "has message", m)
	}
}

// DefaultConstructors gives a default constructor for protobuf out of the global suite
func DefaultConstructors(suite abstract.Suite) protobuf.Constructors {
	constructors := make(protobuf.Constructors)
	var point abstract.Point
	var secret abstract.Scalar
	constructors[reflect.TypeOf(&point).Elem()] = func() interface{} { return suite.Point() }
	constructors[reflect.TypeOf(&secret).Elem()] = func() interface{} { return suite.Scalar() }
	return constructors
}

// Error returns the error that has been encountered during the unmarshaling of
// this message.
func (am *Packet) Error() error {
	return am.err
}

// SetError is workaround so we can set the error after creation of the
// application message
func (am *Packet) SetError(err error) {
	am.err = err
}

type typeRegistry struct {
	types map[PacketTypeID]reflect.Type
	lock  sync.Mutex
}

func newTypeRegistry() *typeRegistry {
	return &typeRegistry{
		types: make(map[PacketTypeID]reflect.Type),
		lock:  sync.Mutex{},
	}
}

// get returns the reflect.Type corresponding to the registered PacketTypeID
// an a boolean indicating if the type is actually registered or not.
func (tr *typeRegistry) get(id PacketTypeID) (reflect.Type, bool) {
	tr.lock.Lock()
	defer tr.lock.Unlock()
	t, ok := tr.types[id]
	return t, ok
}

// put stores the given type in the typeRegistry.
func (tr *typeRegistry) put(id PacketTypeID, typ reflect.Type) {
	tr.lock.Lock()
	defer tr.lock.Unlock()
	tr.types[id] = typ
}

var registry = newTypeRegistry()

var globalOrder = binary.BigEndian

// EmptyApplicationPacket is the default empty message that is returned in case
// something went wrong.
//
// FIXME currently there seems no way with go1.6 for this to compile without repeating
// the definition of ErrorType above as PacketTypeID(uuid.Nil).
// Somehow it still gets inlined (maybe through the indirection).
// should be fixed properly in go1.7:
// https://github.com/golang/go/commit/feb2a5d6103dad76b6374c5f346e33d55612cb2a
var EmptyApplicationPacket = Packet{MsgType: PacketTypeID(uuid.Nil)}

// global mutex for MarshalRegisteredType
var marshalLock sync.Mutex

// MarshalRegisteredType will marshal a struct with its respective type into a
// slice of bytes. That slice of bytes can be then decoded in
// UnmarshalRegisteredType. data must be a pointer to the message.
func MarshalRegisteredType(data Body) ([]byte, error) {
	marshalLock.Lock()
	defer marshalLock.Unlock()
	var msgType PacketTypeID
	if msgType = TypeFromData(data); msgType == ErrorType {
		return nil, fmt.Errorf("type of message %s not registered to the network library", reflect.TypeOf(data))
	}
	b := new(bytes.Buffer)
	if err := binary.Write(b, globalOrder, msgType); err != nil {
		return nil, err
	}
	var buf []byte
	var err error
	if buf, err = protobuf.Encode(data); err != nil {
		log.Errorf("Error for protobuf encoding: %s %+v", err, data)
		if log.DebugVisible() > 0 {
			log.Error(log.Stack())
		}
		return nil, err
	}
	_, err = b.Write(buf)
	return b.Bytes(), err
}

// UnmarshalRegisteredType returns the type, the data and an error trying to
// decode a message from a buffer.
// The type must be registered to the network library in order to be decodable.
func UnmarshalRegisteredType(buf []byte, constructors protobuf.Constructors) (PacketTypeID, Body, error) {
	b := bytes.NewBuffer(buf)
	var tID PacketTypeID
	if err := binary.Read(b, globalOrder, &tID); err != nil {
		return ErrorType, nil, err
	}
	typ, ok := registry.get(tID)
	if !ok {
		return ErrorType, nil, fmt.Errorf("type %s not registered", tID.String())
	}
	ptrVal := reflect.New(typ)
	ptr := ptrVal.Interface()
	if err := protobuf.DecodeWithConstructors(b.Bytes(), ptr, constructors); err != nil {
		return tID, ptrVal.Elem().Interface(), err
	}
	return tID, ptrVal.Elem().Interface(), nil
}

// UnmarshalRegistered is like UnmarshalRegisteredType but it uses a
// default constructor and returns a pointer to struct.
func UnmarshalRegistered(buf []byte) (PacketTypeID, Body, error) {
	b := bytes.NewBuffer(buf)
	var tID PacketTypeID
	if err := binary.Read(b, globalOrder, &tID); err != nil {
		return ErrorType, nil, err
	}
	typ, ok := registry.get(tID)
	if !ok {
		return ErrorType, nil, fmt.Errorf("type %s not registered", tID.String())
	}
	ptrVal := reflect.New(typ)
	ptr := ptrVal.Interface()
	constructors := DefaultConstructors(Suite)
	if err := protobuf.DecodeWithConstructors(b.Bytes(), ptr, constructors); err != nil {
		return ErrorType, nil, err
	}
	return tID, ptrVal.Interface(), nil
}

// MarshalBinary the application packet => to bytes
// Implements BinaryMarshaler interface so it will be used when sending with protobuf
func (am *Packet) MarshalBinary() ([]byte, error) {
	return MarshalRegisteredType(am.Msg)
}

// UnmarshalBinary will decode the incoming bytes
// It uses protobuf for decoding (using the constructors in the Packet).
func (am *Packet) UnmarshalBinary(buf []byte) error {
	t, msg, err := UnmarshalRegisteredType(buf, DefaultConstructors(Suite))
	am.MsgType = t
	am.Msg = msg
	return err
}

// NewNetworkPacket takes a Body and then constructs a
// Message from it. Error if the type is unknown
func NewNetworkPacket(obj Body) (*Packet, error) {
	val := reflect.ValueOf(obj)
	if val.Kind() != reflect.Ptr {
		return nil, fmt.Errorf("Expected a pointer to the message")
	}
	ty := TypeFromData(obj)
	if ty == ErrorType {
		return &Packet{}, fmt.Errorf("Packet to send is not known. Please register packet: %s",
			reflect.TypeOf(obj).String())
	}
	return &Packet{
		MsgType: ty,
		Msg:     obj}, nil
}
