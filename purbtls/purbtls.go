//purbtls is a simple TLS like protocol for encrypted communication.
//Assumes that the client has a public key for the server at the beggining of
//the protocol.

package purbtls

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards"
	//	"github.com/dedis/crypto/cipher/aes"
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/dedis/crypto/padding"
	"github.com/dedis/crypto/purb"
	"github.com/dedis/crypto/random"
	"net"
	"time"
)

//How many bytes symkey+message_start is
//TODO make it easy for different entrypoint sizes.
const DATALEN = 24

const AEADLEN = 16

//Confirmation data
//Currently 24 bytes. 
//TODO make it 8 bytes, and change PURB to actually do AEAD encryption
const CONFDATA = "confirmation message1234"


//Default next recordLen
const DEFAULTLEN = 256

//Default content type
const CONTENT = 0x01

//Default packet type
const PACKET = 0x01

//The overhead from the packet packet type (1) + len (8) + content (1)
const RECORDOVERHEAD = 10

//The maximum length of a record, possibly not needed and caused by me
//not using buffers TODO check buffers
const MAXRECLEN = 16384

//layout of suite entrypoints default
var KEYPOS = map[string][]int{
	edwards.NewAES128SHA256Ed25519(true).String(): {
		0 * purb.KEYLEN, 1 * purb.KEYLEN,
	},
	edwards.NewAES128SHA256Ed1174(true).String(): {
		0 * purb.KEYLEN, 1 * purb.KEYLEN, 2 * purb.KEYLEN,
	},
}

/*

//Entry holds the info required to create an entrypoint for each recipient.
//Duplicated from purbgp code, will probably not be needed.
type Entry struct {
	Suite  abstract.Suite // Ciphersuite this public key is drawn from
	PriKey abstract.Secret
	PubKey abstract.Point // Public key of this entrypoint's owner
	Data   []byte         // Entrypoint data decryptable by owner
}
*/
//Constants for suites.
//const {}
type Config struct {
	//Needed fields
	//List of public key suites to use
	//Server public key. known by client
	//Server Private key. known by server
	//holds the server keys, if it is client then only public keys will be seen
	keys      []purb.Entry
	is_client bool
	//Probably should just be part of PurbConn
	sendKey []byte
	recvKey []byte
	suite   abstract.Suite
}

//listener structure taken from golang tls implementation
type listener struct {
	net.Listener
	config *Config
}

//Possibly use a connection, for all functions.
type PurbConn struct {
	con     net.Conn
	cf      *Config
	sCipher abstract.Cipher
	rCipher abstract.Cipher
	nextLen int
}

//Probably does not need to be a struct?
type record struct {
	msgData    []byte
	nextLen    int    //Only applicable if known?
	len        int    //length of the final record (recVal)
	content    byte   //The content type ??? possibly not needed
	packetType byte   //Place for the packet type. Currently will be 1
	recVal     []byte //unencrypted record

}

//What functions will be needed
//Two phases
//Handshake
//General writing.

//listener structure taken from golang tls implementation
func NewListener(inner net.Listener, config *Config) net.Listener {
	l := new(listener)
	l.Listener = inner
	l.config = config
	return l
}

//Might have some value in making it return net.Conn, as tls go does,
//but for now going to return a PurbConn
func (l *listener) Accept() (conn net.Conn, err error) {
	con, err := l.Listener.Accept()
	if err != nil {
		return
	}

	c := Server(con, l.config)
	return c, nil
}
func Server(c net.Conn, conf *Config) *PurbConn {
	//Handles handshake and returns a connection that is ready
	//to read/Write.
	purbs := new(PurbConn)
	purbs.nextLen = DEFAULTLEN
	//Perform handshake
	//get handshake message
	buf := make([]byte, 1024)
	for {
		l, err := c.Read(buf)

		if err != nil {
			fmt.Println(err)
		}
		if l > 0 {
			//TODO implement trying multiple keys
			//Choose a key
			entry := conf.keys[len(conf.keys)-1]
			//		entry := conf.keys[0]
			//			fmt.Println("-----------Before--------------")
			//			fmt.Println(entry)
			//Mostly good, but (TODO) need to update the encrytion in purb to use AEAD correctly.
			_, _ = purb.AttemptDecodeTLS(&entry, KEYPOS,
				buf, random.Stream, CONFDATA)
			conf.recvKey = entry.RecvKey
			conf.sendKey = entry.SendKey
			conf.suite = entry.Suite
			/*			fmt.Println("-----------After--------------")
						fmt.Println(entry)
						fmt.Println(val.String())
						fmt.Println(l, "recieved purb")*/
			break
		}
	}
	m := "test:"
	cipher := make([]byte, 0)
	purbs.sCipher = conf.suite.Cipher(conf.sendKey)
	purbs.rCipher = conf.suite.Cipher(conf.recvKey)
	//Pad the message before encrypting as it is much cheaper
	padLen := padding.GetPaddingLen(uint64(len(m)), uint64(AEADLEN))
	padBytes := padding.GeneratePadding(padLen)
	padMsg := append([]byte(m), padBytes...)
	//	cipher = conf.suite.Cipher(conf.sendKey).Seal(cipher, []byte(m))
	cipher = purbs.sCipher.Seal(cipher, padMsg)
	ok := padding.CheckZeroBits(uint64(len(cipher)))
	if !ok {
		fmt.Println("Padding is wrong")
	}

	//	fmt.Println(conf.sendKey)
	//	fmt.Println(cipher)
	//	fmt.Println(len(cipher))
	c.Write(cipher)
	purbs.con = c

	return purbs
}
func Client(c net.Conn, conf *Config) *PurbConn {
	//Handles handshake and returns a connection that is ready
	//to read/Write.
	purbc := new(PurbConn)
	purbc.con = c
	purbc.cf = conf
	purbc.nextLen = DEFAULTLEN
	//Set entrypoints
	for i := range conf.keys {
		e := &conf.keys[i]
		e.Data = []byte(CONFDATA)
		/*		fmt.Println(i)
				fmt.Println(e.Suite)
				fmt.Println(e.PubKey)
				fmt.Println(e.Data)*/
	}
	//	fmt.Println("-----------Before--------------")
	//	fmt.Println(conf.keys)
	purbHeader, _ := purb.GenPurbTLS(conf.keys, KEYPOS)
	//Pad the header
	paddingLen := padding.GetPaddingLen(uint64(len(purbHeader)), 0)
	fmt.Println(len(purbHeader))
	//used dedis crypto.Random to generate a byte slice with the right length
	msgPadding := random.Bytes(int(paddingLen), random.Stream)
	paddedMsg := append(purbHeader, msgPadding...)
	//Check length
	padRes := padding.CheckZeroBits(uint64(len(paddedMsg)))
	if !padRes {
		fmt.Println("Padding not correct")
		fmt.Println(len(paddedMsg))
	}
	//	fmt.Println("-----------After--------------")
	//	fmt.Println(conf.keys)
	c.Write(paddedMsg)
	buf := make([]byte, 1024)
	for {
		l, err := c.Read(buf)
		if err != nil {
			fmt.Println(err)
		}

		if l > 0 {
			//Decrypt using shared keys from conf.keys (populated by GenPurbTLS)
			for k := range conf.keys {
				e := conf.keys[k]
				//e := conf.keys[len(conf.keys)-k-1]
				res := make([]byte, 0)
				//				fmt.Println(e.RecvKey)
				//Destroys buf so need to copy
				cpy := make([]byte, l)
				copy(cpy, buf)
				purbc.sCipher = e.Suite.Cipher(e.SendKey)
				purbc.rCipher = e.Suite.Cipher(e.RecvKey)
				//			res, err = e.Suite.Cipher(e.RecvKey).Open(res, cpy)
				res, err = purbc.rCipher.Open(res, cpy)
				//				fmt.Println(cpy)
				if err != nil {
					fmt.Println(err)
					continue
				} else {
					fmt.Println("okay")
				}
				//	fmt.Println(string(buf))
				if string(res[0:5]) == "test:" {
					//					fmt.Println(string(res))
					conf.sendKey = e.SendKey
					conf.recvKey = e.RecvKey
					conf.suite = e.Suite
					break
				}
			}
			break
		}
	}
	return purbc

}

//Terminology for functions is from tls go implementation.
//Listen for the server. Creates a connection and listens.Config
//Probably Listen(network, laddr string, cnf *Config);

//For client a dial(conn net.conn, cnf *Config)

//General use is set up Config, then call either Dial(), or Listen(),

func Listen(network, address string, conf *Config) (net.Listener, error) {

	listen, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	return NewListener(listen, conf), nil
}

//Dial creates a connection to a server using purbtls negotiation.
//Returns err
func Dial(network, address string, conf *Config) (*PurbConn, error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}

	c := Client(conn, conf)
	return c, nil

}

//Takes in a padded record and returns the value of the content byte
//and the index of the content byte
func dePad(data []byte) (byte, int) {
	i := len(data) - 1

	for data[i] == 0x00 {
		i--
	}
	return data[i], i
}

//Record format
//M= [packet byte][data][len][content byte][0...0]

//Creates a record with default arguments
//Pass in the next record length
func (conn *PurbConn) createRecordDefault(msg []byte, nextLen int) record {
	rec := record{msg, conn.nextLen, 0, CONTENT, PACKET, nil}
	//build the record
	//Should use more effecient length encoding
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, int64(nextLen))
	fmt.Println("value of nextLen createRecord", nextLen)
	nLen := buf.Bytes()
	m := make([]byte, 1)
	m[0] = rec.packetType
	m = append(m, msg...)
	m = append(m, nLen...)
	m = append(m, rec.content)
	var padByte []byte
	if len(m) < DEFAULTLEN {
		padByte = padding.GeneratePadding(DEFAULTLEN - uint64(len(m)) - AEADLEN)

	} else {
		padLen := padding.GetPaddingLen(uint64(len(m)), AEADLEN)
		padByte = padding.GeneratePadding(padLen)
	}
	m = append(m, padByte...)
	rec.recVal = m
	rec.len = len(m) + AEADLEN
	fmt.Println("length (w/o aead) :", len(rec.recVal))
	return rec
}

//Decode Record returns a byte slice with any decoded records
func (conn *PurbConn) decodeRecords(records []byte) []byte {

	ret := make([]byte, 0)
	curLen := 0
	for curLen < len(records) {
		fmt.Println(curLen, len(records), conn.nextLen)
		//Get record bytes
		/*	data := make([]byte, conn.nextLen)
			copy(data, records[curLen:conn.nextLen-1])
			fmt.Println(len(data))
			if bytes.Equal(data, records[curLen:conn.nextLen-1]) {
				fmt.Println("They are equal")
			}*/
		data := records[curLen : curLen+conn.nextLen]
		curLen += conn.nextLen
		fmt.Println("test", len(data))
		//decode the record
		decoded, err := conn.rCipher.Open(nil, data)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println("double check")
		//remove padding
		_, padLen := dePad(decoded)

		decoded = decoded[0:padLen]
		conn.nextLen = int(binary.BigEndian.Uint64(decoded[len(decoded)-8:]))
		fmt.Println("Next Len", conn.nextLen)
		msg := decoded[1 : len(decoded)-8]
		fmt.Println(string(msg))
		ret = append(ret, msg...)
	}

	return ret
}
func (conn *PurbConn) Write(data []byte) (int, error) {
	//	c := conn.cf.suite.Cipher(conn.cf.sendKey).Seal(nil, data)
	//Testing

	//Two cases with the record, it will fit into one 256 byte messages
	//Or it needs two records
	maxLen := DEFAULTLEN - AEADLEN - RECORDOVERHEAD
	c := make([]byte, 0)
	if len(data) > maxLen {
		fmt.Println("2 records", len(data))
		m1 := data[0:maxLen]
		m2 := data[maxLen:]
		//Calculate the length of m2
		rec2 := conn.createRecordDefault(m2, DEFAULTLEN)
		rec1 := conn.createRecordDefault(m1, rec2.len)
		c1 := conn.sCipher.Seal(nil, rec1.recVal)
		c2 := conn.sCipher.Seal(nil, rec2.recVal)
		c = append(c1, c2...)
	} else {
		fmt.Println("1 record", len(data))
		rec := conn.createRecordDefault(data, DEFAULTLEN)
		c1 := conn.sCipher.Seal(nil, rec.recVal)
		c = append(c, c1...)
	}
	fmt.Println(len(c))
	//c := conn.sCipher.Seal(nil, data)

	//	fmt.Println(len(c), len(data))
	//	fmt.Println(c)
	//fmt.Println(data)
	return conn.con.Write(c)
}

func (conn *PurbConn) Read(data []byte) (int, error) {
	i, err := conn.con.Read(data)
	if i > 0 {
		//fmt.Println(i)
		//fmt.Println(data[0:i])
		//c := make([]byte, 0)
		cpy := make([]byte, i)
		copy(cpy, data)
		//fmt.Println(cpy)
		//fmt.Println("test")
		//	c, err2 := conn.cf.suite.Cipher(conn.cf.recvKey).Open(c, cpy)
		//Testing
		/*
			c, err2 := conn.rCipher.Open(c, cpy)
			//fmt.Println("test")
			if err2 != nil {
				fmt.Println(err2)
			}*/
		decoded := conn.decodeRecords(cpy)
		//fmt.Println(c)
		//fmt.Println("test")
		//Figure out how to actually clear the buffer
		data := data[:i-AEADLEN]
		i = len(decoded)
		copy(data, decoded)
	}
	return i, err

}
//Functions to finish the conn interface
func (conn *PurbConn) Close() error {
	return conn.con.Close()
}
func (conn *PurbConn) LocalAddr() net.Addr {
	return conn.con.LocalAddr()
}
func (conn *PurbConn) RemoteAddr() net.Addr {
	return conn.con.RemoteAddr()
}
func (conn *PurbConn) SetDeadline(t time.Time) error {
	return conn.con.SetDeadline(t)
}
func (conn *PurbConn) SetReadDeadline(t time.Time) error {
	return conn.con.SetReadDeadline(t)
}
func (conn *PurbConn) SetWriteDeadline(t time.Time) error {
	return conn.con.SetWriteDeadline(t)
}
