package purbtls

import (
	//	"bufio"
	//	"encoding/binary"
	//	"encoding/hex"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"io"
	//	"github.com/dedis/crypto/cipher/aes"
	//"time"
	//"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/edwards"
	//	"github.com/dedis/crypto/padding"
	"github.com/dedis/crypto/purb"
	"github.com/dedis/crypto/random"
	//	"io/ioutil"
	//	"os"
	//	"net"
	"testing"
)

//Runs the server code.
func server(conf *Config) {
	//Create a listener
	//conf := Config{}
	listen, err := Listen("tcp", "localhost:8080", conf)
	if err != nil {
		fmt.Print(err)
	}
	for {
		conn, err := listen.Accept()
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println("Connection created")
		for {
			//Read assumes that the byte buffer has space.
			b := make([]byte, 255)
			i, err := conn.Read(b)
			if err != nil {
				fmt.Println(err)
				if err == io.EOF {
					fmt.Println("Connection closed")
					conn.Close()

				}
			}
			if i > 0 {
				fmt.Println(string(b))

			}
		}
		fmt.Println("Connection closed")
		conn.Close()
	}
}

/*
func TestPurbTLS(t *testing.T) {
	//Create different connections and Config
	go server()
	conn, err := purbtls.Dial("tcp", "localhost:8080")
	if err != nil {
		fmt.Println(err)
	}
	conn.Write([]byte("test Message"))
	input := ""
	fmt.Scanln(&input)
	conn.Close()
}
*/

func TestBasicConn(t *testing.T) {
	//Build the keys.
	suites := []abstract.Suite{edwards.NewAES128SHA256Ed25519(true)}
	ents := genKeys(10, suites)
	cConf := Config{ents, true}
	sConf := Config{ents, false}
	go server(&sConf)
	conn, err := Dial("tcp", "localhost:8080", &cConf)
	if err != nil {
		fmt.Println(err)
	}
	s := "Test Message"
	conn.Write([]byte(s))
	input := ""
	fmt.Scanln(&input)
	conn.Close()

}

//Builds num key pairs in each suite.
func genKeys(num int, suites []abstract.Suite) []purb.Entry {
	entries := make([]purb.Entry, 0)
	for suite := range suites {
		s := suites[suite]
		for i := 0; i < num; i++ {
			pri := s.Secret().Pick(random.Stream)
			pub := s.Point().Mul(nil, pri)
			entries = append(entries, purb.Entry{s, pri, pub, nil})
		}
	}
	return entries
}
