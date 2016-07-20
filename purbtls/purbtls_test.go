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
        "strconv"
        //"time"
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
                serverMsg :=  "Server test message: "
                cnt := 0
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
				//fmt.Println(string(b))
                                fmt.Println(string(b[:i]))
                                //cnt++
                                conn.Write([]byte(serverMsg+ strconv.Itoa(cnt)))

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
	ents, ents2 := genKeys(10, suites)
	sConf := Config{ents, false, nil, nil,nil}
	cConf := Config{ents2, true, nil, nil,nil}
	//sConf.keys[0].PubKey = nil
	fmt.Println(sConf.keys[0])
	fmt.Println(cConf.keys[0])
	go server(&sConf)
	conn, err := Dial("tcp", "localhost:8080", &cConf)
	if err != nil {
		fmt.Println(err)
	}
	s := "Test Message"
	conn.Write([]byte(s))
                serverMsg :=  "Client test message: "
                cnt := 0
		for {
			//Read assumes that the byte buffer has space.
			b := make([]byte, 255)
			i, err := conn.Read(b)
			if err != nil {
				fmt.Println(err)
				if err != nil {
                                        fmt.Println(err)
					fmt.Println("Connection closed")
					conn.Close()

				}
			}
			if i > 0 {
				//fmt.Println(string(b))
                                fmt.Println(string(b[:i]))
                                cnt++
                                if cnt >= 20 {
                                    break
                                }
                                conn.Write([]byte(serverMsg+strconv.Itoa(cnt)))

			}
		}
	conn.Close()

}

//Builds num key pairs in each suite.
func genKeys(num int, suites []abstract.Suite) ([]purb.Entry, []purb.Entry) {
	entries := make([]purb.Entry, 0)
	entries2 := make([]purb.Entry, 0)
	for suite := range suites {
		s := suites[suite]
		for i := 0; i < num; i++ {
			pri := s.Secret().Pick(random.Stream)
			pub := s.Point().Mul(nil, pri)
			entries = append(entries, purb.Entry{s, pri, nil, nil, nil, nil, nil})
			entries2 = append(entries2, purb.Entry{s, nil, pub, nil, nil, nil, nil})
		}
	}
	return entries, entries2
}
