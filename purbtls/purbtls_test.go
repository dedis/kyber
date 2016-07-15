package purbtls

import (
	//	"bufio"
	//	"encoding/binary"
	//	"encoding/hex"
	"fmt"
	//"github.com/dedis/crypto/abstract"
	//	"github.com/dedis/crypto/cipher/aes"
	//"time"
	//	"github.com/dedis/crypto/config"
	//"github.com/dedis/crypto/edwards"
	//	"github.com/dedis/crypto/padding"
	//"github.com/dedis/crypto/random"
	//	"io/ioutil"
	//	"os"
	"net"
	"testing"
)

//Runs the server code.
func server() {
	//Create a listener
	//conf := Config{}
	listen, err = purbtls.Listen("tcp", "localhost:8080", nil)
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
			b := make([]byte, 0)
			i, _ := conn.Read(b)
			if i > 0 {
				fmt.Println(string(b))

			}
		}
		conn.Close()
	}
}

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

func TestBasicConn(t *testing.T) {
	go server()

}
