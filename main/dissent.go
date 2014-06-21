package main

import (
	"io"
	//"os"
	"net"
	"fmt"
	"log"
	"time"
	"flag"
	"net/http"
	//"encoding/hex"
	"encoding/binary"
	"dissent/crypto"
	"dissent/crypto/openssl"
	"dissent/dcnet"
	"github.com/elazarl/goproxy"
)


var suite = crypto.NewAES128SHA256P256()
//var suite = openssl.NewAES128SHA256P256()
var factory = dcnet.OwnedCoderFactory

const nclients = 50
const ntrustees = 3

const relayhost = "localhost:9876"	// XXX
const bindport = ":9876"

//const payloadlen = 1200			// upstream cell size
const payloadlen = 256			// upstream cell size

const downcellmax = 4096		// downstream cell max size

// Number of bytes of cell payload to reserve for connection header, length
const proxyhdrlen = 6

type connbuf struct {
	cno int			// connection number
	buf []byte		// data buffer
}



func testSuites() {
	crypto.TestSuite(crypto.NewAES128SHA256QR512())
	//crypto.TestSuite(crypto.NewAES128SHA256QR1024())
	crypto.TestSuite(crypto.NewAES128SHA256P256())
	crypto.TestSuite(openssl.NewAES128SHA256P256())
}

func benchSuites() {
	println("\nNative QR512 suite:")
	crypto.BenchSuite(crypto.NewAES128SHA256QR512())

	println("\nNative P256 suite:")
	crypto.BenchSuite(crypto.NewAES128SHA256P256())

	println("\nOpenSSL P256 suite:")
	crypto.BenchSuite(openssl.NewAES128SHA256P256())
}

func testDCNet() {
	//dcnet.TestCellCoder(suite, factory)
	dcnet.TestCellCoder(suite, factory)
}


func relayReadConn(cno int, conn net.Conn, downstream chan<- []byte) {
	for {
		buf := make([]byte, 6+downcellmax)
		//fmt.Printf("relayReadConn: Read() on cno %d\n", cno)
		n,err := conn.Read(buf[6:])
		//fmt.Printf("relayReadConn: %d bytes on cno %d\n", n, cno)

		// Forward the data (or close indication if n==0) downstream
		binary.BigEndian.PutUint32(buf[0:4], uint32(cno))
		binary.BigEndian.PutUint16(buf[4:6], uint16(n))
		downstream <- buf[:6+n]

		// Connection error or EOF?
		if n == 0 {
			if err != io.EOF {
				fmt.Println("relayReadConn error: "+err.Error())
			}
			conn.Close()
			return
		}
	}
}

func startRelay() {
	tg := dcnet.TestSetup(suite, factory, nclients, ntrustees)
	me := tg.Relay

	// Start our own local HTTP proxy for simplicity.
	go func() {
		proxy := goproxy.NewProxyHttpServer()
		proxy.Verbose = true
		println("Starting HTTP proxy")
		log.Fatal(http.ListenAndServe(":8888", proxy))
	}()

	lsock,err := net.Listen("tcp", bindport)
	if err != nil {
		panic("Can't open listen socket:"+err.Error())
	}

	// Wait for all the clients and trustees to connect
	ccli := 0
	ctru := 0
	csock := make([]net.Conn, nclients)
	tsock := make([]net.Conn, ntrustees)
	for ; ccli < nclients || ctru < ntrustees ; {
		fmt.Printf("Wating for %d clients, %d trustees\n",
				nclients-ccli, ntrustees-ctru)

		conn,err := lsock.Accept()
		if err != nil {
			panic("Listen error:"+err.Error())
		}

		b := make([]byte,1)
		n,err := conn.Read(b)
		if n < 1 || err != nil {
			panic("Read error:"+err.Error())
		}

		node := int(b[0] & 0x7f)
		if b[0] & 0x80 == 0 && node < nclients {
			if csock[node] != nil {
				panic("Oops, client connected twice")
			}
			csock[node] = conn
			ccli++
		} else if b[0] & 0x80 != 0 && node < ntrustees {
			if tsock[node] != nil {
				panic("Oops, trustee connected twice")
			}
			tsock[node] = conn
			ctru++
		} else {
			panic("illegal node number")
		}
	}
	println("All clients and trustees connected")

	// Create ciphertext slice buffers for all clients and trustees
	clisize := me.Coder.ClientCellSize(payloadlen)
	cslice := make([][]byte, nclients)
	for i := 0; i < nclients; i++ {
		cslice[i] = make([]byte, clisize)
	}
	trusize := me.Coder.TrusteeCellSize(payloadlen)
	tslice := make([][]byte, ntrustees)
	for i := 0; i < ntrustees; i++ {
		tslice[i] = make([]byte, trusize)
	}

	// Periodic stats reporting
	begin := time.Now()
	report := begin
	period,_ := time.ParseDuration("3s")
	totcells := int64(0)
	totupbytes := int64(0)
	totdownbytes := int64(0)

	conns := make(map[int]net.Conn)
	downstream := make(chan []byte)
	nulldown := [6]byte{}	// default empty downstream cell
	window := 2		// Maximum cells in-flight
	inflight := 0		// Current cells in-flight
	for {
		//print(".")

		// Show periodic reports
		now := time.Now()
		if now.After(report) {
			duration := now.Sub(begin).Seconds()
			fmt.Printf("@ %f sec: %d cells, %f cells/sec, %d upbytes, %f upbytes/sec, %d downbytes, %f downbytes/sec\n",
				duration,
				totcells, float64(totcells) / duration,
				totupbytes, float64(totupbytes) / duration,
				totdownbytes, float64(totdownbytes) / duration)

			// Next report time
			report = now.Add(period)
		}

		// See if there's any downstream data to forward.
		var dbuf []byte
		select {
		case dbuf = <-downstream: // some data to forward downstream
			//fmt.Printf("v %d\n", len(dbuf)-6)
		default:		// nothing at the moment to forward
			dbuf = nulldown[:]
		}
		if len(dbuf) < 6 {
			panic("wrong dbuf length")
		}

		// Broadcast the downstream data to all clients.
		for i := 0; i < nclients; i++ {
			//fmt.Printf("client %d -> %d downstream bytes\n",
			//		i, len(dbuf)-6)
			n,err := csock[i].Write(dbuf)
			if n < len(dbuf) {
				panic("Write to client: "+err.Error())
			}
		}
		totdownbytes += int64(len(dbuf)-6)

		inflight++
		if inflight < window {
			continue	// Get more cells in flight
		}

		me.Coder.DecodeStart(payloadlen, me.Histoream)

		// Collect a cell ciphertext from each trustee
		for i := 0; i < ntrustees; i++ {
			n,err := io.ReadFull(tsock[i], tslice[i])
			if n < trusize {
				panic("Read from client: "+err.Error())
			}
			//println("trustee slice")
			//println(hex.Dump(tslice[i]))
			me.Coder.DecodeTrustee(tslice[i])
		}

		// Collect an upstream ciphertext from each client
		for i := 0; i < nclients; i++ {
			n,err := io.ReadFull(csock[i], cslice[i])
			if n < clisize {
				panic("Read from client: "+err.Error())
			}
			//println("client slice")
			//println(hex.Dump(cslice[i]))
			me.Coder.DecodeClient(cslice[i])
		}

		outb := me.Coder.DecodeCell()
		totcells++
		totupbytes += int64(payloadlen)
		inflight--

		// Process the decoded cell
		if outb == nil {
			continue	// empty or corrupt upstream cell
		}
		if len(outb) != payloadlen {
			panic("DecodeCell produced wrong-size payload")
		}

		// Decode the upstream cell header (may be empty, all zeros)
		cno := int(binary.BigEndian.Uint32(outb[0:4]))
		dlen := int(binary.BigEndian.Uint16(outb[4:6]))
		//fmt.Printf("^ %d (conn %d)\n", dlen, cno)
		if cno == 0 {
			continue	// no upstream data
		}
		conn := conns[cno]
		if conn == nil {	// new connection to our http proxy
			conn,err = net.Dial("tcp", "localhost:8888")
			if err != nil {
				panic("error dialing proxy: "+err.Error())
			}
			conns[cno] = conn
			go relayReadConn(cno, conn, downstream)
		}
		if dlen == 0 {		// connection close indicator
			fmt.Printf("closing stream %d\n", cno)
			conn.Close()
			continue
		}
		if 6+dlen > payloadlen {
			panic("upstream cell invalid length")
		}
		//println(hex.Dump(outb[6:6+dlen]))
		n,err := conn.Write(outb[6:6+dlen])
		if n < dlen {
			fmt.Printf("upstream write error: "+err.Error())
			conn.Close()
			continue
		}
	}
}

func openRelay(ctno int) net.Conn {
	conn,err := net.Dial("tcp", relayhost)
	if err != nil {
		panic("Can't connect to relay:"+err.Error())
	}

	// Tell the relay our client or trustee number
	b := make([]byte,1)
	b[0] = byte(ctno)
	n,err := conn.Write(b)
	if n < 1 || err != nil {
		panic("Error writing to socket:"+err.Error())
	}

	return conn
}

func clientListen(newconn chan<- net.Conn) {
	lsock,err := net.Listen("tcp", ":8080")
	if err != nil {
		panic("Can't open HTTP listen socket:"+err.Error())
	}
	for {
		conn,err := lsock.Accept()
		if err != nil {
			panic("Client proxy listen error:"+err.Error())
		}
		newconn <- conn
	}
}

func clientConnRead(cno int, conn net.Conn, upload chan<- []byte,
		close chan<- int) {
	for {
		// Read up to a cell worth of data to send upstream
		buf := make([]byte, payloadlen)
		n,err := conn.Read(buf[proxyhdrlen:])

		// Encode the connection number and actual data length
		binary.BigEndian.PutUint32(buf[0:4], uint32(cno))
		binary.BigEndian.PutUint16(buf[4:6], uint16(n))

		// Send it upstream!
		upload <- buf
		//fmt.Printf("read %d bytes from client %d\n", n, cno)

		// Connection error or EOF?
		if n == 0 {
			if err == io.EOF {
				println("clientUpload: EOF, closing")
			} else {
				println("clientUpload error: "+err.Error())
			}
			conn.Close()
			close <- cno	// signal that channel is closed
			return
		}
	}
}

func clientReadRelay(rconn net.Conn, fromrelay chan<- connbuf) {
	hdr := [6]byte{}
	for {
		// Read the next downstream/broadcast cell from the relay
		n,err := io.ReadFull(rconn, hdr[:])
		if n != len(hdr) {
			panic("clientReadRelay: "+err.Error())
		}
		cno := int(binary.BigEndian.Uint32(hdr[0:4]))
		dlen := int(binary.BigEndian.Uint16(hdr[4:6]))
		//if cno != 0 || dlen != 0 {
		//	fmt.Printf("clientReadRelay: cno %d dlen %d\n",
		//			cno, dlen)
		//}

		// Read the downstream data itself
		buf := make([]byte, dlen)
		n,err = io.ReadFull(rconn, buf)
		if n != dlen {
			panic("clientReadRelay: "+err.Error())
		}

		// Pass the downstream cell to the main loop
		fromrelay <- connbuf{cno,buf}
	}
}

func startClient(clino int) {
	fmt.Printf("startClient %d\n", clino)

	tg := dcnet.TestSetup(suite, factory, nclients, ntrustees)
	me := tg.Clients[clino]
	clisize := me.Coder.ClientCellSize(payloadlen)

	rconn := openRelay(clino)
	fromrelay := make(chan connbuf)
	go clientReadRelay(rconn, fromrelay)
	println("client",clino,"connected")

	// We're the "slot owner" - start an HTTP proxy
	newconn := make(chan net.Conn)
	upload := make(chan []byte)
	close := make(chan int)
	conns := make([]net.Conn, 1)	// reserve conns[0]
	if clino == 0 {
		go clientListen(newconn)
	}

	// Client/proxy main loop
	upq := make([][]byte,0)
	for {
		select {
		case conn := <-newconn:		// New TCP connection
			cno := len(conns)
			conns = append(conns, conn)
			fmt.Printf("new conn %d %p %p\n", cno, conn, conns[cno])
			go clientConnRead(cno, conn, upload, close)

		case buf := <-upload:		// Upstream data from client
			upq = append(upq, buf)

		case cno := <-close:		// Connection closed
			conns[cno] = nil

		case cbuf := <-fromrelay:	// Downstream cell from relay
			//print(".")

			cno := cbuf.cno
			//if cno != 0 || len(cbuf.buf) != 0 {
			//	fmt.Printf("v %d (conn %d)\n",
			//			len(cbuf.buf), cno)
			//}
			if cno > 0 && cno < len(conns) && conns[cno] != nil {
				buf := cbuf.buf
				blen := len(buf)
				//println(hex.Dump(buf))
				if blen > 0 {
					// Data from relay for this connection
					n,err := conns[cno].Write(buf)
					if n < blen {
						panic("Write to client: " +
							err.Error())
					}
				} else {
					// Relay indicating EOF on this conn
					fmt.Printf("upstream closed conn %d",
							cno);
					conns[cno].Close()
				}
			}

			// XXX account for downstream cell in history

			// Produce and ship the next upstream cell
			var p []byte
			if len(upq) > 0 {
				p = upq[0]
				upq = upq[1:]
				//fmt.Printf("^ %d\n", len(p))
			}
			slice := me.Coder.ClientEncode(p, payloadlen,
							me.Histoream)
			//println("client slice")
			//println(hex.Dump(slice))
			if len(slice) != clisize {
				panic("client slice wrong size")
			}
			n,err := rconn.Write(slice)
			if n != len(slice) {
				panic("Write to relay conn: "+err.Error())
			}
		}
	}
}

func startTrustee(tno int) {
	tg := dcnet.TestSetup(suite, factory, nclients, ntrustees)
	me := tg.Trustees[tno]

	conn := openRelay(tno | 0x80)
	println("trustee",tno,"connected")

	// Just generate ciphertext cells and stream them to the server.
	for {
		// Produce a cell worth of trustee ciphertext
		tslice := me.Coder.TrusteeEncode(payloadlen)

		// Send it to the relay
		//println("trustee slice")
		//println(hex.Dump(tslice))
		n,err := conn.Write(tslice)
		if n < len(tslice) || err != nil {
			panic("can't write to socket: "+err.Error())
		}
	}
}

func main() {
	//testSuites()
	//benchSuites()
	//testDCNet()

	isrel := flag.Bool("relay", false, "Start relay node")
	iscli := flag.Int("client", -1, "Start client node")
	istru := flag.Int("trustee", -1, "Start trustee node")
	flag.Parse()

	if *isrel {
		startRelay()
	} else if *iscli >= 0 {
		startClient(*iscli)
	} else if *istru >= 0 {
		startTrustee(*istru)
	} else {
		panic("must specify -relay, -client=n, or -trustee=n")
	}
}

