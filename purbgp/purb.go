// Package nego implements cryptographic negotiation
// and secret entrypoint finding.
package purb

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/cipher/aes"
	"sort"
	"strconv"
)

//Length each entrypoint is(for simplicity assuming all suites HideLen is the same.
const ENTRYLEN = 32

//How much the symkey+message start is
const DATALEN = 24

type Entry struct {
	Suite abstract.Suite // Ciphersuite this public key is drawn from
	//XXX TODO REMOVE: Temporary to make testing much easier
	PriKey abstract.Secret
	PubKey abstract.Point // Public key of this entrypoint's owner
	Data   []byte         // Entrypoint data decryptable by owner
}

func (e *Entry) String() string {
	return fmt.Sprintf("(%s)%p", e.Suite, e)
}

// A ciphersuite used in a negotiation header.
type suiteKey struct {

	// Ephemeral Diffie-Hellman key for all key-holders using this suite.
	// Should have a uniform representation, e.g., an Elligator point.
	dhpri abstract.Secret
	dhpub abstract.Point
	dhrep []byte
}

/*
func (s *suiteKey) fresh(suite abstract.Suite) {
	dhpri := entry.suite.Secret().Pick(rand)
	dhpub := entry.Suite.Point().Mul(nil, dhpri)
	dhrep := dhpub.UniformEncode()
	suites[suite] = suite{dhpri,dhpub}
}
*/

type suiteInfo struct {
	ste  abstract.Suite // ciphersuite
	tag  []uint32       // per-position pseudorandom tag
	pos  []int          // alternative point positions
	plen int            // length of each point in bytes
	max  int            // limit of highest point field

	// layout info
	//nodes []*node			// layout node for reserved positions
	lev int             // layout-chosen level for this suite
	pri abstract.Secret // ephemeral Diffie-Hellman private key
	pub []byte          // corresponding encoded public key
}

func (si *suiteInfo) String() string {
	return "Suite " + si.ste.String()
}

// Return the byte-range for a point at a given level.
func (si *suiteInfo) region(level int) (int, int) {
	lo := si.pos[level]
	hi := lo + si.plen
	return lo, hi
}

// Try to reserve a space for level i of this ciphersuite in the layout.
// If we can't due to a conflict, mark the existing node as conflicted,
// so its owner subsequently knows that it can't use that position either.
/*
func (si *suiteInfo) layout(w *Writer, i int) bool {
	var n node
	lo := si.pos[i]			// compute byte extent
	hi := lo + si.plen
	n.init(si, lo, hi, si.tag[i])	// create suitable node
	fmt.Printf("try insert %s:%d at %d-%d\n", si.ste.String(), i, lo, hi)
	return w.layout.reserve(si, lo, hi, si.tag[i])
}
*/

// A sortable list of suiteInfo objects.
type suiteList struct {
	s []*suiteInfo
}

func (s *suiteList) Len() int {
	return len(s.s)
}
func (s *suiteList) Less(i, j int) bool {
	return s.s[i].max < s.s[j].max
}
func (s *suiteList) Swap(i, j int) {
	s.s[i], s.s[j] = s.s[j], s.s[i]
}

// Writer produces a cryptographic negotiation header,
// which conceals a variable number of "entrypoints"
// within a variable-length binary blob of random-looking bits.
// Each entrypoint hidden in the blob is discoverable and usable only
// by the owner of a particular public key.
// Different public keys may be drawn from different ciphersuites,
// in any combination, without coordination between the ciphersuites.
//
// Each entrypoint contains a short fixed-length blob of encrypted data,
// which the owner of the entrypoint can decrypt and use
// to obtain keys and pointers to the "real" content.
// This "real" content is typically located after the negotiation header
// and encrypted with a symmetric key included in the entrypoint data,
// which can be (but doesn't have to be) shared by many or all entrypoints.
//
type Writer struct {
	suites  suiteList                     // Sorted list of ciphersuites used
	simap   map[abstract.Suite]*suiteInfo // suiteInfo for each Suite
	layout  skipLayout                    // Reservation map representing layout
	entries []Entry                       // Entrypoints defined by caller
	entofs  map[int]int                   // Map of entrypoints to header offsets
	maxLen  int                           // Client-specified maximum header length
	buf     []byte                        // Buffer in which to build message
	keys    map[abstract.Suite]suiteKey   // Holds the public/private key for each suite
}

//Function that will find, place and reserve part of the header for the data
//Hash possibly should not be data, but some sort of int value will possibly have
//to cast it at some point
//All hash tables start after pos 0.
//length might be standard and thus not needed to be passed in like this.
//len is the length stored will be the same for all
//no data is needed, this is just for allocating space in the header
//Second int is the end of the full hash table
func (w *Writer) PlaceHash(hash uint) (int, int) {
	//Basic setup is to check if the block directly after entry 0 is available
	//if it is then hash0[0]=data(would probably be encrypted)
	//if that fails double the hash table size and update its start location
	//check the next 3 as well.
	//this is known so
	//finding the value in the hash table is accomplished like:
	//check hashtable_0[hash], if that decrypts we are good.
	//check hashtable_1[hash], in case of conflicts, check hash+1, hash+2
	//also hashtable_1 starts directly after hashtable_0
	// and so on.
	// to build it we just need to find the first empty hash table
	//The length of each table entry
	entryLen := uint(DATALEN)
	//hash table size
	ts := uint(1)
	//hash table start
	start := uint(ENTRYLEN)

	//Simply checks if the hashtable 0 spot works
	//It seems that reserve returns true if it was able to reserve the region
	//Not sure what the string should be for reserving
	if w.layout.reserve(int(start), int(start+entryLen), true, "hash"+strconv.Itoa(int(ts))) {
		return int(start), int(start + entryLen)
	}

	for {
		//Now update the hash table size and start
		//start = current hash table start + number of entries in the table* the
		//length of each entry
		start = start + ts*entryLen
		//Double the number of entries in each hash table
		ts *= 2
		//Check if the hash works for this table
		for i := uint(0); i < 3; i++ {
			tHash := (hash + i) % ts
			if w.layout.reserve(int(start+tHash*entryLen), int(start+tHash*entryLen+entryLen), true, "hash"+strconv.Itoa(int(ts))) {
				return int(start + tHash*entryLen), int(start + ts*entryLen)
			}
		}
	}
	return -1, -1
}

// Set the optional maximum length for the negotiation header,
// affecting subsequent calls to Layout()
func (w *Writer) SetMaxLen(max int) {
	w.maxLen = max
}

// Initialize a Writer to produce one or more negotiation header
// containing a specified set of entrypoints,
// whose owners' public keys are drawn from a given set of ciphersuites.
//
// The caller must provide a map 'suiteLevel' with one key per ciphersuite,
// whose value is the maximum "level" in the header
// at which the ciphersuite's ephemeral Diffie-Hellman Point may be encoded.
// This maximum level must be standardized for each ciphersuite,
// and should be log2(maxsuites), where maxsuites is the maximum number
// of unique ciphersuites that are likely to exist when this suite is defined.
//
// The Data slices in all entrypoints must have been allocated
// and sized according to the data the caller wants to suppy each entrypoint,
// but the content of these Data slices need not be filled in yet.
//
// This function lays out the entrypoints in the negotiation header,
// and returns the total size of the negotiation headers
// that will be produced from this layout.
//
// After this initialization and layout computation,
// multiple independent negotiation headers with varying entrypoint data
// may be produced more efficiently via Write().
//
// XXX if multiple entrypoints are improperly passed for the same keyholder,
// bad things happen to security - we should harden the API against that.
//
func (w *Writer) Layout(suiteLevel map[abstract.Suite]int,
	entrypoints []Entry,
	rand cipher.Stream,
	suiteEntry map[abstract.Suite][]int) (int, error) {

	w.layout.reset()
	w.entries = entrypoints
	w.entofs = make(map[int]int)
	w.buf = nil

	// Determine the set of ciphersuites in use.
	/*
		suites := make(map[abstract.Suite]struct{})
		for i := range(entrypoints) {
			entry := entrypoints[i]
			if _,ok := suites[suite]; !ok {
				// First time we've seen this ciphersuite.
				suites[suite] = struct{}{}
			}
		}
	*/
	fmt.Println("Starting determine suite entrypoint")

	// Compute the alternative DH point positions for each ciphersuite,
	// and the maximum byte offset for each.
	w.suites.s = make([]*suiteInfo, 0, len(suiteLevel))
	max := 0
	simap := make(map[abstract.Suite]*suiteInfo)
	w.simap = simap
	for suite, _ := range suiteLevel {
		si := suiteInfo{}
		//Assumes suite entry is sorted(easily achieved if its not.
		si.pos = suiteEntry[suite]
		si.plen = suite.Point().(abstract.Hiding).HideLen() // XXX
		si.max = si.pos[len(si.pos)-1] + si.plen
		si.ste = suite
		//Not sure on plen
		if si.max > max {
			max = si.max
		}
		w.suites.s = append(w.suites.s, &si)
		simap[suite] = &si
	}
	nsuites := len(w.suites.s)
	if nsuites > 255 {
		// Our reservation calculation scheme currently can't handle
		// more than 255 ciphersuites.
		return 0, errors.New("too many ciphersuites")
	}
	//ws if w.maxLen !=0&& not sure why there was that
	if max > w.maxLen {
		w.maxLen = max
	}

	// Sort the ciphersuites in order of max position,
	// to give ciphersuites with most restrictive positioning
	// "first dibs" on the lowest positions.
	sort.Sort(&w.suites)

	fmt.Println("Ending determine suite entrypoint")
	// Create two reservation layouts:
	// - In w.layout only each ciphersuite's primary position is reserved.
	// - In exclude we reserve _all_ positions in each ciphersuite.
	// Since the ciphersuites' points will be computed in this same order,
	// each successive ciphersuite's primary position must not overlap
	// any point position for any ciphersuite previously computed,
	// but can overlap positions for ciphersuites to be computed later.
	var exclude skipLayout
	exclude.reset()
	hdrlen := 0
	for i := 0; i < nsuites; i++ {
		si := w.suites.s[i]
		//fmt.Printf("max %d: %s\n", si.max, si.ste.String())

		// Reserve all our possible positions in exclude layout,
		// picking the first non-conflicting position as our primary.
		lev := len(si.pos)
		for j := lev - 1; j >= 0; j-- {
			lo := si.pos[j]
			hi := lo + si.plen
			//fmt.Printf("reserving [%d-%d]\n", lo,hi)
			name := si.String()
			if exclude.reserve(lo, hi, false, name) && j == lev-1 {
				lev = j // no conflict, shift down
			}
		}
		fmt.Println("Middle of suite entry finding")
		if lev == len(si.pos) {
			return 0, errors.New("no viable position for suite" +
				si.ste.String())
		}
		si.lev = lev // lowest unconflicted, non-shadowed level

		// Permanently reserve the primary point position in w.layout
		lo, hi := si.region(lev)
		if hi > hdrlen {
			hdrlen = hi
		}
		name := si.String()
		//fmt.Printf("picked level %d at [%d-%d]\n", lev, lo,hi)
		if !w.layout.reserve(lo, hi, true, name) {
			panic("thought we had that position reserved??")
		}
	}

	fmt.Printf("Total hdrlen: %d\n", hdrlen)
	fmt.Printf("Point layout:\n")
	w.layout.dump()

	//Generate public/private keys for each suite
	keymap := make(map[abstract.Suite]suiteKey)
	w.keys = keymap
	for suite := range simap {
		s := new(suiteKey)
		var priv abstract.Secret
		var pub abstract.Point
		var dhrep []byte
		for i := 0; i != 1; {
			//Doesn't work because suite isn't a real suite?
			priv = suite.Secret().Pick(rand)
			pub = suite.Point().Mul(nil, priv)
			//XXX TODO how do you uniform encode with points?
			dhrep = pub.(abstract.Hiding).HideEncode(rand)
			if dhrep != nil {
				i = 1
			}
		}
		s.dhpri = priv
		s.dhpub = pub
		s.dhrep = dhrep
		w.keys[suite] = suiteKey{priv, pub, dhrep}
	}
	fmt.Println("After key gen")

	//This will be done with a hash table sort of thing.
	// Now layout the entrypoints.
	for i := range entrypoints {
		e := &entrypoints[i]
		si := simap[e.Suite]
		if si == nil {
			panic("suite " + e.Suite.String() + " wasn't on the list")
		}
		l := len(e.Data)
		if l == 0 {
			panic("entrypoint with no data")
		}
		//As it needs to be the same for decryption it will be a hash scheme.
		//Need to generate private keys possibly
		hash := e.Suite.Point().Mul(e.PubKey, w.keys[e.Suite].dhpri) //Probably will need to be DH key
		//Some way to get the hash value from a Point
		//TODO This doesn't always work, some points aren't able to be hide encoded
		fmt.Println("before hide")
		temp := hash.(abstract.Hiding).HideEncode(rand)

		fmt.Println("after hide")
		//In case Hide fails just set it to 0, client knows to do the same.
		//This leads to too large header size though.
		if nil == temp {
			temp = append(temp, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
		}
		intHash := uint(binary.BigEndian.Uint64(temp))
		//probably is a better way:

		ofs, tableEnd := w.PlaceHash(intHash)
		if ofs < 0 {
			fmt.Println("Could not find hash")
		}
		w.entofs[i] = ofs
		if tableEnd > hdrlen {
			hdrlen = tableEnd
		}
		//fmt.Printf("Entrypoint %d (%s) at [%d-%d]\n",
		//	i, si.String(), ofs, ofs+l)
	}
	if w.maxLen > hdrlen {
		hdrlen = w.maxLen
	}
	//not entierly sure why +1 works, but it does(need to make sure the hdr is long enough
	//And it is the correct offset for the appended ciphertext
	w.layout.reserve(hdrlen, hdrlen+1, false, "tablesize")

	fmt.Printf("Point+Entry layout:\n")
	w.layout.dump()

	return hdrlen, nil
}

// Grow the message buffer to include the region from lo to hi,
// and return a slice representing that region.
func (w *Writer) growBuf(lo, hi int) []byte {
	if len(w.buf) < hi {
		b := make([]byte, hi)
		copy(b, w.buf)
		w.buf = b
	}
	return w.buf[lo:hi]
}

// After Layout() has been called to layout the header,
// the client may call Payload() any number of times
// to reserve regions for encrypted payloads in the message.
// Returns the byte offset in the message where the payload was placed.
//
// Although the client could as well encrypt the data before calling Payload(),
// we take a cleartext and a cipher.Stream to "make sure" it gets encrypted.
// (Callers who really want to do their own encryption can pass in
// a no-op cipher.Stream, but this isn't recommended.)
func (w *Writer) Payload(data []byte, encrypt cipher.Stream) int {
	l := len(data)
	if l == 0 {
		panic("zero-length payload not allowed")
	}

	// Allocate space for the payload
	lo := w.layout.alloc(l, "payload")
	hi := lo + l

	// Expand the message buffer capacity as needed
	buf := w.growBuf(lo, hi)

	// Encrypt and copy in the payload.
	encrypt.XORKeyStream(buf, data)

	return lo
}

// Finalize and encrypt the negotiation message.
// The data slices in all the entrypoints must be filled in
// before calling this function.
func (w *Writer) Write(rand cipher.Stream) []byte {

	// Pick an ephemeral secret for each ciphersuite
	// that produces a hide-encodable Diffie-Hellman public key.
	for i := range w.suites.s {
		si := w.suites.s[i]

		/*
			// Create a hiding-encoded DH public key.
			pri := si.ste.Secret()
			pub := si.ste.Point()
			var buf []byte
			for {
				pri.Pick(rand)    // pick fresh secret
				pub.Mul(nil, pri) // get DH public key
				buf = pub.(abstract.Hiding).HideEncode(rand)
				if buf != nil {
					break
				}
			}*/
		if len(w.keys[si.ste].dhrep) != si.plen {
			panic("ciphersuite " + si.String() + " wrong pubkey length")
		}
		si.pri = w.keys[si.ste].dhpri
		si.pub = w.keys[si.ste].dhrep

		// Insert the hidden point into the message buffer.
		lo, hi := si.region(si.lev)
		msgbuf := w.growBuf(lo, hi)
		copy(msgbuf, si.pub)
	}
	fmt.Println("After setting primary entrypoint")

	// Encrypt and finalize all the entrypoints.
	for i := range w.entries {
		e := &w.entries[i]
		si := w.simap[e.Suite]
		lo := w.entofs[i]
		hi := lo + len(e.Data)

		// Form the shared secret with this keyholder.
		dhkey := si.ste.Point().Mul(e.PubKey, si.pri)

		// Encrypt the entrypoint data with it.
		buf, _ := dhkey.MarshalBinary()
		stream := si.ste.Cipher(buf)
		msgbuf := w.growBuf(lo, hi)
		stream.XORKeyStream(msgbuf, e.Data)

	}
	fmt.Println("After finalizing entrypoints")

	// Fill all unused parts of the message with random bits.
	msglen := len(w.buf) // XXX
	w.layout.scanFree(func(lo, hi int) {
		msgbuf := w.growBuf(lo, hi)
		rand.XORKeyStream(msgbuf, msgbuf)
	}, msglen)
	fmt.Println("AFter filling unused parts of message")

	// Finally, XOR-encode all the hidden Diffie-Hellman public keys.
	for i := range w.suites.s {
		si := w.suites.s[i]
		plen := si.plen

		// Copy the hide-encoded public key into the primary position.
		plo, phi := si.region(si.lev)
		pbuf := w.growBuf(plo, phi)
		copy(pbuf, si.pub)

		// XOR all the non-primary point positions into it.
		for j := range si.pos {
			if j != si.lev {
				lo, hi := si.region(j)
				buf := w.buf[lo:hi] // had better exist
				for k := 0; k < plen; k++ {
					pbuf[k] ^= buf[k]
				}
			}
		}
	}
	fmt.Println("after xor encoding entry points")

	return w.buf
}

//First step to decrypt is to xor all possible entry points for the suite
func attemptDecode(suite abstract.Suite, priv abstract.Secret,
	entries map[abstract.Suite][]int, file []byte, rand cipher.Stream) (int, []byte) {
	//make sure suite has entry points
	entPoints := entries[suite]
	if entPoints == nil {
		fmt.Println("We do not know about", suite)
		return 0, nil
	}
	dhpub := make([]byte, ENTRYLEN)
	for i := range entPoints {
		k := entPoints[i]
		temp := file[k : k+ENTRYLEN]
		for j := range temp {
			dhpub[j] ^= temp[j]
		}
	}
	//Now that we have the key for our suite calculate the shared key
	pub := suite.Point()
	pub.(abstract.Hiding).HideDecode(dhpub)
	shared := suite.Point().Mul(pub, priv)
	//Now we have to try and decrypt the message
	//We must go through all possible hash values
	temp := shared.(abstract.Hiding).HideEncode(rand)

	//In case Hide fails just set it to 0, client knows to do the same.
	//This leads to too large header size though.
	if nil == temp {
		temp = append(temp, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	}
	intHash := uint(binary.BigEndian.Uint64(temp))
	ts := uint(1)
	start := uint(ENTRYLEN)
	dLen := uint(DATALEN)
	for start+ts*uint(dLen) <= uint(len(file)) {
		//try to decrypt hashtable[i]->i+3
		//could be sped up slightly for case ts is 1 or 2
		for i := uint(0); i < 3; i++ {
			tHash := (intHash + i) % ts
			data := file[start+tHash*dLen : start+tHash*dLen+dLen]
			//Try to decrypt data.
			buf, _ := shared.MarshalBinary()
			stream := suite.Cipher(buf)
			decrypted := make([]byte, 24)
			stream.XORKeyStream(decrypted, data)
			//fmt.Println(decrypted)
			msgStart := binary.BigEndian.Uint64(decrypted[0:8])
			if msgStart > uint64(len(file)) {
				//fmt.Println(msgStart)
				continue
			}
			key := decrypted[8:24]
			//Try to decrypt
			dec := make([]byte, 0)
			cipher := abstract.Cipher(aes.NewCipher128(key))
			dec, err := cipher.Open(dec, file[msgStart:len(file)])
			if err == nil {

				//Some way to determine if the message is actually english
				if string(dec[8:12]) == "This" || (string(dec[0:4]) == "This") {
					return 0, dec
				}
			}

		}
		start += ts * dLen
		ts *= 2

	}
	return 0, nil
}
