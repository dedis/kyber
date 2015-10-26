package padding

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"strconv"
	"testing"
)

func TestAESGCM(t *testing.T) {
	fmt.Println("Testing padding with AESGCM")
	//need to generate key.
	key, _ := hex.DecodeString("9a4fea86a621a91ab371e492457796c0")
	//initialize pt
	pt := []byte("The standard Lorem Ipsum passage, used since the 1500s Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. Section 1.10.32 of de Finibus Bonorum et Malorum, written by Cicero in 45 BC Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo. Nemo enim ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit, sed quia consequuntur magni dolores eos qui ratione voluptatem sequi nesciunt. Neque porro quisquam est, qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit, sed quia non numquam eius modi tempora incidunt ut labore et dolore magnam aliquam quaerat voluptatem. Ut enim ad minima veniam, quis nostrum exercitationem ullam corporis suscipit laboriosam, nisi ut aliquid ex ea commodi consequatur? Quis autem vel eum iure reprehenderit qui in ea voluptate velit esse quam nihil molestiae consequatur, vel illum qui dolorem eum fugiat quo voluptas nulla pariatur? 1914 translation by H. RackhamBut I must explain to you how all this mistaken idea of denouncing pleasure and praising pain was born and I will give you a complete account of the system, and expound the actual teachings of the great explorer of the truth, the master-builder of human happiness. No one rejects, dislikes, or avoids pleasure itself, because it is pleasure, but because those who do not know how to pursue pleasure rationally encounter consequences that are extremely painful. Nor again is there anyone who loves or pursues or desires to obtain pain of itself, because it is pain, but because occasionally circumstances occur in which toil and pain can procure him some great pleasure. To take a trivial example, which of us ever undertakes laborious physical exercise, except to obtain some advantage from it? But who has any right to find fault with a man who chooses to enjoy a pleasure that has no annoying consequences, or one who avoids a pain that produces no resultant pleasure?Section 1.10.33 of de Finibus Bonorum et Malorum, written by Cicero in 45 BCAt vero eos et accusamus et iusto odio dignissimos ducimus qui blanditiis praesentium voluptatum deleniti atque corrupti quos dolores et quas molestias excepturi sint occaecati cupiditate non provident, similique sunt in culpa qui officia deserunt mollitia animi, id est laborum et dolorum fuga. Et harum quidem rerum facilis est et expedita distinctio. Nam libero tempore, cum soluta nobis est eligendi optio cumque nihil impedit quo minus id quod maxime placeafa")
	//Apparently there is a limit to how large
	pt = append(pt, []byte("ere possimus, omnis voluptas assumenda est, omnis dolor repellendus. Temporibus autem quibusdam et aut officiis debitis aut rerum necessitatibus saepe eveniet ut et voluptates repudiandae sint et molestiae non recusandae. Itaque earum rerum hic tenetur a sapiente delectus, ut aut reiciendis voluptatibus maiores alias consequatur aut perferendis doloribus asperiores repellat.1914 translation by H. RackhamOn the other hand, we denounce with righteous indignation and dislike men who are so beguiled and demoralized by the charms of pleasure of the moment, so blinded by desire, that they cannot foresee the pain and trouble that are bound to ensue; and equal blame belongs to those who fail in their duty through weakness of will, which is the same as saying through shrinking from toil and pain. These cases are perfectly simple and easy to distinguish. In a free hour, when our power of choice is untrammelled and when nothing prevents our being able to do what we like best, every pleasure is to be welcomed and every pain avoided. But in certain circumstances and owing to the claims of duty or the obligations of business it will frequently occur that pleasures have to be repudiated and annoyances accepted. The wise man therefore always holds in these matters to this principle of selection: he rejects pleasures to secure other greater pleasures, or else he endures pains to avoid worse pains.")...)
	//We can add change the size of the message by doubling this part before adding the contest of testmessage.txt, which is a bunch of text from random webpages, and project gutenberg books, that has been copy and pasted somewhat randomly to increase the size.
	pt = append(pt, pt...)
	pt = append(pt, pt...)
	//Add to  our pt from a file to make it easier to test if it works for large files.
	dat, err := ioutil.ReadFile("testmessage.txt")
	if err != nil {
		fmt.Println(err)

	}
	pt = append(pt, dat...)
	ad := []byte("1234567890123456123123123123123123")
	//nonce by default needs to be 12 bytes
	nonce := []byte("123456781238")

	aes, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}
	aesgcm, err := cipher.NewGCMWithNonceSize(aes, len(nonce))
	if err != nil {
		fmt.Println(err)
	}
	//aesgcm adds 16 bytes to the end of the encrpyted message. These 16 bytes are the authentication tag.
	//And an additional 8 bytes for the overhead of how we are padding it.
	x := GetLeakBits(len(pt), 16+8)
	y := GetMsgBits(len(pt), 16+8)
	z := GetZeroBits(len(pt), 16+8)
	p := GetPaddingLen(len(pt), 16+8)
	fmt.Println("Msg w/ static overhead: ", len(pt)+16+8, " Bits to store len: ",
		y, " Leak Bits: ", x, " ZeroBits: ", z)

	fmt.Println("Padding needed: ", p)
	fmt.Printf("Increase in message size caused by the padding (padding+len+oh)/len: %.4f\n", ((float64(p+24) + float64(len(pt))) / float64(len(pt))))

	pt1 := pt
	//PadGeneric takes in a pt, and the overhead that encryption scheme will add. It returns a p' with the format [Amount of padding(8 bytes)][original pt][padding]

	pt = PadGeneric(pt, 16)
	//fmt.Println(pt)
	//Encrypt the plaintext with aesgcm
	ct := aesgcm.Seal(nil, nonce, pt, ad)
	//check if our ct is correctly padded
	if CheckZeroBits(len(ct)) {
		fmt.Println("The ciphertext is of a correct length")
		fmt.Println("Length is ", len(ct))
		fmt.Println(strconv.FormatUint(uint64(len(ct)), 2))
		fmt.Println("Length of original pt: ", len(pt1))
		fmt.Println(strconv.FormatUint(uint64(len(pt1)), 2))

	} else {
		fmt.Println("Error: ciphertext was not correctly padded.")
	}
	//decrypt the ct
	pt, _ = aesgcm.Open(nil, nonce, ct, ad)
	//unpad the pt
	pt = UnPadGeneric(pt)
	//check if the message was recovered correctly.
	if bytes.Equal(pt, pt1) {
		fmt.Println("The message was decrypted, and unpadded successfully ")
	}
}
