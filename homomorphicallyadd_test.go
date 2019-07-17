package go_supernodepdp

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

func TestAdd(t *testing.T) {
	// Generate a 128-bit private key.
	privKey,err := GenerateKey(rand.Reader,256)
	if err != nil{
		fmt.Println(err)
		return
	}
	//Encrypt the number "15"
	m15 := new(big.Int).SetInt64(15)
	fmt.Println("m15:",m15)
	c15,err := Encrypt(&privKey.PublicKey,m15.Bytes())
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("c15:",c15)
	fmt.Println("c15 to bigint:",new(big.Int).SetBytes(c15))
	fmt.Println("n^2:",privKey.NSquared)
	// Decrypt the number "15"
	d,err := Decrypt(privKey,c15)
	if err != nil{
		fmt.Println(err)
		return
	}
	plainText := new(big.Int).SetBytes(d)
	fmt.Println("Decrypted result of 15: ",plainText.String())

	// Encrypt the number "20"
	m20 := new(big.Int).SetInt64(20)
	c20,err := Encrypt(&privKey.PublicKey,m20.Bytes())
	if err != nil{
		fmt.Println(err)
		return
	}
	// Add the encrypted integers 15 and 20 together
	plusM15M20 := AddCipher(&privKey.PublicKey,c15,c20)
	decryptedAddition,err := Decrypt(privKey,plusM15M20)
	if err != nil{
		fmt.Println(err)
		return
	}
	fmt.Println("Result of 15+20 after decryption: ",new(big.Int).SetBytes(decryptedAddition).String())

}
