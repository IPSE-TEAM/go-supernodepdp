package go_supernodepdp

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

func TestMul(t *testing.T){
	// Generate c
	privKey,err := GenerateKey(rand.Reader,128)
	if err != nil{
		fmt.Println(err)
		return
	}
	// Encrypt
	m15 := new(big.Int).SetInt64(15)
	c15,err := Encrypt(&privKey.PublicKey,m15.Bytes())
	if err != nil{
		fmt.Println(err)
		return
	}

	// Decrypt
	d,err := Decrypt(privKey,c15)
	if err != nil {
		fmt.Println(err)
		return
	}
	plainText := new(big.Int).SetBytes(d)
	fmt.Println("Decryption Result of input: ",plainText.String())


	mulEncryted15and20 := Mul(&privKey.PublicKey,c15,new(big.Int).SetInt64(20).Bytes())
	decryptedMul,err := Decrypt(privKey,mulEncryted15and20)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Result of mul after decryption: ",new(big.Int).SetBytes(decryptedMul).String())
}
