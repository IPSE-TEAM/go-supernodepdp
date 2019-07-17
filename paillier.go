package go_supernodepdp

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

var one = big.NewInt(1)

// PublicKey represents the public part of a Pallier key.
type PublicKey struct {
	N	*big.Int // modulus
	G	*big.Int // n+1,since p and q are same length
	NSquared *big.Int
}

// PrivateKey represents a Paillier key.
type PrivateKey struct {
	PublicKey
	p	*big.Int
	pp 	*big.Int			// p*p
	pminusone	*big.Int	// p-1
	q	*big.Int
	qq  *big.Int			// q*q
	qminusone	*big.Int	// q-1
	pinvq	*big.Int		// pinvq 是 p相对q的模逆  pinvq和p满足 pinvq * p % q 三 1
	hp	*big.Int			//
	hq 	*big.Int			//
	n  	*big.Int			// p*q
}

// ErrMessageTooLong is returned when the program to encrypt a message
// which is too large for the size of the public key.
var ErrMessageTooLong = errors.New("pailler: message too long for Paillier public key size")

// GenerateKey: generates an Paillier keypair of the given bit size using
// the random source random.
func GenerateKey(random io.Reader,bits int) (*PrivateKey,error) {
	// First,begin generate of p in the background.
	var p *big.Int
	var errChan = make(chan error,1)
	go func() {
		var err error
		p,err = rand.Prime(random,bits/2)
		errChan <- err
	}()

	// Now,find a prime q in the foreground.
	q,err := rand.Prime(random,bits/2)
	if err != nil{
		return nil,err
	}

	// Wait for generate of p to complete successfully.
	if err := <-errChan; err != nil{
		return nil,err
	}

	n := new(big.Int).Mul(p,q)
	pp := new(big.Int).Mul(p,p)
	qq := new(big.Int).Mul(q,q)

	return &PrivateKey{
		PublicKey:	PublicKey{
			N:	n,
			NSquared:	new(big.Int).Mul(n,n),
			G:	new(big.Int).Add(n,one), // g = n+1
		},
		p:	p,
		pp:	pp,
		pminusone:	new(big.Int).Sub(p,one),
		q:	q,
		qq:	qq,
		qminusone: 	new(big.Int).Sub(q,one),
		pinvq:	new(big.Int).ModInverse(p,q),  	// p相对q的模逆  pinvq和p满足 pinvq*p % q 三 1
		hp: 	h(p,pp,n),
		hq: 	h(q,qq,n),						// 理解成模n，q的同态标签
		n: 	n,
	},nil
}


func h(p *big.Int,pp *big.Int,n *big.Int) *big.Int {
	greatCommonDivisor_p := new(big.Int).Mod(new(big.Int).Sub(one,n),pp)  	// greatCommonDivisor(n-1,pp)
	lp := leastCommonMultiple(greatCommonDivisor_p,p)						// lcm(gp-1,p)
	hp := new(big.Int).ModInverse(lp,p)										// lp相对p的模逆  hp和lp满足  hp*lp % p 三 1
	return hp
}

func leastCommonMultiple(u *big.Int,n *big.Int) *big.Int {
	return new(big.Int).Div(new(big.Int).Sub(u,one), n)	// (u-1)/n
}

// Encrypt function encrypts a plain text represented as a byte array.
// The passed plain text MUST NOT be larger than the modulus of the
// passed public key.
func Encrypt(pubKey *PublicKey,plainText []byte) ([]byte,error) {
	c,_,err := EncryptAndNonece(pubKey,plainText)
	return c,err
}

// EncryptAndNonce function encrypts a plain text represented as a byte array,
// and in addition,returns the nonce used during encryption. The passed plain
// text MUST NOT be larger than the modulus of the passed public key.
func EncryptAndNonece(pubKey *PublicKey,plainText []byte) ([]byte, *big.Int,error) {
	r,err := rand.Int(rand.Reader,pubKey.N)
	if err != nil{
		return nil,nil,err
	}
	ciphertext,err := EncryptWithNonce(pubKey,r,plainText)
	if err != nil {
		return nil,nil,err
	}
	return ciphertext.Bytes(),r,nil
}

// EncryptWithNonce function encrypts a plain text represented as a byte array using
// the provided nonce to perforce encryption. The passed plain text MUST NOT be larger
// than the modulus of the passed public key.
func EncryptWithNonce(pubKey *PublicKey,r *big.Int, plainText []byte) (*big.Int,error) {
	m := new(big.Int).SetBytes(plainText)
	if pubKey.N.Cmp(m) < 1 {  // N < m
		return nil,ErrMessageTooLong
	}

	// c = g^m * r^n mod n^2 = ((m*n+1) mod n^2) * r^n mod n^2
	n := pubKey.N
	ciphertext := new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Mod(new(big.Int).Add(one,new(big.Int).Mul(m,n)),pubKey.NSquared),
			new(big.Int).Exp(r,n,pubKey.NSquared),  // r^n mod n^2
			),
			pubKey.NSquared,
		)
	return ciphertext,nil
}

// Decrypt function decrypts the passed cipher text.
func Decrypt(privKey *PrivateKey,cipherText []byte) ([]byte,error){
	c := new(big.Int).SetBytes(cipherText)
	if privKey.NSquared.Cmp(c) < 1 { // c < n^2
		return nil,ErrMessageTooLong
	}
	cp := new(big.Int).Exp(c,privKey.pminusone,privKey.pp)	// c^privKey mod pp
	lp := leastCommonMultiple(cp,privKey.p)					// (cp-1)/p
	mp := new(big.Int).Mod(new(big.Int).Mul(lp,privKey.hp),privKey.p) // (lp*hp mod p) mod p
	cq := new(big.Int).Exp(c,privKey.qminusone,privKey.qq)	// c ^ (q-1) mod qq
	lq := leastCommonMultiple(cq,privKey.q)					// lcm(cq-1,q)
	mqq := new(big.Int).Mul(lq,privKey.hq)					// lq * hq
	mq := new(big.Int).Mod(mqq,privKey.q)					// mqq mod q
	m := crt(mp,mq,privKey)
	return m.Bytes(),nil
}

func crt(mp *big.Int,mq *big.Int,privKey *PrivateKey) *big.Int {
	u := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Sub(mq,mp),privKey.pinvq),privKey.q) // u = (mq-mp)*pinvq mod q
	m := new(big.Int).Add(mp,new(big.Int).Mul(u,privKey.p))		// m = mp + u * p
	return new(big.Int).Mod(m,privKey.n)
}

// AddCipher function homomorphically adds together two cipher texts.
// to do this we multipy the two cipher texts,upon decryption,the resulting
// plain text will be the sum of the corresponding plain texts.
func AddCipher(pubKey *PublicKey,cipher1,cipher2 []byte) []byte {
	x := new(big.Int).SetBytes(cipher1)
	y := new(big.Int).SetBytes(cipher2)
	return new(big.Int).Mod(new(big.Int).Mul(x,y),pubKey.NSquared).Bytes() // x*y mod n^2
}

// Add function homomorphically adds a passed constant to the encrypted integer (our cipher text).
// We do this by multiplying the constant with our ciphertext. Upon decryption,the resulting
// plain text will be the sum of the plaintext integer and the constant.
func Add(pubKey *PublicKey,cipher,constant []byte) []byte {
	c := new(big.Int).SetBytes(cipher)
	x := new(big.Int).SetBytes(constant)
	// return c*g^x mod n^2
	return new(big.Int).Mod(new(big.Int).Mul(c,new(big.Int).Exp(pubKey.G,x,pubKey.NSquared)),pubKey.NSquared).Bytes()
}

// Mul function homomorphically multiplies an encrypted integer (cipher text) by a constant.
// We do this by raising our cipher text to the power of the passed constant.
// Upon decryption,the resulting plain text will be the product of the plaintext integer and the constant.
func Mul(pubKey *PublicKey,cipher []byte,constant []byte) []byte {
	c := new(big.Int).SetBytes(cipher)
	x := new(big.Int).SetBytes(constant)
	return new(big.Int).Exp(c,x,pubKey.NSquared).Bytes() // c^x mod n^2
}