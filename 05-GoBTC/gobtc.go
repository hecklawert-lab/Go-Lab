/**
 * @author  Hëck Lawert
 * @version 1.0.0, 27/02/21
 * GoBTC: A simple wallet for Bitcoin
 */

package gobtc

import(
	"math/big"
	"crypto/rand"
	"encoding/hex"
)

/******************************************************************************/
/* ECDSA Keypair Generation */
/******************************************************************************/

var secp256k1 EllipticCurve

func init() {
	/* secp256k1 elliptic curve parameters */
	secp256k1.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	secp256k1.A, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000000", 16)
	secp256k1.B, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000007", 16)
	secp256k1.G.X, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	secp256k1.G.Y, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	secp256k1.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	secp256k1.H, _ = new(big.Int).SetString("01", 16)
}

// PublicKey represents a Bitcoin public key.
type PublicKey struct {
	Point
	H string
}

// PrivateKey represents a Bitcoin private key.
type PrivateKey struct {
	D *big.Int
	H string
}

// KeyPair represents a Bitcoin Key Pair
type KeyPair struct {
	PrivateKey
	PublicKey
}

func randomData() []byte{
	buffer := make([]byte, 32)
	_, err := rand.Read(buffer)
	if err != nil {
			panic("Error when generating random data for private key")
	}
	return buffer
}

//NewPrivateKey generates a private bitcoin key
func newPrivateKey() (*PrivateKey){
	n := new(big.Int)
	n,_ = n.SetString(hexEncoder(randomData()), 16)
	key := &PrivateKey{
		D: n,
		H: hexEncoder(randomData()),
	}	
	return key
}

//NewPublicKey generate a public key from a private bitcoin key
func newPublicKey(k *big.Int) (*PublicKey){
	K := secp256k1.ScalarBaseMult(k)
	publicKey := PublicKey{
		Point: K,
		H: "04"+K.X.Text(16)+K.Y.Text(16),
	}
	return &publicKey
}

// GenerateKeys creates a pair of keys for Bitcoin
func GenerateKeys() (*KeyPair){
	privateKey := newPrivateKey()
	publicKey := newPublicKey(privateKey.D)
	keys := &KeyPair{
		PrivateKey: *privateKey,
		PublicKey: *publicKey,
	}
	return keys
}

// GetPrivateKey retrieves the private key
func (k PrivateKey) GetPrivateKey() *PrivateKey{
	return &k
}

// GetPublicKey retrieves the public key
func (K PublicKey) GetPublicKey() *PublicKey{
	return &K
}

/******************************************************************************/
/* Helpers */
/******************************************************************************/

func hexEncoder(buffer []byte) string{
	hexKey := hex.EncodeToString(buffer)
	return hexKey
}