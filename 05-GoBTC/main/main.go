package main

import (
	"fmt"
	"gobtc"
)

func main() {
	// Generate Keys
	KeyPairs := gobtc.GenerateKeys()

	k := KeyPairs.GetPrivateKey()
	K := KeyPairs.GetPublicKey()

	// Get Private Keys
	fmt.Printf("Your private key (Decimal) is : %s\n", k.D.Text(10))
	fmt.Printf("Your private key (Hex) is : %s\n", k.H)

	// Get Public Keys
	fmt.Printf("Your public key (X,Y) is : (%s, %s)\n", K.Point.X, K.Point.Y)
	fmt.Printf("Your public key (Hex) is : %s\n", K.H)
}