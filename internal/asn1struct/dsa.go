package asn1struct

import "math/big"

type DSAPublicKey struct {
	Version int
	P       *big.Int
	Q       *big.Int
	G       *big.Int
	Pub     *big.Int
}

type DSAPrivateKey struct {
	Version int
	P       *big.Int
	Q       *big.Int
	G       *big.Int
	Pub     *big.Int
	Priv    *big.Int
}

type DSAParameters struct {
	P *big.Int
	Q *big.Int
	G *big.Int
}
