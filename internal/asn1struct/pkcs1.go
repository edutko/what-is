package asn1struct

import "math/big"

type PKCS1PublicKey struct {
	N *big.Int
	E int
}

type PKCS1PrivateKey struct {
	Version int
	N       *big.Int
	E       int
	D       *big.Int
	P       *big.Int
	Q       *big.Int

	Dp   *big.Int `asn1:"optional"`
	Dq   *big.Int `asn1:"optional"`
	Qinv *big.Int `asn1:"optional"`

	AdditionalPrimes []PKCS1AdditionalRSAPrime `asn1:"optional,omitempty"`
}

type PKCS1AdditionalRSAPrime struct {
	Prime *big.Int
	Exp   *big.Int
	Coeff *big.Int
}
