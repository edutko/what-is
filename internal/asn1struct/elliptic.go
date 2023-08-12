package asn1struct

import (
	"encoding/asn1"
	"math/big"
)

type ECPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	Params        ECParameters          `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

type ECParameters struct {
	Version  int
	FieldId  FieldId
	Curve    ECCurve
	Base     FieldElement
	Order    *big.Int
	Cofactor int                   `asn1:"optional"`
	Hash     asn1.ObjectIdentifier `asn1:"optional"`
}

type FieldId struct {
	FieldType  asn1.ObjectIdentifier
	Parameters asn1.RawValue
}

type ECCurve struct {
	A    FieldElement
	B    FieldElement
	Seed asn1.BitString `asn1:"optional"`
}

type FieldElement []byte
