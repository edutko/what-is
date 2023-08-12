package asn1struct

import (
	"encoding/asn1"
)

type PKIXPublicKey struct {
	Algorithm AlgorithmIdentifier
	PublicKey asn1.BitString
}

type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}
