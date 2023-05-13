package file

import (
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
)

func dsaPrivateKeyAttributes(k *dsa.PrivateKey) []Attribute {
	return []Attribute{
		{"Algorithm", "DSA"},
		{"Size", fmt.Sprintf("%d bits", k.P.BitLen())},
	}
}

func ecdhPrivateKeyAttributes(k *ecdh.PrivateKey) []Attribute {
	attrs := []Attribute{
		{"Algorithm", "ECDH"},
	}

	if c, ok := k.Curve().(fmt.Stringer); ok {
		attrs = append(attrs, Attribute{"Curve", c.String()})
	}

	return attrs
}

func ecdsaPrivateKeyAttributes(k *ecdsa.PrivateKey) []Attribute {
	return []Attribute{
		{"Algorithm", "ECDSA"},
		{"Curve", k.Curve.Params().Name},
	}
}

func ed25519PrivateKeyAttributes(_ ed25519.PrivateKey) []Attribute {
	return []Attribute{
		{"Algorithm", "Ed25519"},
		{"Curve", "Curve25519"},
	}
}

func rsaPrivateKeyAttributes(k *rsa.PrivateKey) []Attribute {
	return []Attribute{
		{"Algorithm", "RSA"},
		{"Size", fmt.Sprintf("%d bits", k.Size()*8)},
	}
}
