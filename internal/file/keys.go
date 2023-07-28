package file

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"

	"github.com/edutko/what-is/internal/file/names"
)

func cryptoPublicKeyAttributes(k crypto.PublicKey) []Attribute {
	switch t := k.(type) {
	case *dsa.PublicKey:
		return dsaPublicKeyAttributes(*t)
	case dsa.PublicKey:
		return dsaPublicKeyAttributes(t)
	case *ecdh.PublicKey:
		return ecdhPublicKeyAttributes(*t)
	case ecdh.PublicKey:
		return ecdhPublicKeyAttributes(t)
	case *ecdsa.PublicKey:
		return ecdsaPublicKeyAttributes(*t)
	case ecdsa.PublicKey:
		return ecdsaPublicKeyAttributes(t)
	case ed25519.PublicKey:
		return ed25519PublicKeyAttributes(t)
	case *rsa.PublicKey:
		return rsaPublicKeyAttributes(*t)
	case rsa.PublicKey:
		return rsaPublicKeyAttributes(t)
	default:
		return nil
	}
}

func dsaPrivateKeyAttributes(k *dsa.PrivateKey) []Attribute {
	return dsaPublicKeyAttributes(k.PublicKey)
}

func dsaPublicKeyAttributes(k dsa.PublicKey) []Attribute {
	return []Attribute{
		{"Algorithm", "DSA"},
		{"Size", fmt.Sprintf("%d bits", k.P.BitLen())},
	}
}

func ecdhPrivateKeyAttributes(k *ecdh.PrivateKey) []Attribute {
	return ecdhPublicKeyAttributes(*k.PublicKey())
}

func ecdhPublicKeyAttributes(k ecdh.PublicKey) []Attribute {
	attrs := []Attribute{
		{"Algorithm", "ECDH"},
	}

	if c, ok := k.Curve().(fmt.Stringer); ok {
		attrs = append(attrs, Attribute{"Curve", names.Curve(c.String())})
	}

	return attrs
}

func ecdsaPrivateKeyAttributes(k *ecdsa.PrivateKey) []Attribute {
	return ecdsaPublicKeyAttributes(k.PublicKey)
}

func ecdsaPublicKeyAttributes(k ecdsa.PublicKey) []Attribute {
	return []Attribute{
		{"Algorithm", "ECDSA"},
		{"Curve", names.FromCurveParams(k.Curve.Params())},
	}
}

func ed25519PrivateKeyAttributes(k ed25519.PrivateKey) []Attribute {
	return ed25519PublicKeyAttributes(k.Public().(ed25519.PublicKey))
}

func ed25519PublicKeyAttributes(_ ed25519.PublicKey) []Attribute {
	return []Attribute{
		{"Algorithm", "EdDSA"},
		{"Curve", names.Curve("ed25519")},
	}
}

func rsaPrivateKeyAttributes(k *rsa.PrivateKey) []Attribute {
	return rsaPublicKeyAttributes(k.PublicKey)
}

func rsaPublicKeyAttributes(k rsa.PublicKey) []Attribute {
	return []Attribute{
		{"Algorithm", "RSA"},
		{"Size", fmt.Sprintf("%d bits", k.Size()*8)},
	}
}
