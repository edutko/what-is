package file

import (
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
)

func dsaPrivateKeyAttributes(k *dsa.PrivateKey) map[string]string {
	return map[string]string{
		"Algorithm": "DSA",
		"Size":      fmt.Sprintf("%d bits", k.P.BitLen()),
	}
}

func ecdhPrivateKeyAttributes(k *ecdh.PrivateKey) map[string]string {
	attrs := map[string]string{
		"Algorithm": "ECDH",
	}

	if c, ok := k.Curve().(fmt.Stringer); ok {
		attrs["Curve"] = c.String()
	}

	return attrs
}

func ecdsaPrivateKeyAttributes(k *ecdsa.PrivateKey) map[string]string {
	return map[string]string{
		"Algorithm": "ECDSA",
		"Curve":     k.Curve.Params().Name,
	}
}

func ed25519PrivateKeyAttributes(_ ed25519.PrivateKey) map[string]string {
	return map[string]string{
		"Algorithm": "Ed25519",
		"Curve":     "Curve25519",
	}
}

func rsaPrivateKeyAttributes(k *rsa.PrivateKey) map[string]string {
	return map[string]string{
		"Algorithm": "RSA",
		"Size":      fmt.Sprintf("%d bits", k.Size()*8),
	}
}
