package file

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/edutko/decipher/internal/asn1struct"
	"github.com/edutko/decipher/internal/crypto/elliptic"
	"github.com/edutko/decipher/internal/names"
	"github.com/edutko/decipher/internal/oid"
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
		return ed25519PublicKeyAttributes()
	case *rsa.PublicKey:
		return rsaPublicKeyAttributes(*t)
	case rsa.PublicKey:
		return rsaPublicKeyAttributes(t)
	default:
		return nil
	}
}

func pkixPublicKeyAttributes(k asn1struct.PKIXPublicKey) []Attribute {
	var attrs []Attribute

	switch {
	case k.Algorithm.Algorithm.Equal(oid.DSA):
		attrs = append(attrs, Attribute{"Algorithm", names.DSA})
		var p asn1struct.DSAParameters
		_, err := asn1.Unmarshal(k.Algorithm.Parameters.FullBytes, &p)
		if err == nil {
			attrs = append(attrs, dsaParameterAttributes(p)...)
		}

	case k.Algorithm.Algorithm.Equal(oid.RSAEncryption):
		var pk asn1struct.PKCS1PublicKey
		_, err := asn1.Unmarshal(k.PublicKey.Bytes, &pk)
		if err == nil {
			attrs = append(attrs, pkcs1PublicKeyAttributes(pk)...)
		}

	case k.Algorithm.Algorithm.Equal(oid.ECPublicKey):
		attrs = append(attrs, Attribute{"Algorithm", names.ECDSA})
		i, err := parseECParameters(k.Algorithm.Parameters.FullBytes)
		if err == nil {
			attrs = append(attrs, i.Attributes...)
		}

	case k.Algorithm.Algorithm.Equal(oid.Ed25519):
		attrs = ed25519PublicKeyAttributes()
	case k.Algorithm.Algorithm.Equal(oid.Ed448):
		attrs = ed448PublicKeyAttributes()
	case k.Algorithm.Algorithm.Equal(oid.X25519):
		attrs = x25519PublicKeyAttributes()
	case k.Algorithm.Algorithm.Equal(oid.X448):
		attrs = x448PublicKeyAttributes()
	}

	return attrs
}

func dsaPrivateKeyAttributes(k asn1struct.DSAPrivateKey) []Attribute {
	return []Attribute{
		{"Algorithm", names.DSA},
		{"Size", fmt.Sprintf("%d bits", k.P.BitLen())},
	}
}

func dsaPublicKeyAttributes(k dsa.PublicKey) []Attribute {
	return []Attribute{
		{"Algorithm", names.DSA},
		{"Size", fmt.Sprintf("%d bits", k.P.BitLen())},
	}
}

func dsaParameterAttributes(p asn1struct.DSAParameters) []Attribute {
	return []Attribute{
		{"Size", fmt.Sprintf("%d bits", p.P.BitLen())},
	}
}

func ecExplicitParameterAttributes(ecParams asn1struct.ECParameters) []Attribute {
	attrs := make([]Attribute, 0)

	attrs = append(attrs, Attribute{"Field type", names.FieldTypeFromOid(ecParams.FieldId.FieldType)})
	if ecParams.FieldId.FieldType.Equal(oid.PrimeField) {
		var prime *big.Int
		if _, err := asn1.Unmarshal(ecParams.FieldId.Parameters.FullBytes, &prime); err == nil {
			attrs = append(attrs, Attribute{"Prime size", fmt.Sprintf("%d bits", prime.BitLen())})
		}
	}
	if ecParams.FieldId.FieldType.Equal(oid.CharacteristicTwoField) {
		var field struct {
			FieldSize *big.Int
		}
		if _, err := asn1.Unmarshal(ecParams.FieldId.Parameters.FullBytes, &field); err == nil {
			attrs = append(attrs, Attribute{"Field size", fmt.Sprintf("2^%d", field.FieldSize)})
		}
	}

	if name := elliptic.CurveNameFromParameters(ecParams); name != "" {
		attrs = append(attrs, Attribute{Name: "Curve (inferred)", Value: name})
	}

	return attrs
}

func namedCurveAttributes(curveOid asn1.ObjectIdentifier) []Attribute {
	return []Attribute{
		{"Curve", names.CurveNameFromOID(curveOid)},
	}
}

func ecdhPublicKeyAttributes(k ecdh.PublicKey) []Attribute {
	attrs := []Attribute{
		{"Algorithm", names.ECDH},
	}

	if c, ok := k.Curve().(fmt.Stringer); ok {
		attrs = append(attrs, Attribute{"Curve", names.Curve(c.String())})
	}

	return attrs
}

func ecPrivateKeyAttributes(k asn1struct.ECPrivateKey) []Attribute {
	attrs := []Attribute{
		{"Algorithm", names.ECDSA},
	}

	if len(k.NamedCurveOID) > 0 {
		attrs = append(attrs, namedCurveAttributes(k.NamedCurveOID)...)
	} else {
		attrs = append(attrs, ecExplicitParameterAttributes(k.Params)...)
	}

	return attrs
}

func ecdsaPublicKeyAttributes(k ecdsa.PublicKey) []Attribute {
	return []Attribute{
		{"Algorithm", names.ECDSA},
		{"Curve", names.FromCurveParams(k.Curve.Params())},
	}
}

func ed25519PrivateKeyAttributes() []Attribute {
	return ed25519PublicKeyAttributes()
}

func ed25519PublicKeyAttributes() []Attribute {
	return []Attribute{
		{"Algorithm", names.EdDSA},
		{"Curve", names.Curve("Ed25519")},
	}
}

func x25519PrivateKeyAttributes() []Attribute {
	return x25519PublicKeyAttributes()
}

func x25519PublicKeyAttributes() []Attribute {
	return []Attribute{
		{"Algorithm", names.ECDH},
		{"Curve", names.Curve("X25519")},
	}
}

func ed448PrivateKeyAttributes() []Attribute {
	return ed448PublicKeyAttributes()
}

func ed448PublicKeyAttributes() []Attribute {
	return []Attribute{
		{"Algorithm", names.EdDSA},
		{"Curve", names.Curve("Ed448")},
	}
}

func x448PrivateKeyAttributes() []Attribute {
	return x448PublicKeyAttributes()
}

func x448PublicKeyAttributes() []Attribute {
	return []Attribute{
		{"Algorithm", names.ECDH},
		{"Curve", names.Curve("X448")},
	}
}

func pkcs1PrivateKeyAttributes(k asn1struct.PKCS1PrivateKey) []Attribute {
	return []Attribute{
		{"Algorithm", names.RSA},
		{"Size", fmt.Sprintf("%d bits", k.N.BitLen())},
	}
}

func pkcs1PublicKeyAttributes(k asn1struct.PKCS1PublicKey) []Attribute {
	return []Attribute{
		{"Algorithm", names.RSA},
		{"Size", fmt.Sprintf("%d bits", k.N.BitLen())},
	}
}

func rsaPublicKeyAttributes(k rsa.PublicKey) []Attribute {
	return []Attribute{
		{"Algorithm", names.RSA},
		{"Size", fmt.Sprintf("%d bits", k.Size()*8)},
	}
}
