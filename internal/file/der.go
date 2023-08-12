package file

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/edutko/what-is/internal/asn1struct"
	"github.com/edutko/what-is/internal/names"
	"github.com/edutko/what-is/internal/oid"
)

var UnknownASN1Data = Info{Description: "unknown ASN.1 data"}

func parseDERData(b []byte) Info {
	if info, err := parseCertificate(b); err == nil {
		return info
	} else if info, err := parsePKCS8PrivateKey(b); err == nil {
		return info
	} else if info, err := parsePKIXPublicKey(b); err == nil {
		return info
	} else if info, err := parsePKCS1PublicKey(b); err == nil {
		return info
	} else if info, err := parseECPrivateKey(b); err == nil {
		return info
	} else if info, err := parsePKCS1PrivateKey(b); err == nil {
		return info
	} else if info, err := parseDSAPrivateKey(b); err == nil {
		return info
	} else {
		return UnknownASN1Data
	}
}

func parseCertificate(der []byte) (Info, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return UnknownASN1Data, err
	}

	var pubKeyInfo asn1struct.PKIXPublicKey
	_, err = asn1.Unmarshal(c.RawSubjectPublicKeyInfo, &pubKeyInfo)
	if err != nil {
		return UnknownASN1Data, err
	}

	info := Info{
		Description: "x.509 certificate",
		Attributes: []Attribute{
			{"Serial", c.SerialNumber.String()},
			{"Subject", c.Subject.String()},
			{"Issuer", c.Issuer.String()},
			{"Expiration", c.NotAfter.Format("2006-01-02")},
			{"Signature algorithm", c.SignatureAlgorithm.String()},
		},
		Children: []Info{
			{
				Description: "Public key",
				Attributes:  pkixPublicKeyAttributes(pubKeyInfo),
			},
		},
	}

	return info, nil
}

func parsePKCS1PublicKey(der []byte) (Info, error) {
	info := Info{
		Description: "PKCS#1 public key",
	}

	var k asn1struct.PKCS1PublicKey
	_, err := asn1.Unmarshal(der, &k)
	if err != nil {
		return UnknownASN1Data, err
	}

	info.Attributes = pkcs1PublicKeyAttributes(k)

	return info, nil
}

func parsePKIXPublicKey(der []byte) (Info, error) {
	info := Info{
		Description: "PKIX public key",
	}

	var k asn1struct.PKIXPublicKey
	_, err := asn1.Unmarshal(der, &k)
	if err != nil {
		return UnknownASN1Data, err
	}

	info.Attributes = pkixPublicKeyAttributes(k)

	return info, nil
}

func parsePKCS8PrivateKey(der []byte) (Info, error) {
	info := Info{
		Description: "PKCS#8 private key",
	}

	var k asn1struct.PKCS8PrivateKey
	_, err := asn1.Unmarshal(der, &k)
	if err != nil {
		return UnknownASN1Data, err
	}

	switch {
	case k.Algorithm.Algorithm.Equal(oid.DSA):
		info.Attributes = []Attribute{{"Algorithm", names.DSA}}
		i, err := parseDSAParameters(k.Algorithm.Parameters.FullBytes)
		if err == nil {
			info.Attributes = append(info.Attributes, i.Attributes...)
		}
	case k.Algorithm.Algorithm.Equal(oid.RSAEncryption):
		i, err := parsePKCS1PrivateKey(k.PrivateKey)
		if err == nil {
			info.Attributes = i.Attributes
		}
	case k.Algorithm.Algorithm.Equal(oid.ECPublicKey):
		info.Attributes = []Attribute{{"Algorithm", names.ECDSA}}
		i, err := parseECParameters(k.Algorithm.Parameters.FullBytes)
		if err == nil {
			info.Attributes = append(info.Attributes, i.Attributes...)
		}
	case k.Algorithm.Algorithm.Equal(oid.Ed25519):
		info.Attributes = ed25519PrivateKeyAttributes()
	case k.Algorithm.Algorithm.Equal(oid.Ed448):
		info.Attributes = ed448PrivateKeyAttributes()
	case k.Algorithm.Algorithm.Equal(oid.X25519):
		info.Attributes = x25519PrivateKeyAttributes()
	case k.Algorithm.Algorithm.Equal(oid.X448):
		info.Attributes = x448PrivateKeyAttributes()
	}

	return info, nil
}

func parseDSAParameters(der []byte) (Info, error) {
	info := Info{
		Description: "DSA parameters",
	}

	type FieldElement []byte
	var p asn1struct.DSAParameters
	_, err := asn1.Unmarshal(der, &p)
	if err == nil {
		info.Attributes = dsaParameterAttributes(p)
		return info, nil
	}

	return UnknownASN1Data, err
}

// http://www.secg.org/sec1-v2.pdf
func parseECParameters(der []byte) (Info, error) {
	info := Info{
		Description: "EC parameters",
	}

	var curveOid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(der, &curveOid); err == nil {
		info.Attributes = namedCurveAttributes(curveOid)
		return info, nil
	}

	type FieldElement []byte
	var p asn1struct.ECParameters
	_, err := asn1.Unmarshal(der, &p)
	if err == nil {
		info.Attributes = ecExplicitParameterAttributes(p)
		return info, nil
	}

	return UnknownASN1Data, err
}

func parseECPrivateKey(der []byte) (Info, error) {
	info := Info{
		Description: "EC private key",
	}

	var k asn1struct.ECPrivateKey
	_, err := asn1.Unmarshal(der, &k)
	if err != nil {
		return UnknownASN1Data, err
	}

	info.Attributes = ecPrivateKeyAttributes(k)

	return info, nil
}

func parsePKCS1PrivateKey(der []byte) (Info, error) {
	info := Info{
		Description: "PKCS#1 private key",
	}

	var k asn1struct.PKCS1PrivateKey
	_, err := asn1.Unmarshal(der, &k)
	if err != nil {
		return UnknownASN1Data, err
	}

	info.Attributes = pkcs1PrivateKeyAttributes(k)

	return info, nil
}

func parseDSAPrivateKey(der []byte) (Info, error) {
	var k asn1struct.DSAPrivateKey
	_, err := asn1.Unmarshal(der, &k)
	if err != nil {
		return UnknownASN1Data, err
	}

	return Info{
		Description: "DSA private key",
		Attributes:  dsaPrivateKeyAttributes(k),
	}, nil
}

func parseOpenSSHPrivateKey(der []byte) (Info, error) {
	const magic = "openssh-key-v1\x00"
	if len(der) < len(magic) || string(der[:len(magic)]) != magic {
		return UnknownASN1Data, errors.New("ssh: invalid openssh private key format")
	}
	remaining := der[len(magic):]

	info := Info{
		Description: "OpenSSH private key",
	}

	var w struct {
		CipherName   string
		KdfName      string
		KdfOpts      []byte
		NumKeys      uint32
		PubKey       []byte
		PrivKeyBlock []byte
	}

	if err := ssh.Unmarshal(remaining, &w); err != nil {
		return info, err
	}
	if w.NumKeys != 1 {
		// We only support single key files, and so does OpenSSH.
		// https://github.com/openssh/openssh-portable/blob/4103a3ec7/sshkey.c#L4171
		return info, errors.New("ssh: multi-key files are not supported")
	}

	pk, err := ssh.ParsePublicKey(w.PubKey)
	if err != nil {
		return info, errors.New("ssh: malformed OpenSSH key")
	}
	info.Attributes = append(info.Attributes, sshPublicKeyAttributes(pk, "")...)

	if w.CipherName != "none" {
		info.Description = "OpenSSH private key (encrypted)"
		info.Attributes = append(info.Attributes,
			Attribute{"Cipher", w.CipherName},
			Attribute{"KDF", w.KdfName},
		)
		if _, rounds, err := parseKdfOptions(w.KdfOpts); err == nil {
			info.Attributes = append(info.Attributes, Attribute{"KDF rounds", fmt.Sprintf("%d", rounds)})
		}
	}

	return info, nil
}
