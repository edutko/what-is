package file

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"

	"golang.org/x/crypto/ssh"
)

var UnknownASN1Data = Info{Description: "unknown ASN.1 data"}

func parseDERData(b []byte) Info {
	if info, err := parseCertificate(b); err == nil {
		return info
	} else if info, err := parsePKCS1PublicKey(b); err == nil {
		return info
	} else if info, err := parsePKIXPublicKey(b); err == nil {
		return info
	} else if info, err := parsePKCS8PrivateKey(b); err == nil {
		return info
	} else if info, err := parseECPrivateKey(b); err == nil {
		return info
	} else if info, err := parseECParameters(b); err == nil {
		return info
	} else if info, err := parseRSAPrivateKey(b); err == nil {
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

	return Info{
		Description: "x.509 certificate",
		Attributes: []Attribute{
			{"Serial", c.SerialNumber.String()},
			{"Subject", c.Subject.String()},
			{"Issuer", c.Issuer.String()},
			{"Expiration", c.NotAfter.Format("2006-01-02")},
			{"Public key algorithm", c.PublicKeyAlgorithm.String()},
			{"Signature algorithm", c.SignatureAlgorithm.String()},
		},
	}, nil
}

func parsePKCS1PublicKey(der []byte) (Info, error) {
	info := Info{
		Description: "PKCS#1 public key",
	}

	k, err := x509.ParsePKCS1PublicKey(der)
	if err != nil {
		return UnknownASN1Data, err
	}

	info.Attributes = rsaPublicKeyAttributes(*k)

	return info, nil
}

func parsePKIXPublicKey(der []byte) (Info, error) {
	info := Info{
		Description: "PKIX public key",
	}

	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return UnknownASN1Data, err
	}

	if rk, ok := k.(*rsa.PublicKey); ok {
		info.Attributes = rsaPublicKeyAttributes(*rk)
	} else if eck, ok := k.(*ecdsa.PublicKey); ok {
		info.Attributes = ecdsaPublicKeyAttributes(*eck)
	} else if edk, ok := k.(ed25519.PublicKey); ok {
		info.Attributes = ed25519PublicKeyAttributes(edk)
	} else if dhk, ok := k.(*ecdh.PublicKey); ok {
		info.Attributes = ecdhPublicKeyAttributes(*dhk)
	}

	return info, nil
}

func parsePKCS8PrivateKey(der []byte) (Info, error) {
	info := Info{
		Description: "PKCS#8 private key",
	}

	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return UnknownASN1Data, err
	}

	if rk, ok := k.(*rsa.PrivateKey); ok {
		info.Attributes = rsaPrivateKeyAttributes(rk)
	} else if eck, ok := k.(*ecdsa.PrivateKey); ok {
		info.Attributes = ecdsaPrivateKeyAttributes(eck)
	} else if edk, ok := k.(ed25519.PrivateKey); ok {
		info.Attributes = ed25519PrivateKeyAttributes(edk)
	} else if dhk, ok := k.(*ecdh.PrivateKey); ok {
		info.Attributes = ecdhPrivateKeyAttributes(dhk)
	}

	return info, nil
}

func parseECParameters(der []byte) (Info, error) {
	info := Info{
		Description: "EC parameters",
	}

	var curveOid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(der, &curveOid); err == nil {
		info.Attributes = append(info.Attributes, Attribute{"Named curve", curveNameFromOID(curveOid)})
	}

	return info, nil
}

func parseECPrivateKey(der []byte) (Info, error) {
	k, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return UnknownASN1Data, err
	}

	return Info{
		Description: "EC private key",
		Attributes:  ecdsaPrivateKeyAttributes(k),
	}, nil
}

func parseRSAPrivateKey(der []byte) (Info, error) {
	k, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return UnknownASN1Data, err
	}

	return Info{
		Description: "PKCS#1 private key",
		Attributes:  rsaPrivateKeyAttributes(k),
	}, nil
}

func parseDSAPrivateKey(der []byte) (Info, error) {
	k, err := ssh.ParseDSAPrivateKey(der)
	if err != nil {
		return UnknownASN1Data, err
	}

	return Info{
		Description: "PKCS#1 private key",
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
		KdfOpts      string
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

	if w.CipherName != "none" {
		info.Description = "OpenSSH private key (encrypted)"
		info.Attributes = append(info.Attributes,
			Attribute{"Cipher", w.CipherName},
			Attribute{"KDF", w.KdfName},
			Attribute{"KDF options", w.KdfOpts},
		)
	}

	pk, err := ssh.ParsePublicKey(w.PubKey)
	if err != nil {
		if w.CipherName != "none" {
			return info, x509.IncorrectPasswordError
		}
		return info, errors.New("ssh: malformed OpenSSH key")
	}

	info.Attributes = append(info.Attributes, sshPublicKeyAttributes(pk, "")...)

	return info, nil
}
