package file

import (
	"encoding/pem"
	"strings"
)

var UnknownPEMData = Info{Description: "unknown PEM data"}

func parsePEMBlock(b *pem.Block) Info {
	switch strings.ToUpper(b.Type) {
	case "CERTIFICATE", "TRUSTED CERTIFICATE":
		if info, err := parseCertificate(b.Bytes); err != nil {
			return UnknownPEMData
		} else {
			return info
		}
	case "RSA PUBLIC KEY":
		if info, err := parsePKCS1PublicKey(b.Bytes); err != nil {
			return UnknownPEMData
		} else {
			return info
		}
	case "PUBLIC KEY":
		if info, err := parsePKIXPublicKey(b.Bytes); err != nil {
			return UnknownPEMData
		} else {
			return info
		}
	case "PRIVATE KEY":
		if info, err := parsePKCS8PrivateKey(b.Bytes); err != nil {
			return UnknownPEMData
		} else {
			return info
		}
	case "EC PRIVATE KEY":
		if info, err := parseECPrivateKey(b.Bytes); err != nil {
			return UnknownPEMData
		} else {
			return info
		}
	case "EC PARAMETERS":
		if info, err := parseECParameters(b.Bytes); err != nil {
			return UnknownPEMData
		} else {
			return info
		}
	case "RSA PRIVATE KEY":
		if info, err := parseRSAPrivateKey(b.Bytes); err != nil {
			return UnknownPEMData
		} else {
			return info
		}
	case "DSA PRIVATE KEY":
		if info, err := parseDSAPrivateKey(b.Bytes); err != nil {
			return UnknownPEMData
		} else {
			return info
		}
	case "OPENSSH PRIVATE KEY":
		if info, err := parseOpenSSHPrivateKey(b.Bytes); err != nil {
			return UnknownPEMData
		} else {
			return info
		}
	default:
		return UnknownPEMData
	}
}
