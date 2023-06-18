package file

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/edutko/what-is/internal/openpgp/armor"
	"github.com/edutko/what-is/internal/openpgp/packet"
)

func readArmoredPGPData(b []byte) (*armor.Block, error) {
	r := bytes.NewReader(b)
	return armor.Decode(r)
}

var pubkeyAlgorithmNames = map[packet.PublicKeyAlgorithm]string{
	packet.PubKeyAlgoRSA:            "RSA",
	packet.PubKeyAlgoRSAEncryptOnly: "RSA (encrypt only)",
	packet.PubKeyAlgoRSASignOnly:    "RSA (sign only)",
	packet.PubKeyAlgoElGamal:        "ElGamal",
	packet.PubKeyAlgoDSA:            "DSA",
	packet.PubKeyAlgoECDH:           "ECDH",
	packet.PubKeyAlgoECDSA:          "ECDSA",
	packet.PubKeyAlgoEdDSA:          "EdDSA",
}

func keyFlagsToString(s *packet.Signature) string {
	flags := []string{}
	if s.FlagSign {
		flags = append(flags, "sign")
	}
	if s.FlagCertify {
		flags = append(flags, "certify")
	}
	if s.FlagEncryptCommunications {
		flags = append(flags, "encrypt communications")
	}
	if s.FlagEncryptStorage {
		flags = append(flags, "encrypt storage")
	}
	if s.FlagAuthentication {
		flags = append(flags, "authentication")
	}
	return strings.Join(flags, ", ")
}

func gpgPublicKeyAttributes(pk *packet.PublicKey) []Attribute {
	attrs := []Attribute{
		{"Key ID", pk.KeyIdString()},
		{"Fingerprint", strings.ToUpper(hex.EncodeToString(pk.Fingerprint[:]))},
		{"Algorithm", pubkeyAlgorithmNames[pk.PubKeyAlgo]},
	}
	switch t := pk.PublicKey.(type) {
	case *ecdsa.PublicKey:
		attrs = append(attrs, Attribute{"Curve", t.Curve.Params().Name})
	case ed25519.PublicKey:
		attrs = append(attrs, Attribute{"Curve", "Ed25519"})
	}
	l, err := pk.BitLength()
	if err == nil {
		attrs = append(attrs, Attribute{"Size", fmt.Sprintf("%d bits", l)})
	}
	return attrs
}

func gpgSignatureAttributes(s *packet.Signature, keyCreationTime time.Time) []Attribute {
	attrs := []Attribute{
		{"Usage", keyFlagsToString(s)},
		{"Created", s.CreationTime.Format("2006-01-02")},
	}
	if l := s.KeyLifetimeSecs; l != nil {
		exp := time.Duration(*l) * time.Second
		attrs = append(attrs, Attribute{"Expires", keyCreationTime.Add(exp).Format("2006-01-02")})
	} else {
		attrs = append(attrs, Attribute{"Expires", "never"})
	}
	return attrs
}
