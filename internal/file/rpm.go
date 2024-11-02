package file

import (
	"bytes"
	"fmt"

	"github.com/edutko/decipher/internal/openpgp/packet"
)

func rpmSignatureAttributes(sig []byte) []Attribute {
	var attrs []Attribute
	p, err := packet.Read(bytes.NewReader(sig))
	if err != nil {
		attrs = append(attrs, Attribute{"Type", "unknown or malformed"})
		return attrs
	}
	switch s := p.(type) {
	case *packet.Signature:
		attrs = append(attrs, Attribute{"Algorithm", gpgAlgorithmName(s.PubKeyAlgo, s.Hash)})
		if s.IssuerKeyId != nil {
			attrs = append(attrs, Attribute{"Key id", fmt.Sprintf("%X", *s.IssuerKeyId)})
		}
	case *packet.SignatureV3:
		attrs = append(attrs, Attribute{"Algorithm", gpgAlgorithmName(s.PubKeyAlgo, s.Hash)})
		attrs = append(attrs, Attribute{"Key id", fmt.Sprintf("%X", s.IssuerKeyId)})
	}
	return attrs
}
