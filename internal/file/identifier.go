package file

import (
	"bytes"
	"encoding/asn1"
	"strings"

	"github.com/google/uuid"

	"github.com/edutko/decipher/internal/util"
)

type Identifier func(name string, data []byte, fileSize int64) bool

func IsASN1(_ string, data []byte, _ int64) bool {
	return isBinaryASN1(data)
}

func IsBase64ASN1(_ string, data []byte, _ int64) bool {
	decoded, err := util.DecodeAnyBase64(data)
	if err != nil {
		return false
	}
	return isBinaryASN1(decoded)
}

func isBinaryASN1(data []byte) bool {
	var something asn1.RawValue
	extra, err := asn1.Unmarshal(data, &something)
	if err != nil || len(extra) != 0 {
		return false
	}
	return true
}

func IsJWT(_ string, data []byte, _ int64) bool {
	if _, err := ParseJWT(data); err != nil {
		return false
	}
	return true
}

func IsMixedPEM(_ string, data []byte, _ int64) bool {
	start := bytes.Index(data, []byte("-----BEGIN"))
	end := bytes.Index(data, []byte("-----END"))
	return start >= 0 && end > start
}

func IsUUID(_ string, data []byte, _ int64) bool {
	s := strings.TrimSpace(string(data))
	if _, err := uuid.Parse(s); err != nil {
		return false
	}
	return true
}
