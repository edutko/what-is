package file

import (
	"encoding/asn1"
)

type Identifier func(name string, data []byte, fileSize int64) bool

func IsASN1(_ string, data []byte, fileSize int64) bool {
	var something asn1.RawValue
	extra, err := asn1.Unmarshal(data, &something)
	if err != nil || len(extra) != 0 {
		return false
	}
	return true
}
