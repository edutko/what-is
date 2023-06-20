package file

import "github.com/edutko/what-is/internal/asn1utils"

type Identifier func(name string, data []byte, fileSize int64) bool

func IsASN1(_ string, data []byte, fileSize int64) bool {
	_, l, err := asn1utils.ParseTagAndLength(data)
	if err != nil {
		return false
	}
	return int64(l) == fileSize
}
