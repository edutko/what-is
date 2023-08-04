package file

import (
	"github.com/edutko/what-is/internal/asn1struct"
)

func parseASN1Data(b []byte) Info {
	rawStructs, err := asn1struct.ParseRaw(b)
	if err != nil {
		return UnknownASN1Data
	}

	info := Info{Description: "ASN.1 data"}
	info.Children = childrenAsInfo(rawStructs)
	return info
}

func childrenAsInfo(ss []asn1struct.Raw) []Info {
	var infos []Info
	for _, s := range ss {
		info := Info{Description: s.TypeString()}
		info.Children = childrenAsInfo(s.Children)
		if len(info.Children) == 0 {
			info.Description += ": " + s.Value()
		}
		infos = append(infos, info)
	}
	return infos
}
