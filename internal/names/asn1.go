package names

import (
	"encoding/asn1"
	"fmt"
)

func FromAsn1Tag(class, tag int) string {
	if class == asn1.ClassUniversal {
		if s, found := tags[tag]; found {
			return s
		}
	}
	return fmt.Sprintf("%d", tag)
}

var tags = map[int]string{
	1:  "BOOLEAN",
	2:  "INTEGER",
	3:  "BIT STRING",
	4:  "OCTET STRING",
	5:  "NULL",
	6:  "OBJECT IDENTIFIER",
	7:  "ObjectDescriptor",
	8:  "EXTERNAL",
	9:  "REAL",
	10: "ENUMERATED",
	11: "EMBEDDED PDV",
	12: "UTF8String",
	13: "RELATIVE-OID",
	14: "TIME",
	16: "SEQUENCE",
	17: "SET",
	18: "NumericString",
	19: "PrintableString",
	20: "TeletexString, T61String",
	21: "VideotexString",
	22: "IA5String",
	23: "UTCTime",
	24: "GeneralizedTime",
	25: "GraphicString",
	26: "VisibleString",
	27: "GeneralString",
	28: "UniversalString",
	29: "CHARACTER STRING",
	30: "BMPString",
	31: "DATE",
	32: "TIME-OF-DAY",
	33: "DATE-TIME",
	34: "DURATION",
}
