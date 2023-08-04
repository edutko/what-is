package asn1struct

import (
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"time"

	"github.com/edutko/what-is/internal/names"
)

func ParseRaw(data []byte) ([]Raw, error) {
	var items []Raw
	var err error
	rest := data
	for {
		var rawItem asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &rawItem)
		if err != nil {
			return nil, err
		}
		item := Raw{Class: rawItem.Class, Tag: rawItem.Tag, Bytes: rawItem.Bytes, FullBytes: rawItem.FullBytes}
		if rawItem.IsCompound {
			children, err := ParseRaw(rawItem.Bytes)
			if err != nil {
				return nil, err
			}
			item.Children = children
		}
		items = append(items, item)
		if len(rest) == 0 {
			break
		}
	}
	return items, nil
}

type Raw struct {
	Class     int
	Tag       int
	Bytes     []byte
	FullBytes []byte
	Children  []Raw
}

func (r Raw) TypeString() string {
	return names.FromAsn1Tag(r.Class, r.Tag)
}

func (r Raw) Value() string {
	switch r.Tag {
	case asn1.TagBoolean:
		var b bool
		_, err := asn1.Unmarshal(r.FullBytes, &b)
		if err != nil {
			return hex.EncodeToString(r.Bytes)
		}
		if b {
			return "true"
		}
		return "false"

	case asn1.TagInteger:
		var i *big.Int
		_, err := asn1.Unmarshal(r.FullBytes, &i)
		if err != nil {
			return hex.EncodeToString(r.Bytes)
		}
		return i.String()

	case asn1.TagBitString:
		return hex.EncodeToString(r.Bytes)

	case asn1.TagOctetString:
		return hex.EncodeToString(r.Bytes)

	case asn1.TagNull:
		return "null"

	case asn1.TagOID:
		var o asn1.ObjectIdentifier
		_, err := asn1.Unmarshal(r.FullBytes, &o)
		if err != nil {
			return hex.EncodeToString(r.Bytes)
		}
		return o.String()

	case asn1.TagUTF8String, asn1.TagNumericString, asn1.TagPrintableString:
		var s string
		_, err := asn1.Unmarshal(r.FullBytes, &s)
		if err != nil {
			return hex.EncodeToString(r.Bytes)
		}
		return s

	case asn1.TagUTCTime:
		var t time.Time
		_, err := asn1.Unmarshal(r.FullBytes, &t)
		if err != nil {
			return hex.EncodeToString(r.Bytes)
		}
		return t.Format("2006-01-02T15:04Z")

	default:
		return hex.EncodeToString(r.Bytes)
	}
}
