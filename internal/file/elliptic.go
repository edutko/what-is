package file

import "encoding/asn1"

var namedCurvesByOid = map[string]string{
	// https://www.rfc-editor.org/rfc/rfc5480
	asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 1}.String(): "P-192 (secp192r1, prime192v1)",
	asn1.ObjectIdentifier{1, 3, 132, 0, 1}.String():           "sect163k1",
	asn1.ObjectIdentifier{1, 3, 132, 0, 15}.String():          "sect163r2",
	asn1.ObjectIdentifier{1, 3, 132, 0, 33}.String():          "P-224 (secp224r1)",
	asn1.ObjectIdentifier{1, 3, 132, 0, 26}.String():          "sect233k1",
	asn1.ObjectIdentifier{1, 3, 132, 0, 27}.String():          "sect233r1",
	asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}.String(): "P-256 (secp256r1, prime256v1)",
	asn1.ObjectIdentifier{1, 3, 132, 0, 16}.String():          "sect283k1",
	asn1.ObjectIdentifier{1, 3, 132, 0, 17}.String():          "sect283r1",
	asn1.ObjectIdentifier{1, 3, 132, 0, 34}.String():          "P-384 (secp384r1)",
	asn1.ObjectIdentifier{1, 3, 132, 0, 36}.String():          "sect409k1",
	asn1.ObjectIdentifier{1, 3, 132, 0, 37}.String():          "sect409r1",
	asn1.ObjectIdentifier{1, 3, 132, 0, 35}.String():          "P-521 (secp521r1)",
	asn1.ObjectIdentifier{1, 3, 132, 0, 38}.String():          "sect571k1",
	asn1.ObjectIdentifier{1, 3, 132, 0, 39}.String():          "sect571r1",

	// https://www.rfc-editor.org/rfc/rfc8410
	asn1.ObjectIdentifier{1, 3, 101, 110}.String(): "X25519 ",
	asn1.ObjectIdentifier{1, 3, 101, 111}.String(): "X448   ",
	asn1.ObjectIdentifier{1, 3, 101, 112}.String(): "Ed25519",
	asn1.ObjectIdentifier{1, 3, 101, 113}.String(): "Ed448  ",
}

func curveNameFromOID(oid asn1.ObjectIdentifier) string {
	name := namedCurvesByOid[oid.String()]
	if name != "" {
		return name
	}
	return oid.String()
}
