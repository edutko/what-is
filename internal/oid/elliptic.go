package oid

import "encoding/asn1"

// https://www.rfc-editor.org/rfc/rfc5480
var Secp192r1 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 1}
var Sect163k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 1}
var Sect163r2 = asn1.ObjectIdentifier{1, 3, 132, 0, 15}
var Secp224r1 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
var Sect233k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 26}
var Sect233r1 = asn1.ObjectIdentifier{1, 3, 132, 0, 27}
var Secp256r1 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
var Sect283k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 16}
var Sect283r1 = asn1.ObjectIdentifier{1, 3, 132, 0, 17}
var Secp384r1 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
var Sect409k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 36}
var Sect409r1 = asn1.ObjectIdentifier{1, 3, 132, 0, 37}
var Secp521r1 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
var Sect571k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 38}
var Sect571r1 = asn1.ObjectIdentifier{1, 3, 132, 0, 39}

// https://www.rfc-editor.org/rfc/rfc8410
var X25519 = asn1.ObjectIdentifier{1, 3, 101, 110}
var X448 = asn1.ObjectIdentifier{1, 3, 101, 111}
var Ed25519 = asn1.ObjectIdentifier{1, 3, 101, 112}
var Ed448 = asn1.ObjectIdentifier{1, 3, 101, 113}

var PrimeField = asn1.ObjectIdentifier{1, 2, 840, 10045, 1, 1}
var CharacteristicTwoField = asn1.ObjectIdentifier{1, 2, 840, 10045, 1, 2}
