package names

import (
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"strings"

	"github.com/edutko/decipher/internal/oid"
)

const (
	Secp192r1 = "P-192 (secp192r1, prime192v1)"
	Sect163k1 = "sect163k1"
	Sect163r2 = "sect163r2"
	Secp224r1 = "P-224 (secp224r1)"
	Sect233k1 = "sect233k1"
	Sect233r1 = "sect233r1"
	Secp256r1 = "P-256 (secp256r1, prime256v1)"
	Sect283k1 = "sect283k1"
	Sect283r1 = "sect283r1"
	Secp384r1 = "P-384 (secp384r1)"
	Sect409k1 = "sect409k1"
	Sect409r1 = "sect409r1"
	Secp521r1 = "P-521 (secp521r1)"
	Sect571k1 = "sect571k1"
	Sect571r1 = "sect571r1"
	X25519    = "X25519"
	X448      = "X448"
	Ed25519   = "Ed25519"
	Ed448     = "Ed448"
)

type curveNames []string

func (c curveNames) matches(name string) bool {
	name = strings.ToLower(name)
	for _, n := range c {
		if strings.ToLower(n) == name {
			return true
		}
	}
	return false
}

func (c curveNames) String() string {
	if len(c) == 1 {
		return c[0]
	} else {
		return fmt.Sprintf("%s (%s)", c[0], strings.Join(c[1:], ", "))
	}
}

const curveUnknown = "unknown curve"

var namedCurves = []curveNames{
	{"P-192", "secp192r1", "prime192v1"},
	{"P-224", "secp224r1"},
	{"P-256", "secp256r1", "prime256v1"},
	{"P-384", "secp384r1"},
	{"P-521", "secp521r1"},

	{"X25519"},
	{"X448"},
	{"Ed25519"},
	{"Ed448"},

	{"sect163k1"},
	{"sect163r2"},
	{"sect233k1"},
	{"sect233r1"},
	{"sect283k1"},
	{"sect283r1"},
	{"sect409k1"},
	{"sect409r1"},
	{"sect571k1"},
	{"sect571r1"},
}

func FromCurveParams(params *elliptic.CurveParams) string {
	if params.Name == "" {
		// TODO: attempt to match parameters to named curve
		return curveUnknown
	}

	return Curve(params.Name)
}

func Curve(name string) string {
	if name == "" {
		return curveUnknown
	}

	for _, c := range namedCurves {
		if c.matches(name) {
			return c.String()
		}
	}

	return curveUnknown
}

var namedCurvesByOid = map[string]string{
	oid.Secp192r1.String(): Secp192r1,
	oid.Sect163k1.String(): Sect163k1,
	oid.Sect163r2.String(): Sect163r2,
	oid.Secp224r1.String(): Secp224r1,
	oid.Sect233k1.String(): Sect233k1,
	oid.Sect233r1.String(): Sect233r1,
	oid.Secp256r1.String(): Secp256r1,
	oid.Sect283k1.String(): Sect283k1,
	oid.Sect283r1.String(): Sect283r1,
	oid.Secp384r1.String(): Secp384r1,
	oid.Sect409k1.String(): Sect409k1,
	oid.Sect409r1.String(): Sect409r1,
	oid.Secp521r1.String(): Secp521r1,
	oid.Sect571k1.String(): Sect571k1,
	oid.Sect571r1.String(): Sect571r1,

	oid.X25519.String():  X25519,
	oid.X448.String():    X448,
	oid.Ed25519.String(): Ed25519,
	oid.Ed448.String():   Ed448,
}

func CurveNameFromOID(id asn1.ObjectIdentifier) string {
	if name, ok := namedCurvesByOid[id.String()]; ok {
		return name
	}
	return id.String()
}

func FieldTypeFromOid(id asn1.ObjectIdentifier) string {
	switch id.String() {
	case oid.PrimeField.String():
		return "prime field"
	case oid.CharacteristicTwoField.String():
		return "characteristic 2 field"
	default:
		return id.String()
	}
}
