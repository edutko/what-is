package names

import (
	"crypto/elliptic"
	"fmt"
	"strings"
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
