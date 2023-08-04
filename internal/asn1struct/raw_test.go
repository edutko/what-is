package asn1struct

import (
	"encoding/asn1"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseRaw(t *testing.T) {
	data, err := os.ReadFile("testdata/www.microsoft.com.cer")
	assert.Nil(t, err)

	r, err := ParseRaw(data)
	assert.Nil(t, err)
	assert.Lenf(t, r, 1, "expected 1 top-level element")

	cert := r[0]
	assert.Equal(t, asn1.TagSequence, r[0].Tag, "expected top-level element to be a sequence")
	assert.Lenf(t, cert.Children, 3, "expected three second-level elements (tbs, sig alg, signature)")

	tbsCert := cert.Children[0]
	assert.Equal(t, asn1.TagSequence, tbsCert.Tag)

	// TODO: check elements of tbsCert

	sigAlg := cert.Children[1]
	assert.Equal(t, asn1.TagSequence, sigAlg.Tag)
	assert.Lenf(t, sigAlg.Children, 2, "expected 2 elements in signature algorithm sequence")

	sigAlgOid := sigAlg.Children[0]
	assert.Equal(t, asn1.TagOID, sigAlgOid.Tag)
	assert.Equal(t, "1.2.840.113549.1.1.12", sigAlgOid.Value())

	sigAlgParams := sigAlg.Children[1]
	assert.Equal(t, asn1.TagNull, sigAlgParams.Tag)
	assert.Equal(t, "null", sigAlgParams.Value())

	sig := cert.Children[2]
	assert.Equal(t, asn1.TagBitString, sig.Tag)
	assert.Lenf(t, sig.Value(), 2*513, "expected 513-byte signature")
}
