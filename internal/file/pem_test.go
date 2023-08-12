package file

import (
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_parsePEMBlock(t *testing.T) {
	testCases := []struct {
		file string
		info Info
	}{
		{"x509/pem/dsa-1024.key", Info{
			Description: "PKCS#8 private key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "DSA"},
				{Name: "Size", Value: "1024 bits"},
			}},
		},
		{"x509/pem/dsa-1024.pub", Info{
			Description: "PKIX public key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "DSA"},
				{Name: "Size", Value: "1024 bits"},
			}},
		},
		{"x509/pem/dsa-1024-dsa.key", Info{
			Description: "DSA private key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "DSA"},
				{Name: "Size", Value: "1024 bits"},
			}},
		},
		{"x509/pem/rsa-512.key", Info{
			Description: "PKCS#8 private key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "RSA"},
				{Name: "Size", Value: "512 bits"},
			}},
		},
		{"x509/pem/rsa-512-pkcs1.key", Info{
			Description: "PKCS#1 private key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "RSA"},
				{Name: "Size", Value: "512 bits"},
			}},
		},
		{"x509/pem/rsa-512.pub", Info{
			Description: "PKIX public key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "RSA"},
				{Name: "Size", Value: "512 bits"},
			}},
		},
		{"x509/pem/rsa-512-pkcs1.pub", Info{
			Description: "PKCS#1 public key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "RSA"},
				{Name: "Size", Value: "512 bits"},
			}},
		},
		{"x509/pem/prime256v1.key", Info{
			Description: "PKCS#8 private key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "ECDSA"},
				{Name: "Curve", Value: "P-256 (secp256r1, prime256v1)"},
			}},
		},
		{"x509/pem/prime256v1-explicit.key", Info{
			Description: "PKCS#8 private key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "ECDSA"},
				{Name: "Field type", Value: "prime field"},
				{Name: "Prime size", Value: "256 bits"},
			}},
		},
		{"x509/pem/prime256v1-ec.key", Info{
			Description: "EC private key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "ECDSA"},
				{Name: "Curve", Value: "P-256 (secp256r1, prime256v1)"},
			}},
		},
		{"x509/pem/prime256v1-ec-explicit.key", Info{
			Description: "EC private key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "ECDSA"},
				{Name: "Field type", Value: "prime field"},
				{Name: "Prime size", Value: "256 bits"},
			}},
		},
		{"x509/pem/prime256v1.pub", Info{
			Description: "PKIX public key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "ECDSA"},
				{Name: "Curve", Value: "P-256 (secp256r1, prime256v1)"},
			}},
		},
		{"x509/pem/prime256v1.param", Info{
			Description: "EC parameters",
			Attributes: []Attribute{
				{Name: "Curve", Value: "P-256 (secp256r1, prime256v1)"},
			}},
		},
		{"x509/pem/prime256v1-explicit.param", Info{
			Description: "EC parameters",
			Attributes: []Attribute{
				{Name: "Field type", Value: "prime field"},
				{Name: "Prime size", Value: "256 bits"},
			}},
		},
		{"x509/pem/sect233r1-explicit.param", Info{
			Description: "EC parameters",
			Attributes: []Attribute{
				{Name: "Field type", Value: "characteristic 2 field"},
				{Name: "Field size", Value: "2^233"},
			}},
		},
		{"x509/pem/ed25519.key", Info{
			Description: "PKCS#8 private key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "EdDSA"},
				{Name: "Curve", Value: "Ed25519"},
			}},
		},
		{"x509/pem/ed25519.pub", Info{
			Description: "PKIX public key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "EdDSA"},
				{Name: "Curve", Value: "Ed25519"},
			}},
		},
		{"ssh/id_ecdsa_384", Info{
			Description: "OpenSSH private key",
			Attributes: []Attribute{
				{Name: "Type", Value: "ecdsa-sha2-nistp384"},
				{Name: "Algorithm", Value: "ECDSA"},
				{Name: "Curve", Value: "P-384 (secp384r1)"},
			}},
		},
		{"ssh/id_ecdsa_256_enc", Info{
			Description: "OpenSSH private key (encrypted)",
			Attributes: []Attribute{
				{Name: "Type", Value: "ecdsa-sha2-nistp256"},
				{Name: "Algorithm", Value: "ECDSA"},
				{Name: "Curve", Value: "P-256 (secp256r1, prime256v1)"},
				{Name: "Cipher", Value: "aes256-ctr"},
				{Name: "KDF", Value: "bcrypt"},
				{Name: "KDF rounds", Value: "16"},
			}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.file, func(t *testing.T) {
			data := fileContents(tc.file)
			block, _ := pem.Decode(data)
			actual := parsePEMBlock(block)
			assert.Equal(t, tc.info, actual)
		})
	}
}
