package file

import (
	"bytes"
	"path/filepath"
	"strings"

	"github.com/edutko/what-is/internal/ssh1"
)

var filetypes = []filetype{
	{nil, []string{"PuTTY-User-Key-File-2:", "PuTTY-User-Key-File-3:"}, nil, PuttyPPK},
	{nil, []string{"\xCE\xCE\xCE\xCE"}, nil, JCEKeystore},
	{nil, []string{"\xFE\xED\xFE\xED"}, nil, JavaKeystore},
	{nil, []string{ssh1.Header}, nil, SSH1PrivateKey},
	{nil, []string{"-----BEGIN PGP PUBLIC KEY BLOCK-----"}, nil, PGPPublicKey},
	{nil, []string{"-----BEGIN PGP PRIVATE KEY BLOCK-----"}, nil, PGPPrivateKey},
	{nil, []string{"-----BEGIN "}, nil, PEMFile},
	{[]string{"authorized_keys"}, nil, nil, SSHAuthorizedKeys},
	{[]string{"known_hosts"}, nil, nil, SSHKnownHosts},
	{nil, []string{"ssh-dss", "ssh-rsa", "ecdsa-sha2-", "ssh-ed25519", "ssh-ed448"}, nil, SSHPublicKey},
	{nil, nil, IsUUID, UUIDValue},
	{nil, nil, IsASN1, ASN1File},
	{nil, nil, IsBase64ASN1, Base64ASN1File},
	{nil, nil, IsJWT, JWTData},
}

type filetype struct {
	patterns []string
	magics   []string
	identify Identifier
	parser   Parser
}

func (f filetype) MatchesName(name string) bool {
	if name == "" {
		return false
	}
	name = filepath.Base(name)
	for _, p := range f.patterns {
		if p == "*" {
			return true
		}
		s := strings.Trim(p, "*")
		if strings.Contains(s, "*") {
			panic("wildcard must be prefix or suffix")
		}
		if strings.HasPrefix(p, "*") && strings.HasSuffix(p, "*") {
			if strings.Contains(name, s) {
				return true
			}
		} else if strings.HasPrefix(p, "*") {
			if strings.HasSuffix(name, s) {
				return true
			}
		} else if strings.HasSuffix(p, "*") {
			if strings.HasPrefix(name, s) {
				return true
			}
		} else if name == s {
			return true
		}
	}
	return false
}

func (f filetype) MatchesMagic(data []byte) bool {
	for _, magic := range f.magics {
		if len(data) < len(magic) {
			continue
		}
		if bytes.Equal(data[:len(magic)], []byte(magic)) {
			return true
		}
	}
	return false
}

func (f filetype) SmellsLike(name string, data []byte, fileSize int64) bool {
	if f.identify == nil {
		return false
	}
	return f.identify(name, data, fileSize)
}
