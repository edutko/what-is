package putty

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var ppkEcdsaP384 = []byte(`PuTTY-User-Key-File-3: ecdsa-sha2-nistp384
Encryption: none
Comment: putty-ecdsa
Public-Lines: 3
AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBNonH/ZkqT0k
Zj0EOva7YgWv2vz9Tr14l9yqXMt9QvBCkpVhkjaGhMeGa7CKGVmrf/k0XXwslzj2
qT+wthM7EA4quz5Vb0ryswB99bZqWHF+jDaST3U87uWcWyaguxu0tw==
Private-Lines: 2
AAAAMDvcLQ7zC8J6GkcX85kxvgZ9Ow7qIdftwuvlsn53TbVtdiTnWJLW8z8wXJAz
nHGiVw==
Private-MAC: e5cff4c84b7e53b57e990d1bb463c4319e4d6501b410fbb8fb671338f49534c3
`)

func TestParsePPKBytes(t *testing.T) {
	p, err := ParsePPKBytes(ppkEcdsaP384)

	assert.Nil(t, err)
	assert.Equal(t, 3, p.Version)
	assert.Equal(t, "ecdsa-sha2-nistp384", p.Type)
	assert.Equal(t, "none", p.Encryption)
	assert.Equal(t, "putty-ecdsa", p.Comment)
	assert.Equal(t, "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBNonH/ZkqT0kZj0EOva7YgWv2vz9Tr14l9yqXMt9QvBCkpVhkjaGhMeGa7CKGVmrf/k0XXwslzj2qT+wthM7EA4quz5Vb0ryswB99bZqWHF+jDaST3U87uWcWyaguxu0tw==", p.PublicKeyB64)
}
