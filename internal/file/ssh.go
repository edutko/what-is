package file

import (
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

func sshPublicKeyAttributes(pub ssh.PublicKey, comment string) []Attribute {
	attrs := []Attribute{
		{"Type", pub.Type()},
	}
	if comment != "" {
		attrs = append(attrs, Attribute{"Comment", comment})
	}
	if pk, ok := pub.(ssh.CryptoPublicKey); ok {
		attrs = append(attrs, cryptoPublicKeyAttributes(pk.CryptoPublicKey())...)
	}
	return attrs
}

func sshKnownHostsKeyAttributes(hosts []string, pub ssh.PublicKey, comment string) []Attribute {
	attrs := []Attribute{{"Hosts", strings.Join(hosts, ", ")}}
	attrs = append(attrs, sshPublicKeyAttributes(pub, comment)...)
	return attrs
}

func parseKdfOptions(opts []byte) ([]byte, uint32, error) {
	saltLen := binary.BigEndian.Uint32(opts[:4])
	if 4+saltLen+4 != uint32(len(opts)) {
		return nil, 0, fmt.Errorf("invalid KDF options")
	}
	rounds := binary.BigEndian.Uint32(opts[4+saltLen:])
	return opts[4 : 4+saltLen], rounds, nil
}
