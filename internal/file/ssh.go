package file

import (
	"crypto"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/edutko/putty-go/putty"
	"golang.org/x/crypto/ssh"
)

func puttyPublicKeyAttributes(pub putty.PublicKey) []Attribute {
	attrs := []Attribute{
		{"Type", pub.Type()},
	}
	if pub.Comment() != "" {
		attrs = append(attrs, Attribute{"Comment", pub.Comment()})
	}
	if pub.Type() == "ssh-ed448" {
		attrs = append(attrs, ed448PrivateKeyAttributes()...)
	} else {
		attrs = append(attrs, cryptoPublicKeyAttributes(pub.Key())...)
	}
	return attrs
}

func ssh1PublicKeyAttributes(pub crypto.PublicKey, comment string) []Attribute {
	attrs := []Attribute{}
	if comment != "" {
		attrs = append(attrs, Attribute{"Comment", comment})
	}
	attrs = append(attrs, cryptoPublicKeyAttributes(pub)...)
	return attrs
}

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
