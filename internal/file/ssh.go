package file

import (
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
