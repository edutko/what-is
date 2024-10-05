package file

import (
	"bytes"
	"encoding/pem"
	"fmt"

	"github.com/edutko/putty-go/ppk"
	"github.com/edutko/putty-go/putty"
	"golang.org/x/crypto/ssh"

	"github.com/edutko/what-is/internal/openpgp"
	"github.com/edutko/what-is/internal/openpgp/packet"
	"github.com/edutko/what-is/internal/ssh1"
	"github.com/edutko/what-is/internal/util"
)

type Parser func(info Info, data []byte) (Info, error)

func ASN1File(info Info, data []byte) (Info, error) {
	derInfo := parseDERData(data)
	if derInfo.Description != UnknownASN1Data.Description {
		info.Description = derInfo.Description
		info.Attributes = derInfo.Attributes
		info.Children = derInfo.Children
		return info, nil
	}
	asn1nfo := parseASN1Data(data)
	info.Description = asn1nfo.Description
	info.Attributes = asn1nfo.Attributes
	info.Children = asn1nfo.Children
	return info, nil
}

func Base64ASN1File(info Info, data []byte) (Info, error) {
	decoded, err := util.DecodeAnyBase64(data)
	if err != nil {
		return info, err
	}
	return ASN1File(info, decoded)
}

func JavaKeystore(info Info, _ []byte) (Info, error) {
	return Info{
		Path:        info.Path,
		Description: "Java Keystore",
	}, nil
}

func JCEKeystore(info Info, _ []byte) (Info, error) {
	return Info{
		Path:        info.Path,
		Description: "Java JCE Keystore",
	}, nil
}

func PEMFile(info Info, data []byte) (Info, error) {
	var blockInfos []Info
	for rest := data; len(rest) > 0; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return info, fmt.Errorf("failed to parse PEM data")
		}
		blockInfos = append(blockInfos, parsePEMBlock(b))
	}

	if len(blockInfos) == 1 {
		info.Description = blockInfos[0].Description
		info.Attributes = blockInfos[0].Attributes
		info.Children = blockInfos[0].Children
		return info, nil

	} else if len(blockInfos) > 1 {
		info.Description = "multiple PEM blocks"
		for _, c := range blockInfos {
			info.Children = append(info.Children, c)
		}
		return info, nil
	}

	return info, fmt.Errorf("no valid PEM blocks in file")
}

func PGPPrivateKey(info Info, data []byte) (Info, error) {
	info.Description = "GPG/PGP private key"
	return pgpKey(info, data)
}

func PGPPublicKey(info Info, data []byte) (Info, error) {
	info.Description = "GPG/PGP public key"
	return pgpKey(info, data)
}

func pgpKey(info Info, data []byte) (Info, error) {
	blk, err := readArmoredPGPData(data)
	if err != nil {
		return info, fmt.Errorf("readArmoredPGPData: %w", err)
	}

	r := packet.NewReader(blk.Body)
	e, err := openpgp.ReadEntity(r)
	if err != nil {
		return info, fmt.Errorf("openpgp.ReadEntity: %w", err)
	}

	info.Attributes = gpgPublicKeyAttributes(e.PrimaryKey)
	for _, i := range e.Identities {
		attrs := gpgSignatureAttributes(i.SelfSignature, e.PrimaryKey.CreationTime)
		for _, s := range i.Signatures {
			attrs = append(attrs, gpgSignatureAttributes(s, e.PrimaryKey.CreationTime)...)
		}
		info.Children = append(info.Children, Info{
			Description: i.Name,
			Attributes:  attrs,
		})
	}

	for _, s := range e.Subkeys {
		attrs := gpgPublicKeyAttributes(s.PublicKey)
		attrs = append(attrs, gpgSignatureAttributes(s.Sig, s.PublicKey.CreationTime)...)
		info.Children = append(info.Children, Info{
			Description: "GPG/PGP subkey",
			Attributes:  attrs,
		})
	}

	return info, nil
}

func PuttyPPK(info Info, data []byte) (Info, error) {
	k, err := ppk.InsecureParse(data)
	if err != nil {
		return info, fmt.Errorf("putty.ParsePPKBytes: %w", err)
	}
	info.Description = fmt.Sprintf("puTTY private key (version %d)", k.Version)

	pub, err := putty.UnmarshalPublicKey(k.PublicBytes, k.Comment)
	if err != nil {
		return info, fmt.Errorf("ssh.ParsePublicKey: %w", err)
	}
	info.Attributes = puttyPublicKeyAttributes(pub)
	info.Attributes = append(info.Attributes, Attribute{"Encryption", string(k.Encryption)})
	if k.Encryption != ppk.NoEncryption {
		info.Attributes = append(info.Attributes,
			Attribute{"KDF", fmt.Sprintf("%s (%d passes, %d MB, parallelism: %d)",
				k.KeyDerivation, k.Argon2Passes, k.Argon2Memory, k.Argon2Parallelism)})
	}

	return info, nil
}

func SSH1PrivateKey(info Info, data []byte) (Info, error) {
	info.Description = "SSH v1 key"

	priv, comment, err := ssh1.ParsePrivateKey(data, []byte(""))
	if err != nil {
		return info, fmt.Errorf("ssh1.ParsePrivateKey: %w", err)
	}

	info.Attributes = ssh1PublicKeyAttributes(priv.Public(), comment)

	return info, nil
}

func SSHAuthorizedKeys(info Info, data []byte) (Info, error) {
	info.Description = "SSH authorized_keys"
	lines := bytes.Split(data, []byte("\n"))
	var keys []Info
	for _, l := range lines {
		pub, comment, _, _, err := ssh.ParseAuthorizedKey(l)
		if err != nil {
			return info, fmt.Errorf("ssh.ParseAuthorizedKey: %w", err)
		}
		keys = append(keys, Info{
			Description: "SSH public key",
			Attributes:  sshPublicKeyAttributes(pub, comment),
		})
	}
	info.Children = keys
	return info, nil
}

func SSHKnownHosts(info Info, data []byte) (Info, error) {
	info.Description = "SSH known_hosts"
	lines := bytes.Split(data, []byte("\n"))
	var keys []Info
	for _, l := range lines {
		if len(bytes.TrimSpace(l)) == 0 {
			continue
		}
		_, hosts, pub, comment, _, err := ssh.ParseKnownHosts(l)
		if err != nil {
			return info, fmt.Errorf("ssh.ParseKnownHosts: %w", err)
		}
		keys = append(keys, Info{
			Description: "SSH public key",
			Attributes:  sshKnownHostsKeyAttributes(hosts, pub, comment),
		})
	}
	info.Children = keys
	return info, nil
}

func SSHPublicKey(info Info, data []byte) (Info, error) {
	info.Description = "SSH public key"
	pub, comment, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return info, fmt.Errorf("ssh.ParsePublicKey: %w", err)
	}
	info.Attributes = sshPublicKeyAttributes(pub, comment)
	return info, nil
}
