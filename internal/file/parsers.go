package file

import (
	"bytes"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/ssh"
)

type Parser func(info Info, data []byte) (Info, error)

func JavaKeystore(info Info, _ []byte) (Info, error) {
	return Info{
		Path:        info.Path,
		Description: "Java Keystore",
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
		return Info{
			Path:        info.Path,
			Description: blockInfos[0].Description,
			Attributes:  blockInfos[0].Attributes,
		}, nil
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
	blk, err := readArmoredPGPData(data)
	if err != nil {
		return info, fmt.Errorf("readArmoredPGPData: %w", err)
	}

	info.Description = "GPG/PGP private key"
	info.Attributes = map[string]string{}

	r := packet.NewReader(blk.Body)
	p, err := r.Next()
	if err != nil {
		return info, fmt.Errorf("r.Next: %w", err)
	}

	if pk, ok := p.(*packet.PrivateKey); ok {
		info.Attributes["Key ID"] = pk.KeyIdString()
		info.Attributes["Fingerprint"] = strings.ToUpper(hex.EncodeToString(pk.Fingerprint[:]))
		info.Attributes["Algorithm"] = pubkeyAlgorithmNames[pk.PubKeyAlgo]
		l, err := pk.BitLength()
		if err == nil {
			info.Attributes["Size"] = fmt.Sprintf("%d bits", l)
		}
	}

	return info, nil
}

func PGPPublicKey(info Info, data []byte) (Info, error) {
	blk, err := readArmoredPGPData(data)
	if err != nil {
		return info, fmt.Errorf("readArmoredPGPData: %w", err)
	}

	info.Description = "GPG/PGP public key"
	info.Attributes = map[string]string{}

	r := packet.NewReader(blk.Body)
	p, err := r.Next()
	if err != nil {
		return info, fmt.Errorf("r.Next: %w", err)
	}

	if pk, ok := p.(*packet.PublicKey); ok {
		info.Attributes["Key ID"] = pk.KeyIdString()
		info.Attributes["Fingerprint"] = strings.ToUpper(hex.EncodeToString(pk.Fingerprint[:]))
		info.Attributes["Algorithm"] = pubkeyAlgorithmNames[pk.PubKeyAlgo]
		l, err := pk.BitLength()
		if err == nil {
			info.Attributes["Size"] = fmt.Sprintf("%d bits", l)
		}
	}

	return info, nil
}

func PuttyPPK(info Info, _ []byte) (Info, error) {
	return Info{
		Path:        info.Path,
		Description: "puTTY private key",
	}, nil
}

func SSHAuthorizedKeys(info Info, data []byte) (Info, error) {
	lines := bytes.Split(data, []byte("\n"))
	var keys []Info
	for _, l := range lines {
		pub, comment, _, _, err := ssh.ParseAuthorizedKey(l)
		if err != nil {
			return info, fmt.Errorf("ssh.ParseAuthorizedKey: %w", err)
		}
		keys = append(keys, Info{
			Description: "SSH public key",
			Attributes: map[string]string{
				"Type":    pub.Type(),
				"Comment": comment,
			},
		})
	}
	return Info{
		Path:        info.Path,
		Description: "SSH authorized_keys",
		Children:    keys,
	}, nil
}

func SSHKnownHosts(info Info, data []byte) (Info, error) {
	lines := bytes.Split(data, []byte("\n"))
	var keys []Info
	for _, l := range lines {
		_, hosts, pub, comment, _, err := ssh.ParseKnownHosts(l)
		if err != nil {
			return info, fmt.Errorf("ssh.ParseKnownHosts: %w", err)
		}
		keys = append(keys, Info{
			Description: "SSH public key",
			Attributes: map[string]string{
				"Type":    pub.Type(),
				"Hosts":   strings.Join(hosts, ", "),
				"Comment": comment,
			},
		})
	}
	return Info{
		Path:        info.Path,
		Description: "SSH known_hosts",
		Children:    keys,
	}, nil
}

func SSHPublicKey(info Info, data []byte) (Info, error) {
	pub, comment, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return info, fmt.Errorf("ssh.ParsePublicKey: %w", err)
	}
	return Info{
		Path:        info.Path,
		Description: "SSH public key",
		Attributes: map[string]string{
			"Type":    pub.Type(),
			"Comment": comment,
		},
	}, nil
}
