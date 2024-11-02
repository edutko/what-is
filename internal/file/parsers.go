package file

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/edutko/putty-go/ppk"
	"github.com/edutko/putty-go/putty"
	"github.com/google/uuid"
	"github.com/jfrog/go-rpm"
	"golang.org/x/crypto/ssh"

	"github.com/edutko/decipher/internal/names"
	"github.com/edutko/decipher/internal/openpgp"
	"github.com/edutko/decipher/internal/openpgp/packet"
	"github.com/edutko/decipher/internal/ssh1"
	"github.com/edutko/decipher/internal/util"
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

func JWTData(info Info, data []byte) (Info, error) {
	info.Description = "JSON Web Token (JWT)"

	j, err := ParseJWT(data)
	if err != nil {
		return info, err
	}

	info.Attributes = append(info.Attributes, j.HeaderAttributes()...)
	info.Attributes = append(info.Attributes, j.PayloadAttributes()...)
	info.Attributes = append(info.Attributes, Attribute{"Signature", base64.RawURLEncoding.EncodeToString(j.Signature)})

	return info, nil
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

func RPMFile(info Info, data []byte) (Info, error) {
	info.Description = "RPM"

	r, err := rpm.ReadPackageFile(bytes.NewReader(data))
	if err != nil {
		return info, fmt.Errorf("rpm.ReadPackageLead: %w", err)
	}

	if r.RPMVersion() != "" {
		info.Description = fmt.Sprintf("RPM (version %s)", r.RPMVersion())
	}

	info.Attributes = append(info.Attributes, Attribute{"Name", r.Name()})
	info.Attributes = append(info.Attributes, Attribute{"Version", r.Version()})
	info.Attributes = append(info.Attributes, Attribute{"Release", r.Release()})
	info.Attributes = append(info.Attributes, Attribute{"Architecture", r.Architecture()})

	if len(r.Headers) > 0 {
		sigIdx := r.Headers[0].Indexes
		if len(sigIdx) > 0 && sigIdx[0].Tag == rpm.RPMTAG_HEADERSIGNATURES {
			if md5Digest := sigIdx.BytesByTag(rpm.RPMSIGTAG_MD5); len(md5Digest) > 0 {
				info.Attributes = append(info.Attributes, Attribute{names.MD5, hex.EncodeToString(md5Digest)})
			}
			if sha1Digest := sigIdx.StringByTag(rpm.RPMSIGTAG_SHA1); len(sha1Digest) > 0 {
				info.Attributes = append(info.Attributes, Attribute{names.SHA1, sha1Digest})
			}
			if sha256Digest := sigIdx.StringByTag(273); len(sha256Digest) > 0 {
				info.Attributes = append(info.Attributes, Attribute{names.SHA256, sha256Digest})
			}

			foundSig := false
			for _, t := range []int{rpm.RPMSIGTAG_DSA, rpm.RPMSIGTAG_RSA} {
				if sig := sigIdx.BytesByTag(t); len(sig) > 0 {
					foundSig = true
					info.Children = append(info.Children, Info{
						Description: "Signature",
						Attributes:  rpmSignatureAttributes(sig),
					})
				}
			}

			for _, t := range []int{rpm.RPMSIGTAG_GPG, rpm.RPMSIGTAG_PGP} {
				if sig := sigIdx.BytesByTag(t); len(sig) > 0 {
					foundSig = true
					info.Children = append(info.Children, Info{
						Description: "Legacy signature (RPM v3)",
						Attributes:  rpmSignatureAttributes(sig),
					})
				}
			}

			if !foundSig {
				info.Attributes = append(info.Attributes, Attribute{"Signature", "none"})
			}
		}
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

func UUIDValue(info Info, data []byte) (Info, error) {
	s := strings.TrimSpace(string(data))
	u, err := uuid.Parse(s)
	if err != nil {
		return info, fmt.Errorf("uuid.Parse: %w", err)
	}
	info.Description = "UUID (unknown type)"

	// https://datatracker.ietf.org/doc/html/rfc9562
	v := u.Version()
	if v <= 15 {
		switch v {
		case 0:
			if u.String() == uuid.Nil.String() {
				info.Description = "UUID (Nil UUID)"
			}
		case 1:
			info.Description = "UUID v1 (Gregorian time)"
			t := time.Unix(u.Time().UnixTime()).UTC()
			info.Attributes = append(info.Attributes, []Attribute{
				{"Node id", hex.EncodeToString(u.NodeID())},
				{"Time (raw)", fmt.Sprintf("%d", u.Time())},
				{"Time (UTC)", t.Format("2006-01-02 15:04:05.9999999")},
				{"Clock sequence", fmt.Sprintf("%d", u.ClockSequence())},
			}...)
		case 2:
			info.Description = "UUID v2 (DCE)"
			t := time.Unix(u.Time().UnixTime()).UTC()
			info.Attributes = append(info.Attributes, []Attribute{
				{"Domain", u.Domain().String()},
				{"Id", fmt.Sprintf("%d", u.ID())},
				{"Node id", hex.EncodeToString(u.NodeID())},
				{"Time (raw)", fmt.Sprintf("%d", u.Time())},
				{"Time (UTC)", t.Format("2006-01-02 15:04:05.9999999")},
				{"Clock sequence", fmt.Sprintf("%d", u.ClockSequence())},
			}...)
		case 3:
			info.Description = "UUID v3 (MD5)"
		case 4:
			info.Description = "UUID v4 (random)"
		case 5:
			info.Description = "UUID v5 (SHA1)"
		case 6:
			info.Description = "UUID v6 (reordered Gregorian time)"
			t := time.Unix(u.Time().UnixTime()).UTC()
			info.Attributes = append(info.Attributes, []Attribute{
				{"Time (raw)", fmt.Sprintf("%d", u.Time())},
				{"Time (UTC)", t.Format("2006-01-02 15:04:05.9999999")},
			}...)
		case 7:
			info.Description = "UUID v7 (Unix epoch time)"
			t := time.Unix(u.Time().UnixTime()).UTC()
			info.Attributes = append(info.Attributes, []Attribute{
				{"Time (raw)", fmt.Sprintf("%d", u.Time())},
				{"Time (UTC)", t.Format("2006-01-02 15:04:05.9999999")},
			}...)
		case 0xff:
			if u.String() == uuid.Max.String() {
				info.Description = "UUID (Max UUID)"
			}
		}
	}

	return info, nil
}
