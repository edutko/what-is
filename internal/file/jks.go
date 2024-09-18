package file

import (
	"fmt"
	"strings"

	"github.com/edutko/jks-go/keystore"
)

func parseJKSEntry(e keystore.Entry) Info {
	info := Info{
		Description: fmt.Sprintf("%s (%s)", e.Alias, e.Type),
		Attributes: []Attribute{
			{"Date", e.Date.Format("2006-01-02T15:04:05Z07:00")},
		},
	}
	for _, c := range e.Certificates {
		if strings.ToUpper(c.Type) != "X.509" {
			info.Children = append(info.Children, Info{Description: fmt.Sprintf("%s certificate", c.Type)})
			continue
		}
		certInfo, err := parseCertificate(c.Bytes)
		if err != nil {
			continue
		}
		info.Children = append(info.Children, certInfo)
	}

	if e.Type == keystore.PrivateKeyEntry {
		ci := Info{
			Description: "Private key (encrypted)",
		}
		if e.EncryptionAlgorithm().Name != "" {
			ci.Attributes = append(ci.Attributes, Attribute{"Encryption", e.EncryptionAlgorithm().Name})
		}
		info.Children = append(info.Children, ci)

	} else if e.Type == keystore.SecretKeyEntry {
		ci := Info{
			Description: "Symmetric key or password (encrypted)",
		}
		if e.EncryptionAlgorithm().Name != "" {
			ci.Attributes = append(ci.Attributes, Attribute{"Encryption", e.EncryptionAlgorithm().Name})
		}
		info.Children = append(info.Children, ci)
	}

	return info
}
