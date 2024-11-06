package names

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/edutko/decipher/internal/oid"
)

func FromRawDN(dn []byte) string {
	var rdns pkix.RDNSequence
	rest, err := asn1.Unmarshal(dn, &rdns)
	if err != nil || len(rest) > 0 {
		return hex.EncodeToString(dn)
	}
	return FromRDNSequence(rdns)
}

func FromRDNSequence(rdns pkix.RDNSequence) string {
	var ss []string
	for i := len(rdns) - 1; i >= 0; i-- {
		for _, atv := range rdns[i] {
			name := x500AttrTypeFromOID(atv.Type)
			value := escapeRDNAttrValue(fmt.Sprintf("%s", atv.Value))
			ss = append(ss, fmt.Sprintf("%s=%s", name, value))
		}
	}
	return strings.Join(ss, ",")
}

func escapeRDNAttrValue(s string) string {
	escaped := make([]rune, 0, len(s))
	for k, c := range s {
		escape := false

		switch c {
		case ',', '+', '"', '\\', '<', '>', ';':
			escape = true

		case ' ':
			escape = k == 0 || k == len(s)-1

		case '#':
			escape = k == 0
		}

		if escape {
			escaped = append(escaped, '\\', c)
		} else {
			escaped = append(escaped, c)
		}
	}
	return string(escaped)
}

func x500AttrTypeFromOID(id asn1.ObjectIdentifier) string {
	if name, ok := X500AttrTypesByOid[id.String()]; ok {
		return name
	}
	return id.String()
}

var X500AttrTypesByOid = map[string]string{
	oid.X500AttrObjectClass.String():                        "objectClass",
	oid.X500AttrAliasedEntryName.String():                   "aliasedEntryName",
	oid.X500AttrKnowledgeInformation.String():               "knowledgeInformation",
	oid.X500AttrCommonName.String():                         "CN",
	oid.X500AttrSurname.String():                            "surname",
	oid.X500AttrSerialNumber.String():                       "serialNumber",
	oid.X500AttrCountryName.String():                        "C",
	oid.X500AttrLocalityName.String():                       "L",
	oid.X500AttrStateOrProvinceName.String():                "ST",
	oid.X500AttrStreetAddress.String():                      "streetAddress",
	oid.X500AttrOrganizationName.String():                   "O",
	oid.X500AttrOrganizationUnitName.String():               "OU",
	oid.X500AttrTitle.String():                              "title",
	oid.X500AttrDescription.String():                        "description",
	oid.X500AttrSearchGuide.String():                        "searchGuide",
	oid.X500AttrBusinessCategory.String():                   "businessCategory",
	oid.X500AttrPostalAddress.String():                      "postalAddress",
	oid.X500AttrPostalCode.String():                         "postalCode",
	oid.X500AttrPostOfficeBox.String():                      "postOfficeBox",
	oid.X500AttrPhysicalDeliveryOfficeName.String():         "physicalDeliveryOfficeName",
	oid.X500AttrTelephoneNumber.String():                    "telephoneNumber",
	oid.X500AttrTelexNumber.String():                        "telexNumber",
	oid.X500AttrTeletexTerminalIdentifier.String():          "teletexTerminalIdentifier",
	oid.X500AttrFacsimileTelephoneNumber.String():           "facsimileTelephoneNumber",
	oid.X500AttrX121Address.String():                        "x121Address",
	oid.X500AttrInternationalISDNNumber.String():            "internationalISDNNumber",
	oid.X500AttrRegisteredAddress.String():                  "registeredAddress",
	oid.X500AttrDestinationIndicator.String():               "destinationIndicator",
	oid.X500AttrPreferredDeliveryMethod.String():            "preferredDeliveryMethod",
	oid.X500AttrPresentationAddress.String():                "presentationAddress",
	oid.X500AttrSupportedApplicationContext.String():        "supportedApplicationContext",
	oid.X500AttrMember.String():                             "member",
	oid.X500AttrOwner.String():                              "owner",
	oid.X500AttrRoleOccupant.String():                       "roleOccupant",
	oid.X500AttrSeeAlso.String():                            "seeAlso",
	oid.X500AttrUserPassword.String():                       "userPassword",
	oid.X500AttrUserCertificate.String():                    "userCertificate",
	oid.X500AttrCACertificate.String():                      "cACertificate",
	oid.X500AttrAuthorityRevocationList.String():            "authorityRevocationList",
	oid.X500AttrCertificateRevocationList.String():          "certificateRevocationList",
	oid.X500AttrCrossCertificatePair.String():               "crossCertificatePair",
	oid.X500AttrName.String():                               "name",
	oid.X500AttrGivenName.String():                          "givenName",
	oid.X500AttrInitials.String():                           "initials",
	oid.X500AttrGenerationQualifier.String():                "generationQualifier",
	oid.X500AttrUniqueIdentifier.String():                   "uniqueIdentifier",
	oid.X500AttrDnQualifier.String():                        "dnQualifier",
	oid.X500AttrEnhancedSearchGuide.String():                "enhancedSearchGuide",
	oid.X500AttrProtocolInformation.String():                "protocolInformation",
	oid.X500AttrDistinguishedName.String():                  "distinguishedName",
	oid.X500AttrUniqueMember.String():                       "uniqueMember",
	oid.X500AttrHouseIdentifier.String():                    "houseIdentifier",
	oid.X500AttrSupportedAlgorithms.String():                "supportedAlgorithms",
	oid.X500AttrDeltaRevocationList.String():                "deltaRevocationList",
	oid.X500AttrDmdName.String():                            "dmdName",
	oid.X500AttrClearance.String():                          "clearance",
	oid.X500AttrDefaultDirQop.String():                      "defaultDirQop",
	oid.X500AttrAttributeIntegrityInfo.String():             "attributeIntegrityInfo",
	oid.X500AttrAttributeCertificate.String():               "attributeCertificate",
	oid.X500AttrAttributeCertificateRevocationList.String(): "attributeCertificateRevocationList",
	oid.X500AttrConfKeyInfo.String():                        "confKeyInfo",
	oid.X500AttrAACertificate.String():                      "aACertificate",
	oid.X500AttrAttributeDescriptorCertificate.String():     "attributeDescriptorCertificate",
	oid.X500AttrAttributeAuthorityRevocationList.String():   "attributeAuthorityRevocationList",
	oid.X500AttrFamilyInformation.String():                  "family-information",
	oid.X500AttrPseudonym.String():                          "pseudonym",
	oid.X500AttrCommunicationsService.String():              "communicationsService",
	oid.X500AttrCommunicationsNetwork.String():              "communicationsNetwork",
	oid.X500AttrCertificationPracticeStmt.String():          "certificationPracticeStmt",
	oid.X500AttrCertificatePolicy.String():                  "certificatePolicy",
	oid.X500AttrPkiPath.String():                            "pkiPath",
	oid.X500AttrPrivPolicy.String():                         "privPolicy",
	oid.X500AttrRole.String():                               "role",
	oid.X500AttrDelegationPath.String():                     "delegationPath",
	oid.X500AttrProtPrivPolicy.String():                     "protPrivPolicy",
	oid.X500AttrXMLPrivilegeInfo.String():                   "xMLPrivilegeInfo",
	oid.X500AttrXmlPrivPolicy.String():                      "xmlPrivPolicy",
	oid.X500AttrUuidpair.String():                           "uuidpair",
	oid.X500AttrTagOid.String():                             "tagOid",
	oid.X500AttrUiiFormat.String():                          "uiiFormat",
	oid.X500AttrUiiInUrh.String():                           "uiiInUrh",
	oid.X500AttrContentUrl.String():                         "contentUrl",
	oid.X500AttrPermission.String():                         "permission",
	oid.X500AttrUri.String():                                "uri",
	oid.X500AttrPwdAttribute.String():                       "pwdAttribute",
	oid.X500AttrUserPwd.String():                            "userPwd",
	oid.X500AttrUrn.String():                                "urn",
	oid.X500AttrUrl.String():                                "url",
	oid.X500AttrUtmCoordinates.String():                     "utmCoordinates",
	oid.X500AttrUrnC.String():                               "urnC",
	oid.X500AttrUii.String():                                "uii",
	oid.X500AttrEpc.String():                                "epc",
	oid.X500AttrTagAfi.String():                             "tagAfi",
	oid.X500AttrEpcFormat.String():                          "epcFormat",
	oid.X500AttrEpcInUrn.String():                           "epcInUrn",
	oid.X500AttrLdapUrl1.String():                           "ldapUrl",
	oid.X500AttrLdapUrl2.String():                           "ldapUrl",
	oid.X500AttrOrganizationIdentifier.String():             "organizationIdentifier",
}
