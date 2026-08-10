package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
)

var (
	oidCommonName        = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidSurname           = asn1.ObjectIdentifier{2, 5, 4, 4}
	oidOrganization      = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidTitle             = asn1.ObjectIdentifier{2, 5, 4, 12}
	oidGivenName         = asn1.ObjectIdentifier{2, 5, 4, 42}
	oidEmail             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	oidINN               = asn1.ObjectIdentifier{1, 2, 643, 3, 131, 1, 1}
	oidINNLegalEntity    = asn1.ObjectIdentifier{1, 2, 643, 100, 4}
	oidOGRN              = asn1.ObjectIdentifier{1, 2, 643, 100, 1}
	oidOGRNIP            = asn1.ObjectIdentifier{1, 2, 643, 100, 5}
	oidSNILS             = asn1.ObjectIdentifier{1, 2, 643, 100, 3}
	oidKeyUsage          = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtendedKeyUsage  = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidCertificatePolicy = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidAuthorityInfo     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidAccessOCSP        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidAccessCAIssuers   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)

type rawCertificate struct {
	TBSCertificate     rawTBSCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type rawTBSCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           rawValidity
	Subject            asn1.RawValue
	PublicKey          rawPublicKeyInfo
	UniqueID           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueID    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"omitempty,optional,explicit,tag:3"`
}

type rawValidity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

type rawPublicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type certificatePolicy struct {
	Policy asn1.ObjectIdentifier
	Rest   asn1.RawValue `asn1:"optional"`
}

type accessDescription struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue
}

func parseCertificate(der []byte, now time.Time) (certificateResponse, bool, error) {
	var raw rawCertificate
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil || len(rest) != 0 || raw.TBSCertificate.SerialNumber == nil {
		return certificateResponse{}, false, fmt.Errorf("invalid DER certificate")
	}

	subject, err := parseName(raw.TBSCertificate.Subject)
	if err != nil {
		return certificateResponse{}, false, err
	}
	issuer, err := parseName(raw.TBSCertificate.Issuer)
	if err != nil {
		return certificateResponse{}, false, err
	}
	attributes := attributesByOID(subject)
	sha1Sum, sha256Sum := sha1.Sum(der), sha256.Sum256(der)
	keyUsage, keyUsagePresent, extendedKeyUsage, policies, issuers, ocsp, err := parseCertificateExtensions(raw.TBSCertificate.Extensions)
	if err != nil {
		return certificateResponse{}, false, err
	}

	response := certificateResponse{
		SubjectDN:          subject.String(),
		IssuerDN:           issuer.String(),
		SerialNumber:       strings.ToUpper(raw.TBSCertificate.SerialNumber.Text(16)),
		ThumbprintSHA1:     strings.ToUpper(hex.EncodeToString(sha1Sum[:])),
		ThumbprintSHA256:   strings.ToUpper(hex.EncodeToString(sha256Sum[:])),
		ValidFrom:          raw.TBSCertificate.Validity.NotBefore.UTC().Format(time.RFC3339),
		ValidTo:            raw.TBSCertificate.Validity.NotAfter.UTC().Format(time.RFC3339),
		IsCurrentlyValid:   !now.Before(raw.TBSCertificate.Validity.NotBefore) && !now.After(raw.TBSCertificate.Validity.NotAfter),
		CommonName:         firstAttribute(attributes, oidCommonName),
		GivenName:          firstAttribute(attributes, oidGivenName),
		Surname:            firstAttribute(attributes, oidSurname),
		Title:              firstAttribute(attributes, oidTitle),
		OrganizationName:   firstAttribute(attributes, oidOrganization),
		Email:              firstAttribute(attributes, oidEmail),
		INN:                firstAttribute(attributes, oidINN, oidINNLegalEntity),
		OGRN:               firstAttribute(attributes, oidOGRN, oidOGRNIP),
		SNILS:              firstAttribute(attributes, oidSNILS),
		PublicKeyAlgorithm: raw.TBSCertificate.PublicKey.Algorithm.Algorithm.String(),
		KeyUsage:           keyUsage,
		ExtendedKeyUsage:   extendedKeyUsage,
		CertificatePolicy:  policies,
		IssuerCertificates: issuers,
		OCSP:               ocsp,
	}
	keyAllowsSigning := !keyUsagePresent || contains(keyUsage, "digitalSignature") || contains(keyUsage, "contentCommitment")
	return response, keyAllowsSigning, nil
}

func parseName(value asn1.RawValue) (pkix.Name, error) {
	var sequence pkix.RDNSequence
	if rest, err := asn1.Unmarshal(value.FullBytes, &sequence); err != nil || len(rest) != 0 {
		return pkix.Name{}, fmt.Errorf("invalid certificate name")
	}
	var name pkix.Name
	name.FillFromRDNSequence(&sequence)
	return name, nil
}

func attributesByOID(name pkix.Name) map[string][]string {
	result := make(map[string][]string)
	for _, attribute := range name.Names {
		value := strings.TrimSpace(fmt.Sprint(attribute.Value))
		if value != "" {
			key := attribute.Type.String()
			result[key] = append(result[key], value)
		}
	}
	return result
}

func firstAttribute(attributes map[string][]string, oids ...asn1.ObjectIdentifier) string {
	for _, oid := range oids {
		if values := attributes[oid.String()]; len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func parseCertificateExtensions(extensions []pkix.Extension) ([]string, bool, []string, []string, []string, []string, error) {
	var keyUsage, extendedKeyUsage, policies, issuers, ocsp []string
	keyUsagePresent := false
	for _, extension := range extensions {
		switch {
		case extension.Id.Equal(oidKeyUsage):
			keyUsagePresent = true
			var bits asn1.BitString
			if rest, err := asn1.Unmarshal(extension.Value, &bits); err != nil || len(rest) != 0 {
				return nil, false, nil, nil, nil, nil, fmt.Errorf("invalid key usage")
			}
			names := []string{"digitalSignature", "contentCommitment", "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "crlSign", "encipherOnly", "decipherOnly"}
			for index, name := range names {
				if bits.At(index) != 0 {
					keyUsage = append(keyUsage, name)
				}
			}
		case extension.Id.Equal(oidExtendedKeyUsage):
			var values []asn1.ObjectIdentifier
			if rest, err := asn1.Unmarshal(extension.Value, &values); err != nil || len(rest) != 0 {
				return nil, false, nil, nil, nil, nil, fmt.Errorf("invalid extended key usage")
			}
			for _, value := range values {
				extendedKeyUsage = append(extendedKeyUsage, value.String())
			}
		case extension.Id.Equal(oidCertificatePolicy):
			var values []certificatePolicy
			if rest, err := asn1.Unmarshal(extension.Value, &values); err != nil || len(rest) != 0 {
				return nil, false, nil, nil, nil, nil, fmt.Errorf("invalid certificate policies")
			}
			for _, value := range values {
				policies = append(policies, value.Policy.String())
			}
		case extension.Id.Equal(oidAuthorityInfo):
			var values []accessDescription
			if rest, err := asn1.Unmarshal(extension.Value, &values); err != nil || len(rest) != 0 {
				return nil, false, nil, nil, nil, nil, fmt.Errorf("invalid authority information access")
			}
			for _, value := range values {
				if value.Location.Class != 2 || value.Location.Tag != 6 {
					continue
				}
				url := string(value.Location.Bytes)
				switch {
				case value.Method.Equal(oidAccessCAIssuers):
					issuers = append(issuers, url)
				case value.Method.Equal(oidAccessOCSP):
					ocsp = append(ocsp, url)
				}
			}
		}
	}
	return keyUsage, keyUsagePresent, extendedKeyUsage, policies, issuers, ocsp, nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
