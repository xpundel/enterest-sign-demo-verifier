package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifyEndpointPreservesExactBytes(t *testing.T) {
	document := []byte{0x00, 0xff, '\n', '\r', 0x01}
	signature := []byte{0x30, 0x82, 0x01, 0x00}
	app := application{
		logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		maxDocumentBytes:  1024,
		maxSignatureBytes: 1024,
		verify: func(_ context.Context, documentPath, signaturePath string) engineResult {
			gotDocument, err := os.ReadFile(documentPath)
			if err != nil {
				t.Fatal(err)
			}
			gotSignature, err := os.ReadFile(signaturePath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotDocument, document) || !bytes.Equal(gotSignature, signature) {
				t.Fatal("multipart bytes changed before verification")
			}
			return engineResult{valid: true, code: "0x00000000", checks: passedChecks(), signers: []signerResponse{{Index: 0, Valid: true, Code: "VALID"}}}
		},
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	documentPart, _ := writer.CreateFormFile("document", "document.bin")
	_, _ = documentPart.Write(document)
	signaturePart, _ := writer.CreateFormFile("signature", "document.sig")
	_, _ = signaturePart.Write(signature)
	_ = writer.Close()

	request := httptest.NewRequest(http.MethodPost, "/v1/signatures/verify", body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var result verificationResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.Code != "VALID" || result.Decision != "indeterminate" || result.Authorization.Status != "not_checked" {
		t.Fatalf("unexpected response: %+v", result)
	}
}

func TestHelperProtocolExtractsSignerCertificate(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	der := testCertificate(t, now, x509.KeyUsageDigitalSignature)
	protocol := "V\t1\t1\nS\t0\t1\tCADES_VERIFY_SUCCESS\t0x00000000\t0\t0\t" + hex.EncodeToString(der) + "\n"

	result, err := parseHelperOutput(protocol, now)
	if err != nil {
		t.Fatal(err)
	}
	if !result.valid || len(result.signers) != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	signer := result.signers[0]
	if signer.Certificate.INN != "7700000000" || signer.Certificate.OGRN != "1027700000000" || signer.Certificate.CommonName != "Test Signer" {
		t.Fatalf("unexpected certificate: %+v", signer.Certificate)
	}
	if signer.Certificate.IssuerCertificates[0] != "http://ca.test/root.crt" || signer.Certificate.OCSP[0] != "http://ocsp.test" {
		t.Fatalf("unexpected authority information: %+v", signer.Certificate)
	}
}

func TestCertificateWithoutSigningUsageIsRejected(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	certificate, allowed, err := parseCertificate(testCertificate(t, now, x509.KeyUsageKeyEncipherment), now)
	if err != nil {
		t.Fatal(err)
	}
	if allowed || !certificate.IsCurrentlyValid {
		t.Fatalf("allowed = %v, certificate = %+v", allowed, certificate)
	}
}

func TestCertificateStatusIsCheckedAtCurrentTime(t *testing.T) {
	issuedAt := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	der := testCertificate(t, issuedAt, x509.KeyUsageDigitalSignature)
	protocol := "V\t1\t1\nS\t0\t1\tCADES_VERIFY_SUCCESS\t0x00000000\t0\t0\t" + hex.EncodeToString(der) + "\n"

	result, err := parseHelperOutput(protocol, issuedAt.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if result.valid || result.signers[0].Code != "CERTIFICATE_NOT_CURRENTLY_VALID" || result.checks.CertificatePeriod != "failed" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestLastHelperStageIgnoresUnstructuredOutput(t *testing.T) {
	output := "certificate data that must not be logged\nstage=cms_parsed signer_count=1\nstage=verify_started signer_index=0\n"
	if got := lastHelperStage(output); got != "stage=verify_started signer_index=0" {
		t.Fatalf("unexpected helper stage: %q", got)
	}
}

func TestVerifierRecordsHelperProcessID(t *testing.T) {
	helper := filepath.Join(t.TempDir(), "helper.sh")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf 'E\\tCMS_PARSE_FAILED\\t0x00000000\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	result := (cadesVerifier{path: helper, timeout: time.Second}).verify(t.Context(), "document", "signature")
	if result.helperPID <= 0 || result.code != "CMS_PARSE_FAILED" {
		t.Fatalf("unexpected helper result: %+v", result)
	}
}

func testCertificate(t *testing.T, now time.Time, usage x509.KeyUsage) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			CommonName:   "Test Signer",
			Organization: []string{"Example LLC"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{1, 2, 643, 3, 131, 1, 1}, Value: "7700000000"},
				{Type: asn1.ObjectIdentifier{1, 2, 643, 100, 1}, Value: "1027700000000"},
			},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              usage,
		IssuingCertificateURL: []string{"http://ca.test/root.crt"},
		OCSPServer:            []string{"http://ocsp.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
