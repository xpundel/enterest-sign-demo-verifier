package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const maxHelperOutputBytes = 1 << 20

type engineResult struct {
	valid       bool
	code        string
	unavailable bool
	timedOut    bool
	diagnostic  string
	checks      checkResults
	signers     []signerResponse
}

type cadesVerifier struct {
	path    string
	timeout time.Duration
}

func (v cadesVerifier) verify(ctx context.Context, documentPath, signaturePath string) engineResult {
	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, v.path, documentPath, signaturePath)
	cmd.Env = append(os.Environ(), "LANG=C.UTF-8", "LC_ALL=C.UTF-8")
	output := &limitedBuffer{limit: maxHelperOutputBytes}
	diagnostics := &limitedBuffer{limit: 4096}
	cmd.Stdout = output
	cmd.Stderr = diagnostics
	err := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		result := operationalFailure("VERIFICATION_TIMEOUT", false, true)
		result.diagnostic = lastHelperStage(diagnostics.String())
		return result
	}
	var execError *exec.Error
	var pathError *os.PathError
	if errors.As(err, &execError) || errors.As(err, &pathError) {
		return operationalFailure("VERIFIER_UNAVAILABLE", true, false)
	}
	if err != nil {
		result := operationalFailure("CADES_HELPER_FAILED", true, false)
		result.diagnostic = lastHelperStage(diagnostics.String())
		return result
	}

	result, parseErr := parseHelperOutput(output.String(), time.Now())
	if parseErr != nil {
		return operationalFailure("CADES_PROTOCOL_ERROR", true, false)
	}
	return result
}

func lastHelperStage(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for index := len(lines) - 1; index >= 0; index-- {
		line := strings.TrimSpace(lines[index])
		if strings.HasPrefix(line, "stage=") {
			return line
		}
	}
	return ""
}

func parseHelperOutput(output string, now time.Time) (engineResult, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return engineResult{}, fmt.Errorf("empty helper output")
	}
	if fields := strings.Split(lines[0], "\t"); fields[0] == "E" {
		if len(fields) < 2 {
			return engineResult{}, fmt.Errorf("invalid error record")
		}
		return engineResult{code: fields[1], checks: unknownChecks()}, nil
	}

	header := strings.Split(lines[0], "\t")
	if len(header) != 3 || header[0] != "V" || header[1] != "1" {
		return engineResult{}, fmt.Errorf("invalid protocol header")
	}
	count, err := strconv.Atoi(header[2])
	if err != nil || count < 1 || count > 32 || len(lines) != count+1 {
		return engineResult{}, fmt.Errorf("invalid signer count")
	}

	result := engineResult{valid: true, code: "0x00000000", checks: passedChecks()}
	for i := 0; i < count; i++ {
		fields := strings.Split(lines[i+1], "\t")
		if len(fields) != 8 || fields[0] != "S" {
			return engineResult{}, fmt.Errorf("invalid signer record")
		}
		index, err := strconv.Atoi(fields[1])
		if err != nil || index != i {
			return engineResult{}, fmt.Errorf("invalid signer index")
		}
		apiOK := fields[2] == "1"
		status, engineCode := fields[3], fields[4]
		certificateDER, err := hex.DecodeString(fields[7])
		if err != nil || len(certificateDER) == 0 {
			result.valid = false
			result.code = engineCode
			result.checks.SigningCertificate = "failed"
			result.signers = append(result.signers, signerResponse{Index: i, Code: "SIGNER_CERTIFICATE_MISSING", EngineStatus: status, EngineCode: engineCode})
			continue
		}
		certificate, keyAllowsSigning, err := parseCertificate(certificateDER, now)
		if err != nil {
			return engineResult{}, fmt.Errorf("parse signer certificate: %w", err)
		}

		signerValid := apiOK && status == "CADES_VERIFY_SUCCESS" && certificate.IsCurrentlyValid && keyAllowsSigning
		signerCode := signerFailureCode(apiOK, status, certificate.IsCurrentlyValid, keyAllowsSigning)
		signer := signerResponse{
			Index:        i,
			Valid:        signerValid,
			Code:         signerCode,
			EngineStatus: status,
			EngineCode:   engineCode,
			Certificate:  certificate,
		}
		signer.SigningTime = parseUnixTime(fields[5])
		signer.SignatureTimestampTime = parseUnixTime(fields[6])
		result.signers = append(result.signers, signer)
		if !signerValid {
			result.valid = false
			result.code = engineCode
			applyFailedCheck(&result.checks, status, certificate.IsCurrentlyValid, keyAllowsSigning)
		}
	}
	return result, nil
}

func signerFailureCode(apiOK bool, status string, current, keyAllowsSigning bool) string {
	if !apiOK || status != "CADES_VERIFY_SUCCESS" {
		return status
	}
	if !current {
		return "CERTIFICATE_NOT_CURRENTLY_VALID"
	}
	if !keyAllowsSigning {
		return "CERTIFICATE_NOT_ALLOWED_FOR_SIGNING"
	}
	return "VALID"
}

func applyFailedCheck(checks *checkResults, status string, current, keyAllowsSigning bool) {
	if !current {
		checks.CertificatePeriod = "failed"
	}
	if !keyAllowsSigning {
		checks.SigningCertificate = "failed"
	}
	switch status {
	case "CADES_VERIFY_BAD_SIGNATURE":
		checks.ContentBinding, checks.SignatureValue = "failed", "failed"
	case "CADES_VERIFY_NO_CHAIN":
		checks.CertificateChain = "failed"
	case "CADES_VERIFY_END_CERT_REVOCATION", "CADES_VERIFY_CHAIN_CERT_REVOCATION":
		checks.Revocation = "failed"
	case "CADES_VERIFY_SIGNER_NOT_FOUND":
		checks.SigningCertificate = "failed"
	case "CADES_VERIFY_ECONTENTTYPE_NO_MATCH", "CADES_VERIFY_INVALID_REFS_AND_VALUES", "CADES_VERIFY_REFS_AND_VALUES_NO_MATCH":
		checks.CAdESProfile = "failed"
	default:
		if status != "CADES_VERIFY_SUCCESS" {
			unknown := unknownChecks()
			if !current {
				unknown.CertificatePeriod = "failed"
			}
			if !keyAllowsSigning {
				unknown.SigningCertificate = "failed"
			}
			*checks = unknown
		}
	}
}

func parseUnixTime(value string) string {
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || seconds <= 0 {
		return ""
	}
	return time.Unix(seconds, 0).UTC().Format(time.RFC3339)
}

func passedChecks() checkResults {
	return checkResults{"passed", "passed", "passed", "passed", "passed", "passed", "passed", "passed"}
}

func unknownChecks() checkResults {
	return checkResults{"failed_or_unknown", "failed_or_unknown", "failed_or_unknown", "failed_or_unknown", "failed_or_unknown", "failed_or_unknown", "failed_or_unknown", "failed_or_unknown"}
}

func operationalFailure(code string, unavailable, timedOut bool) engineResult {
	return engineResult{code: code, unavailable: unavailable, timedOut: timedOut, checks: unknownChecks()}
}

type limitedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (w *limitedBuffer) Write(p []byte) (int, error) {
	written := len(p)
	remaining := w.limit - w.buffer.Len()
	if remaining > 0 {
		_, _ = w.buffer.Write(p[:min(len(p), remaining)])
	}
	return written, nil
}

func (w *limitedBuffer) String() string { return w.buffer.String() }
