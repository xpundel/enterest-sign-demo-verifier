package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

const (
	defaultListenAddr        = ":8080"
	defaultHelperPath        = "/usr/local/bin/cades-verify"
	defaultVerifyTimeout     = 30 * time.Second
	defaultMaxDocumentBytes  = int64(25 << 20)
	defaultMaxSignatureBytes = int64(5 << 20)
)

type checkResults struct {
	CMS                string `json:"cms"`
	ContentBinding     string `json:"contentBinding"`
	SignatureValue     string `json:"signatureValue"`
	CAdESProfile       string `json:"cadesProfile"`
	CertificatePeriod  string `json:"certificatePeriod"`
	CertificateChain   string `json:"certificateChain"`
	Revocation         string `json:"revocation"`
	SigningCertificate string `json:"signingCertificate"`
}

type certificateResponse struct {
	SubjectDN          string   `json:"subjectDn"`
	IssuerDN           string   `json:"issuerDn"`
	SerialNumber       string   `json:"serialNumber"`
	ThumbprintSHA1     string   `json:"thumbprintSha1"`
	ThumbprintSHA256   string   `json:"thumbprintSha256"`
	ValidFrom          string   `json:"validFrom"`
	ValidTo            string   `json:"validTo"`
	IsCurrentlyValid   bool     `json:"isCurrentlyValid"`
	CommonName         string   `json:"commonName,omitempty"`
	GivenName          string   `json:"givenName,omitempty"`
	Surname            string   `json:"surname,omitempty"`
	Title              string   `json:"title,omitempty"`
	OrganizationName   string   `json:"organizationName,omitempty"`
	Email              string   `json:"email,omitempty"`
	INN                string   `json:"inn,omitempty"`
	OGRN               string   `json:"ogrn,omitempty"`
	SNILS              string   `json:"snils,omitempty"`
	PublicKeyAlgorithm string   `json:"publicKeyAlgorithmOid"`
	KeyUsage           []string `json:"keyUsage,omitempty"`
	ExtendedKeyUsage   []string `json:"extendedKeyUsageOids,omitempty"`
	CertificatePolicy  []string `json:"certificatePolicyOids,omitempty"`
	IssuerCertificates []string `json:"issuerCertificateUrls,omitempty"`
	OCSP               []string `json:"ocspUrls,omitempty"`
}

type signerResponse struct {
	Index                  int                 `json:"index"`
	Valid                  bool                `json:"valid"`
	Code                   string              `json:"code"`
	EngineStatus           string              `json:"engineStatus"`
	EngineCode             string              `json:"engineCode,omitempty"`
	SigningTime            string              `json:"signingTime,omitempty"`
	SignatureTimestampTime string              `json:"signatureTimestampTime,omitempty"`
	Certificate            certificateResponse `json:"certificate"`
}

type authorizationResult struct {
	Status string `json:"status"`
	Code   string `json:"code"`
}

type verificationResponse struct {
	RequestID     string              `json:"requestId"`
	Decision      string              `json:"decision"`
	Valid         bool                `json:"valid"`
	Code          string              `json:"code"`
	Profile       string              `json:"profile"`
	Detached      bool                `json:"detached"`
	Checks        checkResults        `json:"checks"`
	Signers       []signerResponse    `json:"signers"`
	Authorization authorizationResult `json:"authorization"`
	Engine        string              `json:"engine"`
	EngineCode    string              `json:"engineCode,omitempty"`
}

type application struct {
	logger            *slog.Logger
	helperPath        string
	maxDocumentBytes  int64
	maxSignatureBytes int64
	verify            func(context.Context, string, string) engineResult
}

func (app application) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", app.handleLive)
	mux.HandleFunc("GET /health/ready", app.handleReady)
	mux.HandleFunc("POST /v1/signatures/verify", app.handleVerify)
	return mux
}

func (app application) handleLive(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (app application) handleReady(w http.ResponseWriter, _ *http.Request) {
	info, err := os.Stat(app.helperPath)
	if err != nil || info.Mode()&0o111 == 0 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (app application) handleVerify(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	requestID := newRequestID()
	parentRequestID := r.Header.Get("X-Parent-Request-ID")
	status, code, engineCode, signerCount := http.StatusInternalServerError, "INTERNAL_ERROR", "", 0
	valid := false
	defer func() {
		app.logger.Info("signature verification request completed",
			"request_id", requestID,
			"parent_request_id", parentRequestID,
			"status", status,
			"valid", valid,
			"code", code,
			"engine_code", engineCode,
			"signer_count", signerCount,
			"duration_ms", time.Since(started).Milliseconds(),
		)
	}()
	w.Header().Set("X-Request-ID", requestID)
	r.Body = http.MaxBytesReader(w, r.Body, app.maxDocumentBytes+app.maxSignatureBytes+(1<<20))

	tempDir, err := os.MkdirTemp("", "signature-verifier-")
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, requestID, "INTERNAL_ERROR")
		return
	}
	defer os.RemoveAll(tempDir)

	documentPath, signaturePath, err := readMultipartFiles(r, tempDir, app.maxDocumentBytes, app.maxSignatureBytes)
	if err != nil {
		status, code = http.StatusBadRequest, "INVALID_INPUT"
		writeAPIError(w, http.StatusBadRequest, requestID, "INVALID_INPUT")
		return
	}
	documentInfo, _ := os.Stat(documentPath)
	signatureInfo, _ := os.Stat(signaturePath)
	app.logger.Info("signature verification started",
		"request_id", requestID,
		"parent_request_id", parentRequestID,
		"document_bytes", documentInfo.Size(),
		"signature_bytes", signatureInfo.Size(),
	)

	result := app.verify(r.Context(), documentPath, signaturePath)
	if result.diagnostic != "" {
		app.logger.Warn("signature verification helper diagnostic",
			"request_id", requestID,
			"parent_request_id", parentRequestID,
			"engine_code", result.code,
			"helper_stage", result.diagnostic,
		)
	}
	status = http.StatusOK
	decision := "rejected"
	code = "SIGNATURE_INVALID"
	if result.valid {
		decision = "indeterminate"
		code = "VALID"
	} else if result.timedOut {
		status, decision, code = http.StatusGatewayTimeout, "indeterminate", "VERIFICATION_TIMEOUT"
	} else if result.unavailable {
		status, decision, code = http.StatusServiceUnavailable, "indeterminate", "VERIFIER_UNAVAILABLE"
	}
	authorization := authorizationResult{Status: "not_checked", Code: "EXTERNAL_AUTHORIZATION_REQUIRED"}
	if !result.valid && !result.timedOut && !result.unavailable {
		authorization = authorizationResult{Status: "not_applicable", Code: "SIGNATURE_INVALID"}
	}

	writeJSON(w, status, verificationResponse{
		RequestID:     requestID,
		Decision:      decision,
		Valid:         result.valid,
		Code:          code,
		Profile:       "CAdES-BES",
		Detached:      true,
		Checks:        result.checks,
		Signers:       result.signers,
		Authorization: authorization,
		Engine:        "cryptopro-cades",
		EngineCode:    result.code,
	})
	valid, engineCode, signerCount = result.valid, result.code, len(result.signers)
}

func readMultipartFiles(r *http.Request, tempDir string, maxDocumentBytes, maxSignatureBytes int64) (string, string, error) {
	reader, err := r.MultipartReader()
	if err != nil {
		return "", "", err
	}

	var documentPath, signaturePath string
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", "", err
		}

		var target *string
		var filename string
		var limit int64
		switch part.FormName() {
		case "document":
			target, filename, limit = &documentPath, "document.bin", maxDocumentBytes
		case "signature":
			target, filename, limit = &signaturePath, "signature.p7s", maxSignatureBytes
		default:
			_ = part.Close()
			return "", "", fmt.Errorf("unexpected multipart field")
		}
		if *target != "" {
			_ = part.Close()
			return "", "", fmt.Errorf("duplicate multipart field")
		}

		path := filepath.Join(tempDir, filename)
		if err := copyPart(path, part, limit); err != nil {
			_ = part.Close()
			return "", "", err
		}
		_ = part.Close()
		*target = path
	}

	if documentPath == "" || signaturePath == "" {
		return "", "", fmt.Errorf("document and signature are required")
	}
	info, err := os.Stat(signaturePath)
	if err != nil || info.Size() == 0 {
		return "", "", fmt.Errorf("signature is empty")
	}
	return documentPath, signaturePath, nil
}

func copyPart(path string, source *multipart.Part, limit int64) error {
	target, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(target, io.LimitReader(source, limit+1))
	closeErr := target.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written > limit {
		return fmt.Errorf("multipart field exceeds limit")
	}
	return nil
}

func writeAPIError(w http.ResponseWriter, status int, requestID, code string) {
	writeJSON(w, status, map[string]any{"requestId": requestID, "valid": false, "code": code})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func newRequestID() string {
	value := make([]byte, 8)
	if _, err := rand.Read(value); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(value)
}

func envInt64(name string, fallback int64) int64 {
	value, err := strconv.ParseInt(os.Getenv(name), 10, 64)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func envDuration(name string, fallback time.Duration) time.Duration {
	value, err := time.ParseDuration(os.Getenv(name))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	helperPath := os.Getenv("CADES_HELPER_PATH")
	if helperPath == "" {
		helperPath = defaultHelperPath
	}
	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}

	verifier := cadesVerifier{path: helperPath, timeout: envDuration("VERIFY_TIMEOUT", defaultVerifyTimeout)}
	app := application{
		logger:            logger,
		helperPath:        helperPath,
		maxDocumentBytes:  envInt64("MAX_DOCUMENT_BYTES", defaultMaxDocumentBytes),
		maxSignatureBytes: envInt64("MAX_SIGNATURE_BYTES", defaultMaxSignatureBytes),
		verify:            verifier.verify,
	}
	server := &http.Server{
		Addr:              listenAddr,
		Handler:           app.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	logger.Info("signature verifier started", "listen_addr", listenAddr, "engine", "cryptopro-cades", "verify_timeout", verifier.timeout)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("signature verifier stopped", "error", err)
		os.Exit(1)
	}
}
