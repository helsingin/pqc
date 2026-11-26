package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	pqc "github.com/helsingin/pqc"
)

type remoteClient struct {
	baseURL string
	token   string
	client  *http.Client
}

type remoteError struct {
	Error        string          `json:"error"`
	AuditFailure *pqc.AuditEvent `json:"audit_failure"`
	Result       json.RawMessage `json:"result"`
}

type remoteEncryptRequest struct {
	KeyID     string `json:"key_id"`
	Plaintext []byte `json:"plaintext"`
	AAD       []byte `json:"aad,omitempty"`
}

type remoteDecryptRequest struct {
	Envelope pqc.Envelope `json:"envelope"`
	AAD      []byte       `json:"aad,omitempty"`
}

type remoteDecryptResponse struct {
	Plaintext []byte `json:"plaintext"`
}

type remoteSignRequest struct {
	KeyID      string `json:"key_id"`
	Message    []byte `json:"message"`
	Context    []byte `json:"context,omitempty"`
	Randomized bool   `json:"randomized,omitempty"`
}

type remoteVerifyRequest struct {
	Message   []byte                `json:"message"`
	Signature pqc.SignatureEnvelope `json:"signature"`
}

func newRemoteClient(baseURL, token string, tlsOpts clientTLSOptions) (*remoteClient, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("--remote must use http or https URL")
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("--remote URL must include a host")
	}
	httpClient, err := newHTTPClient(parsed.Scheme, tlsOpts)
	if err != nil {
		return nil, err
	}
	return &remoteClient{
		baseURL: strings.TrimRight(parsed.String(), "/"),
		token:   token,
		client:  httpClient,
	}, nil
}

func newHTTPClient(scheme string, tlsOpts clientTLSOptions) (*http.Client, error) {
	if scheme != "https" {
		if tlsOpts.CAFile != "" || tlsOpts.ServerName != "" || tlsOpts.InsecureSkipVerify {
			return nil, fmt.Errorf("TLS options require an https --remote URL")
		}
		return http.DefaultClient, nil
	}
	cfg, err := buildClientTLSConfig(tlsOpts)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = cfg
	transport.ForceAttemptHTTP2 = true
	return &http.Client{Transport: transport}, nil
}

func (c *remoteClient) Generate(ctx context.Context, req pqc.GenerateRequest) (*pqc.KeyMetadata, error) {
	body := struct {
		ID        string `json:"id"`
		Algorithm string `json:"algorithm"`
	}{
		ID:        req.ID,
		Algorithm: string(req.Algorithm),
	}
	var out pqc.KeyMetadata
	if err := c.do(ctx, http.MethodPost, "/v1/keys", body, &out); err != nil {
		if completedAuditFailure(err) {
			return &out, err
		}
		return nil, err
	}
	return &out, nil
}

func (c *remoteClient) Rotate(ctx context.Context, id string) (*pqc.KeyMetadata, error) {
	var out pqc.KeyMetadata
	if err := c.do(ctx, http.MethodPost, "/v1/keys/"+url.PathEscape(id)+"/rotate", nil, &out); err != nil {
		if completedAuditFailure(err) {
			return &out, err
		}
		return nil, err
	}
	return &out, nil
}

func (c *remoteClient) Get(ctx context.Context, id string) (*pqc.KeyMetadata, error) {
	var out pqc.KeyMetadata
	if err := c.do(ctx, http.MethodGet, "/v1/keys/"+url.PathEscape(id), nil, &out); err != nil {
		if completedAuditFailure(err) {
			return &out, err
		}
		return nil, err
	}
	return &out, nil
}

func (c *remoteClient) List(ctx context.Context) ([]pqc.KeyMetadata, error) {
	var out []pqc.KeyMetadata
	if err := c.do(ctx, http.MethodGet, "/v1/keys", nil, &out); err != nil {
		if completedAuditFailure(err) {
			return out, err
		}
		return nil, err
	}
	return out, nil
}

func (c *remoteClient) ExportPublic(ctx context.Context, id string) (*pqc.PublicKey, error) {
	meta, err := c.Get(ctx, id)
	if meta == nil {
		return nil, err
	}
	return &pqc.PublicKey{
		ID:        meta.ID,
		Algorithm: meta.Algorithm,
		Use:       meta.Use,
		Version:   meta.Version,
		PublicKey: append([]byte(nil), meta.PublicKey...),
		CreatedAt: meta.CreatedAt,
	}, err
}

func (c *remoteClient) Encrypt(ctx context.Context, keyID string, plaintext []byte, opts pqc.EncryptOptions) (*pqc.Envelope, error) {
	var out pqc.Envelope
	if err := c.do(ctx, http.MethodPost, "/v1/encrypt", remoteEncryptRequest{
		KeyID:     keyID,
		Plaintext: plaintext,
		AAD:       opts.AAD,
	}, &out); err != nil {
		if completedAuditFailure(err) {
			return &out, err
		}
		return nil, err
	}
	return &out, nil
}

func (c *remoteClient) Decrypt(ctx context.Context, envelope *pqc.Envelope, opts pqc.EncryptOptions) ([]byte, error) {
	var out remoteDecryptResponse
	if err := c.do(ctx, http.MethodPost, "/v1/decrypt", remoteDecryptRequest{
		Envelope: *envelope,
		AAD:      opts.AAD,
	}, &out); err != nil {
		if completedAuditFailure(err) {
			return out.Plaintext, err
		}
		return nil, err
	}
	return out.Plaintext, nil
}

func (c *remoteClient) Sign(ctx context.Context, keyID string, message []byte, opts pqc.SignOptions) (*pqc.SignatureEnvelope, error) {
	var out pqc.SignatureEnvelope
	if err := c.do(ctx, http.MethodPost, "/v1/sign", remoteSignRequest{
		KeyID:      keyID,
		Message:    message,
		Context:    opts.Context,
		Randomized: opts.Randomized,
	}, &out); err != nil {
		if completedAuditFailure(err) {
			return &out, err
		}
		return nil, err
	}
	return &out, nil
}

func (c *remoteClient) Verify(ctx context.Context, message []byte, sig *pqc.SignatureEnvelope) error {
	return c.do(ctx, http.MethodPost, "/v1/verify", remoteVerifyRequest{
		Message:   message,
		Signature: *sig,
	}, nil)
}

func (c *remoteClient) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(in); err != nil {
			return err
		}
		body = &buf
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	res, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var remoteErr remoteError
		if decodeErr := json.NewDecoder(res.Body).Decode(&remoteErr); decodeErr == nil && remoteErr.Error != "" {
			if remoteErr.AuditFailure != nil {
				failure := &pqc.AuditFailure{Event: *remoteErr.AuditFailure, Cause: fmt.Errorf("remote %s: %s", res.Status, remoteErr.Error)}
				if out != nil && failure.Event.Outcome == pqc.AuditSucceeded {
					if len(remoteErr.Result) == 0 || string(remoteErr.Result) == "null" {
						return fmt.Errorf("remote operation succeeded but result is unavailable; audit event %s; do not repeat operation", failure.Event.ID)
					}
					if err := json.Unmarshal(remoteErr.Result, out); err != nil {
						return fmt.Errorf("remote operation succeeded but result cannot be decoded; audit event %s; do not repeat operation: %v", failure.Event.ID, err)
					}
				}
				return failure
			}
			return fmt.Errorf("remote %s: %s", res.Status, remoteErr.Error)
		}
		return fmt.Errorf("remote %s; operation outcome may be unknown", res.Status)
	}

	if out == nil {
		return nil
	}
	decoder := json.NewDecoder(res.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(out)
}

func completedAuditFailure(err error) bool {
	var failure *pqc.AuditFailure
	return errors.As(err, &failure) && failure.Event.Outcome == pqc.AuditSucceeded
}
