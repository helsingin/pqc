package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthenticateRequiresBearerTokenWhenConfigured(t *testing.T) {
	server := &server{bearerToken: "secret"}
	handler := server.authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for name, header := range map[string]string{
		"missing": "",
		"wrong":   "Bearer wrong",
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
			if header != "" {
				req.Header.Set("Authorization", header)
			}
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", res.Code, http.StatusUnauthorized)
			}
		})
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
	req.Header.Set("Authorization", "Bearer secret")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusNoContent)
	}
}

func TestAuthenticatePassesThroughWhenTokenIsUnset(t *testing.T) {
	server := &server{}
	handler := server.authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusNoContent)
	}
}

func TestAuthorizeMapsTLSCertificateIdentityToPolicy(t *testing.T) {
	server := &server{
		authPolicy: &authPolicy{
			DefaultAction: "deny",
			Rules: []policyRule{
				{Identity: "cn:pqc-cli", Allow: []string{"key.list"}},
			},
		},
	}
	handler := server.authorize(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
	req = req.WithContext(withIdentities(req.Context(), "cn:pqc-cli"))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusNoContent {
		t.Fatalf("authorized status = %d", res.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/decrypt", nil)
	req = req.WithContext(withIdentities(req.Context(), "cn:pqc-cli"))
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("denied status = %d, want %d", res.Code, http.StatusForbidden)
	}
}

func TestTLSIdentitiesIncludeCertificateSubjectAndSANs(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{
			Raw: []byte("cert"),
			Subject: pkix.Name{
				CommonName: "pqc-cli",
			},
			DNSNames:       []string{"client.example"},
			EmailAddresses: []string{"ops@example.com"},
		}},
	}
	identities := tlsIdentities(req)
	for _, want := range []string{"cn:pqc-cli", "dns:client.example", "email:ops@example.com"} {
		if !containsIdentity(identities, want) {
			t.Fatalf("identities %v missing %s", identities, want)
		}
	}
}

func containsIdentity(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
