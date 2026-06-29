package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

type identityContextKey struct{}

type authPolicy struct {
	DefaultAction string       `json:"default_action"`
	Rules         []policyRule `json:"rules"`
}

type policyRule struct {
	Identity string   `json:"identity"`
	Allow    []string `json:"allow"`
	Deny     []string `json:"deny,omitempty"`
}

func loadAuthPolicy(path string) (*authPolicy, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var policy authPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, err
	}
	if policy.DefaultAction == "" {
		policy.DefaultAction = "deny"
	}
	return &policy, nil
}

func (s *server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identities := tlsIdentities(r)
		if s.bearerToken != "" {
			const prefix = "Bearer "
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, prefix) {
				writeError(w, http.StatusUnauthorized, fmt.Errorf("missing bearer token"))
				return
			}
			token := strings.TrimPrefix(header, prefix)
			if subtle.ConstantTimeCompare([]byte(token), []byte(s.bearerToken)) != 1 {
				writeError(w, http.StatusUnauthorized, fmt.Errorf("invalid bearer token"))
				return
			}
			identities = append(identities, "bearer")
		}
		next.ServeHTTP(w, r.WithContext(withIdentities(r.Context(), identities...)))
	})
}

func (s *server) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.authPolicy == nil {
			next.ServeHTTP(w, r)
			return
		}
		operation, ok := operationForRequest(r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		if !s.authPolicy.Allows(identitiesFromContext(r.Context()), operation) {
			writeError(w, http.StatusForbidden, fmt.Errorf("operation %q is not authorized", operation))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (p *authPolicy) Allows(identities []string, operation string) bool {
	for _, identity := range identities {
		for _, rule := range p.Rules {
			if rule.Identity != identity {
				continue
			}
			if matchesAny(rule.Deny, operation) {
				return false
			}
			if matchesAny(rule.Allow, operation) {
				return true
			}
		}
	}
	return strings.EqualFold(p.DefaultAction, "allow")
}

func matchesAny(patterns []string, operation string) bool {
	for _, pattern := range patterns {
		if pattern == "*" || pattern == operation {
			return true
		}
		if strings.HasSuffix(pattern, ".*") && strings.HasPrefix(operation, strings.TrimSuffix(pattern, "*")) {
			return true
		}
	}
	return false
}

func operationForRequest(r *http.Request) (string, bool) {
	switch {
	case r.URL.Path == "/v1/keys" && r.Method == http.MethodGet:
		return "key.list", true
	case r.URL.Path == "/v1/keys" && r.Method == http.MethodPost:
		return "key.create", true
	case strings.HasPrefix(r.URL.Path, "/v1/keys/") && strings.HasSuffix(r.URL.Path, "/rotate") && r.Method == http.MethodPost:
		return "key.rotate", true
	case strings.HasPrefix(r.URL.Path, "/v1/keys/") && r.Method == http.MethodGet:
		return "key.get", true
	case r.URL.Path == "/v1/encrypt" && r.Method == http.MethodPost:
		return "encrypt", true
	case r.URL.Path == "/v1/decrypt" && r.Method == http.MethodPost:
		return "decrypt", true
	case r.URL.Path == "/v1/sign" && r.Method == http.MethodPost:
		return "sign", true
	case r.URL.Path == "/v1/verify" && r.Method == http.MethodPost:
		return "verify", true
	default:
		return "", false
	}
}

func tlsIdentities(r *http.Request) []string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	identities := make([]string, 0)
	for _, cert := range r.TLS.PeerCertificates {
		if cert.Subject.CommonName != "" {
			identities = append(identities, "cn:"+cert.Subject.CommonName)
		}
		for _, name := range cert.DNSNames {
			identities = append(identities, "dns:"+name)
		}
		for _, email := range cert.EmailAddresses {
			identities = append(identities, "email:"+email)
		}
		for _, uri := range cert.URIs {
			identities = append(identities, "uri:"+uri.String())
		}
		sum := sha256.Sum256(cert.Raw)
		identities = append(identities, "x509-fingerprint:sha256:"+hex.EncodeToString(sum[:]))
	}
	return identities
}

func withIdentities(ctx context.Context, values ...string) context.Context {
	if len(values) == 0 {
		return ctx
	}
	existing := identitiesFromContext(ctx)
	combined := append(append([]string(nil), existing...), values...)
	return context.WithValue(ctx, identityContextKey{}, combined)
}

func identitiesFromContext(ctx context.Context) []string {
	values, _ := ctx.Value(identityContextKey{}).([]string)
	return values
}
