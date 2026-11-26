package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	pqc "github.com/helsingin/pqc"
	filestore "github.com/helsingin/pqc/store/file"
)

func TestSLHDSAHTTPAPI(t *testing.T) {
	for _, algorithm := range []pqc.Algorithm{pqc.AlgorithmSLHDSASHA2192s, pqc.AlgorithmSLHDSASHA2256s} {
		t.Run(string(algorithm), func(t *testing.T) {
			store, err := filestore.New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			s := &server{manager: pqc.NewManager(store), bearerToken: "test-token"}
			post := func(path string, handler http.HandlerFunc, payload any, status int) []byte {
				t.Helper()
				data, err := json.Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(data))
				req.Header.Set("Authorization", "Bearer test-token")
				req.Header.Set("Content-Type", "application/json")
				res := httptest.NewRecorder()
				s.authenticate(handler).ServeHTTP(res, req)
				if res.Code != status {
					t.Fatalf("%s: status %d: %s", path, res.Code, res.Body.String())
				}
				return res.Body.Bytes()
			}
			post("/v1/keys", s.keys, createKeyRequest{ID: "signer", Algorithm: string(algorithm)}, http.StatusOK)
			post("/v1/keys", s.keys, createKeyRequest{ID: "unsupported", Algorithm: "SLH-DSA"}, http.StatusBadRequest)
			message := []byte("HTTP artifact")
			for _, randomized := range []bool{false, true} {
				data := post("/v1/sign", s.sign, signRequest{KeyID: "signer", Message: message, Context: []byte("api-test"), Randomized: randomized}, http.StatusOK)
				var sig pqc.SignatureEnvelope
				if err := json.Unmarshal(data, &sig); err != nil {
					t.Fatal(err)
				}
				if sig.Algorithm != algorithm {
					t.Fatal("algorithm changed")
				}
				post("/v1/verify", s.verify, verifyRequest{Message: message, Signature: sig}, http.StatusOK)
				sig.Context = []byte("wrong")
				post("/v1/verify", s.verify, verifyRequest{Message: message, Signature: sig}, http.StatusBadRequest)
			}
		})
	}
}
