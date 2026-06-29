package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

type serverTLSOptions struct {
	CertFile          string
	KeyFile           string
	ClientCAFile      string
	RequireClientCert bool
	PQC               bool
}

func buildServerTLSConfig(opts serverTLSOptions) (*tls.Config, bool, error) {
	if opts.CertFile == "" && opts.KeyFile == "" {
		if opts.ClientCAFile != "" || opts.RequireClientCert {
			return nil, false, fmt.Errorf("client certificate options require --tls-cert and --tls-key")
		}
		return nil, false, nil
	}
	if opts.CertFile == "" || opts.KeyFile == "" {
		return nil, false, fmt.Errorf("--tls-cert and --tls-key must be provided together")
	}

	cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
	if err != nil {
		return nil, false, err
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}
	if opts.PQC {
		cfg.CurvePreferences = hybridPQCPreferredCurves()
	} else {
		cfg.CurvePreferences = classicalCurves()
	}

	if opts.ClientCAFile != "" {
		pool, err := loadCertPool(opts.ClientCAFile)
		if err != nil {
			return nil, false, err
		}
		cfg.ClientCAs = pool
		if opts.RequireClientCert {
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			cfg.ClientAuth = tls.VerifyClientCertIfGiven
		}
	} else if opts.RequireClientCert {
		return nil, false, fmt.Errorf("--tls-require-client-cert requires --tls-client-ca")
	}

	return cfg, true, nil
}

func loadCertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}
	return pool, nil
}

func hybridPQCPreferredCurves() []tls.CurveID {
	return []tls.CurveID{
		tls.X25519MLKEM768,
		tls.SecP256r1MLKEM768,
		tls.SecP384r1MLKEM1024,
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	}
}

func classicalCurves() []tls.CurveID {
	return []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	}
}
