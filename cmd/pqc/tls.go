package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

type clientTLSOptions struct {
	CAFile             string
	ServerName         string
	ClientCertFile     string
	ClientKeyFile      string
	InsecureSkipVerify bool
	PQC                bool
}

func buildClientTLSConfig(opts clientTLSOptions) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         opts.ServerName,
		InsecureSkipVerify: opts.InsecureSkipVerify,
	}
	if opts.PQC {
		cfg.CurvePreferences = hybridPQCPreferredCurves()
	} else {
		cfg.CurvePreferences = classicalCurves()
	}
	if opts.CAFile != "" {
		pool, err := loadCertPool(opts.CAFile)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	if opts.ClientCertFile != "" || opts.ClientKeyFile != "" {
		if opts.ClientCertFile == "" || opts.ClientKeyFile == "" {
			return nil, fmt.Errorf("--tls-client-cert and --tls-client-key must be provided together")
		}
		cert, err := tls.LoadX509KeyPair(opts.ClientCertFile, opts.ClientKeyFile)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

func loadCertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
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
