package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"strings"
	"time"

	pqc "github.com/helsingin/pqc"
)

type stringList []string

func (l *stringList) String() string {
	return strings.Join(*l, ",")
}

func (l *stringList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("value cannot be empty")
	}
	*l = append(*l, value)
	return nil
}

type inspectTargetOptions struct {
	Targets       stringList
	TLSServerName string
	TLSCAFile     string
	TLSInsecure   bool
	TLSPQC        bool
	TLSTimeout    time.Duration
}

func registerTargetFlags(fs *flag.FlagSet, opts *inspectTargetOptions) {
	fs.Var(&opts.Targets, "target", "TLS endpoint to inspect; repeatable")
	fs.StringVar(&opts.TLSServerName, "target-server-name", "", "override TLS server name for target inspection")
	fs.StringVar(&opts.TLSCAFile, "target-ca", "", "CA PEM file for target TLS verification")
	fs.BoolVar(&opts.TLSInsecure, "target-insecure-skip-verify", false, "skip TLS certificate verification while inspecting targets")
	fs.BoolVar(&opts.TLSPQC, "target-pqc", true, "prefer hybrid PQC key exchange while inspecting targets")
	fs.DurationVar(&opts.TLSTimeout, "target-timeout", 10*time.Second, "TLS inspection timeout")
}

func buildInventoryReport(ctx context.Context, client commandClient, targetOpts inspectTargetOptions, policyID string) (pqc.InventoryReport, error) {
	var keys []pqc.KeyMetadata
	if client != nil {
		var err error
		keys, err = inventoryKeys(ctx, client)
		if err != nil {
			return pqc.InventoryReport{}, err
		}
	}
	targets := make([]pqc.TLSReport, 0, len(targetOpts.Targets))
	var rootCAs *x509.CertPool
	if targetOpts.TLSCAFile != "" {
		var err error
		rootCAs, err = loadCertPool(targetOpts.TLSCAFile)
		if err != nil {
			return pqc.InventoryReport{}, err
		}
	}
	for _, target := range targetOpts.Targets {
		report, err := pqc.InspectTLS(ctx, target, pqc.TLSInspectOptions{
			ServerName:         targetOpts.TLSServerName,
			Timeout:            targetOpts.TLSTimeout,
			InsecureSkipVerify: targetOpts.TLSInsecure,
			PQC:                targetOpts.TLSPQC,
			RootCAs:            rootCAs,
		})
		if err != nil {
			return pqc.InventoryReport{}, fmt.Errorf("inspect %s: %w", target, err)
		}
		targets = append(targets, report)
	}
	now := time.Now().UTC()
	report := pqc.BuildInventoryReport(keys, targets, now)
	if err := pqc.ApplyTLSReadinessPolicy(&report, policyID, now); err != nil {
		return pqc.InventoryReport{}, err
	}
	return report, nil
}

func inventoryNeedsManager(fs *flag.FlagSet, opts clientOptions, targetCount int) bool {
	if targetCount == 0 || opts.Remote != "" {
		return true
	}
	for _, name := range []string{
		"store",
		"store-type",
		"age-passphrase",
		"age-passphrase-file",
		"remote",
		"token",
		"tls-ca",
		"tls-server-name",
		"tls-client-cert",
		"tls-client-key",
		"tls-insecure-skip-verify",
		"tls-pqc",
	} {
		if flagWasSet(fs, name) {
			return true
		}
	}
	return false
}

func inventoryKeys(ctx context.Context, client commandClient) ([]pqc.KeyMetadata, error) {
	keys, err := client.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]pqc.KeyMetadata, 0, len(keys))
	for _, key := range keys {
		publicKey, err := client.ExportPublic(ctx, key.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, pqc.KeyMetadata{
			ID:        publicKey.ID,
			Algorithm: publicKey.Algorithm,
			Use:       publicKey.Use,
			Version:   publicKey.Version,
			PublicKey: append([]byte(nil), publicKey.PublicKey...),
			CreatedAt: publicKey.CreatedAt,
		})
	}
	return out, nil
}

func publicKeyForSignature(ctx context.Context, client commandClient, sig *pqc.SignatureEnvelope) (*pqc.PublicKey, error) {
	if sig == nil {
		return nil, nil
	}
	publicKey, err := client.ExportPublic(ctx, sig.KeyID)
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}
