package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	pqc "github.com/helsingin/pqc"
	agefilestore "github.com/helsingin/pqc/store/agefile"
	filestore "github.com/helsingin/pqc/store/file"
)

type commandClient interface {
	Generate(context.Context, pqc.GenerateRequest) (*pqc.KeyMetadata, error)
	Rotate(context.Context, string) (*pqc.KeyMetadata, error)
	Get(context.Context, string) (*pqc.KeyMetadata, error)
	List(context.Context) ([]pqc.KeyMetadata, error)
	ExportPublic(context.Context, string) (*pqc.PublicKey, error)
	Encrypt(context.Context, string, []byte, pqc.EncryptOptions) (*pqc.Envelope, error)
	Decrypt(context.Context, *pqc.Envelope, pqc.EncryptOptions) ([]byte, error)
	Sign(context.Context, string, []byte, pqc.SignOptions) (*pqc.SignatureEnvelope, error)
	Verify(context.Context, []byte, *pqc.SignatureEnvelope) error
}

type clientOptions struct {
	StoreDir          string
	StoreType         string
	AgePassphrase     string
	AgePassphraseFile string
	AuditLog          string
	Remote            string
	Token             string
	TLS               clientTLSOptions
}

func registerClientFlags(fs *flag.FlagSet, opts *clientOptions) {
	registerClientAccessFlags(fs, opts)
	fs.StringVar(&opts.AuditLog, "audit-log", os.Getenv("PQC_AUDIT_LOG"), "append metadata-only JSONL audit events")
}

func registerClientAccessFlags(fs *flag.FlagSet, opts *clientOptions) {
	fs.StringVar(&opts.StoreDir, "store", "", "key store directory (default: $PQC_STORE_DIR or ~/.pqc/keys)")
	fs.StringVar(&opts.StoreType, "store-type", getenvDefault("PQC_STORE_TYPE", "file"), "store type: file or age")
	fs.StringVar(&opts.AgePassphrase, "age-passphrase", os.Getenv("PQC_AGE_PASSPHRASE"), "age store passphrase")
	fs.StringVar(&opts.AgePassphraseFile, "age-passphrase-file", os.Getenv("PQC_AGE_PASSPHRASE_FILE"), "file containing age store passphrase")
	fs.StringVar(&opts.Remote, "remote", os.Getenv("PQC_REMOTE"), "pqcd base URL")
	fs.StringVar(&opts.Token, "token", os.Getenv("PQC_API_TOKEN"), "bearer token for --remote")
	fs.StringVar(&opts.TLS.CAFile, "tls-ca", os.Getenv("PQC_TLS_CA"), "CA PEM file for verifying --remote HTTPS server")
	fs.StringVar(&opts.TLS.ServerName, "tls-server-name", os.Getenv("PQC_TLS_SERVER_NAME"), "override HTTPS server name verification")
	fs.StringVar(&opts.TLS.ClientCertFile, "tls-client-cert", os.Getenv("PQC_TLS_CLIENT_CERT"), "client certificate PEM file for remote mTLS")
	fs.StringVar(&opts.TLS.ClientKeyFile, "tls-client-key", os.Getenv("PQC_TLS_CLIENT_KEY"), "client private key PEM file for remote mTLS")
	fs.BoolVar(&opts.TLS.InsecureSkipVerify, "tls-insecure-skip-verify", getenvBool("PQC_TLS_INSECURE_SKIP_VERIFY", false), "skip HTTPS certificate verification for testing")
	fs.BoolVar(&opts.TLS.PQC, "tls-pqc", getenvBool("PQC_TLS_PQC", true), "prefer TLS 1.3 hybrid post-quantum key exchange groups")
}

func openCommandClient(fs *flag.FlagSet, opts clientOptions) (commandClient, error) {
	if opts.Remote != "" {
		if err := rejectLocalFlagsInRemoteMode(fs); err != nil {
			return nil, err
		}
		return newRemoteClient(opts.Remote, opts.Token, opts.TLS)
	}
	if flagWasSet(fs, "token") {
		return nil, fmt.Errorf("--token requires --remote")
	}
	for _, name := range []string{"tls-ca", "tls-server-name", "tls-client-cert", "tls-client-key", "tls-insecure-skip-verify", "tls-pqc"} {
		if flagWasSet(fs, name) {
			return nil, fmt.Errorf("--%s requires --remote", name)
		}
	}
	return openManager(opts.StoreDir, opts.StoreType, opts.AgePassphrase, opts.AgePassphraseFile, opts.AuditLog)
}

func rejectLocalFlagsInRemoteMode(fs *flag.FlagSet) error {
	for _, name := range []string{"store", "store-type", "age-passphrase", "age-passphrase-file", "audit-log"} {
		if flagWasSet(fs, name) {
			return fmt.Errorf("--%s cannot be used with --remote; configure storage and audit on pqcd", name)
		}
	}
	return nil
}

func flagWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func openManager(storeDir, storeType, agePassphrase, agePassphraseFile, auditPath string) (*pqc.Manager, error) {
	if storeDir == "" {
		var err error
		storeDir, err = filestore.DefaultDir()
		if err != nil {
			return nil, err
		}
	}
	store, err := openStore(storeDir, storeType, agePassphrase, agePassphraseFile)
	if err != nil {
		return nil, err
	}
	opts := []pqc.Option{}
	if auditPath != "" {
		auditor, err := pqc.NewFileAuditor(auditPath)
		if err != nil {
			return nil, err
		}
		opts = append(opts, pqc.WithAuditor(auditor))
	}
	return pqc.NewManager(store, opts...), nil
}

func openStore(storeDir, storeType, agePassphrase, agePassphraseFile string) (pqc.Store, error) {
	switch strings.ToLower(strings.TrimSpace(storeType)) {
	case "", "file":
		return filestore.New(storeDir)
	case "age", "agefile":
		passphrase, err := resolveAgePassphrase(agePassphrase, agePassphraseFile)
		if err != nil {
			return nil, err
		}
		return agefilestore.New(storeDir, passphrase)
	default:
		return nil, fmt.Errorf("unsupported store type %q", storeType)
	}
}

func resolveAgePassphrase(passphrase, passphraseFile string) (string, error) {
	if passphraseFile != "" {
		data, err := os.ReadFile(passphraseFile)
		if err != nil {
			return "", err
		}
		passphrase = strings.TrimRight(string(data), "\r\n")
	}
	if passphrase == "" {
		return "", fmt.Errorf("age store requires --age-passphrase, --age-passphrase-file, or PQC_AGE_PASSPHRASE")
	}
	return passphrase, nil
}
