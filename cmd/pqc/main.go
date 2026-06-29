package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	_ "github.com/helsingin/pqc/profiles/all"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

type app struct {
	ctx    context.Context
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	a := &app{
		ctx:    context.Background(),
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
	}
	return a.run(args)
}

func (a *app) run(args []string) int {
	if len(args) == 0 {
		a.printUsage()
		return 2
	}

	switch args[0] {
	case "keys":
		return a.runKeys(args[1:])
	case "encrypt":
		return a.runEncrypt(args[1:])
	case "decrypt":
		return a.runDecrypt(args[1:])
	case "sign":
		return a.runSign(args[1:])
	case "verify":
		return a.runVerify(args[1:])
	case "audit":
		return a.runAudit(args[1:])
	case "transparency":
		return a.runTransparency(args[1:])
	case "tls":
		return a.runTLS(args[1:])
	case "inventory":
		return a.runInventory(args[1:])
	case "readiness":
		return a.runReadiness(args[1:])
	case "mtc":
		return a.runMTC(args[1:])
	case "profiles":
		return a.runProfiles(args[1:])
	case "issue":
		return a.runIssue(args[1:])
	case "verify-artifact":
		return a.runVerifyArtifact(args[1:])
	case "help", "-h", "--help":
		a.printUsage()
		return 0
	default:
		return a.failWithUsage(fmt.Errorf("unknown command %q", args[0]))
	}
}

func (a *app) flagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	return fs
}

func (a *app) fail(err error) int {
	printError(a.stderr, err)
	return 1
}

func (a *app) failUsage(err error, usage func()) int {
	printError(a.stderr, err)
	usage()
	return 2
}

func (a *app) failWithUsage(err error) int {
	printError(a.stderr, err)
	a.printUsage()
	return 2
}

func (a *app) printUsage() {
	_, _ = fmt.Fprint(a.stderr, `Usage:
  pqc keys create --type ml-kem-768 --id service-a
  pqc keys create --type ml-dsa-65 --id signer-a
  pqc keys list
  pqc keys show --id KEY
  pqc keys public --id KEY
  pqc keys rotate --id KEY
  pqc encrypt --key KEY [file]
  pqc decrypt [file]
  pqc sign --key KEY [file]
  pqc verify [--key KEY] message-file signature-file
  pqc audit checkpoint --audit audit.jsonl --sign-key audit-signer
  pqc audit verify --audit audit.jsonl --checkpoint checkpoint.json
  pqc transparency revoke --key service-a --reason key-compromise
  pqc transparency checkpoint --sign-key org-root
  pqc transparency verify checkpoint.json
  pqc tls inspect [--json] example.com:443
  pqc tls readiness example.com:443
  pqc inventory scan [--store DIR] [--target example.com:443]
  pqc readiness scan [--store DIR] [--target example.com:443]
  pqc mtc log init
  pqc mtc issue --subject example.com --public-key public.json
  pqc mtc revoke --index 0 --reason key-compromise
  pqc mtc checkpoint --sign-key org-root
  pqc mtc prove --leaf 0
  pqc mtc verify --proof proof.json --checkpoint checkpoint.json
  pqc mtc treeheads fetch --source URL --out ./treeheads
  pqc mtc treeheads verify ./treeheads
  pqc mtc treeheads export --format openssl-dir
  pqc profiles list
  pqc profiles show mtc
  pqc profiles help mtc
  pqc profiles estimate mtc
  pqc issue --profile mtc --sign-key org-root --subject example.com --dns example.com
  pqc verify-artifact artifact.json

Manager access flags are command-local:
  --store DIR                 key store directory
  --store-type file|age       plain file store or age-encrypted file store
  --age-passphrase VALUE      passphrase for --store-type age
  --age-passphrase-file FILE  file containing passphrase for --store-type age
  --remote URL                use pqcd instead of opening a local store
  --token VALUE               bearer token for --remote
  --tls-ca FILE               CA bundle for HTTPS remote
  --tls-server-name NAME      override HTTPS server name
  --tls-client-cert FILE      client certificate for remote mTLS
  --tls-client-key FILE       client private key for remote mTLS
  --tls-insecure-skip-verify  skip HTTPS cert verification for testing
  --tls-pqc                   prefer hybrid PQC TLS key exchange

Operational key/encrypt/decrypt/sign/verify commands also accept:
  --audit-log FILE            append metadata-only JSONL audit events
`)
}
