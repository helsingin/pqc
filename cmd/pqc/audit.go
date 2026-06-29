package main

import (
	"fmt"
	"os"
	"time"

	pqc "github.com/helsingin/pqc"
)

func (a *app) runAudit(args []string) int {
	if len(args) == 0 {
		a.printAuditUsage()
		return 2
	}
	switch args[0] {
	case "checkpoint":
		return a.runAuditCheckpoint(args[1:])
	case "verify":
		return a.runAuditVerify(args[1:])
	case "help", "-h", "--help":
		a.printAuditUsage()
		return 0
	default:
		return a.failUsage(fmt.Errorf("unknown audit command %q", args[0]), a.printAuditUsage)
	}
}

func (a *app) runAuditCheckpoint(args []string) int {
	fs := a.flagSet("pqc audit checkpoint")
	var clientOpts clientOptions
	registerClientAccessFlags(fs, &clientOpts)
	auditPath := fs.String("audit", "", "JSONL audit log to checkpoint")
	signKey := fs.String("sign-key", "", "ML-DSA key id used to sign the checkpoint")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *auditPath == "" || *signKey == "" || fs.NArg() != 0 {
		return a.failUsage(fmt.Errorf("audit checkpoint requires --audit and --sign-key"), a.printAuditUsage)
	}
	client, err := openCommandClient(fs, clientOpts)
	if err != nil {
		return a.fail(err)
	}
	file, err := os.Open(*auditPath)
	if err != nil {
		return a.fail(err)
	}
	defer file.Close()
	checkpoint, err := pqc.BuildAuditCheckpoint(file, time.Now().UTC())
	if err != nil {
		return a.fail(err)
	}
	if err := pqc.SignAuditCheckpoint(a.ctx, client, checkpoint, *signKey); err != nil {
		return a.fail(err)
	}
	return writeJSON(a.stdout, a.stderr, checkpoint)
}

func (a *app) runAuditVerify(args []string) int {
	fs := a.flagSet("pqc audit verify")
	var clientOpts clientOptions
	registerClientAccessFlags(fs, &clientOpts)
	auditPath := fs.String("audit", "", "JSONL audit log to verify")
	checkpointPath := fs.String("checkpoint", "", "audit checkpoint JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *auditPath == "" || *checkpointPath == "" || fs.NArg() != 0 {
		return a.failUsage(fmt.Errorf("audit verify requires --audit and --checkpoint"), a.printAuditUsage)
	}
	data, err := os.ReadFile(*checkpointPath)
	if err != nil {
		return a.fail(err)
	}
	var checkpoint pqc.AuditCheckpoint
	if err := decodeStrict(data, &checkpoint); err != nil {
		return a.fail(err)
	}
	var publicKey *pqc.PublicKey
	if checkpoint.Signature != nil {
		client, err := openCommandClient(fs, clientOpts)
		if err != nil {
			return a.fail(err)
		}
		publicKey, err = publicKeyForSignature(a.ctx, client, checkpoint.Signature)
		if err != nil {
			return a.fail(err)
		}
	}
	file, err := os.Open(*auditPath)
	if err != nil {
		return a.fail(err)
	}
	defer file.Close()
	if err := pqc.VerifyAuditCheckpoint(file, &checkpoint, publicKey); err != nil {
		return a.fail(err)
	}
	_, err = fmt.Fprintln(a.stdout, "OK")
	if err != nil {
		return a.fail(err)
	}
	return 0
}

func (a *app) printAuditUsage() {
	_, _ = fmt.Fprint(a.stderr, `Usage:
  pqc audit checkpoint --audit audit.jsonl --sign-key KEY [manager access flags]
  pqc audit verify --audit audit.jsonl --checkpoint checkpoint.json [manager access flags]

Manager flags here are access-only; checkpoint commands do not write audit events.
`)
}
