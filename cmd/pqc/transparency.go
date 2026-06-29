package main

import (
	"fmt"
	"os"
	"time"

	pqc "github.com/helsingin/pqc"
)

func (a *app) runTransparency(args []string) int {
	if len(args) == 0 {
		a.printTransparencyUsage()
		return 2
	}
	switch args[0] {
	case "revoke":
		return a.runTransparencyRevoke(args[1:])
	case "checkpoint":
		return a.runTransparencyCheckpoint(args[1:])
	case "verify":
		return a.runTransparencyVerify(args[1:])
	case "help", "-h", "--help":
		a.printTransparencyUsage()
		return 0
	default:
		return a.failUsage(fmt.Errorf("unknown transparency command %q", args[0]), a.printTransparencyUsage)
	}
}

func (a *app) runTransparencyRevoke(args []string) int {
	fs := a.flagSet("pqc transparency revoke")
	keyID := fs.String("key", "", "key id to revoke")
	reason := fs.String("reason", "", "revocation reason")
	revocationPath := fs.String("revocations", defaultRevocationManifestPath, "revocation manifest path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *keyID == "" || *reason == "" || fs.NArg() != 0 {
		return a.failUsage(fmt.Errorf("transparency revoke requires --key and --reason"), a.printTransparencyUsage)
	}
	manifest, err := readOrCreateRevocationManifest(*revocationPath)
	if err != nil {
		return a.fail(err)
	}
	event, err := manifest.Add("key", *keyID, *reason, nil, time.Now().UTC())
	if err != nil {
		return a.fail(err)
	}
	if err := writeRevocationManifestFile(*revocationPath, manifest); err != nil {
		return a.fail(err)
	}
	return writeJSON(a.stdout, a.stderr, event)
}

func (a *app) runTransparencyCheckpoint(args []string) int {
	fs := a.flagSet("pqc transparency checkpoint")
	var clientOpts clientOptions
	var targetOpts inspectTargetOptions
	registerClientAccessFlags(fs, &clientOpts)
	registerTargetFlags(fs, &targetOpts)
	signKey := fs.String("sign-key", "", "ML-DSA key id used to sign the checkpoint")
	includeRevocations := fs.Bool("include-revocations", false, "include revocation manifest in transparency bundle")
	revocationPath := fs.String("revocations", defaultRevocationManifestPath, "revocation manifest path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *signKey == "" || fs.NArg() != 0 {
		return a.failUsage(fmt.Errorf("transparency checkpoint requires --sign-key"), a.printTransparencyUsage)
	}
	client, err := openCommandClient(fs, clientOpts)
	if err != nil {
		return a.fail(err)
	}
	report, err := buildInventoryReport(a.ctx, client, targetOpts, "")
	if err != nil {
		return a.fail(err)
	}
	var revocations *pqc.RevocationManifest
	if *includeRevocations {
		manifest, err := readOrCreateRevocationManifest(*revocationPath)
		if err != nil {
			return a.fail(err)
		}
		revocations = &manifest
	}
	checkpoint, err := pqc.BuildTransparencyCheckpointWithRevocations(report, revocations, time.Now().UTC())
	if err != nil {
		return a.fail(err)
	}
	if err := pqc.SignTransparencyCheckpoint(a.ctx, client, checkpoint, *signKey); err != nil {
		return a.fail(err)
	}
	bundle, err := pqc.BuildTransparencyBundleWithRevocations(report, revocations, checkpoint)
	if err != nil {
		return a.fail(err)
	}
	return writeJSON(a.stdout, a.stderr, bundle)
}

func (a *app) runTransparencyVerify(args []string) int {
	fs := a.flagSet("pqc transparency verify")
	var clientOpts clientOptions
	registerClientAccessFlags(fs, &clientOpts)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		return a.failUsage(fmt.Errorf("transparency verify requires checkpoint-bundle.json"), a.printTransparencyUsage)
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return a.fail(err)
	}
	var bundle pqc.TransparencyBundle
	if err := decodeStrict(data, &bundle); err != nil {
		return a.fail(err)
	}
	var publicKey *pqc.PublicKey
	if bundle.Checkpoint.Signature != nil {
		client, err := openCommandClient(fs, clientOpts)
		if err != nil {
			return a.fail(err)
		}
		publicKey, err = publicKeyForSignature(a.ctx, client, bundle.Checkpoint.Signature)
		if err != nil {
			return a.fail(err)
		}
	}
	if err := pqc.VerifyTransparencyBundle(bundle, publicKey); err != nil {
		return a.fail(err)
	}
	_, err = fmt.Fprintln(a.stdout, "OK")
	if err != nil {
		return a.fail(err)
	}
	return 0
}

func (a *app) printTransparencyUsage() {
	_, _ = fmt.Fprint(a.stderr, `Usage:
  pqc transparency revoke --key KEY --reason REASON [--revocations revocations.json]
  pqc transparency checkpoint --sign-key KEY [--include-revocations] [--revocations revocations.json] [--target HOST:PORT] [manager access flags]
  pqc transparency verify checkpoint-bundle.json [manager access flags]
`)
}
