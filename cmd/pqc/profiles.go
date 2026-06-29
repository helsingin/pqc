package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	pqc "github.com/helsingin/pqc"
	"github.com/helsingin/pqc/profile"
)

func (a *app) runProfiles(args []string) int {
	if len(args) == 0 {
		a.printProfilesUsage()
		return 2
	}
	switch args[0] {
	case "list":
		return a.runProfilesList(args[1:])
	case "show":
		return a.runProfilesShow(args[1:])
	case "inspect":
		return a.runProfilesInspect(args[1:])
	case "estimate":
		return a.runProfilesEstimate(args[1:])
	case "help":
		if len(args) == 1 {
			a.printProfilesUsage()
			return 0
		}
		return a.runProfilesHelp(args[1:])
	case "-h", "--help":
		a.printProfilesUsage()
		return 0
	default:
		return a.failUsage(fmt.Errorf("unknown profiles command %q", args[0]), a.printProfilesUsage)
	}
}

func (a *app) runProfilesHelp(args []string) int {
	fs := a.flagSet("pqc profiles help")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		return a.failUsage(fmt.Errorf("profiles help requires PROFILE"), a.printProfilesUsage)
	}
	plugin, err := profile.MustGet(fs.Arg(0))
	if err != nil {
		return a.fail(err)
	}
	printProfileHelp(a.stdout, plugin.Metadata())
	return 0
}

func (a *app) runProfilesList(args []string) int {
	fs := a.flagSet("pqc profiles list")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		return a.failUsage(fmt.Errorf("profiles list does not take arguments"), a.printProfilesUsage)
	}
	return writeJSON(a.stdout, a.stderr, profile.AllMetadata())
}

func (a *app) runProfilesShow(args []string) int {
	fs := a.flagSet("pqc profiles show")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		return a.failUsage(fmt.Errorf("profiles show requires PROFILE"), a.printProfilesUsage)
	}
	plugin, err := profile.MustGet(fs.Arg(0))
	if err != nil {
		return a.fail(err)
	}
	return writeJSON(a.stdout, a.stderr, plugin.Metadata())
}

func (a *app) runProfilesInspect(args []string) int {
	fs := a.flagSet("pqc profiles inspect")
	target := fs.String("target", "", "artifact profile inspection target")
	inputPath := fs.String("input", "", "artifact profile input JSON file; use - for stdin")
	profileID, err := parseProfileWithFlags(fs, args)
	if err != nil {
		return 2
	}
	if profileID == "" {
		return a.failUsage(fmt.Errorf("profiles inspect requires PROFILE"), a.printProfilesUsage)
	}
	inputs, err := readProfileInput(a.stdin, *inputPath)
	if err != nil {
		return a.fail(err)
	}
	plugin, err := profile.MustGet(profileID)
	if err != nil {
		return a.fail(err)
	}
	inspector, ok := plugin.(profile.Inspector)
	if !ok {
		return a.fail(fmt.Errorf("profile %q does not implement inspect", plugin.ID()))
	}
	result, err := inspector.Inspect(a.ctx, profile.InspectRequest{
		Target: *target,
		Inputs: inputs,
	})
	if err != nil {
		return a.fail(err)
	}
	return writeJSON(a.stdout, a.stderr, result)
}

func (a *app) runProfilesEstimate(args []string) int {
	fs := a.flagSet("pqc profiles estimate")
	inputPath := fs.String("input", "", "artifact profile input JSON file; use - for stdin")
	profileID, err := parseProfileWithFlags(fs, args)
	if err != nil {
		return 2
	}
	if profileID == "" {
		return a.failUsage(fmt.Errorf("profiles estimate requires PROFILE"), a.printProfilesUsage)
	}
	inputs, err := readProfileInput(a.stdin, *inputPath)
	if err != nil {
		return a.fail(err)
	}
	plugin, err := profile.MustGet(profileID)
	if err != nil {
		return a.fail(err)
	}
	estimator, ok := plugin.(profile.Estimator)
	if !ok {
		return a.fail(fmt.Errorf("profile %q does not implement estimate", plugin.ID()))
	}
	result, err := estimator.Estimate(a.ctx, profile.EstimateRequest{Inputs: inputs})
	if err != nil {
		return a.fail(err)
	}
	return writeJSON(a.stdout, a.stderr, result)
}

func (a *app) runIssue(args []string) int {
	fs := a.flagSet("pqc issue")
	var clientOpts clientOptions
	registerClientFlags(fs, &clientOpts)
	profileID := fs.String("profile", "", "artifact profile id")
	profileVersion := fs.String("profile-version", "", "artifact profile version override")
	artifactType := fs.String("type", "", "artifact type override")
	subjectCN := fs.String("subject", "", "subject common name")
	signKey := fs.String("sign-key", "", "ML-DSA key id used to sign the artifact")
	inputPath := fs.String("input", "", "artifact profile input JSON file; use - for stdin")
	ttl := fs.Duration("ttl", 90*24*time.Hour, "artifact validity duration")
	notBeforeValue := fs.String("not-before", "", "RFC3339 validity start")
	notAfterValue := fs.String("not-after", "", "RFC3339 validity end")
	var dnsNames, emails, uris stringList
	fs.Var(&dnsNames, "dns", "subject DNS name; repeatable")
	fs.Var(&emails, "email", "subject email; repeatable")
	fs.Var(&uris, "uri", "subject URI; repeatable")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *profileID == "" || *signKey == "" || *subjectCN == "" || fs.NArg() != 0 {
		return a.failUsage(fmt.Errorf("issue requires --profile, --sign-key, and --subject"), printIssueUsage(a.stderr))
	}
	inputs, err := readProfileInput(a.stdin, *inputPath)
	if err != nil {
		return a.fail(err)
	}
	notBefore, err := parseOptionalTime("not-before", *notBeforeValue)
	if err != nil {
		return a.fail(err)
	}
	notAfter, err := parseOptionalTime("not-after", *notAfterValue)
	if err != nil {
		return a.fail(err)
	}
	if notAfter.IsZero() && *ttl > 0 {
		base := notBefore
		if base.IsZero() {
			base = time.Now().UTC()
		}
		notAfter = base.Add(*ttl)
	}
	client, err := openCommandClient(fs, clientOpts)
	if err != nil {
		return a.fail(err)
	}
	plugin, err := profile.MustGet(*profileID)
	if err != nil {
		return a.fail(err)
	}
	issuer, ok := plugin.(profile.Issuer)
	if !ok {
		return a.fail(fmt.Errorf("profile %q does not implement issue", plugin.ID()))
	}
	artifact, err := issuer.Issue(a.ctx, profile.IssueRequest{
		Profile:        *profileID,
		ProfileVersion: *profileVersion,
		ArtifactType:   *artifactType,
		Subject: profile.Subject{
			CommonName: *subjectCN,
			DNSNames:   append([]string(nil), dnsNames...),
			Emails:     append([]string(nil), emails...),
			URIs:       append([]string(nil), uris...),
		},
		Inputs:    inputs,
		SignKey:   *signKey,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		Signer:    client,
	})
	if err != nil {
		return a.fail(err)
	}
	return writeJSON(a.stdout, a.stderr, artifact)
}

func (a *app) runVerifyArtifact(args []string) int {
	fs := a.flagSet("pqc verify-artifact")
	var clientOpts clientOptions
	registerClientAccessFlags(fs, &clientOpts)
	publicKeyPath := fs.String("public-key", "", "exported public key JSON file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 1 {
		return a.failUsage(fmt.Errorf("verify-artifact takes at most one file"), printVerifyArtifactUsage(a.stderr))
	}
	data, err := readInput(a.stdin, fs.Args())
	if err != nil {
		return a.fail(err)
	}
	var artifact profile.IssuedArtifact
	if err := decodeStrict(data, &artifact); err != nil {
		return a.fail(err)
	}
	plugin, err := profile.MustGet(artifact.Profile)
	if err != nil {
		return a.fail(err)
	}
	verifier, ok := plugin.(profile.Verifier)
	if !ok {
		return a.fail(fmt.Errorf("profile %q does not implement verify", plugin.ID()))
	}
	publicKey, err := loadArtifactPublicKey(a, fs, clientOpts, *publicKeyPath, artifact.Signature)
	if err != nil {
		return a.fail(err)
	}
	result, err := verifier.Verify(a.ctx, profile.VerifyRequest{
		Artifact:  &artifact,
		PublicKey: publicKey,
	})
	if err != nil {
		return a.fail(err)
	}
	return writeJSON(a.stdout, a.stderr, result)
}

func loadArtifactPublicKey(a *app, fs *flag.FlagSet, opts clientOptions, publicKeyPath string, signature *pqc.SignatureEnvelope) (*pqc.PublicKey, error) {
	if publicKeyPath != "" {
		data, err := os.ReadFile(publicKeyPath)
		if err != nil {
			return nil, err
		}
		var publicKey pqc.PublicKey
		if err := decodeStrict(data, &publicKey); err != nil {
			return nil, err
		}
		return &publicKey, nil
	}
	if signature == nil {
		return nil, nil
	}
	client, err := openCommandClient(fs, opts)
	if err != nil {
		return nil, err
	}
	return publicKeyForSignature(a.ctx, client, signature)
}

func readProfileInput(stdin io.Reader, path string) (json.RawMessage, error) {
	if path == "" {
		return json.RawMessage(`{}`), nil
	}
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return json.RawMessage(`{}`), nil
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err != nil {
		return nil, fmt.Errorf("artifact profile input must be valid JSON: %w", err)
	}
	return append(json.RawMessage(nil), compact.Bytes()...), nil
}

func parseOptionalTime(name, value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("--%s must be RFC3339: %w", name, err)
	}
	return parsed.UTC(), nil
}

func printIssueUsage(w io.Writer) func() {
	return func() {
		_, _ = fmt.Fprintln(w, "Usage: pqc issue --profile PROFILE --sign-key KEY --subject NAME [--dns NAME] [--input FILE] [manager flags]")
	}
}

func printVerifyArtifactUsage(w io.Writer) func() {
	return func() {
		_, _ = fmt.Fprintln(w, "Usage: pqc verify-artifact [--public-key public.json] [artifact.json] [manager access flags]")
	}
}

func (a *app) printProfilesUsage() {
	_, _ = fmt.Fprint(a.stderr, `Usage:
  pqc profiles list
  pqc profiles show PROFILE
  pqc profiles help PROFILE
  pqc profiles inspect PROFILE [--target VALUE] [--input FILE]
  pqc profiles estimate PROFILE [--input FILE]
`)
}

func printProfileHelp(w io.Writer, meta profile.Metadata) {
	_, _ = fmt.Fprintf(w, "%s - %s\n", meta.ID, meta.Name)
	if meta.Summary != "" {
		_, _ = fmt.Fprintf(w, "summary: %s\n", meta.Summary)
	}
	if meta.Status != "" {
		_, _ = fmt.Fprintf(w, "status: %s\n", meta.Status)
	}
	if meta.DefaultVersion != "" {
		_, _ = fmt.Fprintf(w, "supported version: %s\n", meta.DefaultVersion)
	}
	if meta.Standardization != "" {
		_, _ = fmt.Fprintf(w, "standardization: %s\n", meta.Standardization)
	}
	if len(meta.ArtifactTypes) != 0 {
		_, _ = fmt.Fprintf(w, "artifact types: %s\n", strings.Join(meta.ArtifactTypes, ", "))
	}
	capabilities := capabilityNames(meta.Capabilities)
	if len(capabilities) != 0 {
		_, _ = fmt.Fprintf(w, "capabilities: %s\n", strings.Join(capabilities, ", "))
	}
	if len(meta.BestFor) != 0 {
		_, _ = fmt.Fprintf(w, "best for: %s\n", strings.Join(meta.BestFor, ", "))
	}
	printProfileHelpList(w, "notes", meta.Notes)
	printProfileHelpList(w, "references", meta.References)
	if len(meta.Parameters) != 0 {
		_, _ = fmt.Fprintln(w, "parameters:")
		keys := make([]string, 0, len(meta.Parameters))
		for key := range meta.Parameters {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			_, _ = fmt.Fprintf(w, "  %s: %s\n", key, jsonValue(meta.Parameters[key]))
		}
	}
}

func printProfileHelpList(w io.Writer, label string, values []string) {
	if len(values) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "%s:\n", label)
	for _, value := range values {
		_, _ = fmt.Fprintf(w, "  - %s\n", value)
	}
}

func capabilityNames(capabilities profile.Capabilities) []string {
	out := []string{}
	if capabilities.Issue {
		out = append(out, "issue")
	}
	if capabilities.Verify {
		out = append(out, "verify")
	}
	if capabilities.Inspect {
		out = append(out, "inspect")
	}
	if capabilities.Estimate {
		out = append(out, "estimate")
	}
	return out
}

func jsonValue(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	return string(data)
}

func parseProfileWithFlags(fs *flag.FlagSet, args []string) (string, error) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		profileID := args[0]
		if err := fs.Parse(args[1:]); err != nil {
			return "", err
		}
		if fs.NArg() != 0 {
			return "", fmt.Errorf("unexpected argument %q", fs.Arg(0))
		}
		return profileID, nil
	}
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if fs.NArg() != 1 {
		return "", nil
	}
	return fs.Arg(0), nil
}
