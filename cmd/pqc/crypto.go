package main

import (
	"fmt"
	"io"
	"os"

	pqc "github.com/helsingin/pqc"
)

func (a *app) runEncrypt(args []string) int {
	fs := a.flagSet("pqc encrypt")
	var clientOpts clientOptions
	registerClientFlags(fs, &clientOpts)
	keyID := fs.String("key", "", "ML-KEM key id")
	aad := fs.String("aad", "", "additional authenticated data")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *keyID == "" || fs.NArg() > 1 {
		return a.failUsage(fmt.Errorf("encrypt requires --key and at most one file"), printEncryptUsage(a.stderr))
	}
	client, err := openCommandClient(fs, clientOpts)
	if err != nil {
		return a.fail(err)
	}
	plaintext, err := readInput(a.stdin, fs.Args())
	if err != nil {
		return a.fail(err)
	}
	envelope, err := client.Encrypt(a.ctx, *keyID, plaintext, pqc.EncryptOptions{AAD: []byte(*aad)})
	if err != nil {
		return a.fail(err)
	}
	return writeJSON(a.stdout, a.stderr, envelope)
}

func (a *app) runDecrypt(args []string) int {
	fs := a.flagSet("pqc decrypt")
	var clientOpts clientOptions
	registerClientFlags(fs, &clientOpts)
	aad := fs.String("aad", "", "additional authenticated data")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 1 {
		return a.failUsage(fmt.Errorf("decrypt takes at most one file"), printDecryptUsage(a.stderr))
	}
	client, err := openCommandClient(fs, clientOpts)
	if err != nil {
		return a.fail(err)
	}
	data, err := readInput(a.stdin, fs.Args())
	if err != nil {
		return a.fail(err)
	}
	var envelope pqc.Envelope
	if err := decodeStrict(data, &envelope); err != nil {
		return a.fail(err)
	}
	plaintext, err := client.Decrypt(a.ctx, &envelope, pqc.EncryptOptions{AAD: []byte(*aad)})
	if err != nil {
		return a.fail(err)
	}
	if _, err := a.stdout.Write(plaintext); err != nil {
		return a.fail(err)
	}
	return 0
}

func (a *app) runSign(args []string) int {
	fs := a.flagSet("pqc sign")
	var clientOpts clientOptions
	registerClientFlags(fs, &clientOpts)
	keyID := fs.String("key", "", "ML-DSA key id")
	contextValue := fs.String("context", "", "ML-DSA context string")
	randomized := fs.Bool("randomized", false, "use randomized ML-DSA signing")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *keyID == "" || fs.NArg() > 1 {
		return a.failUsage(fmt.Errorf("sign requires --key and at most one file"), printSignUsage(a.stderr))
	}
	client, err := openCommandClient(fs, clientOpts)
	if err != nil {
		return a.fail(err)
	}
	message, err := readInput(a.stdin, fs.Args())
	if err != nil {
		return a.fail(err)
	}
	signature, err := client.Sign(a.ctx, *keyID, message, pqc.SignOptions{
		Context:    []byte(*contextValue),
		Randomized: *randomized,
	})
	if err != nil {
		return a.fail(err)
	}
	return writeJSON(a.stdout, a.stderr, signature)
}

func (a *app) runVerify(args []string) int {
	fs := a.flagSet("pqc verify")
	var clientOpts clientOptions
	registerClientFlags(fs, &clientOpts)
	keyID := fs.String("key", "", "expected key id")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 2 {
		return a.failUsage(fmt.Errorf("verify requires message-file and signature-file"), printVerifyUsage(a.stderr))
	}
	client, err := openCommandClient(fs, clientOpts)
	if err != nil {
		return a.fail(err)
	}
	message, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return a.fail(err)
	}
	data, err := os.ReadFile(fs.Arg(1))
	if err != nil {
		return a.fail(err)
	}
	var signature pqc.SignatureEnvelope
	if err := decodeStrict(data, &signature); err != nil {
		return a.fail(err)
	}
	if *keyID != "" && *keyID != signature.KeyID {
		return a.fail(fmt.Errorf("signature key id %q does not match expected %q", signature.KeyID, *keyID))
	}
	if err := client.Verify(a.ctx, message, &signature); err != nil {
		return a.fail(err)
	}
	if _, err := fmt.Fprintln(a.stdout, "OK"); err != nil {
		return a.fail(err)
	}
	return 0
}

func printEncryptUsage(w io.Writer) func() {
	return func() {
		_, _ = fmt.Fprintln(w, "Usage: pqc encrypt --key KEY [--aad DATA] [file] [manager flags]")
	}
}

func printDecryptUsage(w io.Writer) func() {
	return func() {
		_, _ = fmt.Fprintln(w, "Usage: pqc decrypt [--aad DATA] [file] [manager flags]")
	}
}

func printSignUsage(w io.Writer) func() {
	return func() {
		_, _ = fmt.Fprintln(w, "Usage: pqc sign --key KEY [--context DATA] [--randomized] [file] [manager flags]")
	}
}

func printVerifyUsage(w io.Writer) func() {
	return func() {
		_, _ = fmt.Fprintln(w, "Usage: pqc verify [--key KEY] message-file signature-file [manager flags]")
	}
}
