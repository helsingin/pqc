package core

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/slhdsa"
)

// Keep the supported parameter sets explicit. Never pass an untrusted/zero ID
// into CIRCL: its parameter lookup panics for invalid IDs.
func slhDSAID(algorithm Algorithm) (slhdsa.ID, bool) {
	switch algorithm {
	case AlgorithmSLHDSASHA2192s:
		return slhdsa.SHA2_192s, true
	case AlgorithmSLHDSASHA2256s:
		return slhdsa.SHA2_256s, true
	default:
		return 0, false
	}
}

func generateSLHDSAKeyPair(id slhdsa.ID, random io.Reader) ([]byte, []byte, error) {
	pub, priv, err := slhdsa.GenerateKey(random, id)
	if err != nil {
		return nil, nil, err
	}
	publicKey, err := pub.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	privateKey, err := priv.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return publicKey, privateKey, nil
}

func signSLHDSA(id slhdsa.ID, key, message []byte, opts SignOptions, random io.Reader) ([]byte, error) {
	if len(key) != id.Scheme().PrivateKeySize() {
		return nil, fmt.Errorf("invalid %s private key length: %d", id, len(key))
	}
	priv := slhdsa.PrivateKey{ID: id}
	if err := priv.UnmarshalBinary(key); err != nil {
		return nil, err
	}
	// Pure FIPS 205 signatures preserve the existing raw-message/context API.
	// HashSLH-DSA would require a separately identified prehash mode.
	msg := slhdsa.NewMessage(message)
	if opts.Randomized {
		return slhdsa.SignRandomized(&priv, random, msg, opts.Context)
	}
	return slhdsa.SignDeterministic(&priv, msg, opts.Context)
}

func verifySLHDSA(id slhdsa.ID, key, message []byte, sig *SignatureEnvelope) error {
	scheme := id.Scheme()
	if len(key) != scheme.PublicKeySize() {
		return fmt.Errorf("%w: invalid %s public key length: %d", ErrInvalidSignature, id, len(key))
	}
	if len(sig.Signature) != scheme.SignatureSize() {
		return fmt.Errorf("%w: invalid %s signature length: %d", ErrInvalidSignature, id, len(sig.Signature))
	}
	pub := slhdsa.PublicKey{ID: id}
	if err := pub.UnmarshalBinary(key); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	if !slhdsa.Verify(&pub, slhdsa.NewMessage(message), sig.Signature, sig.Context) {
		return fmt.Errorf("%w: verification failed", ErrInvalidSignature)
	}
	return nil
}
