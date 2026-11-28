package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func inspectionServer(t *testing.T, groups []tls.CurveID) (string, *x509.CertPool, *atomic.Int32) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "inspection.example"}, DNSNames: []string{"inspection.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	listener, e := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: groups, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if e != nil {
		t.Fatal(e)
	}
	counter := new(atomic.Int32)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			counter.Add(1)
			c.SetDeadline(time.Now().Add(time.Second))
			c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	t.Cleanup(func() { listener.Close(); <-done })
	return listener.Addr().String(), roots, counter
}
func TestTLSInspectionExplicitProfiles(t *testing.T) {
	for _, tc := range []struct {
		name   string
		group  tls.CurveID
		hybrid bool
	}{{"classical", tls.X25519, false}, {"hybrid", tls.X25519MLKEM768, true}} {
		t.Run(tc.name, func(t *testing.T) {
			addr, roots, counter := inspectionServer(t, []tls.CurveID{tc.group})
			opts := TLSInspectOptions{ServerName: "inspection.example", DialAddress: addr, RootCAs: roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tc.group}}
			report, e := InspectTLS(context.Background(), "https://unresolved.invalid", opts)
			if e != nil || !report.Verified || report.HybridPQCKeyExchange != tc.hybrid || report.RemoteAddress != addr || report.ServerName != "inspection.example" || len(report.OfferedKeyExchanges) != 1 {
				t.Fatalf("profile report: %+v %v", report, e)
			}
			if report.Leaf == nil || len(report.Leaf.RawDER) == 0 || report.Leaf.SerialNumberHex != "1" || len(report.Leaf.PublicKeySHA256) != 64 || report.Leaf.SignatureOID == "" || report.Leaf.PublicKeyOID == "" || report.Leaf.PublicKeyParameters["curve"] != "P-256" {
				t.Fatal("missing public certificate evidence")
			}
			before := counter.Load()
			opts.ServerName = "wrong.example"
			report, e = InspectTLS(context.Background(), "https://unresolved.invalid", opts)
			if e != nil || report.Verified || report.VerificationError == "" || counter.Load() != before+1 {
				t.Fatalf("trust failure must use same connection: %+v %v", report, e)
			}
			opts.InsecureSkipVerify = true
			report, e = InspectTLS(context.Background(), "https://unresolved.invalid", opts)
			if e != nil || report.Verified || report.VerificationMode != TLSVerificationSkipped {
				t.Fatal("skip verification", e)
			}
			opts.CurvePreferences = []tls.CurveID{tls.CurveP384}
			if _, e = InspectTLS(context.Background(), "https://unresolved.invalid", opts); e == nil {
				t.Fatal("unsupported profile silently fell back")
			}
		})
	}
}
func TestTLSInspectionBoundsAndCancellation(t *testing.T) {
	for _, opts := range []TLSInspectOptions{{DialAddress: "example.com:443"}, {DialAddress: "127.0.0.1:0"}, {MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS12}, {PQC: true, CurvePreferences: []tls.CurveID{tls.X25519}}} {
		if _, e := InspectTLS(context.Background(), "https://example.invalid", opts); e == nil {
			t.Fatal("invalid profile accepted")
		}
	}
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := l.Accept()
		if e == nil {
			defer c.Close()
			c.SetDeadline(time.Now().Add(time.Second))
			buffer := make([]byte, 4096)
			for {
				if _, e = c.Read(buffer); e != nil {
					return
				}
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, e = InspectTLS(ctx, "https://example.invalid", TLSInspectOptions{DialAddress: l.Addr().String()}); e == nil {
		t.Fatal("cancellation ignored")
	}
	<-done
}
