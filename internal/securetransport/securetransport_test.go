package securetransport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func makeCA(t *testing.T) testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func makeLeaf(t *testing.T, ca testCA, serial int64, dns []string, client bool, expired bool) ([]byte, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	notBefore, notAfter := now.Add(-time.Minute), now.Add(24*time.Hour)
	if expired {
		notBefore, notAfter = now.Add(-2*time.Hour), now.Add(-time.Hour)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: dns[0]}, DNSNames: dns, NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if client {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	return certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func writePair(t *testing.T, dir, prefix string, cert, key []byte) (string, string) {
	t.Helper()
	certPath, keyPath := filepath.Join(dir, prefix+".crt"), filepath.Join(dir, prefix+".key")
	if err := os.WriteFile(certPath, cert, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestTLSVerificationAndMTLS(t *testing.T) {
	dir := t.TempDir()
	ca := makeCA(t)
	serverCert, serverKey := makeLeaf(t, ca, 2, []string{"server.test"}, false, false)
	clientCert, clientKey := makeLeaf(t, ca, 3, []string{"client.test"}, true, false)
	serverCertFile, serverKeyFile := writePair(t, dir, "server", serverCert, serverKey)
	clientCertFile, clientKeyFile := writePair(t, dir, "client", clientCert, clientKey)
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, ca.pem, 0600); err != nil {
		t.Fatal(err)
	}
	serverTLS, serverFiles, err := (ServerTLSOptions{CertificateFile: serverCertFile, KeyFile: serverKeyFile, ClientCAFile: caFile, RequireClient: true, PollInterval: time.Second}).TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, f := range serverFiles {
			f.Close()
		}
	}()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	srv.TLS = serverTLS
	srv.StartTLS()
	defer srv.Close()

	clientTLS, files, err := (ClientTLSOptions{CAFile: caFile, ServerName: "server.test", CertificateFile: clientCertFile, KeyFile: clientKeyFile}).TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}
	if resp, err := client.Get(srv.URL); err != nil {
		t.Fatalf("verified mTLS request failed: %v", err)
	} else {
		resp.Body.Close()
	}

	noCertTLS, _, err := (ClientTLSOptions{CAFile: caFile, ServerName: "server.test"}).TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: noCertTLS}}).Get(srv.URL); err == nil {
		t.Fatal("required client certificate was accepted without a certificate")
	}
	wrongHostTLS, _, _ := (ClientTLSOptions{CAFile: caFile, ServerName: "other.test", CertificateFile: clientCertFile, KeyFile: clientKeyFile}).TLSConfig()
	if _, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: wrongHostTLS}}).Get(srv.URL); err == nil || !strings.Contains(strings.ToLower(err.Error()), "certificate") {
		t.Fatalf("hostname mismatch err=%v", err)
	}
	unknownTLS, _, _ := (ClientTLSOptions{ServerName: "server.test", CertificateFile: clientCertFile, KeyFile: clientKeyFile}).TLSConfig()
	if _, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: unknownTLS}}).Get(srv.URL); err == nil {
		t.Fatal("unknown CA was accepted")
	}
}

func TestReloadRetainsLastKnownGood(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := SecretFile(path, MinPollInterval, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if got, _ := f.Get(); got != "first" {
		t.Fatalf("initial value %q", got)
	}
	if err := os.WriteFile(path, []byte("   "), 0600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if got, _ := f.Get(); got != "first" {
		t.Fatalf("malformed replacement displaced last-known-good: %q", got)
	}
	if f.Status().FailureCount == 0 || f.Status().Generation != 1 {
		t.Fatalf("reload status=%+v", f.Status())
	}
	if err := os.WriteFile(path, []byte("second"), 0600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if got, _ := f.Get(); got != "second" {
		t.Fatalf("rotated value %q", got)
	}
	if f.Status().Generation != 2 {
		t.Fatalf("generation=%d", f.Status().Generation)
	}
}

func TestExpiredCertificateFailsVerification(t *testing.T) {
	dir := t.TempDir()
	ca := makeCA(t)
	cert, key := makeLeaf(t, ca, 9, []string{"expired.test"}, false, true)
	certFile, keyFile := writePair(t, dir, "expired", cert, key)
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, ca.pem, 0600); err != nil {
		t.Fatal(err)
	}
	serverTLS, files, err := (ServerTLSOptions{CertificateFile: certFile, KeyFile: keyFile}).TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, file := range files {
			file.Close()
		}
	}()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	srv.TLS = serverTLS
	srv.StartTLS()
	defer srv.Close()
	clientTLS, clientFiles, err := (ClientTLSOptions{CAFile: caFile, ServerName: "expired.test"}).TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, file := range clientFiles {
			file.Close()
		}
	}()
	if _, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}).Get(srv.URL); err == nil {
		t.Fatal("expired certificate was accepted")
	}
}
