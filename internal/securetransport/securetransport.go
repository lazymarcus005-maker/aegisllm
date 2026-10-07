// Package securetransport centralizes the gateway's TLS and file-backed
// material handling. Reloads are atomic: a malformed replacement is reported
// and the last-known-good value remains active.
package securetransport

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultPollInterval = 2 * time.Second
	MinPollInterval     = 100 * time.Millisecond
	MaxPollInterval     = 30 * time.Second
)

// Metrics receives bounded, content-free reload events.
type Metrics interface {
	ObserveReloadFailure(kind string)
	ObserveCertificateExpiring(kind string)
}

// Status is safe to expose through readiness and diagnostics. It contains no
// path, key id, certificate subject, or secret material.
type Status struct {
	Loaded            bool
	Generation        uint64
	LastSuccess       time.Time
	LastFailure       time.Time
	FailureCount      uint64
	CertificateExpiry time.Time
}

type loaded[T any] struct {
	value   T
	stat    os.FileInfo
	digest  [32]byte
	expires time.Time
}

// File[T] atomically reloads one file when its metadata changes. It polls in
// a bounded background loop, and Get also performs a bounded best-effort poll
// so callers do not depend on scheduler timing during rotation.
type File[T any] struct {
	path      string
	dependent string
	interval  time.Duration
	load      func([]byte) (T, time.Time, error)
	metrics   Metrics
	value     atomic.Pointer[loaded[T]]
	mu        sync.Mutex
	status    Status
	nextPoll  time.Time
	closed    chan struct{}
	done      chan struct{}
}

func NewFile[T any](path string, interval time.Duration, load func([]byte) (T, time.Time, error), metrics Metrics) (*File[T], error) {
	return newFile(path, "", interval, load, metrics)
}

// NewFileWithDependency watches a second file as part of the material
// fingerprint. It is used for certificate/key pairs so either half of an
// atomic secret-manager rotation is observed.
func NewFileWithDependency[T any](path, dependent string, interval time.Duration, load func([]byte) (T, time.Time, error), metrics Metrics) (*File[T], error) {
	return newFile(path, dependent, interval, load, metrics)
}

func newFile[T any](path, dependent string, interval time.Duration, load func([]byte) (T, time.Time, error), metrics Metrics) (*File[T], error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("material file is required")
	}
	if load == nil {
		return nil, errors.New("material loader is required")
	}
	f := &File[T]{path: path, dependent: dependent, interval: clampInterval(interval), load: load, metrics: metrics, closed: make(chan struct{}), done: make(chan struct{})}
	if err := f.reload(true); err != nil {
		return nil, err
	}
	go f.watch()
	return f, nil
}

func clampInterval(interval time.Duration) time.Duration {
	if interval <= 0 {
		return DefaultPollInterval
	}
	if interval < MinPollInterval {
		return MinPollInterval
	}
	if interval > MaxPollInterval {
		return MaxPollInterval
	}
	return interval
}

func (f *File[T]) watch() {
	defer close(f.done)
	t := time.NewTicker(f.interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			_ = f.reload(false)
		case <-f.closed:
			return
		}
	}
}

func (f *File[T]) reload(initial bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	if !initial && now.Before(f.nextPoll) {
		return nil
	}
	f.nextPoll = now.Add(f.interval)
	stat, err := os.Stat(f.path)
	if err != nil {
		return f.failure(initial, err)
	}
	data, err := os.ReadFile(f.path)
	digestData := append([]byte(nil), data...)
	if err == nil && f.dependent != "" {
		dependent, dependentErr := os.ReadFile(f.dependent)
		if dependentErr != nil {
			err = dependentErr
		} else {
			digestData = append(digestData, dependent...)
		}
	}
	digest := sha256.Sum256(digestData)
	old := f.value.Load()
	if err == nil && !initial && old != nil && old.digest == digest {
		return nil
	}
	if err == nil {
		var value T
		var expiry time.Time
		value, expiry, err = f.load(data)
		if err == nil {
			f.value.Store(&loaded[T]{value: value, stat: stat, digest: digest, expires: expiry})
			f.status.Loaded = true
			f.status.Generation++
			f.status.LastSuccess = now
			f.status.CertificateExpiry = expiry
			if !expiry.IsZero() && expiry.Before(now.Add(30*24*time.Hour)) && f.metrics != nil {
				f.metrics.ObserveCertificateExpiring("certificate")
			}
			return nil
		}
	}
	return f.failure(initial, err)
}

func (f *File[T]) failure(initial bool, err error) error {
	if err == nil {
		err = errors.New("material load failed")
	}
	now := time.Now()
	f.status.LastFailure = now
	f.status.FailureCount++
	if f.metrics != nil && !initial {
		f.metrics.ObserveReloadFailure("file")
	}
	if initial {
		return fmt.Errorf("material file invalid")
	}
	return err
}

// Get returns the current last-known-good value and opportunistically checks
// for a replacement. The returned error is only fatal when no value exists.
func (f *File[T]) Get() (T, error) {
	_ = f.reload(false)
	current := f.value.Load()
	if current == nil {
		var zero T
		return zero, errors.New("material unavailable")
	}
	return current.value, nil
}

func (f *File[T]) Status() Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

// SetMetrics attaches the process-wide content-free metrics sink after a
// component has been constructed. It is safe to call during startup before
// serving requests.
func (f *File[T]) SetMetrics(metrics Metrics) {
	f.mu.Lock()
	f.metrics = metrics
	f.mu.Unlock()
}

// Close stops the bounded polling goroutine.
func (f *File[T]) Close() {
	select {
	case <-f.closed:
		return
	default:
		close(f.closed)
	}
	<-f.done
}

// SecretFile returns a reloadable, trimmed secret. Secret values are never
// included in errors or status.
func SecretFile(path string, interval time.Duration, metrics Metrics) (*File[string], error) {
	return NewFile(path, interval, func(data []byte) (string, time.Time, error) {
		value := strings.TrimSpace(string(data))
		if value == "" {
			return "", time.Time{}, errors.New("empty secret")
		}
		return value, time.Time{}, nil
	}, metrics)
}

// PublicKeyFile loads an asymmetric JWT verification key. The parser is kept
// here so authentication can use the same atomic file lifecycle as secrets.
func PublicKeyFile(path string, interval time.Duration, metrics Metrics) (*File[any], error) {
	return NewFile(path, interval, func(data []byte) (any, time.Time, error) {
		key, err := ParsePublicKey(data)
		return key, time.Time{}, err
	}, metrics)
}

func ParsePublicKey(data []byte) (any, error) {
	block, _ := pemDecode(data)
	if block == nil {
		return nil, errors.New("missing public key")
	}
	if cert, err := x509.ParseCertificate(block); err == nil {
		return cert.PublicKey, nil
	}
	key, err := x509.ParsePKIXPublicKey(block)
	if err == nil {
		return key, nil
	}
	if rsaKey, rsaErr := x509.ParsePKCS1PublicKey(block); rsaErr == nil {
		return rsaKey, nil
	}
	return nil, errors.New("invalid public key")
}

// pemDecode is split out to keep the public-key parser's error surface terse.
func pemDecode(data []byte) ([]byte, []byte) {
	for len(data) > 0 {
		block, rest := decodePEM(data)
		if block != nil {
			return block, rest
		}
		return nil, nil
	}
	return nil, nil
}

// The standard pem package is wrapped so callers cannot accidentally expose
// malformed input in a returned error.
func decodePEM(data []byte) ([]byte, []byte) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, rest
	}
	return block.Bytes, rest
}

type ClientTLSOptions struct {
	CAFile          string
	CertificateFile string
	KeyFile         string
	ServerName      string
	MinVersion      uint16
	MaxVersion      uint16
	PollInterval    time.Duration
	Metrics         Metrics
}

func (o ClientTLSOptions) TLSConfig() (*tls.Config, []*File[tls.Certificate], error) {
	if o.MinVersion == 0 {
		o.MinVersion = tls.VersionTLS12
	}
	if o.MinVersion < tls.VersionTLS12 {
		return nil, nil, errors.New("TLS minimum version must be 1.2 or newer")
	}
	if o.MaxVersion != 0 && o.MaxVersion < o.MinVersion {
		return nil, nil, errors.New("TLS maximum version is below the minimum")
	}
	roots, err := loadRoots(o.CAFile)
	if err != nil {
		return nil, nil, errors.New("TLS CA bundle is invalid")
	}
	var certFiles []*File[tls.Certificate]
	var getCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	if o.CertificateFile != "" || o.KeyFile != "" {
		if o.CertificateFile == "" || o.KeyFile == "" {
			return nil, nil, errors.New("TLS client certificate and key must be provided together")
		}
		certFile, err := NewFileWithDependency(o.CertificateFile, o.KeyFile, o.PollInterval, func(data []byte) (tls.Certificate, time.Time, error) {
			cert, err := tls.X509KeyPair(data, mustRead(o.KeyFile))
			if err != nil {
				return tls.Certificate{}, time.Time{}, errors.New("invalid TLS client certificate")
			}
			return cert, certificateExpiry(cert), nil
		}, o.Metrics)
		if err != nil {
			return nil, nil, err
		}
		// The key file is part of the material fingerprint, so rotating either
		// half of the pair is observed without exposing the private material.
		certFiles = append(certFiles, certFile)
		getCert = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, err := certFile.Get()
			if err != nil {
				return nil, errors.New("TLS client certificate unavailable")
			}
			return &cert, nil
		}
	}
	return &tls.Config{MinVersion: o.MinVersion, MaxVersion: o.MaxVersion, RootCAs: roots, ServerName: o.ServerName, GetClientCertificate: getCert}, certFiles, nil
}

func mustRead(path string) []byte {
	data, _ := os.ReadFile(path)
	return data
}

func loadRoots(path string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if path == "" {
		return pool, nil
	}
	data, err := os.ReadFile(path)
	if err != nil || !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("invalid CA bundle")
	}
	return pool, nil
}

func certificateExpiry(cert tls.Certificate) time.Time {
	if len(cert.Certificate) == 0 {
		return time.Time{}
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return time.Time{}
	}
	return x509Cert.NotAfter
}

type ServerTLSOptions struct {
	CertificateFile string
	KeyFile         string
	ClientCAFile    string
	RequireClient   bool
	MinVersion      uint16
	MaxVersion      uint16
	PollInterval    time.Duration
	Metrics         Metrics
}

func (o ServerTLSOptions) TLSConfig() (*tls.Config, []*File[tls.Certificate], error) {
	if o.CertificateFile == "" || o.KeyFile == "" {
		return nil, nil, errors.New("TLS server certificate and key are required")
	}
	if o.MinVersion == 0 {
		o.MinVersion = tls.VersionTLS12
	}
	if o.MinVersion < tls.VersionTLS12 || o.MaxVersion != 0 && o.MaxVersion < o.MinVersion {
		return nil, nil, errors.New("invalid TLS version range")
	}
	certFile, err := NewFileWithDependency(o.CertificateFile, o.KeyFile, o.PollInterval, func(data []byte) (tls.Certificate, time.Time, error) {
		cert, err := tls.X509KeyPair(data, mustRead(o.KeyFile))
		if err != nil {
			return tls.Certificate{}, time.Time{}, errors.New("invalid TLS server certificate")
		}
		return cert, certificateExpiry(cert), nil
	}, o.Metrics)
	if err != nil {
		return nil, nil, err
	}
	config := &tls.Config{MinVersion: o.MinVersion, MaxVersion: o.MaxVersion, ClientAuth: tls.NoClientCert,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := certFile.Get()
			if err != nil {
				return nil, errors.New("TLS server certificate unavailable")
			}
			return &cert, nil
		}}
	if o.RequireClient {
		if o.ClientCAFile == "" {
			certFile.Close()
			return nil, nil, errors.New("mTLS client CA is required")
		}
		caData, err := os.ReadFile(o.ClientCAFile)
		if err != nil {
			certFile.Close()
			return nil, nil, errors.New("mTLS client CA is unreadable")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			certFile.Close()
			return nil, nil, errors.New("mTLS client CA is invalid")
		}
		config.ClientCAs = pool
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return config, []*File[tls.Certificate]{certFile}, nil
}

// DialContext creates a TLS-aware dialer for Redis and other clients that do
// not use net/http's transport. Hostname verification remains enabled.
func DialContext(base *net.Dialer, cfg *tls.Config) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := base.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		host, _, _ := net.SplitHostPort(address)
		clone := cfg.Clone()
		if clone.ServerName == "" {
			clone.ServerName = host
		}
		tlsConn := tls.Client(conn, clone)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
}

// Fingerprint returns a non-secret material fingerprint useful for tests and
// diagnostics; it is intentionally not included in readiness responses.
func Fingerprint(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:8])
}
