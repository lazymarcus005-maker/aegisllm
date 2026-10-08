// Package credentialbroker resolves opaque credential profile references at
// execution time. It deliberately returns only outbound headers to callers;
// credentials never become part of an MCP request, audit event, or model
// visible response.
package credentialbroker

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aegisllm/gateway/internal/securetransport"
	"gopkg.in/yaml.v3"
)

const (
	TypeHeader  = "header"
	TypeBearer  = "bearer"
	TypeOAuthCC = "oauth2_client_credentials"
)

type TLSConfig struct {
	CAFile          string `yaml:"ca_file,omitempty"`
	CertificateFile string `yaml:"certificate_file,omitempty"`
	KeyFile         string `yaml:"key_file,omitempty"`
	ServerName      string `yaml:"server_name,omitempty"`
}

type Profile struct {
	ID               string    `yaml:"id"`
	Type             string    `yaml:"type"`
	Header           string    `yaml:"header,omitempty"`
	SecretFile       string    `yaml:"secret_file,omitempty"`
	TokenURL         string    `yaml:"token_url,omitempty"`
	ClientID         string    `yaml:"client_id,omitempty"`
	ClientSecretFile string    `yaml:"client_secret_file,omitempty"`
	Scopes           []string  `yaml:"scopes,omitempty"`
	TLS              TLSConfig `yaml:"tls,omitempty"`
}

type Registry struct {
	Schema   string    `yaml:"schema"`
	Version  int       `yaml:"version"`
	Profiles []Profile `yaml:"profiles"`
}

type Credential struct {
	SourceType string
	Headers    http.Header
}

type Config struct {
	PollInterval time.Duration
	TLSMin       uint16
	TLSMax       uint16
	Metrics      securetransport.Metrics
	MaxBody      int64
}

type Broker struct {
	file     *securetransport.File[Registry]
	interval time.Duration
	cfg      Config
	mu       sync.Mutex
	secrets  map[string]*securetransport.File[string]
	states   map[string]*oauthState
	clients  map[string]*http.Client
	certs    map[string][]*securetransport.File[tls.Certificate]
}

type oauthState struct {
	mu      sync.Mutex
	token   string
	expires time.Time
	loading bool
	wait    chan struct{}
}

func New(path string, cfg Config) (*Broker, error) {
	if strings.TrimSpace(path) == "" {
		return &Broker{cfg: cfg, secrets: map[string]*securetransport.File[string]{}, states: map[string]*oauthState{}, clients: map[string]*http.Client{}, certs: map[string][]*securetransport.File[tls.Certificate]{}}, nil
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = securetransport.DefaultPollInterval
	}
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = 64 * 1024
	}
	b := &Broker{cfg: cfg, interval: cfg.PollInterval, secrets: map[string]*securetransport.File[string]{}, states: map[string]*oauthState{}, clients: map[string]*http.Client{}, certs: map[string][]*securetransport.File[tls.Certificate]{}}
	f, err := securetransport.NewFile(path, cfg.PollInterval, func(data []byte) (Registry, time.Time, error) {
		var reg Registry
		if err := yaml.Unmarshal(data, &reg); err != nil {
			return Registry{}, time.Time{}, errors.New("credential registry is invalid")
		}
		if err := validateRegistry(reg); err != nil {
			return Registry{}, time.Time{}, err
		}
		return reg, time.Time{}, nil
	}, cfg.Metrics)
	if err != nil {
		return nil, err
	}
	b.file = f
	return b, nil
}

func validateRegistry(reg Registry) error {
	if reg.Schema != "aegisllm.credentials/v1" || reg.Version != 1 || len(reg.Profiles) == 0 {
		return errors.New("credential registry version or profiles are invalid")
	}
	seen := map[string]bool{}
	for _, p := range reg.Profiles {
		if !safeID(p.ID) || seen[p.ID] {
			return errors.New("credential profile id is invalid")
		}
		seen[p.ID] = true
		switch p.Type {
		case TypeHeader:
			if p.Header == "" || p.SecretFile == "" || p.TokenURL != "" || p.ClientSecretFile != "" {
				return errors.New("header credential profile is invalid")
			}
		case TypeBearer:
			if p.SecretFile == "" || p.TokenURL != "" || p.ClientSecretFile != "" {
				return errors.New("bearer credential profile is invalid")
			}
		case TypeOAuthCC:
			u, err := url.Parse(p.TokenURL)
			if err != nil || (!strings.EqualFold(u.Scheme, "https") && !isLoopbackHost(u.Hostname())) || u.User != nil || p.ClientID == "" || p.ClientSecretFile == "" {
				return errors.New("oauth credential profile is invalid")
			}
		default:
			return errors.New("credential profile type is invalid")
		}
		if p.SecretFile != "" && strings.ContainsAny(p.SecretFile, "\r\n") {
			return errors.New("credential file path is invalid")
		}
	}
	return nil
}

func safeID(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

func isLoopbackHost(host string) bool {
	host = strings.ToLower(host)
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]"
}

func (b *Broker) profile(id string) (Profile, error) {
	if b == nil || b.file == nil {
		return Profile{}, errors.New("credential profile unavailable")
	}
	reg, err := b.file.Get()
	if err != nil {
		return Profile{}, errors.New("credential registry unavailable")
	}
	for _, p := range reg.Profiles {
		if p.ID == id {
			return p, nil
		}
	}
	return Profile{}, errors.New("credential profile unavailable")
}

func (b *Broker) Get(ctx context.Context, id string) (Credential, error) {
	p, err := b.profile(id)
	if err != nil {
		return Credential{}, err
	}
	switch p.Type {
	case TypeHeader, TypeBearer:
		secret, err := b.secret(p.ID, p.SecretFile)
		if err != nil {
			return Credential{}, errors.New("credential unavailable")
		}
		h := make(http.Header)
		if p.Type == TypeBearer {
			h.Set("Authorization", "Bearer "+secret)
		} else {
			h.Set(p.Header, secret)
		}
		return Credential{SourceType: p.Type, Headers: h}, nil
	case TypeOAuthCC:
		token, err := b.oauthToken(ctx, p)
		if err != nil {
			return Credential{}, err
		}
		h := make(http.Header)
		h.Set("Authorization", "Bearer "+token)
		return Credential{SourceType: p.Type, Headers: h}, nil
	default:
		return Credential{}, errors.New("credential unavailable")
	}
}

func (b *Broker) secret(id, path string) (string, error) {
	b.mu.Lock()
	f := b.secrets[id]
	if f == nil {
		var err error
		f, err = securetransport.SecretFile(path, b.interval, b.cfg.Metrics)
		if err != nil {
			b.mu.Unlock()
			return "", err
		}
		b.secrets[id] = f
	}
	b.mu.Unlock()
	return f.Get()
}

func (b *Broker) oauthToken(ctx context.Context, p Profile) (string, error) {
	b.mu.Lock()
	state := b.states[p.ID]
	if state == nil {
		state = &oauthState{}
		b.states[p.ID] = state
	}
	b.mu.Unlock()
	for {
		state.mu.Lock()
		if state.token != "" && time.Until(state.expires) > 30*time.Second {
			token := state.token
			state.mu.Unlock()
			return token, nil
		}
		if state.loading {
			wait := state.wait
			state.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return "", errors.New("credential token unavailable")
			}
		}
		state.loading = true
		state.wait = make(chan struct{})
		wait := state.wait
		state.mu.Unlock()

		token, expiry, err := b.fetchToken(ctx, p)
		state.mu.Lock()
		state.loading = false
		if err == nil {
			state.token, state.expires = token, expiry
		}
		close(wait)
		state.mu.Unlock()
		if err != nil {
			return "", err
		}
		return token, nil
	}
}

func (b *Broker) fetchToken(ctx context.Context, p Profile) (string, time.Time, error) {
	secret, err := b.secret(p.ID+"/client", p.ClientSecretFile)
	if err != nil {
		return "", time.Time{}, errors.New("credential unavailable")
	}
	client, err := b.oauthClient(p)
	if err != nil {
		return "", time.Time{}, errors.New("credential transport unavailable")
	}
	form := url.Values{"grant_type": {"client_credentials"}}
	if len(p.Scopes) > 0 {
		form.Set("scope", strings.Join(p.Scopes, " "))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, errors.New("credential token request failed")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(p.ClientID, secret)
	resp, err := client.Do(req)
	if err != nil {
		return "", time.Time{}, errors.New("credential token request failed")
	}
	defer resp.Body.Close()
	body, tooLarge, err := readBounded(resp.Body, b.cfg.MaxBody)
	if err != nil || tooLarge || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", time.Time{}, errors.New("credential token request failed")
	}
	var result struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &result); err != nil || result.AccessToken == "" {
		return "", time.Time{}, errors.New("credential token response invalid")
	}
	if result.ExpiresIn <= 0 {
		result.ExpiresIn = 60
	}
	return result.AccessToken, time.Now().Add(time.Duration(result.ExpiresIn) * time.Second), nil
}

func (b *Broker) oauthClient(p Profile) (*http.Client, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if client := b.clients[p.ID]; client != nil {
		return client, nil
	}
	tlsCfg, certs, err := (securetransport.ClientTLSOptions{CAFile: p.TLS.CAFile, CertificateFile: p.TLS.CertificateFile, KeyFile: p.TLS.KeyFile, ServerName: p.TLS.ServerName, MinVersion: b.cfg.TLSMin, MaxVersion: b.cfg.TLSMax, PollInterval: b.interval, Metrics: b.cfg.Metrics}).TLSConfig()
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{TLSClientConfig: tlsCfg}
	b.certs[p.ID] = certs
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	b.clients[p.ID] = client
	return client, nil
}

func readBounded(r interface{ Read([]byte) (int, error) }, max int64) ([]byte, bool, error) {
	if max <= 0 {
		max = 64 * 1024
	}
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	return data, int64(len(data)) > max, err
}

func (b *Broker) Status(id string) (securetransport.Status, error) {
	b.mu.Lock()
	f := b.secrets[id]
	b.mu.Unlock()
	if f == nil {
		return securetransport.Status{}, errors.New("credential profile unavailable")
	}
	return f.Status(), nil
}

func (b *Broker) Close() {
	if b == nil {
		return
	}
	if b.file != nil {
		b.file.Close()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, f := range b.secrets {
		f.Close()
	}
	for _, files := range b.certs {
		for _, f := range files {
			f.Close()
		}
	}
	for _, client := range b.clients {
		if t, ok := client.Transport.(*http.Transport); ok {
			t.CloseIdleConnections()
		}
	}
}
