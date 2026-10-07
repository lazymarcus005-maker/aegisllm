// Command loadtest is the bounded, dependency-free HTTP release probe. It is
// intentionally a Go client rather than a shell/curl loop so cancellation,
// response-body ownership, and latency accounting are tested consistently.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type scenario struct {
	Name, Path, Body string
	Expected         map[int]bool
	Stream           bool
}

type sample struct {
	Name         string           `json:"name"`
	Requests     int64            `json:"requests"`
	Errors       int64            `json:"errors"`
	ErrorRate    float64          `json:"error_rate"`
	Throughput   float64          `json:"throughput_per_second"`
	P50MS        float64          `json:"p50_ms"`
	P95MS        float64          `json:"p95_ms"`
	P99MS        float64          `json:"p99_ms"`
	MinMS        float64          `json:"min_ms"`
	MaxMS        float64          `json:"max_ms"`
	AllocBytes   float64          `json:"alloc_bytes_per_request"`
	Mallocs      float64          `json:"mallocs_per_request"`
	StatusCounts map[string]int64 `json:"status_counts"`
}

type report struct {
	SchemaVersion string    `json:"schema_version"`
	StartedAt     time.Time `json:"started_at"`
	DurationMS    int64     `json:"duration_ms"`
	URL           string    `json:"url"`
	Workers       int       `json:"workers"`
	GOMAXPROCS    int       `json:"gomaxprocs"`
	WarmupMS      int64     `json:"warmup_ms"`
	Samples       []sample  `json:"samples"`
	Backpressure  bool      `json:"backpressure_probe"`
	Shutdown      bool      `json:"graceful_shutdown_probe"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "loadtest:", err)
		os.Exit(1)
	}
}

func run() error {
	urlFlag := flag.String("url", "http://127.0.0.1:8080", "gateway base URL")
	duration := flag.Duration("duration", 3*time.Second, "bounded measurement duration")
	warmup := flag.Duration("warmup", 500*time.Millisecond, "warm-up duration excluded from measurements")
	workers := flag.Int("workers", 4, "bounded concurrent workers")
	maxBody := flag.Int64("max-body", 4<<20, "maximum response bytes to read")
	path := flag.String("path", "/v1/chat/completions", "request path")
	scenarioName := flag.String("scenario", "clean", "clean,secret-block,pii-tokenize,stream,mcp,policy-reload,audit-append,vault")
	expect := flag.String("expect", "200", "comma-separated accepted HTTP statuses")
	reportPath := flag.String("report", "build/release/load.json", "JSON report path")
	gomaxprocs := flag.Int("gomaxprocs", 1, "GOMAXPROCS used by the probe")
	backpressure := flag.Bool("backpressure", false, "mark that rate-limit/backpressure behavior is under test")
	shutdown := flag.Bool("shutdown", false, "mark that caller will exercise graceful shutdown")
	flag.Parse()
	runtime.GOMAXPROCS(*gomaxprocs)
	if *workers < 1 || *workers > 256 || *duration <= 0 || *duration > 24*time.Hour || *warmup < 0 || *gomaxprocs < 1 {
		return errors.New("workers, duration, warmup, and gomaxprocs are outside safe bounds")
	}
	if err := os.MkdirAll(filepathDir(*reportPath), 0750); err != nil {
		return err
	}
	accepted, err := parseStatuses(*expect)
	if err != nil {
		return err
	}
	s := makeScenario(*scenarioName, *path, accepted)
	client := &http.Client{Transport: &http.Transport{MaxConnsPerHost: *workers, MaxIdleConnsPerHost: *workers}, Timeout: 15 * time.Second}
	reportStarted := time.Now().UTC()
	if *warmup > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), *warmup)
		warmupRun(ctx, client, *urlFlag, s, *maxBody, *workers)
		cancel()
	}
	start := time.Now()
	deadline := start.Add(*duration)
	var memBefore, memAfter runtime.MemStats
	runtime.ReadMemStats(&memBefore)
	var allMu sync.Mutex
	latencies := make([]float64, 0, *workers*64)
	var requests, errs atomic.Int64
	statusCounts := map[int]int64{}
	var statusMu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				began := time.Now()
				status, requestErr := doRequest(client, *urlFlag, s, *maxBody)
				elapsed := float64(time.Since(began).Microseconds()) / 1000
				requests.Add(1)
				if requestErr != nil || !s.Expected[status] {
					errs.Add(1)
				}
				statusMu.Lock()
				statusCounts[status]++
				statusMu.Unlock()
				allMu.Lock()
				latencies = append(latencies, elapsed)
				allMu.Unlock()
			}
		}()
	}
	wg.Wait()
	measurementMS := time.Since(start).Milliseconds()
	runtime.ReadMemStats(&memAfter)
	if requests.Load() == 0 {
		return errors.New("no requests completed")
	}
	sort.Float64s(latencies)
	makeSample := func() sample {
		counts := map[string]int64{}
		for status, count := range statusCounts {
			counts[strconv.Itoa(status)] = count
		}
		return sample{Name: s.Name, Requests: requests.Load(), Errors: errs.Load(), ErrorRate: float64(errs.Load()) / float64(requests.Load()), Throughput: float64(requests.Load()) / time.Since(start).Seconds(), P50MS: quantile(latencies, .50), P95MS: quantile(latencies, .95), P99MS: quantile(latencies, .99), MinMS: latencies[0], MaxMS: latencies[len(latencies)-1], AllocBytes: float64(memAfter.TotalAlloc-memBefore.TotalAlloc) / float64(requests.Load()), Mallocs: float64(memAfter.Mallocs-memBefore.Mallocs) / float64(requests.Load()), StatusCounts: counts}
	}
	r := report{SchemaVersion: "aegisllm.load/v1", StartedAt: reportStarted, DurationMS: measurementMS, URL: *urlFlag, Workers: *workers, GOMAXPROCS: *gomaxprocs, WarmupMS: warmup.Milliseconds(), Samples: []sample{makeSample()}, Backpressure: *backpressure, Shutdown: *shutdown}
	b, _ := json.MarshalIndent(r, "", "  ")
	if err := os.WriteFile(*reportPath, append(b, '\n'), 0600); err != nil {
		return err
	}
	if errs.Load() > 0 {
		return fmt.Errorf("%d of %d requests failed status/error expectations", errs.Load(), requests.Load())
	}
	return nil
}

func filepathDir(path string) string {
	if i := strings.LastIndexAny(path, "/\\"); i >= 0 {
		if i == 0 {
			return path[:1]
		}
		return path[:i]
	}
	return "."
}

func parseStatuses(value string) (map[int]bool, error) {
	out := map[int]bool{}
	for _, part := range strings.Split(value, ",") {
		code, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || code < 100 || code > 599 {
			return nil, fmt.Errorf("invalid expected status %q", part)
		}
		out[code] = true
	}
	if len(out) == 0 {
		return nil, errors.New("at least one expected status is required")
	}
	return out, nil
}

func makeScenario(name, path string, expected map[int]bool) scenario {
	if name == "secret-block" {
		return scenario{Name: name, Path: path, Body: `{"model":"m","messages":[{"role":"user","content":"Bearer sk-abcdefghijklmnopqrstuvwxyz123456"}]}`, Expected: expected}
	}
	body := `{"model":"m","messages":[{"role":"user","content":"hello release gate"}]} `
	if name == "pii-tokenize" {
		body = `{"model":"m","messages":[{"role":"user","content":"customer phone 0812345678"}]}`
	}
	stream := name == "stream"
	if stream {
		body = `{"model":"m","stream":true,"messages":[{"role":"user","content":"hello stream"}]}`
	}
	return scenario{Name: name, Path: path, Body: body, Expected: expected, Stream: stream}
}

func warmupRun(ctx context.Context, client *http.Client, base string, s scenario, maxBody int64, workers int) {
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				_, _ = doRequest(client, base, s, maxBody)
			}
		}()
	}
	wg.Wait()
}

func doRequest(client *http.Client, base string, s scenario, maxBody int64) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+s.Path, strings.NewReader(s.Body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.Stream {
		req.Header.Set("Accept", "text/event-stream")
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody+1))
	return resp.StatusCode, readErr
}

func quantile(values []float64, q float64) float64 {
	if len(values) == 0 {
		return 0
	}
	idx := int(float64(len(values)-1) * q)
	return values[idx]
}
