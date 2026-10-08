package audit

// This file contains the durable transport. It intentionally uses only the
// standard library so the WAL can be used by the gateway and audittool
// without a broker or an in-memory queue masquerading as durability.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aegisllm/gateway/internal/securetransport"
)

var (
	ErrQuota      = errors.New("audit WAL disk quota exceeded")
	ErrCorrupt    = errors.New("audit WAL corruption detected")
	ErrNotDurable = errors.New("audit record is not durable")
	frameMagic    = [8]byte{'A', 'E', 'G', 'I', 'S', 'W', 'A', 'L'}
	frameVersion  = uint16(1)
)

const frameHeadSize = 8 + 2 + 2 + 8 + 4 + 32 + 32 + 32

type Durability string

const (
	DurabilityWrite Durability = "write"
	DurabilitySync  Durability = "sync"
)

type WALConfig struct {
	Dir               string
	SegmentBytes      int64
	MaxBytes          int64
	Retention         time.Duration
	Fsync             Durability
	HMACKey           []byte
	EncryptionKeyring string
	Sanitize          SanitizeOptions
}

type WALStatus struct {
	Dir              string `json:"dir,omitempty"`
	CurrentSegment   string `json:"current_segment,omitempty"`
	Corruption       string `json:"corruption,omitempty"`
	Bytes            int64  `json:"bytes"`
	QueueBytes       int64  `json:"queue_bytes"`
	Records          uint64 `json:"records"`
	NextSequence     uint64 `json:"next_sequence"`
	OldestAgeSeconds int64  `json:"oldest_age_seconds"`
	Durability       string `json:"durability"`
	Ready            bool   `json:"ready"`
	LastError        string `json:"last_error,omitempty"`
}

type checkpoint struct {
	NextSequence uint64 `json:"next_sequence"`
	LastHash     string `json:"last_hash"`
	Segment      string `json:"segment"`
}

type WAL struct {
	mu        sync.Mutex
	scanMu    sync.RWMutex
	cfg       WALConfig
	key       []byte
	keyID     string
	block     cipher.AEAD
	blocks    map[string]cipher.AEAD
	file      *os.File
	segment   string
	segmentNo uint64
	next      uint64
	previous  [32]byte
	bytes     int64
	records   uint64
	oldest    time.Time
	lastErr   error
	closed    bool
}

type walRecord struct {
	Event Event
	Seq   uint64
	Hash  [32]byte
	Prev  [32]byte
}

func OpenWAL(cfg WALConfig) (*WAL, error) {
	if strings.TrimSpace(cfg.Dir) == "" {
		return nil, errors.New("audit WAL directory is required")
	}
	if cfg.SegmentBytes <= 0 {
		cfg.SegmentBytes = 64 << 20
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = 4 << 30
	}
	if cfg.Fsync == "" {
		cfg.Fsync = DurabilitySync
	}
	if cfg.Fsync != DurabilityWrite && cfg.Fsync != DurabilitySync {
		return nil, errors.New("invalid audit durability")
	}
	if err := os.MkdirAll(cfg.Dir, 0700); err != nil {
		return nil, errors.New("audit WAL directory unavailable")
	}
	w := &WAL{cfg: cfg, key: append([]byte(nil), cfg.HMACKey...)}
	if len(w.key) == 0 {
		path := filepath.Join(cfg.Dir, "hmac.key")
		data, err := securetransport.ReadTrustedFile(path)
		if errors.Is(err, os.ErrNotExist) {
			w.key = make([]byte, 32)
			if _, err = rand.Read(w.key); err != nil {
				return nil, err
			}
			if err = atomicWrite(path, w.key, 0600); err != nil {
				return nil, errors.New("audit HMAC key unavailable")
			}
		} else if err != nil {
			return nil, errors.New("audit HMAC key unavailable")
		} else {
			w.key = data
		}
	}
	if len(w.key) < 32 {
		return nil, errors.New("audit HMAC key must be at least 32 bytes")
	}
	if cfg.EncryptionKeyring != "" {
		keys, id, err := loadEncryptionKeyring(cfg.EncryptionKeyring)
		if err != nil {
			return nil, err
		}
		w.keyID = id
		w.blocks = map[string]cipher.AEAD{}
		for keyID, key := range keys {
			block, err := aes.NewCipher(key)
			if err != nil {
				return nil, errors.New("audit encryption key invalid")
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				return nil, err
			}
			w.blocks[keyID] = gcm
		}
		w.block = w.blocks[id]
	}
	if err := w.recover(); err != nil {
		return nil, err
	}
	return w, nil
}

// NewWAL is the constructor alias used by integrations that prefer the
// conventional NewX naming; both constructors have identical semantics.
func NewWAL(cfg WALConfig) (*WAL, error) { return OpenWAL(cfg) }

func (w *WAL) recover() error {
	files, err := segmentFiles(w.cfg.Dir)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		w.next = 1
		return w.openSegment(1)
	}
	var expected uint64 = 1
	var prev [32]byte
	for fileIndex, name := range files {
		no := segmentNumber(name)
		if no == 0 {
			continue
		}
		f, err := securetransport.OpenTrustedFile(filepath.Join(w.cfg.Dir, name), os.O_RDWR, 0600)
		if err != nil {
			return err
		}
		st, _ := f.Stat()
		size := st.Size()
		var offset int64
		if size > 0 {
			firstSeq, firstPrev, headerErr := firstFrameLink(f)
			if headerErr != nil {
				_ = f.Close()
				return fmt.Errorf("%w: %s", ErrCorrupt, name)
			}
			if fileIndex == 0 {
				expected, prev = firstSeq, firstPrev
			} else if firstSeq != expected || !bytes.Equal(firstPrev[:], prev[:]) {
				_ = f.Close()
				return fmt.Errorf("%w: segment chain", ErrCorrupt)
			}
		}
		for offset < size {
			rec, nextOffset, torn, err := w.readFrame(f, offset, expected, prev)
			if torn {
				if err := f.Truncate(offset); err != nil {
					_ = f.Close()
					return err
				}
				break
			}
			if err != nil {
				_ = f.Close()
				w.lastErr = err
				return fmt.Errorf("%w: %s", ErrCorrupt, name)
			}
			if rec.Seq != expected {
				_ = f.Close()
				return fmt.Errorf("%w: non-contiguous sequence", ErrCorrupt)
			}
			prev, expected, offset = rec.Hash, expected+1, nextOffset
			w.records++
			w.bytes += nextOffset - (nextOffset - int64(frameHeadSize) - int64(len(mustJSON(rec.Event))) - 4)
			if w.oldest.IsZero() {
				w.oldest = rec.Event.Timestamp
			}
		}
		_ = f.Close()
	}
	w.next, w.previous = expected, prev
	last := files[len(files)-1]
	w.segment = last
	w.segmentNo = segmentNumber(last)
	path := filepath.Join(w.cfg.Dir, last)
	w.file, err = securetransport.OpenTrustedFile(path, os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	st, _ := w.file.Stat()
	w.bytes = totalBytes(files, w.cfg.Dir)
	if st.Size() >= w.cfg.SegmentBytes && st.Size() > 0 {
		return w.openSegment(w.segmentNo + 1)
	}
	if w.next == 1 {
		w.next = 1
	}
	return w.writeCheckpoint()
}

func (w *WAL) readFrame(f *os.File, offset int64, expected uint64, previous [32]byte) (walRecord, int64, bool, error) {
	var head = make([]byte, frameHeadSize)
	n, err := f.ReadAt(head, offset)
	if err != nil && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
		return walRecord{}, offset, true, nil
	}
	if n != len(head) {
		return walRecord{}, offset, true, nil
	}
	if !bytes.Equal(head[:8], frameMagic[:]) || binary.BigEndian.Uint16(head[8:10]) != frameVersion {
		return walRecord{}, offset, false, ErrCorrupt
	}
	seq := binary.BigEndian.Uint64(head[12:20])
	length := binary.BigEndian.Uint32(head[20:24])
	if length == 0 || length > 64<<20 {
		return walRecord{}, offset, false, ErrCorrupt
	}
	end := offset + int64(frameHeadSize) + int64(length) + 4
	data := make([]byte, int64(frameHeadSize)+int64(length)+4)
	n, err = f.ReadAt(data, offset)
	if err != nil && errors.Is(err, io.ErrUnexpectedEOF) {
		return walRecord{}, offset, true, nil
	}
	if n != len(data) {
		return walRecord{}, offset, true, nil
	}
	if crc32.ChecksumIEEE(data[:len(data)-4]) != binary.BigEndian.Uint32(data[len(data)-4:]) {
		return walRecord{}, offset, false, ErrCorrupt
	}
	if !bytes.Equal(data[24:56], previous[:]) {
		return walRecord{}, offset, false, ErrCorrupt
	}
	payload, err := w.decrypt(data[frameHeadSize:frameHeadSize+int(length)], data[10:12])
	if err != nil {
		return walRecord{}, offset, false, err
	}
	hash := sha256.Sum256(append(append(u64(seq), previous[:]...), payload...))
	if !bytes.Equal(data[56:88], hash[:]) {
		return walRecord{}, offset, false, ErrCorrupt
	}
	mac := hmac.New(sha256.New, w.key)
	_, _ = mac.Write(hash[:])
	if !hmac.Equal(data[88:120], mac.Sum(nil)) {
		return walRecord{}, offset, false, ErrCorrupt
	}
	var ev Event
	if err := json.Unmarshal(payload, &ev); err != nil {
		return walRecord{}, offset, false, ErrCorrupt
	}
	ev = SanitizeEvent(ev, w.cfg.Sanitize)
	ev.Integrity = Integrity{Sequence: seq, Previous: hex.EncodeToString(previous[:]), RecordHash: hex.EncodeToString(hash[:]), KeyID: w.keyID}
	return walRecord{Event: ev, Seq: seq, Prev: previous, Hash: hash}, end, false, nil
}

func (w *WAL) Append(ctx context.Context, event Event) (Event, error) {
	w.scanMu.Lock()
	defer w.scanMu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return Event{}, errors.New("audit WAL is closed")
	}
	select {
	case <-ctx.Done():
		return Event{}, ctx.Err()
	default:
	}
	ev := SanitizeEvent(event, w.cfg.Sanitize)
	ev.Integrity = Integrity{Sequence: w.next, Previous: hex.EncodeToString(w.previous[:]), KeyID: w.keyID}
	payload, err := json.Marshal(ev)
	if err != nil {
		return Event{}, err
	}
	hash := sha256.Sum256(append(append(u64(w.next), w.previous[:]...), payload...))
	mac := hmac.New(sha256.New, w.key)
	_, _ = mac.Write(hash[:])
	stored, flags, err := w.encrypt(payload)
	if err != nil {
		return Event{}, err
	}
	frame := make([]byte, frameHeadSize+len(stored)+4)
	copy(frame[:8], frameMagic[:])
	binary.BigEndian.PutUint16(frame[8:10], frameVersion)
	binary.BigEndian.PutUint16(frame[10:12], flags)
	binary.BigEndian.PutUint64(frame[12:20], w.next)
	frameLength := uint64(len(stored))
	if frameLength > uint64(^uint32(0)) {
		return Event{}, errors.New("audit frame is too large")
	}
	binary.BigEndian.PutUint32(frame[20:24], uint32(frameLength)) // #nosec G115 -- frameLength is bounded to uint32 above.
	copy(frame[24:56], w.previous[:])
	copy(frame[56:88], hash[:])
	copy(frame[88:120], mac.Sum(nil))
	copy(frame[120:], stored)
	binary.BigEndian.PutUint32(frame[len(frame)-4:], crc32.ChecksumIEEE(frame[:len(frame)-4]))
	if st, _ := w.file.Stat(); st != nil && st.Size() > 0 && st.Size()+int64(len(frame)) > w.cfg.SegmentBytes {
		if err := w.rotate(); err != nil {
			return Event{}, err
		}
	}
	if _, err := w.file.Write(frame); err != nil {
		w.lastErr = err
		return Event{}, ErrNotDurable
	}
	if w.cfg.Fsync == DurabilitySync {
		if err := w.file.Sync(); err != nil {
			w.lastErr = err
			return Event{}, ErrNotDurable
		}
	}
	w.previous, w.next = hash, w.next+1
	w.records++
	w.bytes += int64(len(frame))
	if w.oldest.IsZero() {
		w.oldest = ev.Timestamp
	}
	if err := w.writeCheckpoint(); err != nil {
		w.lastErr = err
		return Event{}, ErrNotDurable
	}
	if err := w.enforceQuota(); err != nil {
		w.lastErr = err
		return Event{}, err
	}
	ev.Integrity.RecordHash = hex.EncodeToString(hash[:])
	return ev, nil
}

func (w *WAL) Replay(ctx context.Context, fn func(Event) error) error {
	return w.replayFrom(ctx, 0, fn)
}
func (w *WAL) ReplayAfter(ctx context.Context, sequence uint64, fn func(Event) error) error {
	return w.replayFrom(ctx, sequence, fn)
}
func (w *WAL) replayFrom(ctx context.Context, after uint64, fn func(Event) error) error {
	w.scanMu.RLock()
	defer w.scanMu.RUnlock()
	w.mu.Lock()
	files, err := segmentFiles(w.cfg.Dir)
	w.mu.Unlock()
	if err != nil {
		return err
	}
	var expected uint64 = 1
	var prev [32]byte
	for fileIndex, name := range files {
		f, err := securetransport.OpenTrustedFile(filepath.Join(w.cfg.Dir, name), os.O_RDONLY, 0)
		if err != nil {
			return err
		}
		st, _ := f.Stat()
		if st.Size() > 0 {
			firstSeq, firstPrev, headerErr := firstFrameLink(f)
			if headerErr != nil {
				_ = f.Close()
				return fmt.Errorf("%w: %s", ErrCorrupt, name)
			}
			if fileIndex == 0 {
				expected, prev = firstSeq, firstPrev
			} else if firstSeq != expected || !bytes.Equal(firstPrev[:], prev[:]) {
				_ = f.Close()
				return fmt.Errorf("%w: segment chain", ErrCorrupt)
			}
		}
		for off := int64(0); off < st.Size(); {
			rec, next, torn, err := w.readFrame(f, off, expected, prev)
			if torn {
				_ = f.Close()
				return fmt.Errorf("%w: torn frame", ErrCorrupt)
			}
			if err != nil {
				_ = f.Close()
				return fmt.Errorf("%w: %s", ErrCorrupt, name)
			}
			expected, prev, off = rec.Seq+1, rec.Hash, next
			if rec.Seq > after {
				if err := fn(rec.Event); err != nil {
					_ = f.Close()
					return err
				}
			}
			select {
			case <-ctx.Done():
				_ = f.Close()
				return ctx.Err()
			default:
			}
		}
		_ = f.Close()
	}
	return nil
}

func (w *WAL) Verify(ctx context.Context) error {
	err := w.replayFrom(ctx, math.MaxUint64, func(Event) error { return nil })
	if err != nil {
		w.mu.Lock()
		w.lastErr = err
		w.mu.Unlock()
	}
	return err
}

func (w *WAL) Status() WALStatus {
	w.mu.Lock()
	defer w.mu.Unlock()
	age := int64(0)
	if !w.oldest.IsZero() {
		age = int64(time.Since(w.oldest).Seconds())
		if age < 0 {
			age = 0
		}
	}
	ready := !w.closed && w.lastErr == nil
	return WALStatus{Dir: w.cfg.Dir, CurrentSegment: w.segment, Corruption: func() string {
		if errors.Is(w.lastErr, ErrCorrupt) {
			return ErrCorrupt.Error()
		}
		return ""
	}(), Bytes: w.bytes, QueueBytes: w.bytes, Records: w.records, NextSequence: w.next, OldestAgeSeconds: age, Durability: string(w.cfg.Fsync), Ready: ready, LastError: safeError(w.lastErr)}
}

func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if w.file == nil {
		return nil
	}
	if w.cfg.Fsync == DurabilitySync {
		_ = w.file.Sync()
	}
	return w.file.Close()
}

type RepairReport struct {
	Directory   string   `json:"directory"`
	Quarantined []string `json:"quarantined,omitempty"`
	Confirmed   bool     `json:"confirmed"`
	Changed     bool     `json:"changed"`
}

// Repair only quarantines complete segment files after explicit operator
// confirmation. It never truncates, rewrites, or silently discards records.
func Repair(dir string, confirm bool) (RepairReport, error) {
	return RepairWithConfig(WALConfig{Dir: dir}, confirm)
}

func RepairWithConfig(cfg WALConfig, confirm bool) (RepairReport, error) {
	dir := cfg.Dir
	report := RepairReport{Directory: dir, Confirmed: confirm}
	if w, openErr := OpenWAL(cfg); openErr == nil {
		_ = w.Close()
		return report, nil
	}
	files, err := segmentFiles(dir)
	if err != nil {
		return report, err
	}
	report.Quarantined = append(report.Quarantined, files...)
	if len(report.Quarantined) == 0 {
		return report, errors.New("audit WAL cannot be opened")
	}
	if !confirm {
		return report, errors.New("repair requires --confirm; no files changed")
	}
	original := append([]string(nil), report.Quarantined...)
	for _, name := range original {
		target := filepath.Join(dir, name+".quarantine-"+time.Now().UTC().Format("20060102T150405Z"))
		if err := os.Rename(filepath.Join(dir, name), target); err != nil {
			return report, err
		}
		report.Quarantined = append(report.Quarantined, filepath.Base(target))
		report.Changed = true
	}
	return report, nil
}

func (w *WAL) rotate() error {
	if w.cfg.Fsync == DurabilitySync {
		if err := w.file.Sync(); err != nil {
			return err
		}
	}
	_ = w.file.Close()
	return w.openSegment(w.segmentNo + 1)
}
func (w *WAL) openSegment(no uint64) error {
	name := fmt.Sprintf("segment-%020d.wal", no)
	f, err := securetransport.OpenTrustedFile(filepath.Join(w.cfg.Dir, name), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	w.file, w.segment, w.segmentNo = f, name, no
	return nil
}
func (w *WAL) writeCheckpoint() error {
	c := checkpoint{NextSequence: w.next, LastHash: hex.EncodeToString(w.previous[:]), Segment: w.segment}
	data, _ := json.Marshal(c)
	return atomicWrite(filepath.Join(w.cfg.Dir, "checkpoint.json"), data, 0600)
}
func (w *WAL) enforceQuota() error {
	files, err := segmentFiles(w.cfg.Dir)
	if err != nil {
		return err
	}
	total := totalBytes(files, w.cfg.Dir)
	if total <= w.cfg.MaxBytes {
		return nil
	}
	cutoff := time.Now().Add(-w.cfg.Retention)
	for _, name := range files {
		if name == w.segment {
			continue
		}
		path := filepath.Join(w.cfg.Dir, name)
		st, _ := os.Stat(path)
		if w.cfg.Retention <= 0 || st.ModTime().Before(cutoff) {
			if err := os.Remove(path); err != nil {
				return err
			}
			total -= st.Size()
			if total <= w.cfg.MaxBytes {
				w.bytes = total
				return nil
			}
		}
	}
	w.bytes = total
	return ErrQuota
}

func (w *WAL) encrypt(payload []byte) ([]byte, uint16, error) {
	if w.block == nil {
		return payload, 0, nil
	}
	nonce := make([]byte, w.block.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, 0, err
	}
	id := []byte(w.keyID)
	if len(id) > 255 {
		return nil, 0, errors.New("audit encryption key id is too long")
	}
	sealed := w.block.Seal(nil, nonce, payload, nil)
	stored := append([]byte{byte(len(id))}, id...)
	stored = append(stored, nonce...)
	return append(stored, sealed...), 1, nil
}
func (w *WAL) decrypt(payload []byte, flags []byte) ([]byte, error) {
	if len(flags) == 0 || binary.BigEndian.Uint16(flags) == 0 {
		return payload, nil
	}
	if w.block == nil || len(payload) < 1 {
		return nil, errors.New("audit encryption key unavailable")
	}
	idLen := int(payload[0])
	if len(payload) < 1+idLen {
		return nil, errors.New("audit encryption frame invalid")
	}
	block := w.blocks[string(payload[1:1+idLen])]
	if block == nil {
		return nil, errors.New("audit encryption key unavailable")
	}
	start := 1 + idLen
	if len(payload) < start+block.NonceSize() {
		return nil, errors.New("audit encryption frame invalid")
	}
	n := payload[start : start+block.NonceSize()]
	return block.Open(nil, n, payload[start+block.NonceSize():], nil)
}

func loadEncryptionKeyring(path string) (map[string][]byte, string, error) {
	data, err := securetransport.ReadTrustedFile(path)
	if err != nil {
		return nil, "", errors.New("audit encryption keyring unavailable")
	}
	var r struct {
		Active string            `json:"active"`
		Keys   map[string]string `json:"keys"`
	}
	if json.Unmarshal(data, &r) != nil || r.Active == "" {
		return nil, "", errors.New("audit encryption keyring invalid")
	}
	keys := map[string][]byte{}
	for id, encoded := range r.Keys {
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(key) != 32 {
			key, err = hex.DecodeString(encoded)
		}
		if err != nil || len(key) != 32 {
			return nil, "", errors.New("audit encryption keyring invalid")
		}
		keys[BoundedLabel(id)] = key
	}
	if len(keys) == 0 || keys[BoundedLabel(r.Active)] == nil {
		return nil, "", errors.New("audit encryption keyring invalid")
	}
	return keys, BoundedLabel(r.Active), nil
}

func segmentFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "segment-") && strings.HasSuffix(e.Name(), ".wal") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}
func segmentNumber(name string) uint64 {
	name = strings.TrimSuffix(strings.TrimPrefix(name, "segment-"), ".wal")
	n, _ := strconv.ParseUint(name, 10, 64)
	return n
}
func firstFrameLink(f *os.File) (uint64, [32]byte, error) {
	var head [frameHeadSize]byte
	if _, err := f.ReadAt(head[:], 0); err != nil {
		return 0, [32]byte{}, err
	}
	if !bytes.Equal(head[:8], frameMagic[:]) || binary.BigEndian.Uint16(head[8:10]) != frameVersion {
		return 0, [32]byte{}, ErrCorrupt
	}
	var previous [32]byte
	copy(previous[:], head[24:56])
	return binary.BigEndian.Uint64(head[12:20]), previous, nil
}
func totalBytes(files []string, dir string) int64 {
	var n int64
	for _, name := range files {
		if st, err := os.Stat(filepath.Join(dir, name)); err == nil {
			n += st.Size()
		}
	}
	return n
}
func u64(v uint64) []byte     { b := make([]byte, 8); binary.BigEndian.PutUint64(b, v); return b }
func mustJSON(v Event) []byte { b, _ := json.Marshal(v); return b }
func safeError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, ErrCorrupt) {
		return ErrCorrupt.Error()
	}
	if errors.Is(err, ErrQuota) {
		return ErrQuota.Error()
	}
	return "audit storage error"
}
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".audit-tmp-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(mode); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	return err
}

// DurableSink acknowledges only after WAL.Append returns. Record remains the
// legacy fire-and-forget Sink API; callers that enforce fail-closed behavior
// should use RecordDurable.
type DurableSink struct {
	wal        *WAL
	mirror     Sink
	failClosed bool
}

func NewDurableSink(wal *WAL, mirror Sink) *DurableSink {
	return &DurableSink{wal: wal, mirror: mirror, failClosed: true}
}
func (s *DurableSink) SetFailClosed(value bool) {
	if s != nil {
		s.failClosed = value
	}
}
func (s *DurableSink) Record(e Event) { _, _ = s.RecordDurable(context.Background(), e) }
func (s *DurableSink) RecordDurable(ctx context.Context, e Event) (Event, error) {
	if s == nil || s.wal == nil {
		return Event{}, ErrNotDurable
	}
	out, err := s.wal.Append(ctx, e)
	if err != nil {
		if !s.failClosed {
			return e, nil
		}
		return Event{}, err
	}
	if s.mirror != nil {
		s.mirror.Record(out)
	}
	return out, nil
}
func (s *DurableSink) Status() WALStatus {
	if s == nil || s.wal == nil {
		return WALStatus{Ready: false, LastError: "audit WAL unavailable"}
	}
	return s.wal.Status()
}
func (s *DurableSink) Verify(ctx context.Context) error { return s.wal.Verify(ctx) }

// MultiSink mirrors a durable event to development output. A mirror failure
// is contained; it can never panic the request path or alter the WAL record.
type MultiSink struct{ sinks []Sink }

func NewMultiSink(sinks ...Sink) *MultiSink { return &MultiSink{sinks: sinks} }
func (s *MultiSink) Record(e Event) {
	for _, sink := range s.sinks {
		if sink != nil {
			sink.Record(e)
		}
	}
}

type ExporterConfig struct {
	URL, AuthFile, CAFile, ClientCertFile, ClientKeyFile, ServerName, DLQDir string
	Timeout, PollInterval, RetryBase, RetryMax                               time.Duration
	BatchSize, MaxRetries, MaxResponseBytes                                  int
	HMACKey                                                                  []byte
}
type ExporterStatus struct {
	State        string    `json:"state"`
	Exported     uint64    `json:"exported"`
	Retried      uint64    `json:"retried"`
	DeadLetter   uint64    `json:"dead_letter"`
	LastError    string    `json:"last_error,omitempty"`
	LastAccepted time.Time `json:"last_accepted,omitempty"`
}
type Exporter struct {
	wal        *WAL
	cfg        ExporterConfig
	client     *http.Client
	stop       chan struct{}
	done       chan struct{}
	mu         sync.Mutex
	state      ExporterStatus
	checkpoint uint64
	started    bool
	certs      []*securetransport.File[tls.Certificate]
	flushMu    sync.Mutex
}

func NewExporter(wal *WAL, cfg ExporterConfig) (*Exporter, error) {
	if wal == nil || strings.TrimSpace(cfg.URL) == "" {
		return nil, errors.New("audit exporter WAL and URL are required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = time.Second
	}
	if cfg.RetryBase <= 0 {
		cfg.RetryBase = 250 * time.Millisecond
	}
	if cfg.RetryMax <= 0 {
		cfg.RetryMax = 30 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 8
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = 64 << 10
	}
	if cfg.DLQDir == "" {
		cfg.DLQDir = filepath.Join(wal.cfg.Dir, "dead-letter")
	}
	if err := os.MkdirAll(cfg.DLQDir, 0700); err != nil {
		return nil, err
	}
	tlsCfg, certs, err := (securetransport.ClientTLSOptions{CAFile: cfg.CAFile, CertificateFile: cfg.ClientCertFile, KeyFile: cfg.ClientKeyFile, ServerName: cfg.ServerName, MinVersion: tls.VersionTLS12, PollInterval: 2 * time.Second}).TLSConfig()
	if err != nil {
		return nil, errors.New("audit exporter TLS configuration invalid")
	}
	e := &Exporter{wal: wal, cfg: cfg, client: &http.Client{Timeout: cfg.Timeout, Transport: &http.Transport{TLSClientConfig: tlsCfg}}, stop: make(chan struct{}), done: make(chan struct{}), state: ExporterStatus{State: "stopped"}}
	e.certs = certs
	if data, readErr := securetransport.ReadTrustedFile(filepath.Join(wal.cfg.Dir, "export.checkpoint")); readErr == nil {
		var cp checkpoint
		if json.Unmarshal(data, &cp) == nil && cp.NextSequence > 0 {
			e.checkpoint = cp.NextSequence - 1
		}
	}
	return e, nil
}
func (e *Exporter) Start(ctx context.Context) {
	e.mu.Lock()
	e.started = true
	e.mu.Unlock()
	go e.loop(ctx)
}
func (e *Exporter) loop(ctx context.Context) {
	defer close(e.done)
	tick := time.NewTicker(e.cfg.PollInterval)
	defer tick.Stop()
	e.mu.Lock()
	e.state.State = "running"
	e.mu.Unlock()
	for {
		if err := e.flush(ctx); err != nil {
			e.mu.Lock()
			e.state.LastError = safeError(err)
			e.mu.Unlock()
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			e.mu.Lock()
			e.state.State = "stopped"
			e.mu.Unlock()
			return
		case <-e.stop:
			e.mu.Lock()
			e.state.State = "stopped"
			e.mu.Unlock()
			return
		}
	}
}
func (e *Exporter) Flush(ctx context.Context) error { return e.flush(ctx) }
func (e *Exporter) flush(ctx context.Context) error {
	e.flushMu.Lock()
	defer e.flushMu.Unlock()
	for {
		var batch []Event
		err := e.wal.replayFrom(ctx, e.checkpoint, func(ev Event) error {
			batch = append(batch, ev)
			if len(batch) >= e.cfg.BatchSize {
				return errBatchStop
			}
			return nil
		})
		if err != nil && !errors.Is(err, errBatchStop) {
			return err
		}
		if len(batch) == 0 {
			return nil
		}
		if err := e.sendBatch(ctx, batch); err != nil {
			return err
		}
		e.checkpoint = batch[len(batch)-1].Integrity.Sequence
		data, _ := json.Marshal(checkpoint{NextSequence: e.checkpoint + 1})
		if err := atomicWrite(filepath.Join(e.wal.cfg.Dir, "export.checkpoint"), data, 0600); err != nil {
			return err
		}
	}
}

var errBatchStop = errors.New("batch full")

func (e *Exporter) sendBatch(ctx context.Context, events []Event) error {
	ids := make([]string, len(events))
	for i := range events {
		ids[i] = events[i].EventID
	}
	body, _ := json.Marshal(struct {
		Schema string  `json:"schema"`
		Events []Event `json:"events"`
	}{Schema: "aegisllm.siem/v1", Events: events})
	var last error
	for attempt := 0; attempt <= e.cfg.MaxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.URL, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", stableIDs(ids))
		if e.cfg.AuthFile != "" {
			secret, err := securetransport.ReadTrustedFile(e.cfg.AuthFile)
			if err != nil {
				return errors.New("audit exporter credential unavailable")
			}
			req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(secret)))
		}
		resp, err := e.client.Do(req)
		if err == nil {
			data, readErr := io.ReadAll(io.LimitReader(resp.Body, int64(e.cfg.MaxResponseBytes)+1))
			_ = resp.Body.Close()
			if readErr == nil && len(data) <= e.cfg.MaxResponseBytes && resp.StatusCode >= 200 && resp.StatusCode < 300 {
				e.mu.Lock()
				e.state.Exported += uint64(len(events))
				e.state.LastAccepted = time.Now().UTC()
				e.state.LastError = ""
				e.mu.Unlock()
				return nil
			}
			if readErr != nil {
				last = readErr
			} else if len(data) > e.cfg.MaxResponseBytes {
				last = errors.New("SIEM response too large")
			} else {
				last = fmt.Errorf("SIEM rejected batch")
			}
			if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
				break
			}
			if retry := retryAfter(resp.Header.Get("Retry-After")); retry > 0 {
				if retry > e.cfg.RetryMax {
					retry = e.cfg.RetryMax
				}
				select {
				case <-time.After(retry):
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		} else {
			last = err
		}
		if attempt < e.cfg.MaxRetries {
			delay := e.cfg.RetryBase * time.Duration(1<<min(attempt, 10))
			if delay > e.cfg.RetryMax {
				delay = e.cfg.RetryMax
			}
			delay += time.Duration(randomJitter(delay))
			e.mu.Lock()
			e.state.Retried++
			e.mu.Unlock()
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	if err := e.deadLetter(events, last); err != nil {
		return err
	}
	e.mu.Lock()
	e.state.DeadLetter += uint64(len(events))
	e.mu.Unlock()
	return nil
}
func (e *Exporter) deadLetter(events []Event, reason error) error {
	ids := make([]string, len(events))
	for i := range events {
		ids[i] = events[i].EventID
	}
	data, _ := json.Marshal(struct {
		Reason string  `json:"reason"`
		Events []Event `json:"events"`
	}{Reason: "SIEM delivery failed", Events: events})
	return atomicWrite(filepath.Join(e.cfg.DLQDir, time.Now().UTC().Format("20060102T150405.000000000Z")+"-"+stableIDs(ids)+".json"), data, 0600)
}
func (e *Exporter) Close(ctx context.Context) error {
	e.mu.Lock()
	started := e.started
	e.mu.Unlock()
	if !started {
		for _, cert := range e.certs {
			cert.Close()
		}
		return e.flush(ctx)
	}
	close(e.stop)
	select {
	case <-e.done:
		for _, cert := range e.certs {
			cert.Close()
		}
		return e.flush(ctx)
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (e *Exporter) Status() ExporterStatus { e.mu.Lock(); defer e.mu.Unlock(); return e.state }
func retryAfter(value string) time.Duration {
	if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(value); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}
func randomJitter(max time.Duration) int64 {
	if max <= 0 {
		return 0
	}
	value, err := rand.Int(rand.Reader, big.NewInt(max.Nanoseconds()/4+1))
	if err != nil {
		return 0
	}
	return value.Int64()
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func stableIDs(ids []string) string {
	h := sha256.Sum256([]byte(strings.Join(ids, "\x00")))
	return hex.EncodeToString(h[:])[:32]
}
