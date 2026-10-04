package store

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/guoyyit/partial-signature-transaction-go/internal/txn"
)

// EventKind enumerates the auditable state transitions.
type EventKind string

const (
	EventSubmitted EventKind = "submitted"
	EventRevoked   EventKind = "revoked"
	EventFinalized EventKind = "finalized"
	EventRejected  EventKind = "rejected"
)

// Event is one append-only audit record.
type Event struct {
	Seq       int64     `json:"seq"`
	Time      int64     `json:"time"`
	Kind      EventKind `json:"kind"`
	Signer    []byte    `json:"signer,omitempty"`
	Signature []byte    `json:"signature,omitempty"`
	Reason    string    `json:"reason,omitempty"`
}

var (
	ErrEnvelopeExists = errors.New("store: transaction envelope already exists")
	ErrCorrupt        = errors.New("store: corrupt persistent data")
)

const (
	envelopeFile = "envelope.dat"
	eventsFile   = "events.log"
	finalFile    = "final.dat"

	envelopeMagic = "PSTENVL1"
	finalMagic    = "PSTFINAL1"
)

// Store persists one transaction's envelope, audit events and final result
// inside a single directory.
type Store struct {
	dir       string
	eventsF   *os.File
	eventsBuf *bufio.Writer
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	ef, err := os.OpenFile(filepath.Join(dir, eventsFile), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &Store{
		dir:       dir,
		eventsF:   ef,
		eventsBuf: bufio.NewWriter(ef),
	}, nil
}

// Close releases the append-only event log handle.
func (s *Store) Close() error {
	if s.eventsF == nil {
		return nil
	}
	if err := s.eventsBuf.Flush(); err != nil {
		return err
	}
	if err := s.eventsF.Sync(); err != nil {
		return err
	}
	return s.eventsF.Close()
}

func lenPrefixed(b []byte) []byte {
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(b)))
	return append(prefix[:], b...)
}

func readLenPrefixed(buf []byte) (blob, rest []byte, err error) {
	if len(buf) < 4 {
		return nil, nil, ErrCorrupt
	}
	n := binary.BigEndian.Uint32(buf[:4])
	if int(n)+4 > len(buf) {
		return nil, nil, ErrCorrupt
	}
	return buf[4 : 4+n], buf[4+n:], nil
}

// atomicWrite writes data to name via a synced temp file and rename, so no
// half-written file is ever observable at name.
func (s *Store) atomicWrite(name string, data []byte) error {
	path := filepath.Join(s.dir, name)
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	dirF, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	err = dirF.Sync()
	if cerr := dirF.Close(); err == nil {
		err = cerr
	}
	return err
}

// InitEnvelope creates the envelope file exactly once.
func (s *Store) InitEnvelope(b txn.Body, p txn.Policy) error {
	path := filepath.Join(s.dir, envelopeFile)
	if _, err := os.Stat(path); err == nil {
		return ErrEnvelopeExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	bodyRaw, err := txn.EncodeBody(b)
	if err != nil {
		return err
	}
	policyRaw, err := txn.EncodePolicy(p)
	if err != nil {
		return err
	}
	data := append([]byte(envelopeMagic), lenPrefixed(bodyRaw)...)
	data = append(data, lenPrefixed(policyRaw)...)
	return s.atomicWrite(envelopeFile, data)
}

// LoadEnvelope reads and strictly re-decodes the stored envelope.
func (s *Store) LoadEnvelope() (txn.Body, txn.Policy, bool, error) {
	raw, err := os.ReadFile(filepath.Join(s.dir, envelopeFile))
	if errors.Is(err, os.ErrNotExist) {
		return txn.Body{}, txn.Policy{}, false, nil
	}
	if err != nil {
		return txn.Body{}, txn.Policy{}, false, err
	}
	if !bytes.HasPrefix(raw, []byte(envelopeMagic)) {
		return txn.Body{}, txn.Policy{}, false, ErrCorrupt
	}
	rest := raw[len(envelopeMagic):]
	bodyRaw, rest, err := readLenPrefixed(rest)
	if err != nil {
		return txn.Body{}, txn.Policy{}, false, err
	}
	policyRaw, tail, err := readLenPrefixed(rest)
	if err != nil {
		return txn.Body{}, txn.Policy{}, false, err
	}
	if len(tail) != 0 {
		return txn.Body{}, txn.Policy{}, false, ErrCorrupt
	}
	b, err := txn.DecodeBody(bodyRaw)
	if err != nil {
		return txn.Body{}, txn.Policy{}, false, fmt.Errorf("%w: body: %v", ErrCorrupt, err)
	}
	p, err := txn.DecodePolicy(policyRaw)
	if err != nil {
		return txn.Body{}, txn.Policy{}, false, fmt.Errorf("%w: policy: %v", ErrCorrupt, err)
	}
	return b, p, true, nil
}

// Append durably appends one audit event.
func (s *Store) Append(e Event) error {
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if _, err := s.eventsBuf.Write(line); err != nil {
		return err
	}
	if err := s.eventsBuf.Flush(); err != nil {
		return err
	}
	return s.eventsF.Sync()
}

// Events replays all audit events in sequence order.
func (s *Store) Events() ([]Event, error) {
	f, err := os.Open(filepath.Join(s.dir, eventsFile))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var events []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 16<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("%w: event: %v", ErrCorrupt, err)
		}
		events = append(events, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

// WriteFinal atomically persists the final transaction bytes.
func (s *Store) WriteFinal(raw []byte) error {
	data := append([]byte(finalMagic), raw...)
	return s.atomicWrite(finalFile, data)
}

// ReadFinal returns the persisted final transaction bytes when present.
func (s *Store) ReadFinal() ([]byte, bool, error) {
	raw, err := os.ReadFile(filepath.Join(s.dir, finalFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !bytes.HasPrefix(raw, []byte(finalMagic)) || len(raw) == len(finalMagic) {
		return nil, false, fmt.Errorf("%w: final", ErrCorrupt)
	}
	return raw[len(finalMagic):], true, nil
}

var _ io.Closer = (*Store)(nil)
