package service

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/guoyyit/partial-signature-transaction-go/internal/store"
	"github.com/guoyyit/partial-signature-transaction-go/internal/txn"
)

// Status of a transaction collection.
type Status uint8

// Collecting until finalized; Finalized once the result is durably written.
const (
	StatusCollecting Status = 1
	StatusFinalized  Status = 2
)

var (
	// ErrFinalized is returned when mutating or finalizing a finalized tx.
	ErrFinalized = errors.New("service: transaction already finalized")
	// ErrExpired is returned when a signature arrives after ValidUntil.
	ErrExpired = errors.New("service: signing window expired")
	// ErrNoSignature is returned when revoking an absent signature.
	ErrNoSignature = errors.New("service: no signature held for signer")
	// ErrConflict is returned when a different signature exists for a signer.
	ErrConflict = errors.New("service: conflicting signature already held for signer")
	// ErrNotInitialized is returned by Open when no envelope exists.
	ErrNotInitialized = errors.New("service: transaction not initialized")
)

// SignerInfo describes one currently-held signature.
type SignerInfo struct {
	Signer      []byte
	SubmittedAt int64
}

// View is an immutable snapshot of service state.
type View struct {
	Body     txn.Body
	Policy   txn.Policy
	Status   Status
	Signers  []SignerInfo
	Final    *txn.Final
	EventSeq int64
}

type heldSig struct {
	signature []byte
	at        int64
}

// Service collects partial signatures for one pending transaction.
type Service struct {
	st    *store.Store
	mu    sync.Mutex
	body  txn.Body
	pol   txn.Policy
	held  map[string]heldSig
	done  bool
	final txn.Final
	seq   int64
	now   func() time.Time
}

// WithClock injects a clock, mainly for tests.
func WithClock(c func() time.Time) func(*Service) {
	return func(s *Service) {
		if c != nil {
			s.now = c
		}
	}
}

// Create initializes a new transaction envelope and returns its service.
func Create(st *store.Store, b txn.Body, p txn.Policy, opts ...func(*Service)) (*Service, error) {
	if err := st.InitEnvelope(b, p); err != nil {
		return nil, err
	}
	return openLocked(st, opts)
}

// Open recovers a service from a previously initialized directory.
func Open(st *store.Store, opts ...func(*Service)) (*Service, error) {
	return openLocked(st, opts)
}

func openLocked(st *store.Store, opts []func(*Service)) (*Service, error) {
	b, p, ok, err := st.LoadEnvelope()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotInitialized
	}
	s := &Service{
		st:   st,
		body: b,
		pol:  p,
		held: make(map[string]heldSig),
		now:  time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	if err := s.replay(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Service) replay() error {
	events, err := s.st.Events()
	if err != nil {
		return err
	}
	var wantSeq int64 = 1
	for _, e := range events {
		if e.Seq != wantSeq {
			return fmt.Errorf("%w: event seq gap at %d", store.ErrCorrupt, wantSeq)
		}
		wantSeq++
		switch e.Kind {
		case store.EventSubmitted:
			s.held[string(e.Signer)] = heldSig{signature: e.Signature, at: e.Time}
		case store.EventRevoked:
			delete(s.held, string(e.Signer))
		case store.EventFinalized:
			s.done = true
		case store.EventRejected:
			// Rejections carry no state transition.
		default:
			return fmt.Errorf("%w: unknown event kind %q", store.ErrCorrupt, e.Kind)
		}
	}
	s.seq = int64(len(events))

	raw, hasFinal, err := s.st.ReadFinal()
	if err != nil {
		return err
	}
	if hasFinal {
		f, err := txn.DecodeFinal(raw)
		if err != nil {
			return fmt.Errorf("%w: final decode: %v", store.ErrCorrupt, err)
		}
		if err := txn.VerifyFinal(f); err != nil {
			return fmt.Errorf("%w: final verify: %v", store.ErrCorrupt, err)
		}
		if !bytes.Equal(f.Body.PolicyHash, s.body.PolicyHash) {
			return fmt.Errorf("%w: final belongs to another transaction", store.ErrCorrupt)
		}
		s.done = true
		s.final = f
		if !lastIsFinalized(events) {
			// Crash window: final bytes landed before the audit event.
			if err := s.append(store.EventFinalized, nil, nil, "recovered"); err != nil {
				return err
			}
		}
	} else if s.done {
		return fmt.Errorf("%w: finalized event without final bytes", store.ErrCorrupt)
	}
	return nil
}

func lastIsFinalized(events []store.Event) bool {
	return len(events) > 0 && events[len(events)-1].Kind == store.EventFinalized
}

func (s *Service) append(kind store.EventKind, signer, sig []byte, reason string) error {
	s.seq++
	e := store.Event{
		Seq:       s.seq,
		Time:      s.now().Unix(),
		Kind:      kind,
		Signer:    signer,
		Signature: sig,
		Reason:    reason,
	}
	return s.st.Append(e)
}

// Submit validates and collects one partial signature.
func (s *Service) Submit(ps txn.PartialSignature) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	reject := func(cause error, reason string) error {
		_ = s.append(store.EventRejected, cloneBytes(ps.Signer), cloneBytes(ps.Signature), reason)
		return cause
	}
	if s.done {
		return reject(ErrFinalized, ErrFinalized.Error())
	}
	if s.now().Unix() > s.body.ValidUntil {
		return reject(ErrExpired, ErrExpired.Error())
	}
	if err := txn.VerifyPartial(s.body, s.pol, ps); err != nil {
		return reject(err, err.Error())
	}
	key := string(ps.Signer)
	if existing, ok := s.held[key]; ok {
		if bytes.Equal(existing.signature, ps.Signature) {
			// Exact duplicate: idempotent no-op, only one signature remains.
			return nil
		}
		return reject(ErrConflict, ErrConflict.Error())
	}
	if err := s.append(store.EventSubmitted,
		cloneBytes(ps.Signer), cloneBytes(ps.Signature), ""); err != nil {
		return err
	}
	s.held[key] = heldSig{
		signature: cloneBytes(ps.Signature),
		at:        s.now().Unix(),
	}
	return nil
}

// Revoke withdraws a signer's signature before finalization.
func (s *Service) Revoke(r txn.Revocation) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	reject := func(cause error, reason string) error {
		_ = s.append(store.EventRejected, cloneBytes(r.Signer), cloneBytes(r.Signature), reason)
		return cause
	}
	if s.done {
		return reject(ErrFinalized, ErrFinalized.Error())
	}
	if err := txn.VerifyRevocation(s.body, r); err != nil {
		return reject(err, err.Error())
	}
	if _, ok := s.held[string(r.Signer)]; !ok {
		return reject(ErrNoSignature, ErrNoSignature.Error())
	}
	if err := s.append(store.EventRevoked, cloneBytes(r.Signer), nil, ""); err != nil {
		return err
	}
	delete(s.held, string(r.Signer))
	return nil
}

// Finalize assembles and durably writes the final transaction once the
// threshold is satisfied by currently-held signatures.
func (s *Service) Finalize() (txn.Final, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.done {
		return s.final, ErrFinalized
	}
	sigs := make([]txn.PartialSignature, 0, len(s.held))
	for key, h := range s.held {
		sigs = append(sigs, txn.PartialSignature{
			Version:   txn.Version,
			Signer:    []byte(key),
			Signature: h.signature,
		})
	}
	f, err := txn.AssembleFinal(s.body, s.pol, sigs)
	if err != nil {
		return txn.Final{}, err
	}
	if err := txn.VerifyFinal(f); err != nil {
		return txn.Final{}, err
	}
	raw, err := txn.EncodeFinal(f)
	if err != nil {
		return txn.Final{}, err
	}
	// Durable bytes first, then the audit event (recovery reconciles).
	if err := s.st.WriteFinal(raw); err != nil {
		return txn.Final{}, err
	}
	if err := s.append(store.EventFinalized, nil, nil, ""); err != nil {
		return txn.Final{}, err
	}
	s.done = true
	s.final = f
	return f, nil
}

// View returns a detached snapshot of the current state.
func (s *Service) View() View {
	s.mu.Lock()
	defer s.mu.Unlock()

	signers := make([]SignerInfo, 0, len(s.held))
	for key, h := range s.held {
		signers = append(signers, SignerInfo{
			Signer:      []byte(key),
			SubmittedAt: h.at,
		})
	}
	sort.Slice(signers, func(i, j int) bool {
		return bytes.Compare(signers[i].Signer, signers[j].Signer) < 0
	})
	status := StatusCollecting
	var finalPtr *txn.Final
	if s.done {
		status = StatusFinalized
		f := s.final
		finalPtr = &f
	}
	return View{
		Body:     s.body,
		Policy:   s.pol,
		Status:   status,
		Signers:  signers,
		Final:    finalPtr,
		EventSeq: s.seq,
	}
}

// Events returns the full audit trail in sequence order.
func (s *Service) Events() ([]store.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Events()
}

func cloneBytes(b []byte) []byte {
	return append([]byte(nil), b...)
}
