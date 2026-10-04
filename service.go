package pst

import (
	"encoding/hex"
	"sync"
	"time"
)

type Config struct {
	Dir string
	Now func() time.Time
}

type Status struct {
	TxID      []byte
	Collected int
	Threshold int
	Expired   bool
	Finalized bool
}

type txState struct {
	meta      *txMeta
	active    map[string]*PartialSignature
	events    []*Event
	finalized bool
	final     *FinalTransaction
}

type Service struct {
	cfg   Config
	mu    sync.Mutex
	store *Store
	txs   map[string]*txState
}

func Open(cfg Config) (*Service, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	st, err := OpenStore(cfg.Dir)
	if err != nil {
		return nil, err
	}
	entries, err := st.loadAll()
	if err != nil {
		return nil, err
	}
	s := &Service{cfg: cfg, store: st, txs: map[string]*txState{}}
	for _, e := range entries {
		s.txs[e.id] = rebuildState(e)
	}
	return s, nil
}

func (s *Service) Register(tx *Transaction, policy *Policy, ttl time.Duration) ([]byte, error) {
	tx = cloneTransaction(tx)
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	txID, err := TransactionID(tx)
	if err != nil {
		return nil, err
	}
	id := hex.EncodeToString(txID)
	meta := &txMeta{Version: encodingVersion, Tx: tx, Policy: policy}
	if ttl > 0 {
		meta.Deadline = s.cfg.Now().Add(ttl)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.txs[id]; exists {
		return txID, nil
	}
	if err := s.store.writeMeta(id, meta); err != nil {
		return nil, err
	}
	s.txs[id] = &txState{
		meta:   meta,
		active: map[string]*PartialSignature{},
	}
	return txID, nil
}

func (s *Service) Submit(ps *PartialSignature) error {
	if ps == nil {
		return ErrInvalidSignature
	}
	id := hex.EncodeToString(ps.TxID)
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.txs[id]
	if !ok {
		return ErrTransactionNotFound
	}
	if err := ps.Verify(st.meta.Tx); err != nil {
		s.recordRejection(st, ps.PublicKey, err)
		return err
	}
	if st.finalized {
		s.recordRejection(st, ps.PublicKey, ErrFinalized)
		return ErrFinalized
	}
	if isPast(st.meta.Deadline, s.cfg.Now()) {
		s.recordRejection(st, ps.PublicKey, ErrExpired)
		return ErrExpired
	}
	if !st.meta.Policy.Allows(ps.PublicKey) {
		s.recordRejection(st, ps.PublicKey, ErrPublicKeyNotAllowed)
		return ErrPublicKeyNotAllowed
	}
	key := string(ps.PublicKey)
	if existing := st.active[key]; existing != nil {
		if !equalBytes(existing.Signature, ps.Signature) {
			s.recordRejection(st, ps.PublicKey, ErrPolicyViolation)
			return ErrPolicyViolation
		}
		return nil
	}
	data, err := ps.Encode()
	if err != nil {
		return err
	}
	if err := s.appendStoredEvent(st, EventSubmitted, ps.PublicKey, data, nil, nil, ""); err != nil {
		return err
	}
	st.active[key] = ps
	return nil
}

func (s *Service) Revoke(r *Revocation) error {
	if r == nil {
		return ErrInvalidSignature
	}
	id := hex.EncodeToString(r.TxID)
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.txs[id]
	if !ok {
		return ErrTransactionNotFound
	}
	if err := r.Verify(txIDFromState(st)); err != nil {
		s.recordRejection(st, r.PublicKey, err)
		return err
	}
	if st.finalized {
		s.recordRejection(st, r.PublicKey, ErrFinalized)
		return ErrFinalized
	}
	if isPast(st.meta.Deadline, s.cfg.Now()) {
		s.recordRejection(st, r.PublicKey, ErrExpired)
		return ErrExpired
	}
	key := string(r.PublicKey)
	if st.active[key] == nil {
		s.recordRejection(st, r.PublicKey, ErrNoSignature)
		return ErrNoSignature
	}
	data, err := r.Encode()
	if err != nil {
		return err
	}
	if err := s.appendStoredEvent(st, EventRevoked, r.PublicKey, nil, data, nil, ""); err != nil {
		return err
	}
	delete(st.active, key)
	return nil
}

func (s *Service) Finalize(txID []byte) (*FinalTransaction, error) {
	id := hex.EncodeToString(txID)
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.txs[id]
	if !ok {
		return nil, ErrTransactionNotFound
	}
	if st.finalized {
		return st.final, nil
	}
	if isPast(st.meta.Deadline, s.cfg.Now()) {
		return nil, ErrExpired
	}
	sigs := make([]*PartialSignature, 0, len(st.active))
	for _, sig := range st.active {
		sigs = append(sigs, sig)
	}
	f, err := assembleFinal(st.meta.Tx, st.meta.Policy, sigs)
	if err != nil {
		return nil, err
	}
	if err := s.store.writeFinal(id, f); err != nil {
		return nil, err
	}
	data, err := f.Encode()
	if err != nil {
		return nil, err
	}
	if err := s.appendStoredEvent(st, EventFinalized, nil, nil, nil, data, ""); err != nil {
		return nil, err
	}
	st.finalized = true
	st.final = f
	return f, nil
}

func (s *Service) Status(txID []byte) (*Status, error) {
	id := hex.EncodeToString(txID)
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.txs[id]
	if !ok {
		return nil, ErrTransactionNotFound
	}
	return &Status{
		TxID:      append([]byte(nil), txID...),
		Collected: len(st.active),
		Threshold: st.meta.Policy.Threshold,
		Expired:   isPast(st.meta.Deadline, s.cfg.Now()),
		Finalized: st.finalized,
	}, nil
}

func (s *Service) appendStoredEvent(st *txState, kind string, pub, partial, revoke, final []byte, reason string) error {
	id := hex.EncodeToString(txIDFromState(st))
	ev := &Event{
		Seq:       int64(len(st.events)) + 1,
		Kind:      kind,
		Time:      s.cfg.Now(),
		PublicKey: pub,
		Partial:   partial,
		Revoke:    revoke,
		Final:     final,
		Reason:    reason,
	}
	if err := s.store.appendEvent(id, ev); err != nil {
		return err
	}
	st.events = append(st.events, ev)
	return nil
}

func (s *Service) recordRejection(st *txState, pub []byte, cause error) {
	_ = s.appendStoredEvent(st, EventRejected, pub, nil, nil, nil, cause.Error())
}

func isPast(deadline, now time.Time) bool {
	return !deadline.IsZero() && now.After(deadline)
}

func txIDFromState(st *txState) []byte {
	txID, _ := TransactionID(st.meta.Tx)
	return txID
}

func cloneTransaction(tx *Transaction) *Transaction {
	if tx == nil {
		return nil
	}
	cp := *tx
	cp.Sender = append([]byte(nil), tx.Sender...)
	cp.Recipient = append([]byte(nil), tx.Recipient...)
	return &cp
}

func rebuildState(e *storeEntry) *txState {
	st := &txState{
		meta:   e.meta,
		active: map[string]*PartialSignature{},
	}
	for _, ev := range e.events {
		st.events = append(st.events, ev)
		switch ev.Kind {
		case EventSubmitted:
			if len(ev.Partial) == 0 {
				continue
			}
			ps, err := DecodePartialSignature(ev.Partial)
			if err != nil {
				continue
			}
			key := string(ps.PublicKey)
			st.active[key] = ps
		case EventRevoked:
			delete(st.active, string(ev.PublicKey))
		case EventFinalized:
			if len(ev.Final) > 0 {
				f, err := DecodeFinal(ev.Final)
				if err == nil {
					st.finalized = true
					st.final = f
					return st
				}
			}
			if e.final != nil {
				st.finalized = true
				st.final = e.final
				return st
			}
		}
	}
	if !st.finalized && e.final != nil {
		if err := e.final.Verify(); err == nil {
			st.finalized = true
			st.final = e.final
		}
	}
	return st
}
