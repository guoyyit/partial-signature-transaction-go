package service

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/guoyyit/partial-signature-transaction-go/internal/store"
	"github.com/guoyyit/partial-signature-transaction-go/internal/txn"
)

type testParty struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func genParties(t *testing.T, n int) []testParty {
	t.Helper()
	out := make([]testParty, n)
	for i := range out {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = testParty{priv: priv, pub: pub}
	}
	return out
}

type fixtureOpts struct {
	threshold  uint16
	validUntil int64
	clock      *time.Time
}

func setupService(t *testing.T, parties []testParty, opts fixtureOpts) (*Service, txn.Body, txn.Policy, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	pubs := make([][]byte, len(parties))
	for i, p := range parties {
		pubs[i] = p.pub
	}
	pol, err := txn.NewPolicy(opts.threshold, pubs)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := txn.PolicyCommitment(pol)
	if err != nil {
		t.Fatal(err)
	}
	b := txn.Body{
		Version:    txn.Version,
		TxID:       []byte("tx-service"),
		Nonce:      99,
		Payload:    []byte("payload"),
		PolicyHash: commit,
		ValidUntil: opts.validUntil,
	}
	clock := time.Now
	if opts.clock != nil {
		ptr := opts.clock
		clock = func() time.Time { return *ptr }
	}
	svc, err := Create(st, b, pol, WithClock(clock))
	if err != nil {
		t.Fatal(err)
	}
	return svc, b, pol, st
}

func TestOutOfOrderArrivalAssemblesSameResult(t *testing.T) {
	parties := genParties(t, 3)
	svc, b, pol, _ := setupService(t, parties, fixtureOpts{threshold: 2, validUntil: time.Now().Add(time.Hour).Unix()})

	ps0, _ := txn.SignBody(parties[0].priv, b)
	ps2, _ := txn.SignBody(parties[2].priv, b)
	if err := svc.Submit(ps2); err != nil {
		t.Fatalf("submit ps2: %v", err)
	}
	if err := svc.Submit(ps0); err != nil {
		t.Fatalf("submit ps0: %v", err)
	}
	f, err := svc.Finalize()
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	want, _ := txn.AssembleFinal(b, pol, []txn.PartialSignature{ps0, ps2})
	gotRaw, _ := txn.EncodeFinal(f)
	wantRaw, _ := txn.EncodeFinal(want)
	if !bytes.Equal(gotRaw, wantRaw) {
		t.Fatal("service assembly differs from canonical assembly")
	}

	// Any party can independently verify the decoded final bytes.
	dec, err := txn.DecodeFinal(gotRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err := txn.VerifyFinal(dec); err != nil {
		t.Fatalf("independent VerifyFinal: %v", err)
	}
}

func TestBelowThresholdFinalizeFails(t *testing.T) {
	parties := genParties(t, 3)
	svc, b, _, _ := setupService(t, parties, fixtureOpts{threshold: 3, validUntil: time.Now().Add(time.Hour).Unix()})
	ps0, _ := txn.SignBody(parties[0].priv, b)
	if err := svc.Submit(ps0); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Finalize(); !errors.Is(err, txn.ErrThreshold) {
		t.Fatalf("expected ErrThreshold, got %v", err)
	}
}

func TestPolicyOutsiderExplicitlyRejectedAndAudited(t *testing.T) {
	parties := genParties(t, 2)
	outsider := genParties(t, 1)[0]
	svc, b, _, _ := setupService(t, parties, fixtureOpts{threshold: 2, validUntil: time.Now().Add(time.Hour).Unix()})

	ps, _ := txn.SignBody(outsider.priv, b)
	if err := svc.Submit(ps); !errors.Is(err, txn.ErrSignerNotAllowed) {
		t.Fatalf("expected ErrSignerNotAllowed, got %v", err)
	}
	if len(svc.View().Signers) != 0 {
		t.Fatal("rejected signature was collected")
	}
	events, _ := svc.Events()
	var hasRejection bool
	for _, e := range events {
		if e.Kind == store.EventRejected {
			hasRejection = true
		}
	}
	if !hasRejection {
		t.Fatal("rejection not recorded in audit log")
	}
}

func TestDuplicateKeptOnceAndConflictRejected(t *testing.T) {
	parties := genParties(t, 2)
	svc, b, _, _ := setupService(t, parties, fixtureOpts{threshold: 2, validUntil: time.Now().Add(time.Hour).Unix()})

	ps0, _ := txn.SignBody(parties[0].priv, b)
	if err := svc.Submit(ps0); err != nil {
		t.Fatal(err)
	}
	if err := svc.Submit(ps0); err != nil {
		t.Fatalf("exact duplicate must be idempotent, got %v", err)
	}
	if len(svc.View().Signers) != 1 {
		t.Fatal("duplicate signature stored twice")
	}

	// A different signature value for the same signer can only be produced by
	// another party impersonating the signer; it must fail cryptographically.
	forged := txn.PartialSignature{
		Version:   txn.Version,
		Signer:    append([]byte(nil), parties[0].pub...),
		Signature: bytes.Repeat([]byte{0x01}, 64),
	}
	if err := svc.Submit(forged); err == nil {
		t.Fatal("forged signature accepted")
	}
	if len(svc.View().Signers) != 1 {
		t.Fatal("state changed after rejected submission")
	}
}

func TestRevokePreventsInclusion(t *testing.T) {
	parties := genParties(t, 2)
	svc, b, _, _ := setupService(t, parties, fixtureOpts{threshold: 2, validUntil: time.Now().Add(time.Hour).Unix()})

	ps0, _ := txn.SignBody(parties[0].priv, b)
	ps1, _ := txn.SignBody(parties[1].priv, b)
	if err := svc.Submit(ps0); err != nil {
		t.Fatal(err)
	}
	if err := svc.Submit(ps1); err != nil {
		t.Fatal(err)
	}
	r0, err := txn.SignRevocation(parties[0].priv, b)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Revoke(r0); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := svc.Finalize(); !errors.Is(err, txn.ErrThreshold) {
		t.Fatalf("revoked signature still counted, got %v", err)
	}

	// Resign after revoke: signature may be collected again.
	if err := svc.Submit(ps0); err != nil {
		t.Fatalf("resubmit after revoke: %v", err)
	}
	f, err := svc.Finalize()
	if err != nil {
		t.Fatalf("Finalize after resubmit: %v", err)
	}
	for _, s := range f.Signatures {
		if bytes.Equal(s.Signer, parties[0].pub) && !bytes.Equal(s.Signature, ps0.Signature) {
			t.Fatal("resubmitted signature differs")
		}
	}
}

func TestRevokeRequiresValidSignature(t *testing.T) {
	parties := genParties(t, 2)
	svc, b, _, _ := setupService(t, parties, fixtureOpts{threshold: 2, validUntil: time.Now().Add(time.Hour).Unix()})

	bad := txn.Revocation{
		Version:   txn.Version,
		Signer:    append([]byte(nil), parties[0].pub...),
		Signature: bytes.Repeat([]byte{0x02}, 64),
	}
	if err := svc.Revoke(bad); !errors.Is(err, txn.ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid, got %v", err)
	}

	r0, _ := txn.SignRevocation(parties[0].priv, b)
	if err := svc.Revoke(r0); !errors.Is(err, ErrNoSignature) {
		t.Fatalf("expected ErrNoSignature, got %v", err)
	}
}

func TestMalformedSubmissionRejected(t *testing.T) {
	parties := genParties(t, 2)
	svc, _, _, _ := setupService(t, parties, fixtureOpts{threshold: 2, validUntil: time.Now().Add(time.Hour).Unix()})

	raw := []byte{0x00, 0x00, 0x7F}
	ps, err := txn.DecodePartial(raw)
	if err == nil {
		t.Fatal("malformed partial decoded")
	}
	_ = ps
	if err := svc.Submit(txn.PartialSignature{Version: 99}); !errors.Is(err, txn.ErrUnknownVersion) {
		t.Fatalf("expected ErrUnknownVersion, got %v", err)
	}
	if err := svc.Revoke(txn.Revocation{Version: 99}); !errors.Is(err, txn.ErrUnknownVersion) {
		t.Fatalf("expected ErrUnknownVersion, got %v", err)
	}
}

func TestExpiryRejectsNewSignatures(t *testing.T) {
	parties := genParties(t, 2)
	deadline := time.Unix(1_000_000, 0)
	clock := deadline
	svc, b, _, _ := setupService(t, parties, fixtureOpts{
		threshold:  2,
		validUntil: deadline.Unix(),
		clock:      &clock,
	})

	ps0, _ := txn.SignBody(parties[0].priv, b)
	clock = deadline.Add(time.Second)
	if err := svc.Submit(ps0); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}

	// At the exact deadline second the window is still open (now <= ValidUntil).
	clock = deadline
	if err := svc.Submit(ps0); err != nil {
		t.Fatalf("submission at exact deadline rejected: %v", err)
	}
}

func TestFinalizedIsImmutable(t *testing.T) {
	parties := genParties(t, 2)
	svc, b, _, _ := setupService(t, parties, fixtureOpts{threshold: 2, validUntil: time.Now().Add(time.Hour).Unix()})

	ps0, _ := txn.SignBody(parties[0].priv, b)
	ps1, _ := txn.SignBody(parties[1].priv, b)
	if err := svc.Submit(ps0); err != nil {
		t.Fatal(err)
	}
	if err := svc.Submit(ps1); err != nil {
		t.Fatal(err)
	}
	f, err := svc.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	if svc.View().Status != StatusFinalized {
		t.Fatal("status not finalized")
	}
	if err := svc.Submit(ps0); !errors.Is(err, ErrFinalized) {
		t.Fatalf("expected ErrFinalized on submit, got %v", err)
	}
	r0, _ := txn.SignRevocation(parties[0].priv, b)
	if err := svc.Revoke(r0); !errors.Is(err, ErrFinalized) {
		t.Fatalf("expected ErrFinalized on revoke, got %v", err)
	}
	if _, err := svc.Finalize(); !errors.Is(err, ErrFinalized) {
		t.Fatalf("expected ErrFinalized on refinalize, got %v", err)
	}
	for _, sig := range f.Signatures {
		_ = sig
	}
}

func TestAuditTrailOrdering(t *testing.T) {
	parties := genParties(t, 2)
	svc, b, _, _ := setupService(t, parties, fixtureOpts{threshold: 2, validUntil: time.Now().Add(time.Hour).Unix()})

	ps0, _ := txn.SignBody(parties[0].priv, b)
	ps1, _ := txn.SignBody(parties[1].priv, b)
	_ = svc.Submit(ps0)
	r0, _ := txn.SignRevocation(parties[0].priv, b)
	_ = svc.Revoke(r0)
	_ = svc.Submit(ps0)
	_ = svc.Submit(ps1)
	_, _ = svc.Finalize()

	events, err := svc.Events()
	if err != nil {
		t.Fatal(err)
	}
	wantKinds := []store.EventKind{
		store.EventSubmitted,
		store.EventRevoked,
		store.EventSubmitted,
		store.EventSubmitted,
		store.EventFinalized,
	}
	if len(events) != len(wantKinds) {
		t.Fatalf("got %d events, want %d", len(events), len(wantKinds))
	}
	for i, k := range wantKinds {
		if events[i].Kind != k || events[i].Seq != int64(i+1) {
			t.Fatalf("event %d: got %s seq %d, want %s", i, events[i].Kind, events[i].Seq, k)
		}
	}
}
