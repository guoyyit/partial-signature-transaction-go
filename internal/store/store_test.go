package store

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/guoyyit/partial-signature-transaction-go/internal/txn"
)

func fixture(t *testing.T) (txn.Body, txn.Policy) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pubs := [][]byte{priv.Public().(ed25519.PublicKey)}
	extra := bytes.Repeat([]byte{0xAB}, 32)
	p, err := txn.NewPolicy(1, append(pubs, extra))
	if err != nil {
		t.Fatal(err)
	}
	commit, err := txn.PolicyCommitment(p)
	if err != nil {
		t.Fatal(err)
	}
	b := txn.Body{
		Version:    txn.Version,
		TxID:       []byte("tx-store"),
		Nonce:      1,
		Payload:    []byte("p"),
		PolicyHash: commit,
		ValidUntil: 1_900_000_000,
	}
	return b, p
}

func TestEnvelopeRoundTripAndOnceOnly(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, p := fixture(t)
	if err := st.InitEnvelope(b, p); err != nil {
		t.Fatalf("InitEnvelope: %v", err)
	}
	if err := st.InitEnvelope(b, p); !errors.Is(err, ErrEnvelopeExists) {
		t.Fatalf("expected ErrEnvelopeExists, got %v", err)
	}

	st2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	gotB, gotP, ok, err := st2.LoadEnvelope()
	if err != nil || !ok {
		t.Fatalf("LoadEnvelope: ok=%v err=%v", ok, err)
	}
	if gotB.Nonce != b.Nonce || !bytes.Equal(gotB.TxID, b.TxID) {
		t.Fatal("body mismatch after reload")
	}
	if gotP.Threshold != p.Threshold || len(gotP.Signers) != len(p.Signers) {
		t.Fatal("policy mismatch after reload")
	}
}

func TestLoadEnvelopeMissing(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := st.LoadEnvelope(); err != nil || ok {
		t.Fatalf("expected absent envelope, ok=%v err=%v", ok, err)
	}
}

func TestCorruptEnvelopeRejected(t *testing.T) {
	dir := t.TempDir()
	st, _ := Open(dir)
	b, p := fixture(t)
	if err := st.InitEnvelope(b, p); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, envelopeFile)
	raw, _ := os.ReadFile(path)
	raw[len(envelopeMagic)] ^= 0xFF
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := st.LoadEnvelope(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("expected ErrCorrupt, got %v", err)
	}
}

func TestEventsAppendAndReplay(t *testing.T) {
	dir := t.TempDir()
	st, _ := Open(dir)
	for i := int64(1); i <= 3; i++ {
		if err := st.Append(Event{
			Seq:    i,
			Time:   100 + i,
			Kind:   EventSubmitted,
			Signer: bytes.Repeat([]byte{byte(i)}, 32),
		}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	st2, _ := Open(dir)
	events, err := st2.Events()
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	if len(events) != 3 || events[2].Seq != 3 {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestFinalAtomicRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st, _ := Open(dir)
	if _, ok, err := st.ReadFinal(); err != nil || ok {
		t.Fatalf("unexpected final: ok=%v err=%v", ok, err)
	}
	data := []byte("final-bytes")
	if err := st.WriteFinal(data); err != nil {
		t.Fatalf("WriteFinal: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, finalFile+".tmp")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("temp file left behind")
	}
	got, ok, err := st.ReadFinal()
	if err != nil || !ok || !bytes.Equal(got, data) {
		t.Fatalf("ReadFinal: ok=%v err=%v match=%v", ok, err, bytes.Equal(got, data))
	}
}

func TestCorruptFinalRejected(t *testing.T) {
	dir := t.TempDir()
	st, _ := Open(dir)
	if err := os.WriteFile(filepath.Join(dir, finalFile), []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.ReadFinal(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("expected ErrCorrupt, got %v", err)
	}
}
