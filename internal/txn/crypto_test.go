package txn

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
)

type party struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newParties(t *testing.T, n int) []party {
	t.Helper()
	out := make([]party, n)
	for i := range out {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		out[i] = party{priv: priv, pub: pub}
	}
	return out
}

func partiesPolicy(t *testing.T, parties []party, threshold uint16) Policy {
	t.Helper()
	pubs := make([][]byte, len(parties))
	for i, p := range parties {
		pubs[i] = p.pub
	}
	p, err := NewPolicy(threshold, pubs)
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	return p
}

func bodyForPolicy(t *testing.T, p Policy) Body {
	t.Helper()
	commit, err := PolicyCommitment(p)
	if err != nil {
		t.Fatalf("PolicyCommitment: %v", err)
	}
	return Body{
		Version:    Version,
		TxID:       []byte("tx-crypto"),
		Nonce:      7,
		Payload:    []byte("hello"),
		PolicyHash: commit,
		ValidUntil: 1_800_000_000,
	}
}

func TestSignAndVerifyPartial(t *testing.T) {
	parties := newParties(t, 3)
	p := partiesPolicy(t, parties, 2)
	b := bodyForPolicy(t, p)

	ps, err := SignBody(parties[0].priv, b)
	if err != nil {
		t.Fatalf("SignBody: %v", err)
	}
	if err := VerifyPartial(b, p, ps); err != nil {
		t.Fatalf("VerifyPartial: %v", err)
	}
	raw, _ := EncodePartial(ps)
	dec, err := DecodePartial(raw)
	if err != nil {
		t.Fatalf("DecodePartial: %v", err)
	}
	if err := VerifyPartial(b, p, dec); err != nil {
		t.Fatalf("VerifyPartial after decode: %v", err)
	}
}

func TestAnyFieldChangeInvalidatesSignature(t *testing.T) {
	parties := newParties(t, 3)
	p := partiesPolicy(t, parties, 2)
	b := bodyForPolicy(t, p)
	ps, err := SignBody(parties[0].priv, b)
	if err != nil {
		t.Fatalf("SignBody: %v", err)
	}

	mutate := func(mut func(*Body)) {
		b2 := b
		mut(&b2)
		if err := VerifyPartial(b2, p, ps); !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("expected ErrSignatureInvalid, got %v", err)
		}
	}
	mutate(func(x *Body) { x.TxID = []byte("tx-changed") })
	mutate(func(x *Body) { x.Nonce++ })
	mutate(func(x *Body) { x.Payload = []byte("tampered") })
	mutate(func(x *Body) { x.ValidUntil++ })

	// Changing the policy (threshold) while keeping the same body fails the
	// body-policy commitment binding rather than being silently accepted.
	pChanged := Policy{Version: Version, Threshold: 1, Signers: p.Signers}
	if err := VerifyPartial(b, pChanged, ps); !errors.Is(err, ErrPolicyMismatch) {
		t.Fatalf("expected ErrPolicyMismatch, got %v", err)
	}
}

func TestNonPolicySignerRejected(t *testing.T) {
	parties := newParties(t, 3)
	outside := newParties(t, 1)[0]
	p := partiesPolicy(t, parties, 2)
	b := bodyForPolicy(t, p)

	ps, err := SignBody(outside.priv, b)
	if err != nil {
		t.Fatalf("SignBody: %v", err)
	}
	if err := VerifyPartial(b, p, ps); !errors.Is(err, ErrSignerNotAllowed) {
		t.Fatalf("expected ErrSignerNotAllowed, got %v", err)
	}
}

func TestRevocation(t *testing.T) {
	parties := newParties(t, 2)
	p := partiesPolicy(t, parties, 2)
	b := bodyForPolicy(t, p)

	r, err := SignRevocation(parties[0].priv, b)
	if err != nil {
		t.Fatalf("SignRevocation: %v", err)
	}
	if err := VerifyRevocation(b, r); err != nil {
		t.Fatalf("VerifyRevocation: %v", err)
	}

	b2 := b
	b2.Nonce++
	if err := VerifyRevocation(b2, r); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("revocation accepted over changed body: %v", err)
	}

	// A body signature must not verify as a revocation and vice versa.
	ps, _ := SignBody(parties[0].priv, b)
	forged := Revocation{Version: Version, Signer: ps.Signer, Signature: ps.Signature}
	if err := VerifyRevocation(b, forged); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("cross-use signature accepted as revocation: %v", err)
	}
}

func TestAssembleOrderIndependentAndVerifyFinal(t *testing.T) {
	parties := newParties(t, 3)
	p := partiesPolicy(t, parties, 2)
	b := bodyForPolicy(t, p)

	ps0, _ := SignBody(parties[0].priv, b)
	ps2, _ := SignBody(parties[2].priv, b)

	f1, err := AssembleFinal(b, p, []PartialSignature{ps0, ps2})
	if err != nil {
		t.Fatalf("AssembleFinal: %v", err)
	}
	f2, err := AssembleFinal(b, p, []PartialSignature{ps2, ps0})
	if err != nil {
		t.Fatalf("AssembleFinal reversed: %v", err)
	}
	r1, _ := EncodeFinal(f1)
	r2, _ := EncodeFinal(f2)
	if !bytes.Equal(r1, r2) {
		t.Fatal("assembly result depends on arrival order")
	}
	if err := VerifyFinal(f1); err != nil {
		t.Fatalf("VerifyFinal: %v", err)
	}
	dec, err := DecodeFinal(r1)
	if err != nil {
		t.Fatalf("DecodeFinal: %v", err)
	}
	if err := VerifyFinal(dec); err != nil {
		t.Fatalf("VerifyFinal decoded: %v", err)
	}
}

func TestAssembleBelowThreshold(t *testing.T) {
	parties := newParties(t, 3)
	p := partiesPolicy(t, parties, 3)
	b := bodyForPolicy(t, p)
	ps0, _ := SignBody(parties[0].priv, b)
	ps1, _ := SignBody(parties[1].priv, b)
	if _, err := AssembleFinal(b, p, []PartialSignature{ps0, ps1}); !errors.Is(err, ErrThreshold) {
		t.Fatalf("expected ErrThreshold, got %v", err)
	}
}

func TestFinalTamperRejected(t *testing.T) {
	parties := newParties(t, 2)
	p := partiesPolicy(t, parties, 2)
	b := bodyForPolicy(t, p)
	ps0, _ := SignBody(parties[0].priv, b)
	ps1, _ := SignBody(parties[1].priv, b)
	f, _ := AssembleFinal(b, p, []PartialSignature{ps0, ps1})

	f2 := f
	f2.Body.Payload = []byte("changed")
	if err := VerifyFinal(f2); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("tampered final accepted: %v", err)
	}
}
