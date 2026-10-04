package txn

import (
	"bytes"
	"testing"
)

func testPolicy(t *testing.T) Policy {
	t.Helper()
	p, err := NewPolicy(2, [][]byte{
		bytes.Repeat([]byte{0x02}, 32),
		bytes.Repeat([]byte{0x01}, 32),
	})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	return p
}

func testBody(t *testing.T) Body {
	t.Helper()
	p := testPolicy(t)
	commit, err := PolicyCommitment(p)
	if err != nil {
		t.Fatalf("PolicyCommitment: %v", err)
	}
	return Body{
		Version:    Version,
		TxID:       []byte("tx-001"),
		Nonce:      42,
		Payload:    []byte("pay {\"a\":1}"),
		PolicyHash: commit,
		ValidUntil: 1_700_000_000,
	}
}

func TestBodyRoundTrip(t *testing.T) {
	b := testBody(t)
	raw, err := EncodeBody(b)
	if err != nil {
		t.Fatalf("EncodeBody: %v", err)
	}
	got, err := DecodeBody(raw)
	if err != nil {
		t.Fatalf("DecodeBody: %v", err)
	}
	if got.Nonce != b.Nonce || got.ValidUntil != b.ValidUntil ||
		!bytes.Equal(got.TxID, b.TxID) || !bytes.Equal(got.Payload, b.Payload) ||
		!bytes.Equal(got.PolicyHash, b.PolicyHash) {
		t.Fatalf("round trip mismatch: %+v vs %+v", got, b)
	}
	if raw2, _ := EncodeBody(got); !bytes.Equal(raw, raw2) {
		t.Fatal("re-encoding not deterministic")
	}
}

func TestPolicyCanonicalizesSigners(t *testing.T) {
	p := testPolicy(t)
	if bytes.Compare(p.Signers[0], p.Signers[1]) >= 0 {
		t.Fatal("signers not sorted")
	}
	if _, err := NewPolicy(1, [][]byte{
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x01}, 32),
	}); err == nil {
		t.Fatal("duplicate signer accepted")
	}
	if _, err := NewPolicy(3, [][]byte{bytes.Repeat([]byte{0x01}, 32)}); err == nil {
		t.Fatal("threshold above signer count accepted")
	}
	if _, err := NewPolicy(0, [][]byte{bytes.Repeat([]byte{0x01}, 32)}); err == nil {
		t.Fatal("zero threshold accepted")
	}
}

func TestDecodeRejectsUnknownVersion(t *testing.T) {
	raw, _ := EncodeBody(testBody(t))
	raw[0] = 0x00
	raw[1] = 0x02
	if _, err := DecodeBody(raw); err == nil {
		t.Fatal("unknown version accepted")
	}
	raw2, _ := EncodePolicy(testPolicy(t))
	raw2[0] = 0x00
	raw2[1] = 0x09
	if _, err := DecodePolicy(raw2); err == nil {
		t.Fatal("unknown policy version accepted")
	}
}

func TestDecodeRejectsTrailingBytes(t *testing.T) {
	raw, _ := EncodeBody(testBody(t))
	if _, err := DecodeBody(append(raw, 0x00)); err == nil {
		t.Fatal("trailing byte accepted")
	}
	if _, err := DecodeBody(raw[:len(raw)-1]); err == nil {
		t.Fatal("truncated encoding accepted")
	}
}

func TestDecodeRejectsFrameDisorder(t *testing.T) {
	raw, _ := EncodeBody(testBody(t))
	// Frames start after the 2-byte version. Duplicate the first frame at the
	// end by appending its bytes.
	tag := raw[2]
	length := uint32(raw[3])<<24 | uint32(raw[4])<<16 | uint32(raw[5])<<8 | uint32(raw[6])
	frame := raw[2 : 7+length]
	mut := append(append([]byte(nil), raw...), frame...)
	_ = tag
	if _, err := DecodeBody(mut); err == nil {
		t.Fatal("duplicate frame accepted")
	}
}

func TestDecodeRejectsUnknownTag(t *testing.T) {
	p := testPolicy(t)
	raw, _ := EncodePolicy(p)
	// Inject an unknown tag 0x7F frame with empty payload before existing
	// frames (ascending tags stay ordered).
	var injected []byte
	injected = append(injected, raw[:2]...)
	injected = append(injected, 0x7F, 0x00, 0x00, 0x00, 0x00)
	injected = append(injected, raw[2:]...)
	if _, err := DecodePolicy(injected); err == nil {
		t.Fatal("unknown frame tag accepted")
	}
}

func TestDecodePolicyRejectsNonCanonicalSignerOrder(t *testing.T) {
	p := testPolicy(t)
	raw, _ := EncodePolicy(p)
	// Swap the two 32-byte signer entries inside the signers payload.
	// Locate signers frame (tag 2): scan after version + threshold frame.
	// threshold frame = 1(tag)+4(len)+2(payload)=7 bytes after version.
	base := 2 + 7
	if raw[base] != tagPolicySigners {
		t.Fatalf("unexpected layout tag=%d", raw[base])
	}
	payloadStart := base + 5
	entryLen := 4 + 32
	payload := raw[payloadStart:]
	if len(payload) != 2*entryLen {
		t.Fatalf("unexpected payload length %d", len(payload))
	}
	first := append([]byte(nil), payload[:entryLen]...)
	second := append([]byte(nil), payload[entryLen:2*entryLen]...)
	copy(payload[:entryLen], second)
	copy(payload[entryLen:2*entryLen], first)
	if _, err := DecodePolicy(raw); err == nil {
		t.Fatal("descending signer order accepted")
	}
}
