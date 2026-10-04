package pst

import (
	"bytes"
	"strings"
	"testing"
)

func testTx() *Transaction {
	return &Transaction{
		Version:   uint64(encodingVersion),
		ChainID:   "local",
		Nonce:     7,
		Sender:    []byte{1, 2, 3, 4},
		Recipient: []byte{5, 6, 7, 8},
		Amount:    1000,
		Reference: "hello",
	}
}

func mustKeys(t *testing.T, n int) []*KeyPair {
	t.Helper()
	keys := make([]*KeyPair, n)
	for i := range keys {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		keys[i] = kp
	}
	return keys
}

func mustPolicy(keys []*KeyPair, threshold int) *Policy {
	p := &Policy{Version: encodingVersion, Threshold: threshold}
	for _, k := range keys {
		p.AllowedKeys = append(p.AllowedKeys, append([]byte(nil), k.Public...))
	}
	return p
}

func TestSignVerifyAndTamper(t *testing.T) {
	keys := mustKeys(t, 2)
	tx := testTx()

	sig, err := SignTransaction(keys[0].Private, tx)
	if err != nil {
		t.Fatal(err)
	}
	if err := sig.Verify(tx); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	if err := sig.Verify(tx); err != nil {
		t.Fatalf("second verifier rejected: %v", err)
	}

	tampered := testTx()
	tampered.Amount = 1001
	if err := sig.Verify(tampered); err == nil {
		t.Fatal("signature stayed valid after changing amount")
	}
	tampered2 := testTx()
	tampered2.Reference = "hell0"
	if err := sig.Verify(tampered2); err == nil {
		t.Fatal("signature stayed valid after changing reference")
	}
	tampered3 := testTx()
	tampered3.Sender = []byte{9, 9}
	if err := sig.Verify(tampered3); err == nil {
		t.Fatal("signature stayed valid after changing sender")
	}

	other, err := SignTransaction(keys[1].Private, testTx())
	if err != nil {
		t.Fatal(err)
	}
	corrupt := *sig
	corrupt.Signature = append([]byte(nil), other.Signature...)
	if err := corrupt.Verify(tx); err == nil {
		t.Fatal("foreign signature accepted")
	}
}

func TestCanonicalDeterminismAndStrictDecode(t *testing.T) {
	tx := testTx()
	a, err := CanonicalTransaction(tx)
	if err != nil {
		t.Fatal(err)
	}
	b, err := CanonicalTransaction(testTx())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("canonical encoding is not deterministic")
	}
	decoded, err := DecodeTransaction(a)
	if err != nil {
		t.Fatalf("canonical bytes must decode strictly: %v", err)
	}
	recoded, _ := CanonicalTransaction(decoded)
	if !bytes.Equal(recoded, a) {
		t.Fatal("canonical encode/decode round trip changed bytes")
	}

	badInputs := [][]byte{
		bytes.Replace(a, []byte("{"), []byte("{ "), 1),
		append(append([]byte{}, a...), '\n'),
		[]byte(`{"version":1,"chain_id":"local","nonce":7,"sender":"AQIDBA==","recipient":"BQYHCA==","amount":1000,"reference":"hello","extra":1}`),
		dupKeyTransactionJSON(),
	}
	for i, in := range badInputs {
		if _, err := DecodeTransaction(in); err == nil {
			t.Fatalf("non-canonical input %d accepted", i)
		}
	}

	var unknownVersion Transaction
	raw := []byte(`{"version":99,"chain_id":"local","nonce":7,"sender":"AQIDBA==","recipient":"BQYHCA==","amount":1000,"reference":"hello"}`)
	if err := strictDecodeJSON(raw, &unknownVersion); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if _, err := CanonicalTransaction(&unknownVersion); err == nil {
		t.Fatal("unknown transaction version accepted")
	}
}

func dupKeyTransactionJSON() []byte {
	return []byte(`{"version":1,"chain_id":"local","nonce":7,"sender":"AQIDBA==","recipient":"BQYHCA==","amount":1000,"reference":"hello","amount":1001}`)
}

func TestPartialSignatureEncoding(t *testing.T) {
	keys := mustKeys(t, 1)
	sig, err := SignTransaction(keys[0].Private, testTx())
	if err != nil {
		t.Fatal(err)
	}
	data, err := sig.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodePartialSignature(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Verify(testTx()); err != nil {
		t.Fatal(err)
	}

	unknown := bytes.Replace(data, []byte(`"v":1`), []byte(`"v":2`), 1)
	if _, err := DecodePartialSignature(unknown); err == nil {
		t.Fatal("unknown version accepted")
	}
	spaced := bytes.Replace(data, []byte(","), []byte(", "), 1)
	if _, err := DecodePartialSignature(spaced); err == nil {
		t.Fatal("whitespace-padded encoding accepted")
	}
	if _, err := DecodePartialSignature(append(append([]byte{}, data...), ' ', 'x')); err == nil {
		t.Fatal("trailing garbage accepted")
	}

	if strings.Contains(string(data), "\n") {
		t.Fatal("encoded signature must be single-line compact JSON")
	}
}

func TestPolicyValidation(t *testing.T) {
	keys := mustKeys(t, 2)

	p := mustPolicy(keys, 2)
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}

	cases := []*Policy{
		{Version: encodingVersion, Threshold: 0},
		{Version: encodingVersion, Threshold: 1},
		{Version: encodingVersion, Threshold: 3, AllowedKeys: [][]byte{keys[0].Public}},
		{Version: 99, Threshold: 1, AllowedKeys: [][]byte{keys[0].Public}},
		{Version: encodingVersion, Threshold: 1, AllowedKeys: [][]byte{{1, 2, 3}}},
		{Version: encodingVersion, Threshold: 1, AllowedKeys: [][]byte{keys[0].Public, keys[0].Public}},
	}
	for i, c := range cases {
		if err := c.Validate(); err == nil {
			t.Fatalf("invalid policy %d accepted", i)
		}
	}
	if p.Allows(keys[0].Public) != true {
		t.Fatal("allowed key rejected")
	}
	foreign := mustKeys(t, 1)[0].Public
	if p.Allows(foreign) {
		t.Fatal("foreign key accepted")
	}
}

func TestAssembleOrderIndependent(t *testing.T) {
	keys := mustKeys(t, 3)
	tx := testTx()
	policy := mustPolicy(keys, 2)

	var sigs []*PartialSignature
	for _, k := range keys {
		s, err := SignTransaction(k.Private, tx)
		if err != nil {
			t.Fatal(err)
		}
		sigs = append(sigs, s)
	}

	f1, err := assembleFinal(tx, policy, []*PartialSignature{sigs[2], sigs[0], sigs[1]})
	if err != nil {
		t.Fatal(err)
	}
	f2, err := assembleFinal(tx, policy, []*PartialSignature{sigs[1], sigs[2], sigs[0]})
	if err != nil {
		t.Fatal(err)
	}
	e1, _ := f1.Encode()
	e2, _ := f2.Encode()
	if !bytes.Equal(e1, e2) {
		t.Fatal("final transaction depends on arrival order")
	}
	if err := f1.Verify(); err != nil {
		t.Fatalf("independent verification failed: %v", err)
	}

	if _, err := assembleFinal(tx, policy, sigs[:1]); err != ErrThresholdNotMet {
		t.Fatalf("want ErrThresholdNotMet, got %v", err)
	}

	foreignKeys := mustKeys(t, 1)
	foreign, _ := SignTransaction(foreignKeys[0].Private, tx)
	if _, err := assembleFinal(tx, policy, []*PartialSignature{foreign, sigs[0]}); err != ErrPublicKeyNotAllowed {
		t.Fatalf("want ErrPublicKeyNotAllowed, got %v", err)
	}

	again, _ := SignTransaction(keys[0].Private, tx)
	if _, err := assembleFinal(tx, policy, []*PartialSignature{sigs[0], again}); err != ErrPolicyViolation {
		t.Fatalf("duplicate key in assembly should fail, got %v", err)
	}
}

func TestFinalEncodingAndVerify(t *testing.T) {
	keys := mustKeys(t, 2)
	tx := testTx()
	policy := mustPolicy(keys, 2)
	var sigs []*PartialSignature
	for _, k := range keys {
		s, _ := SignTransaction(k.Private, tx)
		sigs = append(sigs, s)
	}
	f, err := assembleFinal(tx, policy, sigs)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := f.Encode()
	decoded, err := DecodeFinal(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := decoded.Verify(); err != nil {
		t.Fatal(err)
	}

	decoded.Tx.Amount++
	if err := decoded.Verify(); err == nil {
		t.Fatal("final stayed valid after body tamper")
	}

	unknown := bytes.Replace(data, []byte(`"v":1`), []byte(`"v":7`), 1)
	if _, err := DecodeFinal(unknown); err == nil {
		t.Fatal("unknown final version accepted")
	}
	if _, err := DecodeFinal(append(append([]byte{}, data...), []byte(" {}")...)); err == nil {
		t.Fatal("trailing data after final transaction accepted")
	}
}

func TestRevocationSignature(t *testing.T) {
	keys := mustKeys(t, 1)
	txID, _ := TransactionID(testTx())
	r, err := SignRevocation(keys[0].Private, txID)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(txID); err != nil {
		t.Fatal(err)
	}
	other, _ := TransactionID(func() *Transaction {
		tx := testTx()
		tx.Nonce = 8
		return tx
	}())
	if err := r.Verify(other); err == nil {
		t.Fatal("revocation verified against wrong transaction")
	}
	data, _ := r.Encode()
	decoded, err := DecodeRevocation(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := decoded.Verify(txID); err != nil {
		t.Fatal(err)
	}
}
