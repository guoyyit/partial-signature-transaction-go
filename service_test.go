package pst

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func newTestService(t *testing.T, dir string, now time.Time) (*Service, *fakeClock) {
	t.Helper()
	clock := &fakeClock{t: now}
	svc, err := Open(Config{Dir: dir, Now: func() time.Time { return clock.t }})
	if err != nil {
		t.Fatal(err)
	}
	return svc, clock
}

func setupTx(t *testing.T, svc *Service, keys []*KeyPair, threshold int, ttl time.Duration) (*Transaction, []byte) {
	t.Helper()
	tx := testTx()
	txID, err := svc.Register(tx, mustPolicy(keys, threshold), ttl)
	if err != nil {
		t.Fatal(err)
	}
	return tx, txID
}

func txDir(txID []byte) string {
	return hexEncode(txID)
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func reopenAndFinalize(t *testing.T, dir string, now time.Time, txID []byte) (*FinalTransaction, error) {
	t.Helper()
	svc, err := Open(Config{Dir: dir, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return svc.Finalize(txID)
}

func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[i*2] = digits[x>>4]
		out[i*2+1] = digits[x&0xf]
	}
	return string(out)
}

func TestOutOfOrderCollectionAndFinalize(t *testing.T) {
	svc, _ := newTestService(t, t.TempDir(), time.Unix(1000, 0))
	keys := mustKeys(t, 3)
	tx, txID := setupTx(t, svc, keys, 2, time.Minute)

	s2, _ := SignTransaction(keys[2].Private, tx)
	if err := svc.Submit(s2); err != nil {
		t.Fatal(err)
	}
	s0, _ := SignTransaction(keys[0].Private, tx)
	if err := svc.Submit(s0); err != nil {
		t.Fatal(err)
	}

	f, err := svc.Finalize(txID)
	if err != nil {
		t.Fatalf("threshold should be met: %v", err)
	}
	if err := f.Verify(); err != nil {
		t.Fatal(err)
	}
	if len(f.Signatures) != 2 {
		t.Fatalf("want 2 signatures, got %d", len(f.Signatures))
	}
	if err := svc.Submit(s2); err != ErrFinalized {
		t.Fatalf("submit after finalize want ErrFinalized, got %v", err)
	}
	f2, err := svc.Finalize(txID)
	if err != nil {
		t.Fatal(err)
	}
	e1, _ := f.Encode()
	e2, _ := f2.Encode()
	if string(e1) != string(e2) {
		t.Fatal("repeated finalize is not stable")
	}
}

func TestNonAllowedAndInvalidSignaturesRejected(t *testing.T) {
	svc, _ := newTestService(t, t.TempDir(), time.Unix(1000, 0))
	keys := mustKeys(t, 2)
	tx, _ := setupTx(t, svc, keys, 2, time.Minute)

	foreign, err := SignTransaction(mustKeys(t, 1)[0].Private, tx)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Submit(foreign); err != ErrPublicKeyNotAllowed {
		t.Fatalf("want ErrPublicKeyNotAllowed, got %v", err)
	}

	bad, _ := SignTransaction(keys[0].Private, tx)
	bad.Signature[0] ^= 0xff
	if err := svc.Submit(bad); err != ErrInvalidSignature {
		t.Fatalf("want ErrInvalidSignature, got %v", err)
	}

	forged, _ := SignTransaction(keys[0].Private, tx)
	forged.TxID = append([]byte(nil), forged.TxID...)
	forged.TxID[0] ^= 0xff
	if err := svc.Submit(forged); err != ErrTransactionNotFound {
		t.Fatalf("mismatched tx id want ErrTransactionNotFound, got %v", err)
	}

	if err := svc.Submit(&PartialSignature{Version: encodingVersion}); err != ErrTransactionNotFound {
		t.Fatalf("want ErrTransactionNotFound, got %v", err)
	}

	txID, _ := TransactionID(tx)
	status, err := svc.Status(txID)
	if err != nil {
		t.Fatal(err)
	}
	if status.Collected != 0 {
		t.Fatalf("rejected signatures must not be collected, got %d", status.Collected)
	}
}

func TestConcurrentSubmitNoLossAndDuplicates(t *testing.T) {
	dir := t.TempDir()
	svc, _ := newTestService(t, dir, time.Unix(1000, 0))
	keys := mustKeys(t, 20)
	tx, txID := setupTx(t, svc, keys, 15, time.Hour)

	var wg sync.WaitGroup
	for round := 0; round < 3; round++ {
		for _, k := range keys {
			wg.Add(1)
			go func(kp *KeyPair) {
				defer wg.Done()
				sig, err := SignTransaction(kp.Private, tx)
				if err != nil {
					t.Error(err)
					return
				}
				if err := svc.Submit(sig); err != nil {
					t.Errorf("submit: %v", err)
				}
			}(k)
		}
	}
	wg.Wait()

	status, err := svc.Status(txID)
	if err != nil {
		t.Fatal(err)
	}
	if status.Collected != 20 {
		t.Fatalf("want 20 unique signatures, got %d", status.Collected)
	}

	f, err := svc.Finalize(txID)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Signatures) != 20 {
		t.Fatalf("want 20 final signatures, got %d", len(f.Signatures))
	}
	if err := f.Verify(); err != nil {
		t.Fatal(err)
	}

	f2, err := reopenAndFinalize(t, dir, time.Unix(1000, 0), txID)
	if err != nil {
		t.Fatal(err)
	}
	e1, _ := f.Encode()
	e2, _ := f2.Encode()
	if string(e1) != string(e2) {
		t.Fatal("reloaded final transaction differs")
	}
}

func TestRevokeRaceWithFinalize(t *testing.T) {
	const iterations = 60
	start := time.Unix(2000, 0)
	keys := mustKeys(t, 4)

	for i := 0; i < iterations; i++ {
		dir := t.TempDir()
		svc, _ := newTestService(t, dir, start)
		tx, txID := setupTx(t, svc, keys, 2, time.Hour)
		for _, k := range keys {
			sig, _ := SignTransaction(k.Private, tx)
			if err := svc.Submit(sig); err != nil {
				t.Fatal(err)
			}
		}

		rev, _ := SignRevocation(keys[1].Private, txID)
		var wg sync.WaitGroup
		var f *FinalTransaction
		var ferr, rerr error
		wg.Add(2)
		go func() { defer wg.Done(); f, ferr = svc.Finalize(txID) }()
		go func() { defer wg.Done(); rerr = svc.Revoke(rev) }()
		wg.Wait()
		if ferr != nil {
			t.Fatalf("finalize failed: %v", ferr)
		}

		reloaded, rerr2 := reopenAndFinalize(t, dir, start, txID)
		if rerr2 != nil {
			t.Fatalf("reload finalize failed: %v", rerr2)
		}
		e1, _ := f.Encode()
		e2, _ := reloaded.Encode()
		if string(e1) != string(e2) {
			t.Fatal("in-memory and reloaded outcomes diverge")
		}

		switch {
		case rerr == nil:
			for _, item := range []*FinalTransaction{f, reloaded} {
				for _, sig := range item.Signatures {
					if string(sig.PublicKey) == string(keys[1].Public) {
						t.Fatal("revoked signature entered final transaction when revoke won")
					}
				}
				if err := item.Verify(); err != nil {
					t.Fatal(err)
				}
			}
			if len(f.Signatures) != 3 || len(reloaded.Signatures) != 3 {
				t.Fatalf("revoke-first outcome must keep 3 sigs, got %d/%d", len(f.Signatures), len(reloaded.Signatures))
			}
		case rerr == ErrFinalized:
			if err := f.Verify(); err != nil {
				t.Fatal(err)
			}
			if len(f.Signatures) != 4 {
				t.Fatalf("finalize-first outcome must keep 4 sigs, got %d", len(f.Signatures))
			}
		default:
			t.Fatalf("unexpected revoke result: %v", rerr)
		}
	}
}

func TestSerialRevokeWinsFinalization(t *testing.T) {
	dir := t.TempDir()
	start := time.Unix(2100, 0)
	svc, _ := newTestService(t, dir, start)
	keys := mustKeys(t, 4)
	tx, txID := setupTx(t, svc, keys, 2, time.Hour)
	for _, k := range keys {
		sig, _ := SignTransaction(k.Private, tx)
		if err := svc.Submit(sig); err != nil {
			t.Fatal(err)
		}
	}
	rev, _ := SignRevocation(keys[1].Private, txID)
	if err := svc.Revoke(rev); err != nil {
		t.Fatal(err)
	}
	f, err := svc.Finalize(txID)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Signatures) != 3 {
		t.Fatalf("want 3 sigs after revoke, got %d", len(f.Signatures))
	}
	for _, sig := range f.Signatures {
		if string(sig.PublicKey) == string(keys[1].Public) {
			t.Fatal("revoked signature present")
		}
	}

	reloaded, err := reopenAndFinalize(t, dir, start, txID)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Signatures) != 3 {
		t.Fatalf("reloaded want 3 sigs, got %d", len(reloaded.Signatures))
	}
	for _, sig := range reloaded.Signatures {
		if string(sig.PublicKey) == string(keys[1].Public) {
			t.Fatal("revoked signature present after reload")
		}
	}
}

func TestSerialFinalizationWinsRevoke(t *testing.T) {
	dir := t.TempDir()
	start := time.Unix(2200, 0)
	svc, _ := newTestService(t, dir, start)
	keys := mustKeys(t, 4)
	tx, txID := setupTx(t, svc, keys, 2, time.Hour)
	for _, k := range keys {
		sig, _ := SignTransaction(k.Private, tx)
		if err := svc.Submit(sig); err != nil {
			t.Fatal(err)
		}
	}
	f, err := svc.Finalize(txID)
	if err != nil {
		t.Fatal(err)
	}
	rev, _ := SignRevocation(keys[1].Private, txID)
	if err := svc.Revoke(rev); err != ErrFinalized {
		t.Fatalf("want ErrFinalized, got %v", err)
	}
	if len(f.Signatures) != 4 {
		t.Fatalf("want 4 immutable sigs, got %d", len(f.Signatures))
	}
	reloaded, err := reopenAndFinalize(t, dir, start, txID)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Signatures) != 4 {
		t.Fatalf("reloaded want 4 sigs, got %d", len(reloaded.Signatures))
	}
}

func TestRevokeAndResubmit(t *testing.T) {
	svc, _ := newTestService(t, t.TempDir(), time.Unix(1000, 0))
	keys := mustKeys(t, 2)
	tx, txID := setupTx(t, svc, keys, 1, time.Hour)

	sig, _ := SignTransaction(keys[0].Private, tx)
	if err := svc.Submit(sig); err != nil {
		t.Fatal(err)
	}
	rev, _ := SignRevocation(keys[0].Private, txID)
	if err := svc.Revoke(rev); err != nil {
		t.Fatal(err)
	}
	if err := svc.Revoke(rev); err != ErrNoSignature {
		t.Fatalf("double revoke want ErrNoSignature, got %v", err)
	}
	status, _ := svc.Status(txID)
	if status.Collected != 0 {
		t.Fatalf("want 0 after revoke, got %d", status.Collected)
	}
	if _, err := svc.Finalize(txID); err != ErrThresholdNotMet {
		t.Fatalf("want ErrThresholdNotMet, got %v", err)
	}
	if err := svc.Submit(sig); err != nil {
		t.Fatalf("resubmit after revoke should succeed: %v", err)
	}
	f, err := svc.Finalize(txID)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Signatures) != 1 {
		t.Fatalf("want 1 signature, got %d", len(f.Signatures))
	}
}

func TestExpiryRejectsNewSignatures(t *testing.T) {
	dir := t.TempDir()
	start := time.Unix(3000, 0)
	svc, clock := newTestService(t, dir, start)
	keys := mustKeys(t, 2)
	tx, txID := setupTx(t, svc, keys, 2, time.Minute)

	s0, _ := SignTransaction(keys[0].Private, tx)
	if err := svc.Submit(s0); err != nil {
		t.Fatal(err)
	}

	clock.t = start.Add(61 * time.Second)
	s1, _ := SignTransaction(keys[1].Private, tx)
	if err := svc.Submit(s1); err != ErrExpired {
		t.Fatalf("want ErrExpired, got %v", err)
	}
	rev, _ := SignRevocation(keys[0].Private, txID)
	if err := svc.Revoke(rev); err != ErrExpired {
		t.Fatalf("revoke after expiry want ErrExpired, got %v", err)
	}
	if _, err := svc.Finalize(txID); err != ErrExpired {
		t.Fatalf("want ErrExpired, got %v", err)
	}

	status, _ := svc.Status(txID)
	if !status.Expired || status.Collected != 1 {
		t.Fatalf("unexpected status: %+v", status)
	}

	svc2, _ := newTestService(t, dir, clock.t)
	status2, err := svc2.Status(txID)
	if err != nil {
		t.Fatal(err)
	}
	if !status2.Expired || status2.Collected != 1 {
		t.Fatalf("expiry state must survive restart, got %+v", status2)
	}
}

func TestRestartContinuesCollection(t *testing.T) {
	dir := t.TempDir()
	start := time.Unix(4000, 0)
	svc, _ := newTestService(t, dir, start)
	keys := mustKeys(t, 3)
	tx, txID := setupTx(t, svc, keys, 2, 10*time.Minute)

	s0, _ := SignTransaction(keys[0].Private, tx)
	if err := svc.Submit(s0); err != nil {
		t.Fatal(err)
	}

	svc2, _ := newTestService(t, dir, start)
	status, _ := svc2.Status(txID)
	if status.Collected != 1 {
		t.Fatalf("want 1 signature after restart, got %d", status.Collected)
	}
	s1, _ := SignTransaction(keys[1].Private, tx)
	if err := svc2.Submit(s1); err != nil {
		t.Fatal(err)
	}
	f, err := svc2.Finalize(txID)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Verify(); err != nil {
		t.Fatal(err)
	}

	svc3, _ := newTestService(t, dir, start)
	status3, _ := svc3.Status(txID)
	if !status3.Finalized {
		t.Fatal("finalized state must survive restart")
	}
	f3, err := svc3.Finalize(txID)
	if err != nil {
		t.Fatal(err)
	}
	e1, _ := f.Encode()
	e3, _ := f3.Encode()
	if string(e1) != string(e3) {
		t.Fatal("final transaction changed after restart")
	}
	if _, err := DecodeFinal(mustReadFile(t, filepath.Join(dir, txDir(txID), "final.json"))); err != nil {
		t.Fatalf("on-disk final.json must be strict-decodable: %v", err)
	}
}

func TestTornLogTailRecovered(t *testing.T) {
	dir := t.TempDir()
	start := time.Unix(5000, 0)
	svc, _ := newTestService(t, dir, start)
	keys := mustKeys(t, 2)
	tx, txID := setupTx(t, svc, keys, 2, time.Hour)
	s0, _ := SignTransaction(keys[0].Private, tx)
	if err := svc.Submit(s0); err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(dir, txDir(txID), "events.log")
	good := mustReadFile(t, logPath)
	torn := append(good, []byte(`{"seq":2,"kind":"submi`)...)
	if err := os.WriteFile(logPath, torn, 0o644); err != nil {
		t.Fatal(err)
	}

	svc2, _ := newTestService(t, dir, start)
	status, _ := svc2.Status(txID)
	if status.Collected != 1 {
		t.Fatalf("want 1 signature after torn-tail recovery, got %d", status.Collected)
	}

	s1, _ := SignTransaction(keys[1].Private, tx)
	if err := svc2.Submit(s1); err != nil {
		t.Fatalf("append after torn-tail recovery failed: %v", err)
	}
	f, err := svc2.Finalize(txID)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Verify(); err != nil {
		t.Fatal(err)
	}
	events, _ := os.ReadFile(logPath)
	if !containsAllValidLines(events) {
		t.Fatal("recovered log contains garbage between records")
	}
}

func containsAllValidLines(data []byte) bool {
	start := 0
	count := 0
	for start < len(data) {
		end := start
		for end < len(data) && data[end] != '\n' {
			end++
		}
		if end > start {
			if _, err := decodeEvent(data[start:end]); err != nil {
				return false
			}
			count++
		}
		start = end + 1
	}
	return count >= 2
}

func TestMetaCorruptionDetected(t *testing.T) {
	dir := t.TempDir()
	svc, _ := newTestService(t, dir, time.Unix(6000, 0))
	keys := mustKeys(t, 1)
	tx, txID := setupTx(t, svc, keys, 1, time.Hour)
	_ = tx
	metaPath := filepath.Join(dir, txDir(txID), "meta.json")
	good := mustReadFile(t, metaPath)
	if err := os.WriteFile(metaPath, append(good, ' ', ' '), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Config{Dir: dir, Now: func() time.Time { return time.Unix(6000, 0) }}); err == nil {
		t.Fatal("non-canonical meta.json on disk must be rejected on open")
	}
}
