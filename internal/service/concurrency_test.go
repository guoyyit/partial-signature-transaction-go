package service

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/guoyyit/partial-signature-transaction-go/internal/store"
	"github.com/guoyyit/partial-signature-transaction-go/internal/txn"
)

func TestConcurrentSubmissionsNoLossOrDuplicates(t *testing.T) {
	parties := genParties(t, 5)
	svc, b, _, st := setupService(t, parties, fixtureOpts{
		threshold:  3,
		validUntil: time.Now().Add(time.Hour).Unix(),
	})

	sigs := make([]txn.PartialSignature, len(parties))
	for i, p := range parties {
		ps, err := txn.SignBody(p.priv, b)
		if err != nil {
			t.Fatal(err)
		}
		sigs[i] = ps
	}

	var wg sync.WaitGroup
	for round := 0; round < 20; round++ {
		for i := range parties {
			wg.Add(1)
			go func(ps txn.PartialSignature) {
				defer wg.Done()
				_ = svc.Submit(ps)
			}(sigs[i])
		}
	}
	wg.Wait()

	v := svc.View()
	if len(v.Signers) != len(parties) {
		t.Fatalf("expected %d held signatures, got %d", len(parties), len(v.Signers))
	}
	f, err := svc.Finalize()
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if err := txn.VerifyFinal(f); err != nil {
		t.Fatalf("VerifyFinal: %v", err)
	}
	if len(f.Signatures) != len(parties) {
		t.Fatalf("final has %d signatures, want %d", len(f.Signatures), len(parties))
	}

	events, _ := st.Events()
	submitted := 0
	for _, e := range events {
		if e.Kind == store.EventSubmitted {
			submitted++
		}
	}
	if submitted != len(parties) {
		t.Fatalf("expected %d submitted events, got %d", len(parties), submitted)
	}
}

func TestSubmitFinalizeRace(t *testing.T) {
	parties := genParties(t, 4)
	svc, b, _, _ := setupService(t, parties, fixtureOpts{
		threshold:  3,
		validUntil: time.Now().Add(time.Hour).Unix(),
	})

	ps0, _ := txn.SignBody(parties[0].priv, b)
	ps1, _ := txn.SignBody(parties[1].priv, b)
	if err := svc.Submit(ps0); err != nil {
		t.Fatal(err)
	}
	if err := svc.Submit(ps1); err != nil {
		t.Fatal(err)
	}
	ps2, _ := txn.SignBody(parties[2].priv, b)
	ps3, _ := txn.SignBody(parties[3].priv, b)

	var wg sync.WaitGroup
	results := make(chan error, 4)
	finalized := make(chan txn.Final, 2)
	runFinalize := func() {
		defer wg.Done()
		f, err := svc.Finalize()
		if err == nil {
			finalized <- f
		}
		results <- err
	}
	wg.Add(4)
	go func() { defer wg.Done(); results <- svc.Submit(ps2) }()
	go func() { defer wg.Done(); results <- svc.Submit(ps3) }()
	go runFinalize()
	go runFinalize()
	wg.Wait()
	close(results)
	close(finalized)

	var submitOK int
	var thresholdFails, finalizedFails int
	for err := range results {
		switch {
		case errors.Is(err, txn.ErrThreshold):
			thresholdFails++
		case errors.Is(err, ErrFinalized):
			finalizedFails++
		case err == nil:
			submitOK++
		}
	}
	// Both submits must always succeed; they never race each other.
	if submitOK != 2 {
		t.Fatalf("expected both submissions to succeed, got %d", submitOK)
	}

	v := svc.View()
	if v.Status == StatusFinalized {
		// A finalize crossed the threshold: exactly one success, other fails.
		if len(finalized) != 1 {
			t.Fatalf("exactly one Finalize must succeed, got %d", len(finalized))
		}
		f := <-finalized
		if err := txn.VerifyFinal(f); err != nil {
			t.Fatalf("VerifyFinal: %v", err)
		}
		if len(f.Signatures) < 3 {
			t.Fatalf("final carries %d signatures", len(f.Signatures))
		}
		if thresholdFails+finalizedFails != 1 {
			t.Fatalf("unexpected finalize outcomes: threshold=%d finalized=%d",
				thresholdFails, finalizedFails)
		}
	} else {
		// Both finalize attempts ran while fewer than three signatures were
		// held; state remains collecting and all four signatures are present.
		if len(finalized) != 0 {
			t.Fatal("final reported despite collecting status")
		}
		if len(v.Signers) != 4 {
			t.Fatalf("expected 4 held signatures, got %d", len(v.Signers))
		}
		if thresholdFails != 2 {
			t.Fatalf("expected 2 threshold failures, got %d", thresholdFails)
		}
		f, err := svc.Finalize()
		if err != nil {
			t.Fatalf("post-race Finalize: %v", err)
		}
		if err := txn.VerifyFinal(f); err != nil {
			t.Fatalf("VerifyFinal: %v", err)
		}
	}
}

func TestRevokeFinalizeRace(t *testing.T) {
	for iter := 0; iter < 200; iter++ {
		parties := genParties(t, 3)
		svc, b, _, _ := setupService(t, parties, fixtureOpts{
			threshold:  3,
			validUntil: time.Now().Add(time.Hour).Unix(),
		})
		for _, p := range parties {
			ps, _ := txn.SignBody(p.priv, b)
			if err := svc.Submit(ps); err != nil {
				t.Fatal(err)
			}
		}
		r0, _ := txn.SignRevocation(parties[0].priv, b)

		var wg sync.WaitGroup
		var finErr, revErr error
		wg.Add(2)
		go func() { defer wg.Done(); _, finErr = svc.Finalize() }()
		go func() { defer wg.Done(); revErr = svc.Revoke(r0) }()
		wg.Wait()

		switch {
		case finErr == nil && revErr == nil:
			t.Fatal("both finalize and revoke reported success")
		case finErr == nil:
			if !errors.Is(revErr, ErrFinalized) {
				t.Fatalf("revoke after finalize: %v", revErr)
			}
			f := svc.View().Final
			if f == nil || len(f.Signatures) != 3 {
				t.Fatalf("final missing signatures: %+v", f)
			}
			if err := txn.VerifyFinal(*f); err != nil {
				t.Fatalf("VerifyFinal: %v", err)
			}
		case revErr == nil:
			if !errors.Is(finErr, txn.ErrThreshold) {
				t.Fatalf("finalize after revoke: %v", finErr)
			}
			if svc.View().Status != StatusCollecting {
				t.Fatal("status finalized despite revoked signature")
			}
			for _, info := range svc.View().Signers {
				if bytes.Equal(info.Signer, parties[0].pub) {
					t.Fatal("revoked signer still present")
				}
			}
		default:
			t.Fatalf("both failed: fin=%v rev=%v", finErr, revErr)
		}
	}
}
