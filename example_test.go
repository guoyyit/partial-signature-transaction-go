package pst_test

import (
	"fmt"
	"os"
	"time"

	pst "github.com/guoyyit/partial-signature-transaction-go"
)

// Example shows the full local, offline flow: three key holders sign
// independently, one revokes, the service finalizes once the threshold holds,
// and any party verifies the result standalone.
func Example() {
	dir, err := os.MkdirTemp("", "pst-example-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	holders := make([]*pst.KeyPair, 3)
	for i := range holders {
		holders[i], err = pst.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
	}

	tx := &pst.Transaction{
		Version:   1,
		ChainID:   "local",
		Nonce:     42,
		Sender:    []byte("alice"),
		Recipient: []byte("bob"),
		Amount:    99,
		Reference: "demo",
	}

	policy := &pst.Policy{Version: 1, Threshold: 2}
	for _, h := range holders {
		policy.AllowedKeys = append(policy.AllowedKeys, h.Public)
	}

	svc, err := pst.Open(pst.Config{Dir: dir})
	if err != nil {
		panic(err)
	}
	txID, err := svc.Register(tx, policy, time.Hour)
	if err != nil {
		panic(err)
	}

	for _, h := range holders[:2] {
		sig, err := pst.SignTransaction(h.Private, tx)
		if err != nil {
			panic(err)
		}
		if err := svc.Submit(sig); err != nil {
			panic(err)
		}
	}

	final, err := svc.Finalize(txID)
	if err != nil {
		panic(err)
	}
	blob, err := final.Encode()
	if err != nil {
		panic(err)
	}

	received, err := pst.DecodeFinal(blob)
	if err != nil {
		panic(err)
	}
	if err := received.Verify(); err != nil {
		panic(err)
	}
	fmt.Printf("finalized with %d signatures\n", len(received.Signatures))
	// Output: finalized with 2 signatures
}
