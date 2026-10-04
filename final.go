package pst

import (
	"bytes"
	"sort"
)

type FinalTransaction struct {
	Version    int                 `json:"v"`
	Tx         *Transaction        `json:"tx"`
	Policy     *Policy             `json:"policy"`
	Signatures []*PartialSignature `json:"signatures"`
}

func assembleFinal(tx *Transaction, policy *Policy, sigs []*PartialSignature) (*FinalTransaction, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	accepted := make([]*PartialSignature, 0, len(sigs))
	for _, sig := range sigs {
		if err := sig.Verify(tx); err != nil {
			return nil, err
		}
		key := string(sig.PublicKey)
		if _, dup := seen[key]; dup {
			return nil, ErrPolicyViolation
		}
		if !policy.Allows(sig.PublicKey) {
			return nil, ErrPublicKeyNotAllowed
		}
		seen[key] = struct{}{}
		accepted = append(accepted, sig)
	}
	if len(accepted) < policy.Threshold {
		return nil, ErrThresholdNotMet
	}
	sort.Slice(accepted, func(i, j int) bool {
		return bytes.Compare(accepted[i].PublicKey, accepted[j].PublicKey) < 0
	})
	return &FinalTransaction{
		Version:    encodingVersion,
		Tx:         tx,
		Policy:     policy,
		Signatures: accepted,
	}, nil
}

func (f *FinalTransaction) Encode() ([]byte, error) {
	if f == nil || f.Version != encodingVersion {
		return nil, ErrUnknownVersion
	}
	return canonicalJSON(f)
}

func DecodeFinal(data []byte) (*FinalTransaction, error) {
	var f FinalTransaction
	if err := strictDecodeJSON(data, &f); err != nil {
		return nil, err
	}
	if f.Version != encodingVersion {
		return nil, ErrUnknownVersion
	}
	return &f, nil
}

// Verify lets any party independently verify a finalized transaction without
// trusting the service: the policy is valid, the signatures are in canonical
// order, each one covers exactly the embedded transaction body and belongs to
// an allowed key, and the threshold is met.
func (f *FinalTransaction) Verify() error {
	if f == nil {
		return ErrUnknownVersion
	}
	if f.Version != encodingVersion {
		return ErrUnknownVersion
	}
	if err := f.Policy.Validate(); err != nil {
		return err
	}
	if len(f.Signatures) < f.Policy.Threshold {
		return ErrThresholdNotMet
	}
	seen := map[string]struct{}{}
	var prev []byte
	for _, sig := range f.Signatures {
		if err := sig.Verify(f.Tx); err != nil {
			return err
		}
		key := sig.PublicKey
		if prev != nil && bytes.Compare(prev, key) >= 0 {
			return ErrNonCanonical
		}
		prev = key
		if _, dup := seen[string(key)]; dup {
			return ErrPolicyViolation
		}
		seen[string(key)] = struct{}{}
		if !f.Policy.Allows(key) {
			return ErrPublicKeyNotAllowed
		}
	}
	return nil
}
