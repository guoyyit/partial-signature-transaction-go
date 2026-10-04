package txn

import (
	"bytes"
	"crypto/ed25519"
	"sort"
)

// Domain-separation prefixes keep signature and revocation messages distinct.
var (
	signMessagePrefix   = []byte("PSIG-BODY-V1\n")
	revokeMessagePrefix = []byte("PSIG-REVOKE-V1\n")
)

func bodyRaw(b Body) ([]byte, error) {
	raw, err := EncodeBody(b)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func signMessage(b Body) ([]byte, error) {
	raw, err := bodyRaw(b)
	if err != nil {
		return nil, err
	}
	return append(append([]byte(nil), signMessagePrefix...), raw...), nil
}

func revokeMessage(b Body) ([]byte, error) {
	raw, err := bodyRaw(b)
	if err != nil {
		return nil, err
	}
	return append(append([]byte(nil), revokeMessagePrefix...), raw...), nil
}

func checkPolicyBinding(b Body, p Policy) error {
	commit, err := PolicyCommitment(p)
	if err != nil {
		return err
	}
	if !bytes.Equal(commit, b.PolicyHash) {
		return ErrPolicyMismatch
	}
	return nil
}

func isListedSigner(p Policy, signer []byte) bool {
	for _, s := range p.Signers {
		if bytes.Equal(s, signer) {
			return true
		}
	}
	return false
}

// SignBody produces a partial signature covering the canonical encoding of
// the whole Body.
func SignBody(priv ed25519.PrivateKey, b Body) (PartialSignature, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return PartialSignature{}, ErrInvalidField
	}
	msg, err := signMessage(b)
	if err != nil {
		return PartialSignature{}, err
	}
	sig := ed25519.Sign(priv, msg)
	pub := priv.Public().(ed25519.PublicKey)
	return PartialSignature{
		Version:   Version,
		Signer:    append([]byte(nil), pub...),
		Signature: append([]byte(nil), sig...),
	}, nil
}

// VerifyPartial checks that ps is a policy-listed signature over the current
// canonical Body under the policy committed to by the Body.
func VerifyPartial(b Body, p Policy, ps PartialSignature) error {
	if ps.Version != Version {
		return ErrUnknownVersion
	}
	if len(ps.Signer) != ed25519PubLen || len(ps.Signature) != ed25519SigLen {
		return ErrInvalidField
	}
	if err := checkPolicyBinding(b, p); err != nil {
		return err
	}
	if !isListedSigner(p, ps.Signer) {
		return ErrSignerNotAllowed
	}
	msg, err := signMessage(b)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(ps.Signer), msg, ps.Signature) {
		return ErrSignatureInvalid
	}
	return nil
}

// SignRevocation authenticates withdrawal of the signer's partial signature.
func SignRevocation(priv ed25519.PrivateKey, b Body) (Revocation, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Revocation{}, ErrInvalidField
	}
	msg, err := revokeMessage(b)
	if err != nil {
		return Revocation{}, err
	}
	sig := ed25519.Sign(priv, msg)
	pub := priv.Public().(ed25519.PublicKey)
	return Revocation{
		Version:   Version,
		Signer:    append([]byte(nil), pub...),
		Signature: append([]byte(nil), sig...),
	}, nil
}

// VerifyRevocation checks that r was issued by its named signer for this Body.
func VerifyRevocation(b Body, r Revocation) error {
	if r.Version != Version {
		return ErrUnknownVersion
	}
	if len(r.Signer) != ed25519PubLen || len(r.Signature) != ed25519SigLen {
		return ErrInvalidField
	}
	msg, err := revokeMessage(b)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(r.Signer), msg, r.Signature) {
		return ErrSignatureInvalid
	}
	return nil
}

// AssembleFinal validates, deduplicates and orders signatures independently
// of arrival order, then builds the Final transaction.
func AssembleFinal(b Body, p Policy, sigs []PartialSignature) (Final, error) {
	if err := checkPolicyBinding(b, p); err != nil {
		return Final{}, err
	}
	bySigner := make(map[string]PartialSignature, len(sigs))
	for _, ps := range sigs {
		if err := VerifyPartial(b, p, ps); err != nil {
			return Final{}, err
		}
		bySigner[string(ps.Signer)] = ps
	}
	if len(bySigner) < int(p.Threshold) {
		return Final{}, ErrThreshold
	}
	ordered := make([]PartialSignature, 0, len(bySigner))
	for _, ps := range bySigner {
		ordered = append(ordered, ps)
	}
	sort.Slice(ordered, func(i, j int) bool {
		return bytes.Compare(ordered[i].Signer, ordered[j].Signer) < 0
	})
	return Final{
		Version:    Version,
		Body:       b,
		Policy:     p,
		Signatures: ordered,
	}, nil
}

// VerifyFinal lets any party independently verify the assembled transaction.
func VerifyFinal(f Final) error {
	if f.Version != Version {
		return ErrUnknownVersion
	}
	if err := checkPolicyBinding(f.Body, f.Policy); err != nil {
		return err
	}
	if len(f.Signatures) < int(f.Policy.Threshold) {
		return ErrThreshold
	}
	for i, ps := range f.Signatures {
		if i > 0 && bytes.Compare(f.Signatures[i-1].Signer, ps.Signer) >= 0 {
			return ErrNonCanonical
		}
		if err := VerifyPartial(f.Body, f.Policy, ps); err != nil {
			return err
		}
	}
	return nil
}
