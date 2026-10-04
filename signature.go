package pst

import "crypto/ed25519"

const (
	partialSigDomain = "PST/PARTIAL/v1/"
	revocationDomain = "PST/REVOKE/v1/"
)

type PartialSignature struct {
	Version   int    `json:"v"`
	TxID      []byte `json:"tx_id"`
	PublicKey []byte `json:"pubkey"`
	Signature []byte `json:"sig"`
}

func SignTransaction(priv ed25519.PrivateKey, tx *Transaction) (*PartialSignature, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, ErrInvalidSignature
	}
	txID, err := TransactionID(tx)
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	msg := append([]byte(partialSigDomain), txID...)
	sig := ed25519.Sign(priv, msg)
	return &PartialSignature{
		Version:   encodingVersion,
		TxID:      txID,
		PublicKey: append([]byte(nil), pub...),
		Signature: sig,
	}, nil
}

// Verify checks that the signature was produced by its embedded public key over
// the canonical encoding of exactly the given transaction.
func (s *PartialSignature) Verify(tx *Transaction) error {
	if s == nil {
		return ErrInvalidSignature
	}
	if s.Version != encodingVersion {
		return ErrUnknownVersion
	}
	if len(s.PublicKey) != ed25519.PublicKeySize || len(s.Signature) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	txID, err := TransactionID(tx)
	if err != nil {
		return err
	}
	if !equalBytes(s.TxID, txID) {
		return ErrInvalidSignature
	}
	msg := append([]byte(partialSigDomain), txID...)
	if !ed25519.Verify(ed25519.PublicKey(s.PublicKey), msg, s.Signature) {
		return ErrInvalidSignature
	}
	return nil
}

func (s *PartialSignature) Encode() ([]byte, error) {
	if s == nil || s.Version != encodingVersion {
		return nil, ErrUnknownVersion
	}
	return canonicalJSON(s)
}

func DecodePartialSignature(data []byte) (*PartialSignature, error) {
	var s PartialSignature
	if err := strictDecodeJSON(data, &s); err != nil {
		return nil, err
	}
	if s.Version != encodingVersion {
		return nil, ErrUnknownVersion
	}
	if len(s.PublicKey) != ed25519.PublicKeySize || len(s.Signature) != ed25519.SignatureSize {
		return nil, ErrInvalidSignature
	}
	return &s, nil
}

type Revocation struct {
	Version   int    `json:"v"`
	TxID      []byte `json:"tx_id"`
	PublicKey []byte `json:"pubkey"`
	Signature []byte `json:"sig"`
}

func SignRevocation(priv ed25519.PrivateKey, txID []byte) (*Revocation, error) {
	if len(priv) != ed25519.PrivateKeySize || len(txID) == 0 {
		return nil, ErrInvalidSignature
	}
	pub := priv.Public().(ed25519.PublicKey)
	msg := append([]byte(revocationDomain), txID...)
	sig := ed25519.Sign(priv, msg)
	return &Revocation{
		Version:   encodingVersion,
		TxID:      append([]byte(nil), txID...),
		PublicKey: append([]byte(nil), pub...),
		Signature: sig,
	}, nil
}

func (r *Revocation) Verify(txID []byte) error {
	if r == nil || r.Version != encodingVersion {
		if r == nil {
			return ErrInvalidSignature
		}
		return ErrUnknownVersion
	}
	if len(r.PublicKey) != ed25519.PublicKeySize || len(r.Signature) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	if !equalBytes(r.TxID, txID) {
		return ErrInvalidSignature
	}
	msg := append([]byte(revocationDomain), txID...)
	if !ed25519.Verify(ed25519.PublicKey(r.PublicKey), msg, r.Signature) {
		return ErrInvalidSignature
	}
	return nil
}

func (r *Revocation) Encode() ([]byte, error) {
	if r == nil || r.Version != encodingVersion {
		return nil, ErrUnknownVersion
	}
	return canonicalJSON(r)
}

func DecodeRevocation(data []byte) (*Revocation, error) {
	var r Revocation
	if err := strictDecodeJSON(data, &r); err != nil {
		return nil, err
	}
	if r.Version != encodingVersion {
		return nil, ErrUnknownVersion
	}
	if len(r.PublicKey) != ed25519.PublicKeySize || len(r.Signature) != ed25519.SignatureSize {
		return nil, ErrInvalidSignature
	}
	return &r, nil
}
