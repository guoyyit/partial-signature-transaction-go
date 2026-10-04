package txn

// Version is the only supported encoding version.
const Version uint16 = 1

// Body is the canonical transaction document that every party signs.
type Body struct {
	Version    uint16
	TxID       []byte
	Nonce      uint64
	Payload    []byte
	PolicyHash []byte
	ValidUntil int64
}

// Policy declares which public keys may sign and how many signatures are
// required for a valid final transaction.
type Policy struct {
	Version   uint16
	Threshold uint16
	Signers   [][]byte
}

// PartialSignature is one party's signature over the canonical Body.
type PartialSignature struct {
	Version   uint16
	Signer    []byte
	Signature []byte
}

// Revocation authenticates withdrawal of a signer's own partial signature.
type Revocation struct {
	Version   uint16
	Signer    []byte
	Signature []byte
}

// Final is the fully assembled transaction carrying body, policy and the
// collected partial signatures.
type Final struct {
	Version    uint16
	Body       Body
	Policy     Policy
	Signatures []PartialSignature
}
