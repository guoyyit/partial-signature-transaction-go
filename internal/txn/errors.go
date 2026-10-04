package txn

import "errors"

var (
	ErrUnknownVersion   = errors.New("txn: unknown encoding version")
	ErrNonCanonical     = errors.New("txn: non-canonical encoding")
	ErrMalformed        = errors.New("txn: malformed encoding")
	ErrInvalidField     = errors.New("txn: invalid field")
	ErrSignatureInvalid = errors.New("txn: signature does not cover transaction")
	ErrSignerNotAllowed = errors.New("txn: signer not listed by policy")
	ErrPolicyMismatch   = errors.New("txn: policy commitment does not match body")
	ErrThreshold        = errors.New("txn: signature threshold not satisfied")
)
