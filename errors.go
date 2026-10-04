package pst

import "errors"

var errNotImplemented = errors.New("pst: not implemented")

var (
	ErrUnknownVersion      = errors.New("pst: unknown encoding version")
	ErrNonCanonical        = errors.New("pst: non-canonical encoding")
	ErrInvalidSignature    = errors.New("pst: invalid signature")
	ErrPublicKeyNotAllowed = errors.New("pst: public key not allowed by policy")
	ErrPolicyViolation     = errors.New("pst: invalid signing policy")
	ErrTransactionNotFound = errors.New("pst: transaction not found")
	ErrThresholdNotMet     = errors.New("pst: signature threshold not met")
	ErrFinalized           = errors.New("pst: transaction already finalized")
	ErrExpired             = errors.New("pst: transaction expired")
	ErrNoSignature         = errors.New("pst: no active signature for public key")
)
