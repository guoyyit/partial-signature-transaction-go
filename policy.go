package pst

import "crypto/ed25519"

type Policy struct {
	Version     int      `json:"v"`
	AllowedKeys [][]byte `json:"allowed_keys"`
	Threshold   int      `json:"threshold"`
}

func (p *Policy) Validate() error {
	if p == nil {
		return ErrPolicyViolation
	}
	if p.Version != encodingVersion {
		return ErrUnknownVersion
	}
	if len(p.AllowedKeys) == 0 {
		return ErrPolicyViolation
	}
	if p.Threshold < 1 || p.Threshold > len(p.AllowedKeys) {
		return ErrPolicyViolation
	}
	seen := map[string]struct{}{}
	for _, k := range p.AllowedKeys {
		if len(k) != ed25519.PublicKeySize {
			return ErrPolicyViolation
		}
		if _, dup := seen[string(k)]; dup {
			return ErrPolicyViolation
		}
		seen[string(k)] = struct{}{}
	}
	return nil
}

func (p *Policy) Allows(pub []byte) bool {
	if p == nil {
		return false
	}
	for _, k := range p.AllowedKeys {
		if equalBytes(k, pub) {
			return true
		}
	}
	return false
}
