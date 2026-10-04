package txn

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"sort"
)

// maxBlob bounds allocations when reading length-prefixed fields.
const maxBlob = 16 << 20

const (
	ed25519PubLen = 32
	ed25519SigLen = 64
	policyHashLen = sha256.Size
)

// Frame tags.
const (
	tagBodyTxID       byte = 1
	tagBodyNonce      byte = 2
	tagBodyPayload    byte = 3
	tagBodyPolicyHash byte = 4
	tagBodyValidUntil byte = 5

	tagPolicyThreshold byte = 1
	tagPolicySigners   byte = 2

	tagSigSigner byte = 1
	tagSigValue  byte = 2

	tagFinalBody byte = 1
	tagFinalPol  byte = 2
	tagFinalSigs byte = 3
)

func appendU16(buf []byte, v uint16) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return append(buf, b[:]...)
}

func appendU64(buf []byte, v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return append(buf, b[:]...)
}

func appendLenBytes(buf, v []byte) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(len(v)))
	buf = append(buf, b[:]...)
	return append(buf, v...)
}

func appendFrame(buf []byte, tag byte, payload []byte) []byte {
	buf = append(buf, tag)
	return appendLenBytes(buf, payload)
}

func u16Payload(v uint16) []byte {
	return appendU16(make([]byte, 0, 2), v)
}

func u64Payload(v uint64) []byte {
	return appendU64(make([]byte, 0, 8), v)
}

type cursor struct {
	buf []byte
	pos int
}

func (c *cursor) take(n int) ([]byte, error) {
	if n < 0 || c.pos+n > len(c.buf) {
		return nil, ErrMalformed
	}
	v := c.buf[c.pos : c.pos+n]
	c.pos += n
	return v, nil
}

func (c *cursor) u16() (uint16, error) {
	v, err := c.take(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(v), nil
}

func (c *cursor) u32() (uint32, error) {
	v, err := c.take(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(v), nil
}

func (c *cursor) u64() (uint64, error) {
	v, err := c.take(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(v), nil
}

func (c *cursor) lenBytes() ([]byte, error) {
	n, err := c.u32()
	if err != nil {
		return nil, err
	}
	if int(n) > maxBlob {
		return nil, ErrMalformed
	}
	return c.take(int(n))
}

// readFrames parses tag+payload frames, requiring strictly ascending unique
// tags and consuming the whole input exactly.
func readFrames(raw []byte) (map[byte][]byte, error) {
	c := &cursor{buf: raw}
	frames := make(map[byte][]byte)
	var lastTag byte
	haveTag := false
	for c.pos < len(raw) {
		tagBytes, err := c.take(1)
		if err != nil {
			return nil, err
		}
		tag := tagBytes[0]
		if haveTag && tag <= lastTag {
			return nil, ErrNonCanonical
		}
		payload, err := c.lenBytes()
		if err != nil {
			return nil, err
		}
		frames[tag] = payload
		lastTag = tag
		haveTag = true
	}
	return frames, nil
}

func requireFrames(frames map[byte][]byte, tags ...byte) error {
	for _, t := range tags {
		if _, ok := frames[t]; !ok {
			return ErrMalformed
		}
	}
	for t := range frames {
		known := false
		for _, k := range tags {
			if t == k {
				known = true
				break
			}
		}
		if !known {
			return ErrNonCanonical
		}
	}
	return nil
}

func checkVersion(v uint16) error {
	if v != Version {
		return ErrUnknownVersion
	}
	return nil
}

func exactU16(p []byte) (uint16, error) {
	c := &cursor{buf: p}
	v, err := c.u16()
	if err != nil || c.pos != len(p) {
		return 0, ErrNonCanonical
	}
	return v, nil
}

func exactU64(p []byte) (uint64, error) {
	c := &cursor{buf: p}
	v, err := c.u64()
	if err != nil || c.pos != len(p) {
		return 0, ErrNonCanonical
	}
	return v, nil
}

// ---------- Body ----------

func EncodeBody(b Body) ([]byte, error) {
	if err := checkVersion(b.Version); err != nil {
		return nil, err
	}
	if len(b.TxID) == 0 || len(b.PolicyHash) != policyHashLen {
		return nil, ErrInvalidField
	}
	buf := make([]byte, 0, 64+len(b.TxID)+len(b.Payload))
	buf = appendU16(buf, Version)
	buf = appendFrame(buf, tagBodyTxID, b.TxID)
	buf = appendFrame(buf, tagBodyNonce, u64Payload(b.Nonce))
	buf = appendFrame(buf, tagBodyPayload, b.Payload)
	buf = appendFrame(buf, tagBodyPolicyHash, b.PolicyHash)
	buf = appendFrame(buf, tagBodyValidUntil, u64Payload(uint64(b.ValidUntil)))
	return buf, nil
}

func DecodeBody(raw []byte) (Body, error) {
	c := &cursor{buf: raw}
	v, err := c.u16()
	if err != nil {
		return Body{}, ErrMalformed
	}
	if err := checkVersion(v); err != nil {
		return Body{}, err
	}
	frames, err := readFrames(raw[c.pos:])
	if err != nil {
		return Body{}, err
	}
	if err := requireFrames(frames, tagBodyTxID, tagBodyNonce, tagBodyPayload, tagBodyPolicyHash, tagBodyValidUntil); err != nil {
		return Body{}, err
	}
	txID := frames[tagBodyTxID]
	if len(txID) == 0 {
		return Body{}, ErrNonCanonical
	}
	policyHash := frames[tagBodyPolicyHash]
	if len(policyHash) != policyHashLen {
		return Body{}, ErrNonCanonical
	}
	nonce, err := exactU64(frames[tagBodyNonce])
	if err != nil {
		return Body{}, err
	}
	validUntil, err := exactU64(frames[tagBodyValidUntil])
	if err != nil {
		return Body{}, err
	}
	return Body{
		Version:    Version,
		TxID:       append([]byte(nil), txID...),
		Nonce:      nonce,
		Payload:    append([]byte(nil), frames[tagBodyPayload]...),
		PolicyHash: append([]byte(nil), policyHash...),
		ValidUntil: int64(validUntil),
	}, nil
}

// ---------- Policy ----------

// NewPolicy builds a Policy with signers in canonical (sorted, unique) order.
func NewPolicy(threshold uint16, signers [][]byte) (Policy, error) {
	canonical := make([][]byte, len(signers))
	for i, s := range signers {
		if len(s) != ed25519PubLen {
			return Policy{}, ErrInvalidField
		}
		canonical[i] = append([]byte(nil), s...)
	}
	sort.Slice(canonical, func(i, j int) bool {
		return bytes.Compare(canonical[i], canonical[j]) < 0
	})
	for i := 1; i < len(canonical); i++ {
		if bytes.Equal(canonical[i-1], canonical[i]) {
			return Policy{}, ErrInvalidField
		}
	}
	if threshold == 0 || int(threshold) > len(canonical) {
		return Policy{}, ErrInvalidField
	}
	return Policy{Version: Version, Threshold: threshold, Signers: canonical}, nil
}

func PolicyCommitment(p Policy) ([]byte, error) {
	raw, err := EncodePolicy(p)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	return sum[:], nil
}

func encodeSignerList(signers [][]byte) ([]byte, error) {
	payload := make([]byte, 0)
	for _, s := range signers {
		if len(s) != ed25519PubLen {
			return nil, ErrInvalidField
		}
		payload = appendLenBytes(payload, s)
	}
	return payload, nil
}

func decodeSignerList(raw []byte) ([][]byte, error) {
	c := &cursor{buf: raw}
	var out [][]byte
	for c.pos < len(raw) {
		s, err := c.lenBytes()
		if err != nil {
			return nil, ErrMalformed
		}
		if len(s) != ed25519PubLen {
			return nil, ErrNonCanonical
		}
		out = append(out, append([]byte(nil), s...))
	}
	if len(out) == 0 {
		return nil, ErrNonCanonical
	}
	for i := 1; i < len(out); i++ {
		if bytes.Compare(out[i-1], out[i]) >= 0 {
			return nil, ErrNonCanonical
		}
	}
	return out, nil
}

func EncodePolicy(p Policy) ([]byte, error) {
	if err := checkVersion(p.Version); err != nil {
		return nil, err
	}
	if p.Threshold == 0 || int(p.Threshold) > len(p.Signers) || len(p.Signers) == 0 {
		return nil, ErrInvalidField
	}
	for i := 1; i < len(p.Signers); i++ {
		if bytes.Compare(p.Signers[i-1], p.Signers[i]) >= 0 {
			return nil, ErrNonCanonical
		}
	}
	signers, err := encodeSignerList(p.Signers)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, 16+len(signers))
	buf = appendU16(buf, Version)
	buf = appendFrame(buf, tagPolicyThreshold, u16Payload(p.Threshold))
	buf = appendFrame(buf, tagPolicySigners, signers)
	return buf, nil
}

func DecodePolicy(raw []byte) (Policy, error) {
	c := &cursor{buf: raw}
	v, err := c.u16()
	if err != nil {
		return Policy{}, ErrMalformed
	}
	if err := checkVersion(v); err != nil {
		return Policy{}, err
	}
	frames, err := readFrames(raw[c.pos:])
	if err != nil {
		return Policy{}, err
	}
	if err := requireFrames(frames, tagPolicyThreshold, tagPolicySigners); err != nil {
		return Policy{}, err
	}
	threshold, err := exactU16(frames[tagPolicyThreshold])
	if err != nil {
		return Policy{}, err
	}
	signers, err := decodeSignerList(frames[tagPolicySigners])
	if err != nil {
		return Policy{}, err
	}
	if threshold == 0 || int(threshold) > len(signers) {
		return Policy{}, ErrNonCanonical
	}
	return Policy{Version: Version, Threshold: threshold, Signers: signers}, nil
}

func encodeEnvelope(signer, sig []byte) ([]byte, error) {
	if len(signer) != ed25519PubLen || len(sig) != ed25519SigLen {
		return nil, ErrInvalidField
	}
	buf := make([]byte, 0, 16+len(signer)+len(sig))
	buf = appendU16(buf, Version)
	buf = appendFrame(buf, tagSigSigner, signer)
	buf = appendFrame(buf, tagSigValue, sig)
	return buf, nil
}

func decodeEnvelope(raw []byte) (signer, sig []byte, err error) {
	c := &cursor{buf: raw}
	v, err := c.u16()
	if err != nil {
		return nil, nil, ErrMalformed
	}
	if err := checkVersion(v); err != nil {
		return nil, nil, err
	}
	frames, err := readFrames(raw[c.pos:])
	if err != nil {
		return nil, nil, err
	}
	if err := requireFrames(frames, tagSigSigner, tagSigValue); err != nil {
		return nil, nil, err
	}
	signer = frames[tagSigSigner]
	sig = frames[tagSigValue]
	if len(signer) != ed25519PubLen || len(sig) != ed25519SigLen {
		return nil, nil, ErrNonCanonical
	}
	return append([]byte(nil), signer...), append([]byte(nil), sig...), nil
}

func EncodePartial(ps PartialSignature) ([]byte, error) {
	return encodeEnvelope(ps.Signer, ps.Signature)
}

func DecodePartial(raw []byte) (PartialSignature, error) {
	signer, sig, err := decodeEnvelope(raw)
	if err != nil {
		return PartialSignature{}, err
	}
	return PartialSignature{Version: Version, Signer: signer, Signature: sig}, nil
}

func EncodeRevocation(r Revocation) ([]byte, error) {
	return encodeEnvelope(r.Signer, r.Signature)
}

func DecodeRevocation(raw []byte) (Revocation, error) {
	signer, sig, err := decodeEnvelope(raw)
	if err != nil {
		return Revocation{}, err
	}
	return Revocation{Version: Version, Signer: signer, Signature: sig}, nil
}

// ---------- Final ----------

func EncodeFinal(f Final) ([]byte, error) {
	if err := checkVersion(f.Version); err != nil {
		return nil, err
	}
	bodyRaw, err := EncodeBody(f.Body)
	if err != nil {
		return nil, err
	}
	policyRaw, err := EncodePolicy(f.Policy)
	if err != nil {
		return nil, err
	}
	if len(f.Signatures) == 0 {
		return nil, ErrInvalidField
	}
	sigsPayload := make([]byte, 0)
	for i, ps := range f.Signatures {
		if i > 0 && bytes.Compare(f.Signatures[i-1].Signer, ps.Signer) >= 0 {
			return nil, ErrNonCanonical
		}
		psRaw, err := EncodePartial(ps)
		if err != nil {
			return nil, err
		}
		sigsPayload = appendLenBytes(sigsPayload, psRaw)
	}
	buf := make([]byte, 0, 16+len(bodyRaw)+len(policyRaw)+len(sigsPayload))
	buf = appendU16(buf, Version)
	buf = appendFrame(buf, tagFinalBody, bodyRaw)
	buf = appendFrame(buf, tagFinalPol, policyRaw)
	buf = appendFrame(buf, tagFinalSigs, sigsPayload)
	return buf, nil
}

func DecodeFinal(raw []byte) (Final, error) {
	c := &cursor{buf: raw}
	v, err := c.u16()
	if err != nil {
		return Final{}, ErrMalformed
	}
	if err := checkVersion(v); err != nil {
		return Final{}, err
	}
	frames, err := readFrames(raw[c.pos:])
	if err != nil {
		return Final{}, err
	}
	if err := requireFrames(frames, tagFinalBody, tagFinalPol, tagFinalSigs); err != nil {
		return Final{}, err
	}
	body, err := DecodeBody(frames[tagFinalBody])
	if err != nil {
		return Final{}, err
	}
	policy, err := DecodePolicy(frames[tagFinalPol])
	if err != nil {
		return Final{}, err
	}
	sc := &cursor{buf: frames[tagFinalSigs]}
	var sigs []PartialSignature
	var lastSigner []byte
	have := false
	for sc.pos < len(frames[tagFinalSigs]) {
		psRaw, err := sc.lenBytes()
		if err != nil {
			return Final{}, ErrMalformed
		}
		ps, err := DecodePartial(psRaw)
		if err != nil {
			return Final{}, err
		}
		if have && bytes.Compare(lastSigner, ps.Signer) >= 0 {
			return Final{}, ErrNonCanonical
		}
		sigs = append(sigs, ps)
		lastSigner = ps.Signer
		have = true
	}
	if len(sigs) == 0 {
		return Final{}, ErrNonCanonical
	}
	return Final{Version: Version, Body: body, Policy: policy, Signatures: sigs}, nil
}
