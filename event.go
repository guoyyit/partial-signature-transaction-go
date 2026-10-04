package pst

import (
	"encoding/json"
	"time"
)

const (
	EventSubmitted = "submitted"
	EventRevoked   = "revoked"
	EventFinalized = "finalized"
	EventRejected  = "rejected"
)

type Event struct {
	Seq       int64           `json:"seq"`
	Kind      string          `json:"kind"`
	Time      time.Time       `json:"time"`
	PublicKey []byte          `json:"pubkey,omitempty"`
	Reason    string          `json:"reason,omitempty"`
	Partial   json.RawMessage `json:"partial,omitempty"`
	Revoke    json.RawMessage `json:"revoke,omitempty"`
	Final     json.RawMessage `json:"final,omitempty"`
}

func (e *Event) encode() ([]byte, error) {
	if e == nil || e.Seq < 0 {
		return nil, ErrNonCanonical
	}
	switch e.Kind {
	case EventSubmitted, EventRevoked, EventFinalized, EventRejected:
	default:
		return nil, ErrNonCanonical
	}
	return canonicalJSON(e)
}

func decodeEvent(data []byte) (*Event, error) {
	var e Event
	if err := strictDecodeJSON(data, &e); err != nil {
		return nil, err
	}
	switch e.Kind {
	case EventSubmitted, EventRevoked, EventFinalized, EventRejected:
	default:
		return nil, ErrNonCanonical
	}
	return &e, nil
}
