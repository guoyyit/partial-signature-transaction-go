package pst

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"io"
)

const encodingVersion = 1

func equalBytes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func strictDecodeJSON(data []byte, v any) error {
	if err := rejectDuplicateKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return ErrNonCanonical
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err == nil {
		return ErrNonCanonical
	}
	want, err := canonicalJSON(v)
	if err != nil {
		return err
	}
	if !bytes.Equal(want, data) {
		return ErrNonCanonical
	}
	return nil
}

func rejectDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	type frame struct {
		isArray bool
		wantKey bool
		keys    map[string]struct{}
	}
	stack := []frame{}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return ErrNonCanonical
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				stack = append(stack, frame{wantKey: true, keys: map[string]struct{}{}})
			case '[':
				stack = append(stack, frame{isArray: true})
			case '}', ']':
				if len(stack) == 0 {
					return ErrNonCanonical
				}
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && !stack[len(stack)-1].isArray {
					stack[len(stack)-1].wantKey = true
				}
			}
		case string:
			top := len(stack) - 1
			if top >= 0 && !stack[top].isArray && stack[top].wantKey {
				if _, dup := stack[top].keys[t]; dup {
					return ErrNonCanonical
				}
				stack[top].keys[t] = struct{}{}
				stack[top].wantKey = false
			} else if top >= 0 && !stack[top].isArray {
				stack[top].wantKey = true
			}
		default:
			top := len(stack) - 1
			if top >= 0 && !stack[top].isArray {
				stack[top].wantKey = true
			}
		}
	}
	if len(stack) != 0 {
		return ErrNonCanonical
	}
	return nil
}
