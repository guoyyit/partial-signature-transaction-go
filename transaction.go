package pst

import "crypto/sha256"

type Transaction struct {
	Version   uint64 `json:"version"`
	ChainID   string `json:"chain_id"`
	Nonce     uint64 `json:"nonce"`
	Sender    []byte `json:"sender"`
	Recipient []byte `json:"recipient"`
	Amount    uint64 `json:"amount"`
	Reference string `json:"reference"`
}

func CanonicalTransaction(tx *Transaction) ([]byte, error) {
	if tx == nil {
		return nil, ErrNonCanonical
	}
	if tx.Version != uint64(encodingVersion) {
		return nil, ErrUnknownVersion
	}
	if len(tx.Sender) == 0 || len(tx.Recipient) == 0 {
		return nil, ErrNonCanonical
	}
	return canonicalJSON(tx)
}

func DecodeTransaction(data []byte) (*Transaction, error) {
	var tx Transaction
	if err := strictDecodeJSON(data, &tx); err != nil {
		return nil, err
	}
	return &tx, nil
}

func TransactionID(tx *Transaction) ([]byte, error) {
	raw, err := CanonicalTransaction(tx)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	return sum[:], nil
}
