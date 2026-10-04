package pst

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

type txMeta struct {
	Version  int          `json:"v"`
	Tx       *Transaction `json:"tx"`
	Policy   *Policy      `json:"policy"`
	Deadline time.Time    `json:"deadline"`
}

type storeEntry struct {
	id     string
	meta   *txMeta
	events []*Event
	final  *FinalTransaction
}

type Store struct {
	root string
}

func OpenStore(root string) (*Store, error) {
	if root == "" {
		return nil, errors.New("pst: store root must not be empty")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	return &Store{root: root}, nil
}

func (s *Store) loadAll() (map[string]*storeEntry, error) {
	out := map[string]*storeEntry{}
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, err
	}
	for _, d := range entries {
		if !d.IsDir() {
			continue
		}
		entry, err := s.loadOne(d.Name())
		if err != nil {
			return nil, err
		}
		out[entry.id] = entry
	}
	return out, nil
}

func (s *Store) writeMeta(id string, meta *txMeta) error {
	dir := s.dir(id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := canonicalJSON(meta)
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(dir, "meta.json"), data)
}

func (s *Store) appendEvent(id string, ev *Event) error {
	data, err := ev.encode()
	if err != nil {
		return err
	}
	data = append(data, '\n')
	path := filepath.Join(s.dir(id), "events.log")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (s *Store) writeFinal(id string, f *FinalTransaction) error {
	data, err := f.Encode()
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(s.dir(id), "final.json"), data)
}

func (s *Store) dir(id string) string {
	return filepath.Join(s.root, id)
}

func (s *Store) loadOne(dirName string) (*storeEntry, error) {
	dir := filepath.Join(s.root, dirName)
	txID, err := hex.DecodeString(dirName)
	if err != nil {
		return nil, err
	}
	entry := &storeEntry{id: hex.EncodeToString(txID)}

	metaBytes, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return nil, err
	}
	var meta txMeta
	if err := strictDecodeJSON(metaBytes, &meta); err != nil {
		return nil, err
	}
	entry.meta = &meta

	logBytes, err := os.ReadFile(filepath.Join(dir, "events.log"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	logPath := filepath.Join(dir, "events.log")
	lines, lineStart, err := scanLogLines(logBytes)
	if err != nil {
		return nil, err
	}
	for i, line := range lines {
		ev, err := decodeEvent(line)
		if err != nil {
			if i != len(lines)-1 {
				return nil, err
			}
			if terr := os.Truncate(logPath, int64(lineStart[i])); terr != nil {
				return nil, terr
			}
			break
		}
		entry.events = append(entry.events, ev)
	}

	finalBytes, err := os.ReadFile(filepath.Join(dir, "final.json"))
	if err == nil {
		f, err := DecodeFinal(finalBytes)
		if err != nil {
			return nil, err
		}
		entry.final = f
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return entry, nil
}

func scanLogLines(data []byte) (lines [][]byte, lineStart []int, err error) {
	offset := 0
	for offset < len(data) {
		nl := bytes.IndexByte(data[offset:], '\n')
		if nl < 0 {
			nl = len(data) - offset
		}
		line := data[offset : offset+nl]
		if len(bytes.TrimSpace(line)) > 0 {
			lines = append(lines, bytes.Clone(line))
			lineStart = append(lineStart, offset)
		}
		offset += nl
		if offset < len(data) && data[offset] == '\n' {
			offset++
		}
	}
	return lines, lineStart, nil
}

func atomicWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}
