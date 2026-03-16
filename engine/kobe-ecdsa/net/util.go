package kobenet

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"io"
)

// randReader adapts crypto/rand to io.Reader for nonce generation.
type randReader struct{}

func (randReader) Read(p []byte) (int, error) { return rand.Read(p) }

// writeJSON length-prefixes and writes v as JSON (used by the handshake).
func writeJSON(w io.Writer, v any) error {
	bz, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(bz)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(bz)
	return err
}

// readJSON reads a length-prefixed JSON document into v.
func readJSON(r io.Reader, v any) error {
	bz, err := readFrameBytes(r)
	if err != nil {
		return err
	}
	return json.Unmarshal(bz, v)
}
