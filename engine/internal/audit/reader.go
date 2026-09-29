package audit

import (
	"bytes"
	"io"
)

// newLineReader lets the JSON decoder walk a JSONL file.
func newLineReader(b []byte) io.Reader { return bytes.NewReader(b) }
