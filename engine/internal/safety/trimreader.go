package safety

import (
	"bytes"
	"io"
)

// newTrimReader strips a UTF-8 BOM so hand-edited config files do not fail to
// parse for an invisible reason.
func newTrimReader(b []byte) io.Reader {
	return bytes.NewReader(bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF}))
}
