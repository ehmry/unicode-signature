package unisig

import (
	"bufio"
	"bytes"
	"errors"
	"io"

	"github.com/ehmry/encoding/base256"
)

var InvalidSignature = errors.New("invalid signature")

type Verifier struct {
	r   *bufio.Reader
	buf bytes.Buffer
	h   Signer
	w   io.Writer
}


// NewVerifier returns a Verifier that reads signatures from r
// and verifies them with h.
func NewVerifier(r io.Reader, h Signer) *Verifier {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
	}

	v := &Verifier{
		r: br,
		h: h,
	}
	v.w = io.MultiWriter(&v.buf, v.h)
	return v
}

// Next returns the text and validity of successive
// signatures in the undelying reader. Non-signature text is skipped.
func (v *Verifier) Next() (text []byte, valid bool, err error) {
	var (
		ru     rune
		line   []byte
		sigBuf bytes.Buffer
	)

	// Find the start of a signature.
	for err == nil {
		ru, _, err = v.r.ReadRune()

		if err == nil {
			line, err = v.r.ReadSlice('\n')
			if ru == '┌' {
				break
			}
		}
	}
	if err != nil {
		return
	}

	defer v.h.Reset() // Clean the signature at the end.

	// Read the text.
	for err == nil {
		ru, _, err = v.r.ReadRune()

		if err == nil {
			line, err = v.r.ReadSlice('\n')
			if ru != '│' {
				break
			}
			v.w.Write(line)
		}
	}
	text = v.buf.Bytes()
	v.buf.Reset()
	if err != nil {
		return
	}
	if ru != '├' {
		err = InvalidSignature
		return
	}

	// Read the signature.
	for err == nil {
		ru, _, err = v.r.ReadRune()

		if err == nil {
			line, err = v.r.ReadSlice('\n')
			if ru != '│' {
				break
			}

			if len(line) > 0 {
				sigBuf.Write(line[:len(line)-1]) // drop trailing newline
			}
		}
	}

	if err != nil && err != io.EOF {
		return
	}
	if ru != '└' {
		err = InvalidSignature
		return
	}

	// Verify the signature.
	sigDec := make([]byte, base256.Braille.DecodedLen(sigBuf.Len()))
	_, err = base256.Braille.Decode(sigDec, sigBuf.Bytes())
	sigBuf.Reset()

	valid = bytes.Equal(sigDec, v.h.Sum(nil))
	return
}
