package unisig

import (
	"bufio"
	"bytes"
	"io"

	"github.com/ehmry/encoding/base256"
)

var (
	Header = []byte("┌\n")
	Delim  = []byte("├\n")
	Footer = []byte("└\n")
)

type Signer interface {
	// Write (via the embedded io.Writer interface) adds more data to the running signature.
	// It never returns an error.
	io.Writer

	// Sum appends the current signature to b and returns the resulting slice.
	// It does not change the underlying signature state.
	Sum(b []byte) []byte

	// Reset resets the signature to its initial state.
	Reset()
}

type preferredWriter interface {
	io.Writer
	WriteByte(c byte) error
	WriteRune(r rune) (size int, err error)
	Flush() error
}

type Writer struct {
	Header, Delim, Footer []byte

	w  preferredWriter
	mw io.Writer
	h  Signer

	fresh  bool
	buf    bytes.Buffer
}

// NewWriter returns a Writer that writes signatures generated from h to w.
// header, delim, and footer default to Header, Delim, and Footer when nil.
func NewWriter(w io.Writer, h Signer, header, delim, footer []byte) *Writer {
	if header == nil {
		header = Header
	}
	if delim == nil {
		delim = Delim
	}
	if footer == nil {
		footer = Footer
	}

	pw, ok := w.(preferredWriter)
	if !ok {
		pw = bufio.NewWriter(w)
	}

	return &Writer{
		Header: header,
		Delim:  delim,
		Footer: footer,

		w:  pw,
		mw: io.MultiWriter(pw, h),
		h:  h,

		fresh:  true,
	}
}

func (s *Writer) Write(p []byte) (n int, err error) {
	var i, N int

	if s.fresh {
		// Write the start rune.
		N, err = s.w.Write(s.Header)
		if N != 0 {
			s.fresh = false
		}
	}

	for err == nil {
		i = bytes.IndexByte(p, '\n')
		if i == -1 {
			N, _ = s.buf.Write(p)
			n += N
			return
		}

		if len(p) == 0 {
			break
		}

		_, err = s.w.WriteRune('│')
		if err == nil {
			N, err = s.mw.Write(p[:i+1])
			p = p[N:]
			n += N
		}
	}
	return
}

func (s *Writer) Flush() (err error) {
	var b []byte

	if s.buf.Len() > 0 {
		_, err = s.w.WriteRune('│')
		if err == nil {
			b = s.buf.Bytes()
			_, err = s.mw.Write(b)
			if err == nil && b[len(b)-1] != '\n' {
				// Need a trailing newline.
				_, err = s.mw.Write([]byte{'\n'})
			}
		}
	}

	if err == nil {
		_, err = s.w.Write(s.Delim)

		if err == nil {
			_, err = s.w.WriteRune('│')

			if err == nil {
				b = s.h.Sum(b[:0])
				enc := make([]byte, base256.Braille.EncodedLen(len(b)))
				base256.Braille.Encode(enc, b)
				_, err = s.w.Write(enc)

				if err == nil {
					err = s.w.WriteByte('\n')

					if err == nil {
						_, err = s.w.Write(s.Footer)

						if err == nil {
							s.h.Reset()
							s.buf.Reset()
							err = s.w.Flush()
							s.fresh = true;
						}
					}
				}
			}
		}
	}
	return
}
