package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"

	"code.google.com/p/go.crypto/sha3"
	"github.com/ehmry/encoding/base256"
)

var err error

func checkError() {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func main() {
	var (
		r      rune
		line   []byte
		sigBuf bytes.Buffer
	)

	h := sha3.New256()
	mw := io.MultiWriter(os.Stdout, h)
	br := bufio.NewReader(os.Stdin)

	// Find the start of the text.
	for err == nil {
		r, _, err = br.ReadRune()
		checkError()

		line, err = br.ReadBytes('\n')
		if r == '┌' {
			break
		}
	}
	checkError()

	// Read the text.
	for err == nil {
		r, _, err = br.ReadRune()
		checkError()

		line, err = br.ReadBytes('\n')
		if r != '│' {
			break
		}
		checkError()
		_, err = mw.Write(line)
	}
	checkError()

	if r != '├' {
		fmt.Fprintf(os.Stderr, "Invalid %r prefix at %q.\n", r, line)
	}

	// Read the signature.
	for err == nil {
		r, _, err = br.ReadRune()
		checkError()

		line, err = br.ReadBytes('\n')
		if r != '│' {
			break
		}
		if len(line) > 1 {
			sigBuf.Write(line[:len(line)-1])
		}
	}
	if err != io.EOF {
		checkError()
	}

	if r != '└' {
		fmt.Fprintf(os.Stderr, "Invalid signature at %q.\n", line)
	}

	// Verify the signature.
	ours := h.Sum(nil)
	theirs := make([]byte, base256.Braille.DecodedLen(sigBuf.Len()))
	_, err = base256.Braille.Decode(theirs, sigBuf.Bytes())
	checkError()

	if bytes.Equal(ours, theirs) {
		os.Exit(0)
	}

	fmt.Fprintf(os.Stderr, "%x != %x\n", ours, theirs)
	os.Exit(1)
}
