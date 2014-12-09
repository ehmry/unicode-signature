package main

import (
	"bufio"
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
	h := sha3.New256()
	mw := io.MultiWriter(os.Stdout, h)
	br := bufio.NewReader(os.Stdin)

	// Write the start rune.
	_, err = os.Stdout.Write([]byte("┌\n"))

	// Write the message.
	var line []byte
	for err == nil {
		line, err = br.ReadBytes('\n')
		if err == nil {
			_, err = os.Stdout.Write([]byte("│"))
		}
		if err == nil {
			_, err = mw.Write(line)
		}
	}

	if err != io.EOF {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Write the deliminator.
	_, err = os.Stdout.Write([]byte("├\n"))
	checkError()

	digest := h.Sum(nil)

	// Write the signature.
	buf := make([]byte, base256.Braille.EncodedLen(len(digest)))
	base256.Braille.Encode(buf, digest)
	_, err = os.Stdout.Write([]byte("│"))
	checkError()

	_, err = os.Stdout.Write(buf)
	checkError()

	// Write the end rune.
	_, err = os.Stdout.Write([]byte("\n└\n"))
	checkError()
}
