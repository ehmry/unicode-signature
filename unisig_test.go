package unisig

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"code.google.com/p/go.crypto/sha3"
)

func TestSignVerify(t *testing.T) {
	var (
		valid bool
		err   error

		msg = []byte("What a guy!")

		text1, text2 []byte
	)

	n := 32

	text1 = msg
	for i := 0; i < n; i++ {
		// recursively sign
		buf := bytes.NewBuffer(nil)
		s := NewWriter(buf, sha3.New256(), nil, nil, nil)

		_, err = s.Write(text1)
		if err == nil {
			err = s.Flush()
		}
		if err != nil {
			t.Fatalf("Sign error after recursions %d, %s", i, err)
		}

		text1 = buf.Bytes()

		text2 = text1
		// recursively verify
		for j := i; j >= 0; j-- {
			v := NewVerifier(bytes.NewReader(text2), sha3.New256())
			text2, valid, err = v.Next()

			if err != nil && err != io.EOF {
				t.Fatalf("Verify error: %s\n%s", err, text2)
			}
			if !valid {
				t.Fatalf("Signature not valid after %d recursions", i)
			}
		}
	}
}

func ExampleNewWriter() {
	var buf bytes.Buffer
	s := NewWriter(&buf, sha3.New256(), nil, nil, nil)

	fmt.Fprint(s, "Smoke me a kipper, I'll be back for breakfast!")
	s.Flush()

	fmt.Print(buf.String())
	// Output:
	// ┌
	// │Smoke me a kipper, I'll be back for breakfast!
	// ├
	// │⡒⢇⣇⠃⠟⠲⠍⠓⣹⣓⢏⠙⣽⣥⣜⢴⠉⣆⠠⡬⠅⠡⢹⠥⠧⢦⣾⢞⢦⠅⠡⡪
	// └
}

type dummySig bool

func (d dummySig) Write(p []byte) (int, error) { return len(p), nil }
func (d dummySig) Sum(b []byte) []byte         { return []byte{} }
func (d dummySig) Reset()                      {}

func Benchmark(b *testing.B) {
	junk := make([]byte, 1024)
	for i := 0; i < 1024; i += 32 {
		copy(junk[i:], []byte("abcdefghijklmnopqrstuvwyxz12345\n"))
	}

	var buf bytes.Buffer
	s := NewWriter(&buf, new(dummySig), nil, nil, nil)
	v := NewVerifier(&buf, new(dummySig))

	var n int64
	for i := 0; i < b.N; i++ {
		s.Write(junk)
		s.Flush()

		v.Next()
		n += 2048
	}
	b.SetBytes(n)
}
