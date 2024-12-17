// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package chacha20poly1305 implements the ChaCha20-Poly1305 AEAD and its
// extended nonce variant XChaCha20-Poly1305, as specified in RFC 8439 and
// draft-irtf-cfrg-xchacha-01.
package chacha20poly1305

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/chacha20"
)

const (
	// KeySize is the size of the key used by this AEAD, in bytes.
	KeySize = 32

	// NonceSize is the size of the nonce used with the standard variant of this
	// AEAD, in bytes.
	//
	// Note that this is too short to be safely generated at random if the same
	// key is reused more than 2³² times.
	NonceSize = 12

	// NonceSizeX is the size of the nonce used with the XChaCha20-Poly1305
	// variant of this AEAD, in bytes.
	NonceSizeX = 24

	// Overhead is the size of the Poly1305 authentication tag, and the
	// difference between a ciphertext length and its plaintext.
	Overhead = 16
)

type chacha20poly1305 struct {
	key [KeySize]byte
}

type Chacha20poly1305 = chacha20poly1305

// New returns a ChaCha20-Poly1305 AEAD that uses the given 256-bit key.
func New(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("chacha20poly1305: bad key length")
	}
	ret := new(chacha20poly1305)
	copy(ret.key[:], key)
	return ret, nil
}

func (c *chacha20poly1305) NonceSize() int {
	return NonceSize
}

func (c *chacha20poly1305) Overhead() int {
	return Overhead
}

func (c *chacha20poly1305) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != NonceSize {
		panic("chacha20poly1305: bad nonce length passed to Seal")
	}

	if uint64(len(plaintext)) > (1<<38)-64 {
		panic("chacha20poly1305: plaintext too large")
	}

	return c.seal(dst, nonce, plaintext, additionalData)
}

// EBPF_CRYPTO_TAG
func (c *chacha20poly1305) Start1RTTCryptoBitstreamStorage(nonce []byte, pn uint64) {

	// tmp_file := "/tmp/ebpf_crypto_tag.txt" // TODO: remove this tmp file
	// // Open file using READ & WRITE permission.
	// file, err := os.OpenFile(tmp_file, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	// if err != nil {
	// 	fmt.Println("Error: ", err)
	// 	os.Exit(1)
	// }
	// defer file.Close()

	// fmt.Fprintln(file, "Start1RTTCryptoBitstreamStorage (pn: ", pn, ")")

	// fmt.Fprintln(file, "Key")
	// for i := 0; i < len(c.key); i++ {
	// 	fmt.Fprintf(file, "%02x ", c.key[i])
	// }
	// fmt.Fprintln(file)

	// fmt.Fprintln(file, "Nonce")
	// for i := 0; i < len(nonce); i++ {
	// 	fmt.Fprintf(file, "%02x ", nonce[i])
	// }
	// fmt.Fprintln(file)

	key_copy := make([]byte, len(c.key))
	n := copy(key_copy, c.key[:])
	nonce_copy := make([]byte, len(nonce))
	m := copy(nonce_copy, nonce[:])
	if n != KeySize || m != NonceSize {
		panic("chacha20poly1305: bad key or nonce length passed to Start1RTTCryptoBitstreamStorage")
	}

	cipher, err := chacha20.NewUnauthenticatedCipher(key_copy, nonce_copy)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
	// cipher.SetCounter(1) // set the counter to 1, skipping 32 bytes // TODO: what's the polykey thing in the real code?
	cipher.SetCounter(0)

	cipher.Start1RTTCryptoBitstreamStorage(pn)

}

var errOpen = errors.New("chacha20poly1305: message authentication failed")

func (c *chacha20poly1305) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		panic("chacha20poly1305: bad nonce length passed to Open")
	}
	if len(ciphertext) < 16 {
		return nil, errOpen
	}
	if uint64(len(ciphertext)) > (1<<38)-48 {
		panic("chacha20poly1305: ciphertext too large")
	}

	return c.open(dst, nonce, ciphertext, additionalData)
}

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
