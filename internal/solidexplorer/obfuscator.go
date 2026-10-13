// Package solidexplorer reimplements the AES obfuscation Solid Explorer
// (`pl.solidexplorer2`) uses to protect its license preferences, so those values
// can be read and written outside the app.
//
// Reversed from `pl.solidexplorer.preferences.AESObfuscator` and
// `PreferenceObfuscator` in Solid Explorer (see NOTES.md). Every parameter is a
// constant read out of the class, not a guess:
//
//	IV      16 bytes, compiled in
//	salt    20 bytes, compiled in
//	KDF     PBEWITHSHAAND256BITAES-CBC-BC, 1024 iterations, 256-bit key
//	key     password = packageName + androidId
//	cipher  AES/CBC/PKCS5Padding
//	header  "com.android.vending.licensing.AESObfuscator-1|" + keyName
//
// The scheme is the one Google shipped in the Android License Verification
// Library. It is obfuscation, not encryption in a meaningful sense: the key is
// derived from values any process on the device can read, and the salt and IV
// are constants inside the APK. Reproducing it here is what makes the stored
// license values readable — which is the point, and also the reason the scheme
// should not be mistaken for a secret.
package solidexplorer

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// pbkdf2SHA1 is PBKDF2 with HMAC-SHA1, implemented here so the package has no
// dependencies. The client gets this from the JCE provider named
// PBEWITHSHAAND256BITAES-CBC-BC; the "BC" is BouncyCastle (the provider), not a
// different digest -- the PRF is HMAC-SHA1, which is what this computes.
//
// Verified against the RFC 6070 test vectors in the test file.
func pbkdf2SHA1(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha1.New, password)
	hashLen := prf.Size()

	numBlocks := (keyLen + hashLen - 1) / hashLen
	derived := make([]byte, 0, numBlocks*hashLen)

	buf := make([]byte, 4)
	for block := 1; block <= numBlocks; block++ {
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)

		prf.Reset()
		prf.Write(salt)
		prf.Write(buf)
		u := prf.Sum(nil)

		t := make([]byte, len(u))
		copy(t, u)

		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for i := range t {
				t[i] ^= u[i]
			}
		}
		derived = append(derived, t...)
	}
	return derived[:keyLen]
}

// Salt is the 20-byte salt compiled into SELicenseManager
// (`private static final byte[] SALT = {-46, 65, 30, ...}`).
var Salt = []byte{
	0xd2, 0x41, 0x1e, 0x80, 0x99, 0xc7, 0x4a, 0xc0, 0x33, 0x58,
	0xa1, 0xd3, 0x4d, 0x8b, 0xdc, 0x8f, 0xf5, 0x20, 0xc0, 0x59,
}

// IV is the 16-byte initialisation vector compiled into AESObfuscator
// (`private static final byte[] IV = {16, 74, 71, -80, ...}`).
var IV = []byte{
	0x10, 0x4a, 0x47, 0xb0, 0x20, 0x65, 0xd1, 0x48,
	0x75, 0xf2, 0x00, 0xe3, 0x46, 0x41, 0xf4, 0x4a,
}

// HeaderPrefix is the marker every obfuscated value must start with, from the
// LVL scheme, followed by the preference key.
const HeaderPrefix = "com.android.vending.licensing.AESObfuscator-1|"

// PBKDF2Iterations and KeyBits are the KDF parameters from the constructor:
// `new PBEKeySpec((str + str2).toCharArray(), bArr, 1024, 256)`.
const (
	PBKDF2Iterations = 1024
	KeyBits          = 256
)

// ErrBadHeader is returned when a value decrypts but does not carry the header,
// which means it was written with different key material.
var ErrBadHeader = errors.New("header not found (invalid data or key)")

// ErrNotBase64 is returned when a stored value is not valid base64.
var ErrNotBase64 = errors.New("value is not valid base64")

// Obfuscator holds the key derived from a device's identity.
//
// The constructor in the client is:
//
//	new AESObfuscator(bArr /*salt*/, str /*package*/, str2 /*androidId*/)
//
// and the key comes from `(str + str2)` — package name concatenated with the
// Android ID, with no separator.
type Obfuscator struct {
	block cipher.Block

	// Package and AndroidID are kept so callers can see what the key was
	// derived from, which is the whole reason the store is readable.
	Package   string
	AndroidID string
}

// NewObfuscator derives the key the way the client does.
//
// `password` is packageName + androidId, concatenated with nothing between them.
func NewObfuscator(pkg, androidID string) (*Obfuscator, error) {
	if pkg == "" {
		return nil, errors.New("package name is required")
	}
	if androidID == "" {
		return nil, errors.New("android id is required")
	}

	password := pkg + androidID

	// The client asks the JCE for PBEWITHSHAAND256BITAES-CBC-BC. That is
	// PBKDF2-HMAC-SHA1 (the "SHA" in the name; the "BC" is BouncyCastle, the
	// provider, not the digest) producing a 256-bit key.
	key := pbkdf2SHA1([]byte(password), Salt, PBKDF2Iterations, KeyBits/8)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	return &Obfuscator{block: block, Package: pkg, AndroidID: androidID}, nil
}

// EncryptRaw encrypts an already-padded plaintext without adding padding.
//
// The client never does this, and neither does any caller that just wants to
// store a value — Obfuscate is the entry point for that. It exists because the
// padding-validation path is otherwise unreachable: a caller can only produce a
// malformed pad by controlling the plaintext after padding, which Obfuscate will
// not let them do. A reader that validates padding is only worth having if that
// validation is exercised, so the seam is exposed deliberately.
//
// The plaintext length must be a multiple of the block size.
func (o *Obfuscator) EncryptRaw(padded []byte) (string, error) {
	if len(padded) == 0 || len(padded)%aes.BlockSize != 0 {
		return "", fmt.Errorf("plaintext is %d bytes, not a multiple of %d", len(padded), aes.BlockSize)
	}
	return base64.StdEncoding.EncodeToString(o.encryptNoPad(padded)), nil
}

// encryptNoPad applies AES/CBC to an input already a multiple of the block size.
func (o *Obfuscator) encryptNoPad(plain []byte) []byte {
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(o.block, IV).CryptBlocks(out, plain)
	return out
}

// encrypt applies AES/CBC/PKCS5Padding with the compiled-in IV.
func (o *Obfuscator) encrypt(plain []byte) []byte {
	// PKCS#5/7 padding: the block is padded so its length is a multiple of the
	// block size, each pad byte equal to the pad length.
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	padded := make([]byte, len(plain)+pad)
	copy(padded, plain)
	for i := len(plain); i < len(padded); i++ {
		padded[i] = byte(pad)
	}

	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(o.block, IV).CryptBlocks(out, padded)
	return out
}

// decrypt reverses encrypt, removing valid padding.
func (o *Obfuscator) decrypt(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is %d bytes, not a multiple of %d", len(data), aes.BlockSize)
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(o.block, IV).CryptBlocks(out, data)

	// Unpad, and validate the padding: a wrong key almost always produces an
	// invalid pad, which is how the client's BadPaddingException arises.
	pad := int(out[len(out)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(out) {
		return nil, errors.New("invalid padding (wrong key or corrupt data)")
	}
	for _, b := range out[len(out)-pad:] {
		if int(b) != pad {
			return nil, errors.New("invalid padding (wrong key or corrupt data)")
		}
	}
	return out[:len(out)-pad], nil
}

// Obfuscate produces the stored form of a value under a preference key.
//
// The client wraps the plaintext as header+key then plaintext:
//
//	return Base64.encodeToString(cipher.doFinal(
//	    ("com.android.vending.licensing.AESObfuscator-1|" + key + plain).getBytes("UTF-8")), 0)
func (o *Obfuscator) Obfuscate(key, plain string) string {
	wrapped := HeaderPrefix + key + plain
	return base64.StdEncoding.EncodeToString(o.encrypt([]byte(wrapped)))
}

// Unobfuscate reads a stored value, checking the header the way the client does.
//
// The client strips `46 + len(key)` characters — 46 being the header prefix
// length. Building that from the constant rather than writing 46 keeps the two
// from drifting.
func (o *Obfuscator) Unobfuscate(key, stored string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(stored)
	if err != nil {
		// The client passes flags 0 to both Base64 calls, which tolerates
		// standard padding; try the raw variant before giving up.
		raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(stored, "="))
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrNotBase64, err)
		}
	}

	plain, err := o.decrypt(raw)
	if err != nil {
		return "", err
	}

	want := HeaderPrefix + key
	if !bytes.HasPrefix(plain, []byte(want)) {
		return "", ErrBadHeader
	}
	return string(plain[len(want):]), nil
}
