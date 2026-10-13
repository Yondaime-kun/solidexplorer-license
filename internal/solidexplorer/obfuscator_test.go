package solidexplorer

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// The PBKDF2 implementation is checked against the published RFC 6070 vectors
// before anything is built on it. A KDF that is only self-consistent would make
// every round-trip test pass while disagreeing with the client.
func TestPBKDF2RFC6070(t *testing.T) {
	cases := []struct {
		name     string
		password string
		salt     string
		iter     int
		keyLen   int
		want     string
	}{
		{
			name:     "c=1, dkLen=20",
			password: "password", salt: "salt", iter: 1, keyLen: 20,
			want: "0c60c80f961f0e71f3a9b524af6012062fe037a6",
		},
		{
			name:     "c=2, dkLen=20",
			password: "password", salt: "salt", iter: 2, keyLen: 20,
			want: "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
		},
		{
			name:     "c=4096, dkLen=20",
			password: "password", salt: "salt", iter: 4096, keyLen: 20,
			want: "4b007901b765489abead49d926f721d065a429c1",
		},
		{
			name:     "c=1, dkLen=25 (multi-block)",
			password: "passwordPASSWORDpassword",
			salt:     "saltSALTsaltSALTsaltSALTsaltSALTsalt",
			iter:     4096, keyLen: 25,
			want: "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := pbkdf2SHA1([]byte(c.password), []byte(c.salt), c.iter, c.keyLen)
			if hex.EncodeToString(got) != c.want {
				t.Errorf("pbkdf2 = %s, want %s", hex.EncodeToString(got), c.want)
			}
		})
	}
}

// The salt and IV are constants out of the APK. Pinning them here means a
// transcription slip is caught, rather than producing a key that cannot read
// anything the app wrote.
func TestConstantsMatchTheReversedBytes(t *testing.T) {
	if len(Salt) != 20 {
		t.Errorf("salt is %d bytes, want 20", len(Salt))
	}
	if got := hex.EncodeToString(Salt); got != "d2411e8099c74ac03358a1d34d8bdc8ff520c059" {
		t.Errorf("salt = %s", got)
	}
	if len(IV) != 16 {
		t.Errorf("iv is %d bytes, want 16", len(IV))
	}
	if got := hex.EncodeToString(IV); got != "104a47b02065d14875f200e34641f44a" {
		t.Errorf("iv = %s", got)
	}
	if len(HeaderPrefix) != 46 {
		t.Errorf("header prefix is %d chars, want 46 (the client strips 46+len(key))", len(HeaderPrefix))
	}
}

// The encrypted form is pinned to a fixed value. Round-trip tests cannot catch a
// changed KDF parameter or key length, because both writer and reader move
// together and still agree. Fixing the ciphertext makes a change to the
// iteration count, key length, or password composition break these vectors.
//
// What these vectors do NOT do is validate the salt and IV. They were produced by
// this implementation, so if a constant were transcribed wrongly the vectors
// would encode the same mistake and still match — which is exactly what happened
// first time round (the salt had 0x8d where the bytecode has 0x8b). The salt and
// IV are validated against the APK itself in apk_test.go; keep both tests, since
// they catch different failures: this one catches a change to the derivation,
// that one catches a wrong constant.
func TestGoldenVectors(t *testing.T) {
	o, err := NewObfuscator("pl.solidexplorer2", "a1b2c3d4e5f60718")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ plain, stored string }{
		{
			plain:  "LICENSED",
			stored: "xB4Ih3MxNEKbxlXvUIIUsN3cBdBQUHV4C6et90xydNAu1GKzPQJo1QFrHk+kd67Ofvoe9s8svtcyosHkRWFq6TVMf72YgmIWBqikWjQJCoA=",
		},
		{
			plain:  "TRIAL",
			stored: "xB4Ih3MxNEKbxlXvUIIUsN3cBdBQUHV4C6et90xydNAu1GKzPQJo1QFrHk+kd67OLaTaWXwfidDdfaeTGYbiReN2xAsmtK+P8ZOStJzoviA=",
		},
	}
	for _, c := range cases {
		got := o.Obfuscate("license_status", c.plain)
		if got != c.stored {
			t.Errorf("Obfuscate(%q):\n got %s\nwant %s", c.plain, got, c.stored)
		}
		back, err := o.Unobfuscate("license_status", c.stored)
		if err != nil {
			t.Errorf("Unobfuscate(%q): %v", c.plain, err)
		} else if back != c.plain {
			t.Errorf("Unobfuscate gave %q, want %q", back, c.plain)
		}
	}
}

// The padding check must verify the pad bytes, not only the pad length. A
// plaintext whose final byte announces a legal length while the preceding bytes
// do not is malformed input, and the reader must reject it rather than hand back
// a value that was never written.
//
// This is tested by encrypting a deliberately malformed padding block. The
// ciphertext route cannot reach this case: flipping a ciphertext byte changes
// both the pad length and a pad byte together, so the length check fires first.
// The encrypt path is used here because producing an inconsistent pad requires
// controlling the plaintext, which the reader never lets a caller do.
func TestPaddingBytesAreChecked(t *testing.T) {
	o := newTestObfuscator(t)

	// Four ciphertext blocks: three of payload and one of full padding, so the
	// pad length is 0x10.
	const key = "k"
	wrapped := len(HeaderPrefix) + len(key)
	target := 48
	plain := strings.Repeat("A", target-wrapped)

	// Rebuild the wrapped plaintext and its correct padding, then corrupt one
	// interior pad byte while leaving the length byte at 0x10.
	body := []byte(HeaderPrefix + key + plain)
	pad := aes.BlockSize
	padded := make([]byte, len(body)+pad)
	copy(padded, body)
	for i := len(body); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	// Byte 14 of the padding block: a pad byte that is not the length byte.
	padded[len(padded)-2] = 0x00

	// EncryptRaw is used rather than encrypt: encrypt would append another full
	// block of padding, pushing the corrupted byte into the payload where it is
	// never validated. That was the bug in the first version of this test — it
	// passed against a reader that ignored pad bytes entirely.
	bad, err := o.EncryptRaw(padded)
	if err != nil {
		t.Fatal(err)
	}

	if got, err := o.Unobfuscate(key, bad); err == nil {
		t.Fatalf("a value with an inconsistent padding byte decrypted to %q; "+
			"pad bytes must be checked, not only the pad length", got)
	}
}

// EncryptRaw refuses a plaintext that is not a whole number of blocks, since
// CBC cannot process a partial block and silently truncating would produce a
// value that decrypts to something shorter than what was handed in.
func TestEncryptRawRequiresWholeBlocks(t *testing.T) {
	o := newTestObfuscator(t)
	for _, n := range []int{0, 1, 15, 17, 31} {
		if _, err := o.EncryptRaw(make([]byte, n)); err == nil {
			t.Errorf("EncryptRaw accepted %d bytes; not a block multiple", n)
		}
	}
	for _, n := range []int{16, 32} {
		if _, err := o.EncryptRaw(make([]byte, n)); err != nil {
			t.Errorf("EncryptRaw rejected a valid %d-byte input: %v", n, err)
		}
	}
}

func newTestObfuscator(t *testing.T) *Obfuscator {
	t.Helper()
	o, err := NewObfuscator("pl.solidexplorer2", "a1b2c3d4e5f60718")
	if err != nil {
		t.Fatalf("NewObfuscator: %v", err)
	}
	return o
}

func TestRoundTrip(t *testing.T) {
	o := newTestObfuscator(t)
	for _, plain := range []string{
		"LICENSED",
		"TRIAL",
		"NOT LICENSED",
		"",
		strings.Repeat("x", 1000),
		"unicode: ünïcödé ✓ 日本語",
	} {
		stored := o.Obfuscate("license_status", plain)
		got, err := o.Unobfuscate("license_status", stored)
		if err != nil {
			t.Fatalf("Unobfuscate(%q): %v", plain, err)
		}
		if got != plain {
			t.Errorf("round trip of %q gave %q", plain, got)
		}
	}
}

// The key is bound to the preference name: the name is inside the encrypted
// plaintext, so a value moved to a different key must be rejected. This is the
// property that makes the header worth checking, and a reader that skipped it
// would silently return another preference's value.
func TestValueIsBoundToItsKey(t *testing.T) {
	o := newTestObfuscator(t)
	stored := o.Obfuscate("license_status", "LICENSED")

	if _, err := o.Unobfuscate("some_other_key", stored); err == nil {
		t.Fatal("a value read under the wrong key must be rejected")
	} else if err != ErrBadHeader {
		t.Errorf("err = %v, want ErrBadHeader", err)
	}
}

// The key is also bound to the device: the password is package + androidId, so
// a store copied from another device must not decrypt. That is the anti-restore
// behaviour the client relies on, and it is the whole reason a copied
// preferences file is not enough.
func TestWrongDeviceFails(t *testing.T) {
	writer := newTestObfuscator(t)
	stored := writer.Obfuscate("license_status", "LICENSED")

	other, err := NewObfuscator("pl.solidexplorer2", "0000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Unobfuscate("license_status", stored); err == nil {
		t.Fatal("a value written with another android id must not decrypt")
	}
}

func TestWrongPackageFails(t *testing.T) {
	writer := newTestObfuscator(t)
	stored := writer.Obfuscate("license_status", "LICENSED")

	other, err := NewObfuscator("com.example.other", "a1b2c3d4e5f60718")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Unobfuscate("license_status", stored); err == nil {
		t.Fatal("a value written under another package must not decrypt")
	}
}

// The stored form is base64 and decrypts to a header-prefixed payload. Checking
// the shape catches an encoding mistake that a round trip alone would hide.
func TestStoredFormShape(t *testing.T) {
	o := newTestObfuscator(t)
	stored := o.Obfuscate("license_status", "LICENSED")

	if _, err := base64.StdEncoding.DecodeString(stored); err != nil {
		t.Errorf("stored value is not valid base64: %v", err)
	}
	// It must not contain the plaintext, or the scheme would be pointless.
	if strings.Contains(stored, "LICENSED") {
		t.Error("stored value contains the plaintext")
	}
}

func TestUnobfuscateRejectsGarbage(t *testing.T) {
	o := newTestObfuscator(t)
	for _, bad := range []string{
		"not base64 at all!!",
		base64.StdEncoding.EncodeToString([]byte("too short")),
		base64.StdEncoding.EncodeToString(make([]byte, 16)),
	} {
		if got, err := o.Unobfuscate("license_status", bad); err == nil {
			t.Errorf("Unobfuscate(%q) = %q, want an error", bad, got)
		}
	}
}

// Padding must be validated, not merely stripped: a wrong key almost always
// yields an invalid pad, and accepting it would decrypt garbage into a value.
func TestPaddingIsValidated(t *testing.T) {
	o := newTestObfuscator(t)
	// Encrypt something, then flip a byte in the last block so the padding is
	// wrong, and confirm it is rejected rather than returned.
	stored := o.Obfuscate("license_status", "LICENSED")
	raw, err := base64.StdEncoding.DecodeString(stored)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xFF
	tampered := base64.StdEncoding.EncodeToString(raw)

	if got, err := o.Unobfuscate("license_status", tampered); err == nil {
		t.Errorf("a tampered value decrypted to %q; padding must be validated", got)
	}
}

func TestNewObfuscatorRequiresIdentity(t *testing.T) {
	if _, err := NewObfuscator("", "id"); err == nil {
		t.Error("empty package must be rejected")
	}
	if _, err := NewObfuscator("pkg", ""); err == nil {
		t.Error("empty android id must be rejected")
	}
}

// The licence status vocabulary, from SELicenseManager. These are the exact
// strings the app stores under "license_status".
func TestLicenseStatusVocabulary(t *testing.T) {
	o := newTestObfuscator(t)
	for _, status := range []string{"LICENSED", "TRIAL", "NOT LICENSED"} {
		got, err := o.Unobfuscate("license_status", o.Obfuscate("license_status", status))
		if err != nil {
			t.Fatalf("%s: %v", status, err)
		}
		if got != status {
			t.Errorf("got %q, want %q", got, status)
		}
	}
}
