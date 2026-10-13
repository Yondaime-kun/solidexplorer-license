package solidexplorer

import (
	"bytes"
	"compress/flate"
	"encoding/hex"
	"io"
	"os"
	"testing"
)

// apkPath is where the Solid Explorer APK lives when it is available. The test
// that uses it skips when the file is absent, so the suite stays runnable
// without the artifact, but when it is present the constants are checked
// against the shipped bytecode rather than against a value typed from a
// decompiler listing.
const apkPath = "testdata/soldi.apk"

// TestConstantsMatchTheAPKBytecode reads the salt and IV out of classes4.dex and
// compares them to the constants in the package.
//
// This exists because the constants were first transcribed from a decompiler
// listing, and one byte of the salt was wrong (0x8d where the bytecode has 0x8b).
// A test that pinned the constant to the decompiler's value agreed with the bug:
// it locked in the same mistake the code made. Only reading the artifact catches
// that class of error, so the check is done against the APK.
func TestConstantsMatchTheAPKBytecode(t *testing.T) {
	raw, err := os.ReadFile(apkPath)
	if err != nil {
		t.Skipf("APK not present (%v); constants cannot be cross-checked here", err)
	}

	dex := extractDEXEntry(t, raw, "classes4.dex")

	// The IV appears as a contiguous run of bytes in the file.
	if !bytes.Contains(dex, IV) {
		t.Errorf("IV %s does not appear in classes4.dex", hex.EncodeToString(IV))
	}

	// The salt is stored as a fill-array-data payload, which does not keep the
	// bytes contiguous with the code that references them, but the payload body
	// itself is the raw byte sequence and does appear in the file.
	if !bytes.Contains(dex, Salt) {
		t.Errorf("salt %s does not appear in classes4.dex", hex.EncodeToString(Salt))
	}
}

// extractDEXEntry returns the contents of a file inside the APK zip. The APK is
// read directly rather than through a dependency: only stored, uncompressed
// entries are needed here, and the test skips if the entry is not readable.
func extractDEXEntry(t *testing.T, apk []byte, name string) []byte {
	t.Helper()

	// Locate the end-of-central-directory record to find the central directory.
	eocd := bytes.LastIndex(apk, []byte{'P', 'K', 0x05, 0x06})
	if eocd < 0 || eocd+22 > len(apk) {
		t.Fatalf("no end-of-central-directory record in APK")
	}
	cdSize := int(le32(apk[eocd+12:]))
	cdOff := int(le32(apk[eocd+16:]))
	if cdOff+cdSize > len(apk) {
		t.Fatalf("central directory runs past the end of the file")
	}

	for off := cdOff; off+46 <= cdOff+cdSize; {
		if !bytes.Equal(apk[off:off+4], []byte{'P', 'K', 0x01, 0x02}) {
			break
		}
		compMethod := int(le16(apk[off+10:]))
		compSize := int(le32(apk[off+20:]))
		nameLen := int(le16(apk[off+28:]))
		extraLen := int(le16(apk[off+30:]))
		commentLen := int(le16(apk[off+32:]))
		localOff := int(le32(apk[off+42:]))
		entryName := string(apk[off+46 : off+46+nameLen])

		if entryName == name {
			// Local header: skip its own name and extra lengths to reach data.
			lNameLen := int(le16(apk[localOff+26:]))
			lExtraLen := int(le16(apk[localOff+28:]))
			dataOff := localOff + 30 + lNameLen + lExtraLen
			if dataOff+compSize > len(apk) {
				t.Fatalf("%s data runs past the end of the file", name)
			}
			data := apk[dataOff : dataOff+compSize]

			switch compMethod {
			case 0:
				return data
			case 8:
				// Deflate. compress/flate is part of the standard library, so
				// this adds no dependency; the APK stores DEX entries deflated.
				r := flate.NewReader(bytes.NewReader(data))
				defer r.Close()
				out, err := io.ReadAll(r)
				if err != nil {
					t.Fatalf("inflating %s: %v", name, err)
				}
				return out
			default:
				t.Skipf("%s uses compression method %d, which is not handled here", name, compMethod)
			}
		}
		off += 46 + nameLen + extraLen + commentLen
	}
	t.Skipf("%s not found in the APK", name)
	return nil
}

func le16(b []byte) uint16 { return uint16(b[0]) | uint16(b[1])<<8 }
func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
