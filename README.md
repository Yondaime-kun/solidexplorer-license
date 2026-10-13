# solidexplorer-license

Reads and writes the license preferences **Solid Explorer File Manager**
(`pl.solidexplorer2`) keeps on the device, by reimplementing the obfuscation and
the storage rules taken from the shipped APK.

This is a reimplementation of what the app does with its own license state, built
from reading its code. It is not a patch, and it does not touch Google Play
Billing.

## What it does

```
$ solidexplorer-license keys
package          pl.solidexplorer2
salt (20 bytes)  d2411e8099c74ac03358a1d34d8bdc8ff520c059
iv   (16 bytes)  104a47b02065d14875f200e34641f44a
kdf              PBKDF2-HMAC-SHA1, 1024 iterations, 256-bit key
cipher           AES/CBC/PKCS5Padding
password         package + androidId
header           "com.android.vending.licensing.AESObfuscator-1|" (46 chars)

keys:  license_status  id  sale_active  special_offer
status values:  LICENSED  TRIAL  NOT LICENSED
trial length:   336h0m0s
```

Encode a value the way the app stores it, and read it back:

```
$ solidexplorer-license encode -id a1b2c3d4e5f60718 -key license_status -value LICENSED
xB4Ih3MxNEKbxlXvUIIUsN3cBdBQUHV4C6et90xydNAu1GKzPQJo1QFrHk+kd67Ofvoe9s8svtcyosHkRWFq6TVMf72YgmIWBqikWjQJCoA=

$ solidexplorer-license decode -id a1b2c3d4e5f60718 -key license_status \
      -value xB4Ih3MxNEKbxlXvUIIUsN3cBdBQUHV4C6et90xydNAu1GKzPQJo1QFrHk+kd67Ofvoe9s8svtcyosHkRWFq6TVMf72YgmIWBqikWjQJCoA=
LICENSED
```

The same value under a different device fails, which is the property the scheme
is built around:

```
$ solidexplorer-license decode -id 0000000000000000 -key license_status -value xB4Ih3Mx...=="
cannot read value: invalid padding (wrong key or corrupt data)
this is what the app does when the key or device does not match
```

Show the rules end to end, including what the device check does:

```
$ solidexplorer-license store -id a1b2c3d4e5f60718 -other-id ffffffffffffffff
device            a1b2c3d4e5f60718
status            LICENSED (licensed: true)

stored values (as they sit in SharedPreferences):
  license_status   xB4Ih3MxNEKbxlXvUIIUsN3cBdBQUHV4C6et90xydNAu1GKzPQJo1QFrHk+…
  sale_active      xB4Ih3MxNEKbxlXvUIIUsN3cBdBQUHV4C6et90xydNAu1GKzPQJo1QFrHk+…

trial remaining   300h0m0s (running: true)
read as device ffffffffffffffff -> cleared: true
```

## The scheme

Read out of `pl.solidexplorer.preferences.AESObfuscator`. Every parameter is a
constant from that class — see `RESEARCH.md` for the lines.

- **key**: `PBKDF2-HMAC-SHA1(password = packageName + androidId, salt, 1024, 256)`
  - `PBEWITHSHAAND256BITAES-CBC-BC` in the Java source; `SHA` names the PRF and
    `BC` names the provider, not the digest
- **cipher**: AES-256-CBC with PKCS#5/7 padding, fixed 16-byte IV
- **wrap**: `Base64(AES("com.android.vending.licensing.AESObfuscator-1|" + key + value))`
- **read**: decrypt, check the header and the key name, return the remainder

Two properties fall out of that construction, and both are tested here:

1. **The preference name is inside the encrypted payload**, so a value read under
   a different name is rejected rather than silently returned.
2. **The key is derived from the device identity**, so values are bound to one
   device and one package. A store copied elsewhere does not decrypt, and the
   app's response to a mismatched device identifier is to clear the licence
   preferences outright.

## Storage rules reproduced

| rule | behaviour |
| --- | --- |
| `license_status` | `LICENSED` / `TRIAL` / `NOT LICENSED`, normalised for case and whitespace |
| `id` | the device identifier, stored in the clear; compared on access |
| mismatch | every licence preference is cleared, not merely reported |
| `IsLicensed` | only `LICENSED`; a trial is not licensed |
| trial length | 14 days (`1209600000` ms in the client) |
| trial start in the future | full period remaining, rather than a negative remainder |

## What is measured, and how

```
build        go build ./...        clean
vet          go vet ./...          clean
format       gofmt -l              clean
tests        38 run, 0 failures    (28 top-level)
race         go test -race         clean
mutations    23 of 23 caught
```

The KDF is checked against the **RFC 6070 PBKDF2 vectors** before anything is
built on it, so "it round-trips" is not the only evidence that the derivation is
right. A round trip only shows the reader and the writer agree with each other.

The salt and IV are checked against `classes4.dex` **inside the real APK**
(`apk_test.go`), which is what caught a transcription error: the salt had `0x8d`
where the bytecode has `0x8b`. A self-produced golden vector could not have found
that, because the vector would have been built with the same wrong constant. Both
tests are kept, because they catch different failures — the golden vectors catch
a change to the derivation, the APK check catches a wrong constant.

Every mutation in the table below was applied to the source, the suite was run,
and the mutation was required to turn it red:

```
salt 0x8b -> 0x8d                    caught      device mismatch stops clearing     caught
IV 0xb0 -> 0xb1                      caught      empty id treated as a match        caught
iterations 1024 -> 1                 caught      TRIAL reported as licensed         caught
key bits 256 -> 128                  caught      status not normalised              caught
header prefix changed                caught      future trial start -> expired      caught
pad bytes not checked                caught      trial length 14d -> 7d             caught
pad length not validated             caught      decryption error read as present   caught
header check skipped                 caught      Clear does not clear               caught
password = package only              caught      IsLicensed: trial passes as paid   caught
PBKDF2 one block only                caught
no unpadding                         caught
PKCS#5 pad byte always 1             caught
PBKDF2 XOR step skipped              caught
EncryptRaw does not check blocks     caught
```

## Limitations

Stated plainly, because each of these is a place where the program stops short.

- **It does not reproduce a purchase.** `billing.properties` shows
  `billing_client=6.0.1`: the transaction is Google's. What is reimplemented is
  the storage scheme the app uses for the *result*, not the path that produces it.
- **The app was not run.** The scheme is read from the code and verified against
  the artifact, and the demonstration uses values this implementation produces.
  Whether the app accepts a modified store as proof of purchase was not observed
  and is not claimed.
- **Only one build was examined** (version 6.0.1, the one Aptoide serves). A
  different version could use a different salt, and the format `.activation`
  style versioning seen in other apps is not present here — this app hardcodes
  the constants in the class.
- **`sale_active` and `special_offer` are passed through, not interpreted.** The
  key names are confirmed present in the DEX; what the app does with the values
  was not traced, so no behaviour is claimed for them.
- **The APK cross-check skips when `testdata/soldi.apk` is absent.** The 20 MB
  artifact is not committed, so a fresh clone runs the other 37 tests and skips
  the bytecode comparison. `run.sh` reports which path was taken.

## Layout

```
PLAN.md                                  the question, the failure conditions, the method
RESEARCH.md                              the reading trail, with the quoted code
DOD.md                                   the evidence for each claim above
internal/solidexplorer/obfuscator.go     the scheme, and PBKDF2-HMAC-SHA1
internal/solidexplorer/store.go          the storage rules and the device check
internal/solidexplorer/*_test.go         RFC 6070, round trips, padding, mutation targets
internal/solidexplorer/apk_test.go       the constants checked against classes4.dex
cmd/solidexplorer-license/main.go        keys / encode / decode / store
run.sh                                   builds, tests, mutates, and reports honestly
```

## Running it

```
./run.sh
```

`run.sh` builds, runs the tests, and then runs the mutation checks, printing the
exit code of each step. It needs Go and nothing else — the package has no
dependencies beyond the standard library, on purpose, so the KDF is visible
rather than delegated.

## License

MIT. See `LICENSE`.

The obfuscation scheme reproduced here is the one Google shipped in the Android
License Verification Library; the salt and IV are Solid Explorer's own constants.
This project is not affiliated with the app's author.
