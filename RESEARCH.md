# RESEARCH — solidexplorer-license

Everything below was read from the shipped APK. Values are quoted from the code
that uses them; nothing is inferred from how similar apps behave.

## Getting the artifact

Aptoide's API answers plain `curl` when the CDN mirror sites do not (APKMirror
and APKPure return Cloudflare 403, and a browser gets the challenge page).

```
GET https://ws2-cache.aptoide.com/api/7/app/getMeta?package_name=pl.solidexplorer2
```

The response carries `data.file.path` (the APK URL) and `data.file.md5sum`. The
download was checked against it:

```
pl.solidexplorer2
size    20,664,887 bytes
md5     d7250633aec6f6cc0271aca651c601e5   (matches the metadata)
```

The build identifies itself as `version=6.0.1`, `client=billing`,
`billing_client=6.0.1` in `billing.properties` — Google Play Billing 6.0.1.

## What is in the package

Read from the ZIP central directory before decompiling anything, because the
central classes are named in the resource references:

```
AndroidManifest.xml
billing.properties                          50 bytes
classes.dex               8,520,852 bytes
classes2.dex              9,637,892 bytes
classes3.dex              6,596,660 bytes
classes4.dex              1,961,036 bytes
lib/x86_64/lib7z.so       3,395,624 bytes   archive handling
lib/x86_64/libgif.so         30,864 bytes
res/layout/list_item_trial_license.xml  3,348 bytes   the trial/upsell row
res/raw/licenses.xml                    6,786 bytes   OSS notices, not licensing
META-INF/BNDLTOOL.RSA                                 bundletool, not the dev key
```

Note `BNDLTOOL.RSA`: this is an AAB converted to an APK, so the signature
material is bundletool's, not the developer's. A certificate check against this
build would compare against the wrong certificate, which is worth knowing before
proposing one.

## The licensing classes

Found by searching the decompiled tree for the app's own package:

```
pl/solidexplorer/licensing/SELicenseManager.java
pl/solidexplorer/licensing/LicenseCategory.java
pl/solidexplorer/licensing/PurchaseActivity.java
pl/solidexplorer/preferences/PreferenceObfuscator.java
pl/solidexplorer/preferences/AESObfuscator.java
pl/solidexplorer/util/GooglePlayBilling.java
pl/solidexplorer/util/remoteservices/SEBilling.java
pl/solidexplorer/TrialStartDialog.java
```

The licensing logic is the app's own code, not a third-party SDK wrapper: the
classes are in `pl.solidexplorer`, and the only billing class from outside is
Google's.

## The obfuscation, read from AESObfuscator

```java
private static final byte[] IV = {16, 74, 71, -80, 32, 101, -47, 72,
                                 117, -14, 0, -29, 70, 65, -12, 74};

new SecretKeySpec(
    SecretKeyFactory.getInstance("PBEWITHSHAAND256BITAES-CBC-BC")
        .generateSecret(new PBEKeySpec((str + str2).toCharArray(), bArr, 1024, 256))
        .getEncoded(), "AES")

Cipher.getInstance("AES/CBC/PKCS5Padding");
```

and the wrap, from `obfuscate` / `unobfuscate`:

```java
obfuscate:   Base64.encodeToString(cipher.doFinal(
                 ("com.android.vending.licensing.AESObfuscator-1|" + key + plain)
                     .getBytes("UTF-8")), 0)

unobfuscate: plain = new String(cipher.doFinal(Base64.decode(value, 0)), "UTF-8");
             if (!plain.startsWith("com.android.vending.licensing.AESObfuscator-1|" + key))
                 throw new SEException(...);
             return plain.substring(46 + key.length());
```

Read off as parameters:

- **salt** — 20 bytes, from `SELicenseManager`
- **IV** — 16 bytes, above
- **KDF** — `PBEWITHSHAAND256BITAES-CBC-BC`, which is PBKDF2 with HMAC-SHA1
  (`"SHA"` names the PRF; `"BC"` is BouncyCastle, the provider)
- **iterations** — 1024
- **key length** — 256 bits
- **cipher** — AES/CBC/PKCS5Padding
- **password** — `packageName + androidId`, concatenated, no separator
- **header** — `com.android.vending.licensing.AESObfuscator-1|`, 46 characters

This is the scheme Google shipped in the License Verification Library, with the
app's own salt and IV compiled in.

## The storage rules, read from PreferenceObfuscator and SELicenseManager

```
keys:           license_status   id   sale_active   special_offer
status values:  LICENSED   TRIAL   NOT LICENSED
trial length:   1209600000 ms  = 14 days
```

The device rule: the store keeps the device identifier in the clear under `id`,
and compares it on access. A mismatch clears every license preference. That is
what makes a preference file copied from another device useless, and it is the
reason the rule exists rather than a plain comparison — the key is derived from
package+androidId, so values written elsewhere would not decrypt anyway; clearing
turns a decryption failure into an empty store.

## A correction worth recording

The salt was first transcribed from a decompiler listing as

```
d2411e8099c74ac03358a1d34d8ddc8ff520c059
                          ^^ 0x8d
```

The bytecode in `classes4.dex` holds

```
d2411e8099c74ac03358a1d34d8bdc8ff520c059
                          ^^ 0x8b
```

Found by searching the raw DEX for the byte run, not by reading the listing
again. The IV was confirmed the same way (present as a contiguous run at offset
1,203,580 of `classes4.dex`), and the header string, all four key names, all
three status values, the PBE scheme name, and the cipher name were confirmed
present in the DEX.

The lesson: a round-trip test and a self-produced golden vector cannot catch a
wrong constant, because the constant is used to produce the vector. The constant
has to be checked against the artifact. That check is now a test.

## What is not established

- Nothing here touches Google Play Billing. The purchase is transacted by
  Google; this reproduces the storage scheme, not the purchase path.
- The app was not run. The scheme is reproduced from the code, verified against
  the artifacts, and demonstrated on values this implementation produces.
- Whether the app would accept a hand-written preference file as proof of
  purchase is not claimed. The storage format is reproduced; the app's behaviour
  on a modified store was not observed.
