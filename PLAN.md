# PLAN — solidexplorer-license

## Question

Solid Explorer is a paid Android file manager. Its license state lives on the
device, not on a server, and the app has to read it back on every launch. What
does it actually store, where, and what check makes a value from another device
unusable — and can that be reproduced from the shipped binary alone?

## Failure conditions (written before the code)

This project fails if any of these is true at the end:

1. **The scheme is guessed, not read.** If any parameter — salt, IV, iteration
   count, key length, PBE scheme, header string, password composition — is
   assumed from "how LVL usually works" rather than taken from a constant in the
   decompiled class, the result is worthless regardless of whether it round-trips.
2. **The key derivation disagrees with the client.** A KDF that is only
   self-consistent would pass every round-trip test while producing values the
   app cannot read. It must be checked against an external vector.
3. **The device binding does not actually bind.** If a value written with one
   Android ID can be read with another, the central rule has been missed and the
   reimplementation is wrong about the one thing that matters.
4. **The device check does not clear.** The client clears license preferences on
   mismatch; a reimplementation that merely reports a mismatch has not
   reproduced the behaviour that makes a copied preference file useless.
5. **A test cannot fail.** Every test must be shown to go red when the code it
   covers is mutated. A suite that stays green under mutation is decoration.
6. **The write path is claimed without evidence.** Being able to read a stored
   value is not the same as producing the byte-for-byte form the app writes.
   Producing the exact stored string the app would produce must be demonstrated.

## Approach

1. Get the APK and confirm it is the real artifact (size and MD5 against the
   mirror's metadata).
2. Read the resource and class inventory before decompiling, because the central
   classes are named in the resource references.
3. Read `SELicenseManager`, `PreferenceObfuscator`, and `AESObfuscator` for the
   constants and the storage rules. Take every value from a literal in the class.
4. Implement in Go with no dependencies, including PBKDF2-HMAC-SHA1, so the KDF
   is explicit and can be checked against RFC 6070.
5. Test the KDF against the RFC vectors first, then test the obfuscation, then
   the store rules.
6. Mutate every constant and every branch in the code and confirm each mutation
   turns the suite red.
7. Demonstrate the write path: produce a stored value from a known device and
   confirm it is stable and device-bound.

## Explicitly not in scope

- **Google Play Billing.** `billing.properties` shows `billing_client=6.0.1`, and
  the purchase itself is transacted by Google. Nothing here touches that path,
  and the README must say so rather than implying a purchase can be fabricated.
- **Emulating the app end to end.** This reproduces the storage scheme and the
  rules around it. It does not run Solid Explorer and does not claim the app
  accepts a hand-written preference file as proof of purchase.
- **Signature verification of the APK.** The build carries `META-INF/BNDLTOOL.RSA`
  (bundletool), not the developer's signing block; deciding what that implies for
  a repackaged build is not needed for this question.

## Definition of done

`README.md` stating what is reproduced, what is measured, and what is not;
`RESEARCH.md` with the reading trail; `DOD.md` with the evidence; tests that pass
and that have been shown to fail under mutation; `run.sh` that reproduces the
whole thing from a clean checkout.
