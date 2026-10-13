// Package solidexplorer reimplements the storage rules Solid Explorer
// (`pl.solidexplorer2`) applies to its license preferences: which values are
// obfuscated, what they mean, and the device check that invalidates them.
//
// Everything here comes from the shipped APK — see NOTES.md for the class and
// line each rule was read from. Nothing is inferred from behaviour or assumed
// from a similar app.
package solidexplorer

import (
	"errors"
	"strings"
	"time"
)

// License status values. SELicenseManager writes exactly these strings under the
// "license_status" key; the case matters, so they are constants rather than
// free-form text.
const (
	StatusLicensed    = "LICENSED"
	StatusTrial       = "TRIAL"
	StatusNotLicensed = "NOT LICENSED"
)

// Preference keys Solid Explorer uses for licensing, read from
// SELicenseManager and Preferences. These are the names the app passes to the
// obfuscator, and because the name is inside the encrypted payload, reading a
// value under the wrong name fails — the key is part of the data.
const (
	KeyLicenseStatus = "license_status"
	KeyDeviceID      = "id"
	KeySaleActive    = "sale_active"
	KeySpecialOffer  = "special_offer"
)

// TrialLength is the trial period the client measures against. It appears in the
// class as the literal 1209600000, which is 14 days in milliseconds. Writing it
// as 14*24*time.Hour keeps the arithmetic visible and the value checkable
// against the constant.
const TrialLength = 14 * 24 * time.Hour

// ErrDeviceMismatch is returned when a stored device identifier does not match
// the device reading it. The client responds by clearing the license
// preferences, which is what makes a copied preference file useless.
var ErrDeviceMismatch = errors.New("stored device id does not match this device")

// Store holds the license preferences for one device.
//
// The client stores these through PreferenceObfuscator, which writes each value
// as a base64 AES blob rather than plaintext. This type models that: the
// accessors take and return plaintext in memory, and the on-disk form is the
// obfuscator's business.
type Store struct {
	obf *Obfuscator

	// raw is the set of stored (already obfuscated) values, keyed by preference
	// name, exactly as they would sit in SharedPreferences.
	raw map[string]string
}

// NewStore creates an empty store for a device.
func NewStore(pkg, androidID string) (*Store, error) {
	obf, err := NewObfuscator(pkg, androidID)
	if err != nil {
		return nil, err
	}
	return &Store{obf: obf, raw: make(map[string]string)}, nil
}

// DeviceID is the identifier the store was created for. The client keeps the
// device identifier in the clear under "id" and compares it on every access, so
// it is exposed here for the same reason.
func (s *Store) DeviceID() string { return s.obf.AndroidID }

// Set writes a value under a preference name in obfuscated form.
func (s *Store) Set(key, value string) {
	s.raw[key] = s.obf.Obfuscate(key, value)
}

// Get reads a value, returning ok=false when the key is absent.
//
// A value that fails to decrypt is also reported as absent rather than as an
// error: in the client, any failure to unobfuscate lands in the same catch that
// treats the preference as unset, and callers cannot act differently on the two
// cases.
func (s *Store) Get(key string) (string, bool) {
	stored, present := s.raw[key]
	if !present {
		return "", false
	}
	value, err := s.obf.Unobfuscate(key, stored)
	if err != nil {
		return "", false
	}
	return value, true
}

// Raw returns the stored (obfuscated) value for a key, as it would be written to
// preferences. This is what a reader of a real device's preference file sees.
func (s *Store) Raw(key string) (string, bool) {
	v, ok := s.raw[key]
	return v, ok
}

// SetRaw installs an already-obfuscated value, for reading a real preference
// file. The value is not validated here; Get applies the header and padding
// checks when it is read.
func (s *Store) SetRaw(key, stored string) { s.raw[key] = stored }

// LoadDeviceID records which device the stored values belong to. The client
// writes the identifier in the clear, so it is not obfuscated.
func (s *Store) LoadDeviceID(id string) { s.raw[KeyDeviceID] = id }

// CheckDevice compares the stored identifier against the device now reading it
// and reports whether the stored values are valid here.
//
// This is the rule from the client's PreferenceObfuscator: a mismatch clears
// every license preference, because the key is derived from package+androidId
// and values written elsewhere would not decrypt anyway. Clearing first means a
// later read sees an empty store rather than a decryption error.
//
// An absent identifier is reported as a mismatch: the client treats a missing
// "id" the same way, since a store without one was not written by this device.
func (s *Store) CheckDevice(currentAndroidID string) (bool, error) {
	stored, present := s.raw[KeyDeviceID]
	if !present || stored == "" {
		s.Clear()
		return false, ErrDeviceMismatch
	}
	if stored != currentAndroidID {
		s.Clear()
		return false, ErrDeviceMismatch
	}
	return true, nil
}

// Clear removes every license preference, which is what the client does on a
// device mismatch.
func (s *Store) Clear() {
	s.raw = make(map[string]string)
}

// Keys returns the preference names currently held, sorted by the caller if
// order matters. It exists so a report can show what was present before a clear.
func (s *Store) Keys() []string {
	out := make([]string, 0, len(s.raw))
	for k := range s.raw {
		out = append(out, k)
	}
	return out
}

// Status reads the license status, normalising case and whitespace.
//
// The client compares against its own constants; doing the same here avoids
// reporting "licensed" as unknown because of a trailing space in a hand-edited
// preference file, while still treating an absent or unrecognised value as not
// licensed rather than guessing.
func (s *Store) Status() string {
	v, ok := s.Get(KeyLicenseStatus)
	if !ok {
		return StatusNotLicensed
	}
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case StatusLicensed:
		return StatusLicensed
	case StatusTrial:
		return StatusTrial
	default:
		return StatusNotLicensed
	}
}

// IsLicensed reports whether the store says the app is licensed. Only the
// licensed status counts: a trial is not licensed, which matters because the
// client gates features on the distinction.
func (s *Store) IsLicensed() bool { return s.Status() == StatusLicensed }

// TrialRemaining returns how much of the trial is left given a start time, and
// whether the trial is still running.
//
// The client stores the trial start and computes the remainder against
// TrialLength. A start time in the future is treated as the full period
// remaining rather than a negative remainder, since a clock moved backwards
// should not grant extra time or report nonsense.
func (s *Store) TrialRemaining(start time.Time, now time.Time) (time.Duration, bool) {
	if start.After(now) {
		return TrialLength, true
	}
	left := TrialLength - now.Sub(start)
	if left <= 0 {
		return 0, false
	}
	return left, true
}
