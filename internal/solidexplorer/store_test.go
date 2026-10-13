package solidexplorer

import (
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore("pl.solidexplorer2", "a1b2c3d4e5f60718")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s
}

func TestStoreRoundTrip(t *testing.T) {
	s := newTestStore(t)
	s.Set(KeyLicenseStatus, StatusLicensed)

	got, ok := s.Get(KeyLicenseStatus)
	if !ok {
		t.Fatal("Get reported the value absent")
	}
	if got != StatusLicensed {
		t.Errorf("got %q, want %q", got, StatusLicensed)
	}
}

// The stored form must not be the plaintext: this is the property that makes the
// obfuscation worth reproducing, and a regression to plaintext would round-trip
// fine without it.
func TestStoreStoresObfuscatedValues(t *testing.T) {
	s := newTestStore(t)
	s.Set(KeyLicenseStatus, StatusLicensed)

	raw, ok := s.Raw(KeyLicenseStatus)
	if !ok {
		t.Fatal("no stored value")
	}
	if raw == StatusLicensed || len(raw) < 20 {
		t.Errorf("stored value %q looks like plaintext", raw)
	}
}

func TestGetAbsentKey(t *testing.T) {
	s := newTestStore(t)
	if v, ok := s.Get("never_set"); ok {
		t.Errorf("absent key returned %q, want ok=false", v)
	}
}

// A value that cannot be decrypted is reported as absent, not as an error: the
// client funnels both into "preference unset".
func TestUndecryptableValueReadsAsAbsent(t *testing.T) {
	s := newTestStore(t)
	s.SetRaw(KeyLicenseStatus, "bm90IGEgcmVhbCB2YWx1ZQ==")

	if v, ok := s.Get(KeyLicenseStatus); ok {
		t.Errorf("undecryptable value returned %q, want ok=false", v)
	}
}

// A value written under one preference name must not be readable under another,
// because the key is inside the encrypted payload.
func TestValueMovedToAnotherKeyFails(t *testing.T) {
	s := newTestStore(t)
	s.Set(KeyLicenseStatus, StatusLicensed)

	moved := s.raw[KeyLicenseStatus]
	s.SetRaw(KeySaleActive, moved)

	if v, ok := s.Get(KeySaleActive); ok {
		t.Errorf("value read under the wrong key gave %q, want ok=false", v)
	}
}

func TestDeviceIDCheck(t *testing.T) {
	s := newTestStore(t)
	s.LoadDeviceID("a1b2c3d4e5f60718")
	s.Set(KeyLicenseStatus, StatusLicensed)

	ok, err := s.CheckDevice("a1b2c3d4e5f60718")
	if !ok || err != nil {
		t.Fatalf("same device rejected: ok=%v err=%v", ok, err)
	}
	if v, _ := s.Get(KeyLicenseStatus); v != StatusLicensed {
		t.Error("a successful check must not clear the store")
	}
}

// The device check clears the store on mismatch. This is what makes copying a
// preference file to another device useless, and it is the reason the check
// exists rather than a plain comparison.
func TestDeviceMismatchClearsStore(t *testing.T) {
	s := newTestStore(t)
	s.LoadDeviceID("a1b2c3d4e5f60718")
	s.Set(KeyLicenseStatus, StatusLicensed)

	ok, err := s.CheckDevice("ffffffffffffffff")
	if ok {
		t.Fatal("mismatched device accepted")
	}
	if err != ErrDeviceMismatch {
		t.Errorf("err = %v, want ErrDeviceMismatch", err)
	}
	if len(s.Keys()) != 0 {
		t.Errorf("store still holds %v; a mismatch must clear it", s.Keys())
	}
	if v, _ := s.Get(KeyLicenseStatus); v != "" {
		t.Errorf("value survived the clear: %q", v)
	}
}

// A store with no identifier was not written by this device, so it must be
// treated as a mismatch rather than silently accepted.
func TestMissingDeviceIDIsMismatch(t *testing.T) {
	s := newTestStore(t)
	s.Set(KeyLicenseStatus, StatusLicensed)

	ok, err := s.CheckDevice("a1b2c3d4e5f60718")
	if ok || err != ErrDeviceMismatch {
		t.Fatalf("missing id: ok=%v err=%v, want false/ErrDeviceMismatch", ok, err)
	}
	if len(s.Keys()) != 0 {
		t.Errorf("store still holds %v after a missing-id check", s.Keys())
	}
}

// An identifier that is present but empty is a different code path from one
// that is absent, and it must be rejected too: a blank string equals nothing,
// including a device with no id, so treating it as a match would accept a store
// written by nobody.
func TestEmptyDeviceIDIsMismatch(t *testing.T) {
	s := newTestStore(t)
	s.LoadDeviceID("")
	s.Set(KeyLicenseStatus, StatusLicensed)

	ok, err := s.CheckDevice("")
	if ok || err != ErrDeviceMismatch {
		t.Fatalf("empty id: ok=%v err=%v, want false/ErrDeviceMismatch", ok, err)
	}
	if len(s.Keys()) != 0 {
		t.Errorf("store still holds %v after an empty-id check", s.Keys())
	}

	// And a real identifier must not match a blank stored one either.
	s2 := newTestStore(t)
	s2.LoadDeviceID("")
	s2.Set(KeyLicenseStatus, StatusLicensed)
	if ok, _ := s2.CheckDevice("a1b2c3d4e5f60718"); ok {
		t.Error("a blank stored id matched a real device id")
	}
}

func TestStatusInterpretation(t *testing.T) {
	cases := []struct {
		stored string
		want   string
	}{
		{StatusLicensed, StatusLicensed},
		{StatusTrial, StatusTrial},
		{StatusNotLicensed, StatusNotLicensed},
		{"  LICENSED  ", StatusLicensed},
		{"trial", StatusTrial},
		{"something else", StatusNotLicensed},
		{"", StatusNotLicensed},
	}
	for _, c := range cases {
		s := newTestStore(t)
		if c.stored != "" {
			s.Set(KeyLicenseStatus, c.stored)
		}
		if got := s.Status(); got != c.want {
			t.Errorf("Status() for %q = %q, want %q", c.stored, got, c.want)
		}
	}
}

// Only LICENSED counts as licensed. A trial is deliberately not licensed, and a
// check that treated "not NOT LICENSED" as licensed would pass the trial as paid.
func TestTrialIsNotLicensed(t *testing.T) {
	s := newTestStore(t)
	s.Set(KeyLicenseStatus, StatusTrial)

	if s.IsLicensed() {
		t.Error("a trial must not report as licensed")
	}
	if s.Status() != StatusTrial {
		t.Errorf("status = %q, want %q", s.Status(), StatusTrial)
	}
}

func TestIsLicensed(t *testing.T) {
	s := newTestStore(t)
	if s.IsLicensed() {
		t.Error("an empty store must not be licensed")
	}
	s.Set(KeyLicenseStatus, StatusLicensed)
	if !s.IsLicensed() {
		t.Error("a licensed store must report licensed")
	}
}

func TestTrialRemaining(t *testing.T) {
	s := newTestStore(t)
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

	// The length must be the constant from the client: 1209600000 ms.
	if TrialLength != 1209600000*time.Millisecond {
		t.Errorf("TrialLength = %v, want 1209600000ms (14 days)", TrialLength)
	}

	cases := []struct {
		name      string
		start     time.Time
		wantLeft  time.Duration
		wantAlive bool
	}{
		{"just started", now, TrialLength, true},
		{"one day in", now.Add(-24 * time.Hour), 13 * 24 * time.Hour, true},
		{"one second left", now.Add(-TrialLength + time.Second), time.Second, true},
		{"exactly expired", now.Add(-TrialLength), 0, false},
		{"long expired", now.Add(-30 * 24 * time.Hour), 0, false},
		{"start in the future", now.Add(24 * time.Hour), TrialLength, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			left, alive := s.TrialRemaining(c.start, now)
			if alive != c.wantAlive {
				t.Errorf("alive = %v, want %v", alive, c.wantAlive)
			}
			if left != c.wantLeft {
				t.Errorf("left = %v, want %v", left, c.wantLeft)
			}
		})
	}
}
