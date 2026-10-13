// Command solidexplorer-license reads and writes the license preferences Solid
// Explorer (`pl.solidexplorer2`) stores, using the scheme reversed from the app.
//
// It is a reimplementation of the app's own storage rules, not a patch: the
// obfuscation is the LVL AES scheme with the app's compiled-in salt and IV, and
// the values it reads are the ones the app wrote.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/yondaime-kun/solidexplorer-license/internal/solidexplorer"
)

const defaultPackage = "pl.solidexplorer2"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "keys":
		cmdKeys(os.Args[2:])
	case "encode":
		cmdEncode(os.Args[2:])
	case "decode":
		cmdDecode(os.Args[2:])
	case "store":
		cmdStore(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `solidexplorer-license — read and write Solid Explorer license preferences

The key is derived from the package name plus the device's Android ID, so both
are required for anything that touches a value.

Commands:
  keys                      show the constants reversed from the APK
  encode -id ID -key K -value V
                            produce the stored (obfuscated) form of a value
  decode -id ID -key K -value STORED
                            read a stored value back
  store  -id ID [-json]     show a store as the app would see it

Flags:
  -pkg NAME   package name (default `+defaultPackage+`)
  -id ID      Android ID of the device (required for encode/decode/store)
`)
}

func cmdKeys(args []string) {
	fs := flag.NewFlagSet("keys", flag.ExitOnError)
	fs.Parse(args)

	fmt.Printf("package          %s\n", defaultPackage)
	fmt.Printf("salt (%d bytes)  %s\n", len(solidexplorer.Salt), hex.EncodeToString(solidexplorer.Salt))
	fmt.Printf("iv   (%d bytes)  %s\n", len(solidexplorer.IV), hex.EncodeToString(solidexplorer.IV))
	fmt.Printf("kdf              PBKDF2-HMAC-SHA1, %d iterations, %d-bit key\n",
		solidexplorer.PBKDF2Iterations, solidexplorer.KeyBits)
	fmt.Printf("cipher           AES/CBC/PKCS5Padding\n")
	fmt.Printf("password         package + androidId\n")
	fmt.Printf("header           %q (%d chars)\n", solidexplorer.HeaderPrefix, len(solidexplorer.HeaderPrefix))
	fmt.Println()
	fmt.Printf("keys:  %s\n", strings.Join([]string{
		solidexplorer.KeyLicenseStatus,
		solidexplorer.KeyDeviceID,
		solidexplorer.KeySaleActive,
		solidexplorer.KeySpecialOffer,
	}, "  "))
	fmt.Printf("status values:  %s  %s  %s\n",
		solidexplorer.StatusLicensed, solidexplorer.StatusTrial, solidexplorer.StatusNotLicensed)
	fmt.Printf("trial length:   %v\n", solidexplorer.TrialLength)
}

func cmdEncode(args []string) {
	fs := flag.NewFlagSet("encode", flag.ExitOnError)
	pkg := fs.String("pkg", defaultPackage, "package name")
	id := fs.String("id", "", "Android ID of the device")
	key := fs.String("key", "", "preference name")
	value := fs.String("value", "", "plaintext value")
	fs.Parse(args)

	requireFlags(*id, *key)

	obf, err := solidexplorer.NewObfuscator(*pkg, *id)
	if err != nil {
		fatal(err)
	}
	fmt.Println(obf.Obfuscate(*key, *value))
}

func cmdDecode(args []string) {
	fs := flag.NewFlagSet("decode", flag.ExitOnError)
	pkg := fs.String("pkg", defaultPackage, "package name")
	id := fs.String("id", "", "Android ID of the device")
	key := fs.String("key", "", "preference name")
	value := fs.String("value", "", "stored (obfuscated) value")
	fs.Parse(args)

	requireFlags(*id, *key, *value)

	obf, err := solidexplorer.NewObfuscator(*pkg, *id)
	if err != nil {
		fatal(err)
	}
	plain, err := obf.Unobfuscate(*key, *value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read value: %v\n", err)
		fmt.Fprintln(os.Stderr, "this is what the app does when the key or device does not match")
		os.Exit(1)
	}
	fmt.Println(plain)
}

// cmdStore demonstrates the full rule set on a store built in memory: write a
// status, read it back, then show what the device check does. It is the
// end-to-end check that the pieces agree with each other.
func cmdStore(args []string) {
	fs := flag.NewFlagSet("store", flag.ExitOnError)
	pkg := fs.String("pkg", defaultPackage, "package name")
	id := fs.String("id", "", "Android ID of the device")
	asJSON := fs.Bool("json", false, "emit JSON")
	other := fs.String("other-id", "", "check the store against a second device id")
	fs.Parse(args)

	requireFlags(*id)

	s, err := solidexplorer.NewStore(*pkg, *id)
	if err != nil {
		fatal(err)
	}
	s.LoadDeviceID(*id)
	s.Set(solidexplorer.KeyLicenseStatus, solidexplorer.StatusLicensed)
	s.Set(solidexplorer.KeySaleActive, "true")

	report := map[string]any{}
	stored := map[string]string{}
	for _, k := range []string{solidexplorer.KeyLicenseStatus, solidexplorer.KeySaleActive} {
		if raw, ok := s.Raw(k); ok {
			stored[k] = raw
		}
	}
	report["stored"] = stored

	// Read the state that describes the store as written, before any device
	// check runs: the check clears the store on mismatch, and reporting the
	// post-clear state as though it were the stored state would be misleading.
	now := time.Now()
	left, alive := s.TrialRemaining(now.Add(-36*time.Hour), now)
	status := s.Status()
	licensed := s.IsLicensed()
	report["status"] = status
	report["is_licensed"] = licensed
	report["trial_remaining"] = left.String()
	report["trial_running"] = alive

	if *other != "" {
		ok, err := s.CheckDevice(*other)
		report["device_check_other"] = ok
		report["device_check_other_error"] = fmt.Sprint(err)
		report["keys_after_other"] = s.Keys()
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fatal(err)
		}
		return
	}

	fmt.Printf("device            %s\n", *id)
	fmt.Printf("status            %s (licensed: %v)\n", status, licensed)
	fmt.Println()
	fmt.Println("stored values (as they sit in SharedPreferences):")
	for k, v := range stored {
		fmt.Printf("  %-16s %s\n", k, truncate(v, 72))
	}
	fmt.Println()
	fmt.Printf("trial remaining   %v (running: %v)\n", left, alive)
	if *other != "" {
		fmt.Printf("read as device %s -> cleared: %v\n", *other, len(s.Keys()) == 0)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func requireFlags(vals ...string) {
	names := []string{"-id", "-key", "-value"}
	for i, v := range vals {
		if v == "" {
			fmt.Fprintf(os.Stderr, "%s is required\n", names[i])
			os.Exit(2)
		}
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
