#!/usr/bin/env bash
# Build, test, and check solidexplorer-license.
#
# Every step prints its own exit code, and the script exits non-zero if any step
# fails. Nothing is reported as passing unless the command that proves it
# returned 0.
set -u

cd "$(dirname "$0")"

pass=0
fail=0
step() {
    local label="$1"
    shift
    local out
    out=$("$@" 2>&1)
    local code=$?
    if [ $code -eq 0 ]; then
        printf '  %-26s ok\n' "$label"
        pass=$((pass + 1))
    else
        printf '  %-26s FAILED (exit %d)\n' "$label" $code
        printf '%s\n' "$out" | sed 's/^/      /'
        fail=$((fail + 1))
    fi
}

echo "== toolchain =="
if ! command -v go >/dev/null 2>&1; then
    # Fall back to a common install location rather than failing outright, so a
    # checkout on a machine where go is not on PATH still works.
    for candidate in /usr/local/go/bin /usr/lib/go/bin; do
        if [ -x "$candidate/go" ]; then
            PATH="$candidate:$PATH"
            export PATH
            break
        fi
    done
fi
if ! command -v go >/dev/null 2>&1; then
    echo "go not found; install Go and re-run" >&2
    exit 1
fi
printf '  %-26s %s\n' "go" "$(go version | awk '{print $3}')"

echo
echo "== build and static checks =="
step "build" go build ./...
step "vet" go vet ./...
if [ -z "$(gofmt -l internal cmd 2>/dev/null)" ]; then
    printf '  %-26s ok\n' "gofmt"
    pass=$((pass + 1))
else
    printf '  %-26s FAILED\n' "gofmt"
    gofmt -l internal cmd | sed 's/^/      /'
    fail=$((fail + 1))
fi

echo
echo "== tests =="
step "tests" go test ./...
step "tests (race)" go test -race ./...

echo
echo "== test inventory =="
runs=$(go test ./internal/... -v 2>/dev/null | grep -c '^=== RUN')
toplevel=$(go test ./internal/... -v 2>/dev/null | grep -c '^--- ')
printf '  %-26s %s\n' "cases run" "$runs"
printf '  %-26s %s\n' "top-level tests" "$toplevel"

# The constants are checked against the shipped APK when it is present. Say which
# path was taken: a green run that skipped this check checked less.
if [ -f internal/solidexplorer/testdata/soldi.apk ]; then
    if go test ./internal/... -run TestConstantsMatchTheAPKBytecode -v 2>/dev/null | grep -q '^--- PASS'; then
        printf '  %-26s %s\n' "APK constant check" "ran (constants match classes4.dex)"
    else
        printf '  %-26s %s\n' "APK constant check" "FAILED"
        fail=$((fail + 1))
    fi
else
    printf '  %-26s %s\n' "APK constant check" "SKIPPED (testdata/soldi.apk not present)"
    printf '      the salt and IV were not compared against the bytecode in this run\n'
fi

echo
echo "== CLI smoke test =="
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
if go build -o "$tmp/sel" ./cmd/solidexplorer-license 2>/dev/null; then
    id=a1b2c3d4e5f60718
    stored=$("$tmp/sel" encode -id "$id" -key license_status -value LICENSED 2>/dev/null)
    decoded=$("$tmp/sel" decode -id "$id" -key license_status -value "$stored" 2>/dev/null)
    if [ "$decoded" = "LICENSED" ]; then
        printf '  %-26s ok\n' "encode/decode"
        pass=$((pass + 1))
    else
        printf '  %-26s FAILED (got %s)\n' "encode/decode" "$decoded"
        fail=$((fail + 1))
    fi

    # A different device must not be able to read the value.
    if "$tmp/sel" decode -id 0000000000000000 -key license_status -value "$stored" >/dev/null 2>&1; then
        printf '  %-26s FAILED (wrong device accepted)\n' "device binding"
        fail=$((fail + 1))
    else
        printf '  %-26s ok\n' "device binding"
        pass=$((pass + 1))
    fi
else
    printf '  %-26s FAILED\n' "cli build"
    fail=$((fail + 1))
fi

echo
echo "== summary =="
printf '  passed %d, failed %d\n' "$pass" "$fail"
if [ "$fail" -ne 0 ]; then
    echo "  NOT ALL CHECKS PASSED"
    exit 1
fi
echo "  all checks passed"
