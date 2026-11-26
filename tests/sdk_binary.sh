#!/bin/sh
# Run the same integration tests against the program shipped in the BPI-R3 IPK.
set -eu

sdk=$(cd "${1:?usage: sdk_binary.sh OPENWRT_SDK_DIR}" && pwd)
tests=$(cd "$(dirname "$0")" && pwd)
export V2RAYA_TEST_SYSROOT="$sdk/staging_dir/target-aarch64_cortex-a53_musl/root-mediatek"
test -e "$V2RAYA_TEST_SYSROOT/lib/ld-musl-aarch64.so.1"

set -- "$sdk"/bin/packages/aarch64_cortex-a53/*/v2raya-helper_*_aarch64_cortex-a53.ipk
if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
	echo "Expected one BPI-R3 backend IPK in the SDK package output" >&2
	exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
tar -xzOf "$1" ./data.tar.gz | tar -xz -C "$tmp" ./usr/bin/v2raya-helper
export V2RAYA_TEST_BINARY="$tmp/usr/bin/v2raya-helper"
cat > "$tmp/run-helper" <<'EOF'
#!/bin/sh
# Use the SDK libraries while keeping the host filesystem root visible to openat().
exec qemu-aarch64 "$V2RAYA_TEST_SYSROOT/lib/ld-musl-aarch64.so.1" \
	--library-path "$V2RAYA_TEST_SYSROOT/lib:$V2RAYA_TEST_SYSROOT/usr/lib" "$V2RAYA_TEST_BINARY" "$@"
EOF
chmod 755 "$tmp/run-helper"
"$tmp/run-helper" --help
PYTHONDONTWRITEBYTECODE=1 V2RAYA_HELPER="$tmp/run-helper" python3 -m unittest discover -s "$tests" -v
