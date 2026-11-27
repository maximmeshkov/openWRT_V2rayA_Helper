#!/bin/sh
# Run the same integration tests against the program shipped in the target IPK.
# The target, its musl loader and the matching qemu-user come from the SDK itself.
set -eu

sdk=$(cd "${1:?usage: sdk_binary.sh OPENWRT_SDK_DIR}" && pwd)
tests=$(cd "$(dirname "$0")" && pwd)

set -- "$sdk"/staging_dir/target-*_musl/root-*
if [ "$#" -ne 1 ] || [ ! -d "$1" ]; then
	echo "Expected one target root in the SDK staging directory" >&2
	exit 1
fi
export V2RAYA_TEST_SYSROOT="$1"

set -- "$V2RAYA_TEST_SYSROOT"/lib/ld-musl-*.so.1
if [ "$#" -ne 1 ] || [ ! -e "$1" ]; then
	echo "Expected one musl loader in $V2RAYA_TEST_SYSROOT/lib" >&2
	exit 1
fi
export V2RAYA_TEST_LOADER="$1"
case "${V2RAYA_TEST_LOADER##*/}" in
	ld-musl-aarch64*) V2RAYA_TEST_EMULATOR=qemu-aarch64 ;;
	ld-musl-mipsel*) V2RAYA_TEST_EMULATOR=qemu-mipsel ;;
	ld-musl-mips*) V2RAYA_TEST_EMULATOR=qemu-mips ;;
	ld-musl-armhf*|ld-musl-arm*) V2RAYA_TEST_EMULATOR=qemu-arm ;;
	ld-musl-x86_64*) V2RAYA_TEST_EMULATOR= ;;
	*) echo "No emulator known for ${V2RAYA_TEST_LOADER##*/}" >&2; exit 1 ;;
esac
export V2RAYA_TEST_EMULATOR

set -- "$sdk"/bin/packages/*/*/v2raya-helper_*.ipk
if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
	echo "Expected one backend IPK in the SDK package output" >&2
	exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
tar -xzOf "$1" ./data.tar.gz | tar -xz -C "$tmp" ./usr/bin/v2raya-helper
export V2RAYA_TEST_BINARY="$tmp/usr/bin/v2raya-helper"
cat > "$tmp/run-helper" <<'EOF'
#!/bin/sh
# Use the SDK libraries while keeping the host filesystem root visible to openat().
exec $V2RAYA_TEST_EMULATOR "$V2RAYA_TEST_LOADER" \
	--library-path "$V2RAYA_TEST_SYSROOT/lib:$V2RAYA_TEST_SYSROOT/usr/lib" "$V2RAYA_TEST_BINARY" "$@"
EOF
chmod 755 "$tmp/run-helper"
"$tmp/run-helper" --help
PYTHONDONTWRITEBYTECODE=1 V2RAYA_HELPER="$tmp/run-helper" python3 -m unittest discover -s "$tests" -v
