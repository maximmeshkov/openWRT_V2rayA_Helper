#!/bin/bash
# Build both IPKs in a pinned OpenWrt SDK and run the tests against the shipped binary.
# Usage: sdk-package.sh RELEASE TARGET OUTPUT_DIR    (TARGET like mediatek/filogic)
# Works in the current directory; CI and a local run use the same script.
set -euo pipefail
release=${1:?release} target=${2:?target} out=${3:?output directory}
repo=$(cd "$(dirname "$0")/.." && pwd)

# Feed commits come from the release's feeds.buildinfo; base is the release tag commit.
case "$release" in
	23.05.5)
		gcc=12.3.0 ext=xz
		base=28cf53e6bd9bb68958aae7958e7950d967f02b46
		packages=b5ed85f6e94aa08de1433272dc007550f4a28201
		luci=63ba3cba5b7bfb803a875d4d8f01248634687fd5 ;;
	24.10.8)
		gcc=13.3.0 ext=zst
		base=0b795ce79e23b553aa184080c390f9ce92a2b6d4
		packages=23abaa6f3b0fdfd76b570031107e5718476ff0c8
		luci=cac97ed67cfbcad90db49f5f3b1245c2c4cbfae5 ;;
	*) echo "Unknown OpenWrt release $release" >&2; exit 2 ;;
esac

archive="openwrt-sdk-$release-${target//\//-}_gcc-${gcc}_musl.Linux-x86_64.tar.$ext"
[ -f "$archive" ] || curl -fL --retry 3 -O "https://downloads.openwrt.org/releases/$release/targets/$target/$archive"
grep -F "  $archive" "$repo/.github/openwrt-sdk.sha256" | sha256sum -c -
rm -rf sdk
mkdir sdk
tar -xf "$archive" --strip-components=1 -C sdk
cd sdk

fetch_feed() {
	local name=$1 repository=$2 ref=$3
	local dir="$PWD/release-feeds/$name"
	git init -q "$dir"
	git -C "$dir" fetch -q --depth=1 "https://github.com/openwrt/$repository.git" "$ref"
	git -C "$dir" checkout -q --detach FETCH_HEAD
	echo "src-link $name $dir" >> feeds.conf
}
: > feeds.conf
fetch_feed base openwrt "$base"
fetch_feed packages packages "$packages"
fetch_feed luci luci "$luci"
mkdir -p package/v2raya-helper
cp -r "$repo"/{Makefile,files,src} package/v2raya-helper/
./scripts/feeds update -a
./scripts/feeds install libcurl libjson-c ca-bundle rpcd luci-mod-status
printf '%s\n' CONFIG_PACKAGE_v2raya-helper=m CONFIG_PACKAGE_luci-app-v2raya-helper=m >> .config
make defconfig
make -j"$(nproc)" package/v2raya-helper/compile V=s
sh "$repo/tests/sdk_binary.sh" "$PWD"

mkdir -p "$out"
find bin/packages -name '*v2raya-helper_*.ipk' -exec cp '{}' "$out" \;
cd "$out"
test -f "$(ls v2raya-helper_*.ipk)"
test -f "$(ls luci-app-v2raya-helper_*.ipk)"
sha256sum *.ipk > SHA256SUMS
