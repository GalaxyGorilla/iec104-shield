#!/bin/sh
# Verify the release assets produced by `make release-assets`.
#
#   sh scripts/verify-release.sh
#
# Checks every SHA256 in dist/SHA256SUMS and, when a detached signature exists,
# verifies it with gpg. Exit 77 when gpg is needed but missing.
set -eu
cd "$(dirname "$0")/.."

[ -f dist/SHA256SUMS ] || {
	echo "missing dist/SHA256SUMS; run 'make release-assets' first" >&2
	exit 1
}

echo "== checking SHA256SUMS"
(cd dist && shasum -a 256 -c SHA256SUMS)

found=0
for sig in dist/*.asc; do
	[ -f "$sig" ] || continue
	found=1
	base=${sig%.asc}
	command -v gpg >/dev/null 2>&1 || {
		echo "gpg is required to verify $sig" >&2
		exit 77
	}
	echo "== verifying $sig"
	gpg --batch --verify "$sig" "$base"
done

if [ "$found" = "0" ]; then
	echo "no detached signatures found; checksums verified only"
fi
echo "release verification: PASS"
