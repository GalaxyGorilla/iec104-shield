#!/bin/sh
# Sign release assets with a GPG key.
#
#   RELEASE_GPG_KEY=<key-id-or-fingerprint> sh scripts/release-sign.sh
#
# Run `make release-assets` first. Exit 77 when gpg is missing; a missing key
# is an error, not a skip, so a release cannot silently go unsigned.
set -eu
cd "$(dirname "$0")/.."

command -v gpg >/dev/null 2>&1 || {
	echo "skip: gpg not installed" >&2
	exit 77
}
[ -n "${RELEASE_GPG_KEY:-}" ] || {
	echo "RELEASE_GPG_KEY is required (key id or fingerprint)" >&2
	exit 1
}
[ -f dist/SHA256SUMS ] || {
	echo "missing dist/SHA256SUMS; run 'make release-assets' first" >&2
	exit 1
}

for f in dist/SHA256SUMS dist/*.spdx.json dist/*.cdx.json; do
	[ -f "$f" ] || continue
	gpg --batch --yes --local-user "$RELEASE_GPG_KEY" --armor --detach-sign "$f"
	gpg --batch --verify "$f.asc" "$f" >/dev/null
	echo "signed $f"
done
echo "release signing: PASS"
