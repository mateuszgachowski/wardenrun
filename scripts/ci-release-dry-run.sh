#!/bin/sh
# CI: runs the whole signing pipeline with a throw-away certificate, so that a broken script is
# found in a pull request and not at the first tag. macOS only; touches a temporary keychain and
# nothing else. The result is NOT a release: the certificate is generated here and thrown away.
# Usage: sh scripts/ci-release-dry-run.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)

[ "$(uname -s)" = Darwin ] || { echo "ci-release-dry-run: needs macOS" >&2; exit 1; }

work=$(mktemp -d "${TMPDIR:-/tmp}/wardenrun-dry-run.XXXXXX")
keychain="$work/signing.keychain-db"
cleanup() {
    security delete-keychain "$keychain" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM

# Use the system openssl (LibreSSL): its PKCS#12 output is what `security import` reads.
cat > "$work/cert.conf" <<CONF
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = wardenrun ci dry run
[ext]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, codeSigning
CONF
/usr/bin/openssl req -x509 -newkey rsa:2048 -nodes -days 2 -config "$work/cert.conf" \
    -keyout "$work/key.pem" -out "$work/cert.pem" >/dev/null 2>&1
P12_PASSWORD=$(/usr/bin/openssl rand -hex 16)
KEYCHAIN_PASSWORD=$(/usr/bin/openssl rand -hex 16)
export P12_PASSWORD KEYCHAIN_PASSWORD
/usr/bin/openssl pkcs12 -export -inkey "$work/key.pem" -in "$work/cert.pem" -out "$work/cert.p12" \
    -passout env:P12_PASSWORD >/dev/null 2>&1

cert=$(sh "$here/import-signing-cert.sh" "$work/cert.p12" "$keychain")
echo "dry run: imported a throw-away certificate, SHA-1 $cert"

# 0.0.0 only names the tarball; the binary says what the source says.
SIGN_IDENTITY=$cert SIGN_KEYCHAIN=$keychain DIST="$work/dist" sh "$here/package-release.sh" 0.0.0
# The release workflow deletes the signing keychain right after signing, before it runs the
# signed binary: do the same here, so that the dry run covers that order.
security delete-keychain "$keychain"
asset=$(sh "$here/release-info.sh" name 0.0.0)
mkdir "$work/unpacked"
tar -C "$work/unpacked" -xzf "$work/dist/$asset"
(cd "$work/dist" && shasum -a 256 -c "$asset.sha256")
source_version=$(sh "$here/release-info.sh" print-version "$root")
sh "$here/verify-release-binary.sh" "$work/unpacked/wardenrun" "$cert" "$source_version"

# A different certificate must not satisfy the verifier.
status=0
wrong=$(sh "$here/verify-release-binary.sh" "$work/unpacked/wardenrun" 0000000000000000000000000000000000000000 "$source_version" 2>&1) || status=$?
[ "$status" -eq 1 ] || { echo "dry run: the verifier accepted the wrong certificate ($status)" >&2; exit 1; }
printf '%s\n' "$wrong" | grep -q 'does not name certificate' || { echo "dry run: unexpected verifier output: $wrong" >&2; exit 1; }

# The formula renders and its Ruby parses.
sha=$(cut -d ' ' -f 1 "$work/dist/$asset.sha256")
sh "$here/render-formula.sh" 0.0.0 "$sha" "$cert" > "$work/wardenrun.rb"
ruby -c "$work/wardenrun.rb" >/dev/null

echo "dry run: ok"
