#!/usr/bin/env bash
# Installs a pinned Pulumi CLI for the CI/CD runners: download over HTTPS only, verify the SHA-256 published
# with the release, then extract. Never pipes a downloaded script into a shell.
# To upgrade: take the version and the linux-x64 line from
# https://github.com/pulumi/pulumi/releases/download/v<version>/pulumi-<version>-checksums.txt
set -euo pipefail

PULUMI_VERSION="3.268.0"
PULUMI_SHA256="903cafeaa9f6327e4bf53a8b7b99ae660f26198acfa804a2f982bf5de3f1de0b" # pulumi-v3.268.0-linux-x64.tar.gz

dest="${RUNNER_TEMP:-$(mktemp -d)}"
file="pulumi-v${PULUMI_VERSION}-linux-x64.tar.gz"
cd "$dest"
curl --proto '=https' --tlsv1.2 -fsSL -o "$file" "https://github.com/pulumi/pulumi/releases/download/v${PULUMI_VERSION}/${file}"
echo "${PULUMI_SHA256}  ${file}" | sha256sum -c -
tar -xzf "$file"
rm -f "$file"
if [[ -n "${GITHUB_PATH:-}" ]]; then echo "$dest/pulumi" >> "$GITHUB_PATH"; fi
"$dest/pulumi/pulumi" version
