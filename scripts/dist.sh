#!/usr/bin/env bash
# Builds the release archives of the plugin: dist/runnel-plugin-<name>_<version>_<os>_<arch>.zip,
# each with the folder <name>/ (plugin.yaml, bin/<name>[.exe], LICENSE, THIRD_PARTY_NOTICES),
# and dist/SHA256SUMS (docs/dev/PLUGINS.md of Runnel, "Namen und Veröffentlichung").
# The plugin.yaml in the archive names only the program of its system.
set -euo pipefail

name=$(sed -n 's/^name:[[:space:]]*//p' plugin.yaml)
version=$(sed -n 's/^version:[[:space:]]*//p' plugin.yaml)
platforms=${PLATFORMS:-"windows/amd64 windows/arm64 linux/amd64 linux/arm64 darwin/arm64"}

rm -rf dist
mkdir -p dist
for platform in $platforms; do
	goos=${platform%/*}
	goarch=${platform#*/}
	exe=$name
	[ "$goos" = windows ] && exe=$name.exe
	stage=dist/stage/${goos}_${goarch}/$name
	mkdir -p "$stage/bin"
	CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch go build -trimpath -ldflags "-s -w" -o "$stage/bin/$exe" .
	# executable only for this system, so the archive needs nothing else
	sed '/^executable:/,/^[^[:space:]]/{/^executable:/!{/^[[:space:]]/d}}' plugin.yaml |
		sed "s|^executable:.*|executable: bin/$exe|" >"$stage/plugin.yaml"
	cp LICENSE THIRD_PARTY_NOTICES "$stage/"
	archive=runnel-plugin-${name}_${version}_${goos}_${goarch}.zip
	(cd "dist/stage/${goos}_${goarch}" && zip -qrX "../../$archive" "$name")
	echo "dist/$archive"
done
rm -rf dist/stage
(cd dist && sha256sum ./*.zip | sed 's| \./| |' >SHA256SUMS)
