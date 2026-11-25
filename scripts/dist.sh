#!/usr/bin/env bash
# Builds the release archives of the plugin: dist/runnel-plugin-<name>_<version>_<os>_<arch>.zip,
# each with the folder <name>/ (plugin.yaml, README.md, bin/<name>[.exe], LICENSE, THIRD_PARTY_NOTICES),
# a CycloneDX SBOM per archive (.cdx.json) and dist/SHA256SUMS (docs/dev/PLUGINS.md of Runnel,
# "Namen und Veröffentlichung"). THIRD_PARTY_NOTICES and the SBOMs are generated from the
# dependencies; a dependency without license or with a license that is not allowed fails.
# The plugin.yaml in the archive names only the program of its system.
# CYCLONEDX_GOMOD is the path of cyclonedx-gomod (make dist installs the pinned version).
set -euo pipefail

name=$(sed -n 's/^name:[[:space:]]*//p' plugin.yaml)
version=$(sed -n 's/^version:[[:space:]]*//p' plugin.yaml)
platforms=${PLATFORMS:-"windows/amd64 windows/arm64 linux/amd64 linux/arm64 darwin/arm64"}

cyclonedx=${CYCLONEDX_GOMOD:-cyclonedx-gomod}

rm -rf dist
mkdir -p dist
PLATFORMS=$platforms scripts/third-party-notices.sh >dist/THIRD_PARTY_NOTICES
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
	cp LICENSE README.md dist/THIRD_PARTY_NOTICES "$stage/"
	archive=runnel-plugin-${name}_${version}_${goos}_${goarch}.zip
	(cd "dist/stage/${goos}_${goarch}" && zip -qrX "../../$archive" "$name")
	GOOS=$goos GOARCH=$goarch "$cyclonedx" app -json -licenses -assert-licenses -std \
		-main . -output "dist/${archive%.zip}.cdx.json" .
	echo "dist/$archive"
done
rm -rf dist/stage dist/THIRD_PARTY_NOTICES
scripts/check-licenses.sh dist/*.cdx.json
(cd dist && sha256sum ./*.zip ./*.cdx.json | sed 's| \./| |' >SHA256SUMS)
