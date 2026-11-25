#!/usr/bin/env bash
# Prints the license texts of all third-party software compiled into the plugin: the Go
# modules of every release target and the Go standard library. Required by the licenses of
# those dependencies (ADR 0004 of Runnel). Fails if a module has no license file.
set -euo pipefail

cd "$(dirname "$0")/.."
name=$(sed -n 's/^name:[[:space:]]*//p' plugin.yaml)
platforms=${PLATFORMS:-"windows/amd64 windows/arm64 linux/amd64 linux/arm64 darwin/arm64"}

cat <<HEADER
Third-party software notices for the Runnel plugin $name
$(printf '=%.0s' $(seq 1 $((44 + ${#name}))))

The plugin includes the following third-party software. Their license texts follow.
HEADER

# Union of the dependencies of all release targets (some are platform-specific).
modules() {
	for platform in $platforms; do
		GOOS=${platform%/*} GOARCH=${platform#*/} go list -deps \
			-f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}} {{.Dir}}{{end}}{{end}}' .
	done
	# The Go standard library and runtime are compiled into every binary as well.
	echo "Go-standard-library $(go env GOVERSION) $(go env GOROOT)"
}

go mod download
modules |
	sort -u |
	while read -r path version dir; do
		[[ -z "$path" ]] && continue
		printf '\n\n--------------------------------------------------------------------------------\n'
		printf '%s %s\n' "$path" "$version"
		printf -- '--------------------------------------------------------------------------------\n\n'
		found=0
		for f in "$dir"/LICENSE* "$dir"/LICENCE* "$dir"/COPYING* "$dir"/NOTICE*; do
			[[ -f "$f" ]] || continue
			cat "$f"
			found=1
		done
		if [[ $found -eq 0 ]]; then
			echo "ERROR: no license file found for $path $version" >&2
			exit 1
		fi
	done
