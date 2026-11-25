#!/usr/bin/env bash
# Checks the licenses in CycloneDX SBOMs against the licenses Runnel allows for compiled-in
# software (MIT-compatible, ADR 0004 of Runnel). Fails for any other or a missing license.
# The Go standard library (purl pkg:golang/std@…) has no license in the SBOMs of
# cyclonedx-gomod; its license is BSD-3-Clause (the Go license, text in THIRD_PARTY_NOTICES).
# Usage: scripts/check-licenses.sh dist/*.cdx.json
set -euo pipefail

allowed='["MIT","BSD-2-Clause","BSD-3-Clause","Apache-2.0","ISC"]'
status=0
for sbom in "$@"; do
	bad=$(jq -r --argjson allowed "$allowed" '
		.components[]? | . as $c |
		[$c.licenses[]? | .license.id // .expression // empty] as $raw |
		(if ($raw | length) == 0 and (($c.purl // "") | startswith("pkg:golang/std@")) then ["BSD-3-Clause"] else $raw end) as $ids |
		select(($ids | length) == 0 or any($ids[]; . as $id | ($allowed | index($id)) == null)) |
		"\($c.name) \($c.version // "") \(if ($ids | length) == 0 then "(no license)" else ($ids | join(", ")) end)"
' "$sbom")
	if [[ -n "$bad" ]]; then
		echo "ERROR: $sbom has licenses that are not allowed (allowed: $allowed):" >&2
		echo "$bad" >&2
		status=1
	fi
done
exit $status
