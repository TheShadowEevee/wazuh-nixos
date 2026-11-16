#!/usr/bin/env bash
#
# Move every Wazuh pin in this repository to one new Wazuh version.
#
# Usage:
#   ./scripts/upgrade-wazuh.sh <version|latest> [options]
#
#   <version>                 A Wazuh tag without the v, for example 4.14.9.
#   latest                    The newest non-prerelease on wazuh/wazuh.
#
# Options:
#   --package-revision <n>    Debian revision of the indexer and dashboard
#                             packages. The default is 1.
#   --skip-manager-image      Do not pin a new wazuh/wazuh-manager image for
#                             checks.enrollment. The image is several GB.
#   --pin-manager-image       Pin the image. This is the default.
#   --force                   Run the steps also when the pins already name
#                             the version.
#
# The script changes these files:
#   pkgs/common/default.nix                    version, revs, source hashes
#   pkgs/dependencies/external_dependencies.nix
#   pkgs/wazuh-server/dependency-hashes.json
#   pkgs/wazuh-indexer/source.json
#   pkgs/wazuh-dashboard/source.json
#   pkgs/wazuh-testing.nix                     qa-integration-framework tag
#   nixos/tests/common/wazuh-manager-image.nix and its <arch>.json pins
#   modules/wazuh                              submodule commit
#
# Requirements:
#   - Network access to api.github.com, github.com, raw.githubusercontent.com,
#     packages.wazuh.com and, for the manager image, registry-1.docker.io.
#   - nix, git, curl, jq, openssl, tar, gzip. `nix develop` supplies all of
#     them except nix.
#   - The files above have no uncommitted changes.
#
# If a step fails, the script restores every file above and exits 1.
# The script does not commit. Read `git diff`, then commit.
#
# Exit codes: 0 pins changed or already current, 1 failure, 2 bad usage.
# The last line on stdout is "changed <old> <new>" or "current <version>".

set -euo pipefail

usage() {
	sed -n '3,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
	exit 2
}

target=""
package_revision="1"
skip_manager_image=0
force=0
while [ "$#" -gt 0 ]; do
	case "$1" in
	--package-revision)
		[ "$#" -ge 2 ] || usage
		package_revision="$2"
		shift 2
		;;
	--pin-manager-image)
		skip_manager_image=0
		shift
		;;
	--skip-manager-image)
		skip_manager_image=1
		shift
		;;
	--force)
		force=1
		shift
		;;
	-h | --help) usage ;;
	-*)
		echo "upgrade-wazuh: unknown option $1" >&2
		usage
		;;
	*)
		[ -z "${target}" ] || usage
		target="$1"
		shift
		;;
	esac
done
[ -n "${target}" ] || usage
[[ "${package_revision}" =~ ^[0-9]+$ ]] || {
	echo "upgrade-wazuh: --package-revision must be a number." >&2
	exit 2
}

for tool in nix git curl jq openssl tar gzip awk sed; do
	if ! command -v "${tool}" >/dev/null 2>&1; then
		echo "upgrade-wazuh: ${tool} is not on the PATH. Run the script inside 'nix develop'." >&2
		exit 1
	fi
done

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"

common="pkgs/common/default.nix"
testing="pkgs/wazuh-testing.nix"
manager_nix="nixos/tests/common/wazuh-manager-image.nix"
pin_files=(
	"${common}"
	pkgs/dependencies/external_dependencies.nix
	pkgs/wazuh-server/dependency-hashes.json
	pkgs/wazuh-indexer/source.json
	pkgs/wazuh-dashboard/source.json
	"${testing}"
	"${manager_nix}"
)
for f in nixos/tests/common/wazuh-manager-image.*.json; do
	[ -e "${f}" ] && pin_files+=("${f}")
done

say() { echo "upgrade-wazuh: $*" >&2; }
die() {
	say "$*"
	exit 1
}

# GitHub allows 60 anonymous API requests per hour. A token raises the limit.
github_api() {
	local auth=()
	if [ -n "${GITHUB_TOKEN:-}" ]; then
		auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
	fi
	curl -sS --fail --retry 2 -H 'Accept: application/vnd.github+json' "${auth[@]}" "https://api.github.com/$1"
}

# Print the commit that a tag names. Annotated tags point at a tag object first.
tag_commit() {
	local repo="$1" tag="$2" ref type sha
	ref="$(github_api "repos/${repo}/git/refs/tags/${tag}")" || return 1
	type="$(jq -er '.object.type' <<<"${ref}")" || return 1
	sha="$(jq -er '.object.sha' <<<"${ref}")" || return 1
	if [ "${type}" = "tag" ]; then
		sha="$(github_api "repos/${repo}/git/tags/${sha}" | jq -er '.object.sha')" || return 1
	fi
	[[ "${sha}" =~ ^[0-9a-f]{40}$ ]] || return 1
	echo "${sha}"
}

# Print the SRI hash of an unpacked archive, as fetchFromGitHub computes it.
unpacked_sri() {
	nix-prefetch-url --unpack --type sha256 "$1" 2>/dev/null |
		xargs nix hash convert --from nix32 --to sri --hash-algo sha256
}

# Print the SRI hash of a flat file, as fetchurl computes it.
flat_sri() {
	local file
	file="$(mktemp)"
	if ! curl -sS --fail -L --retry 2 -o "${file}" "$1"; then
		rm -f "${file}"
		return 1
	fi
	echo "sha256-$(openssl dgst -sha256 -binary "${file}" | openssl base64 -A)"
	rm -f "${file}"
}

# Replace the value of `key = "..."` on the first line after a line that
# matches anchor. Fail unless exactly one line changes.
set_after() {
	local file="$1" anchor="$2" key="$3" value="$4" tmp
	tmp="$(mktemp)"
	awk -v anchor="${anchor}" -v key="${key}" -v value="${value}" '
		armed && $0 ~ "^[ ]*" key " = \"[^\"]*\";$" {
			sub("\"[^\"]*\"", "\"" value "\"")
			armed = 0
			count++
		}
		!armed && index($0, anchor) { armed = 1 }
		{ print }
		END { if (count != 1) exit 3 }
	' "${file}" >"${tmp}" || {
		rm -f "${tmp}"
		die "cannot find ${key} after '${anchor}' in ${file}. Its layout changed."
	}
	cat "${tmp}" >"${file}"
	rm -f "${tmp}"
}

# Replace `  key = "...";` at two-space indent. Fail unless exactly one matches.
set_top() {
	local file="$1" key="$2" value="$3" count
	count="$(grep -c "^  ${key} = \"[^\"]*\";$" "${file}" || true)"
	[ "${count}" = "1" ] || die "${file} has ${count} lines '  ${key} = \"...\";', expected 1."
	sed -i "s|^  ${key} = \"[^\"]*\";$|  ${key} = \"${value}\";|" "${file}"
}

read_top() {
	sed -n "s/^  $2 = \"\([^\"]*\)\";$/\1/p" "$1"
}

# 1. Resolve the version.
if [ "${target}" = "latest" ]; then
	target="$(github_api "repos/wazuh/wazuh/releases/latest" | jq -er '.tag_name')" ||
		die "cannot read the latest release of wazuh/wazuh."
	target="${target#v}"
fi
[[ "${target}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
	say "'${target}' is not a version like 4.14.9."
	exit 2
}

current="$(read_top "${common}" version)"
[ -n "${current}" ] || die "cannot read version from ${common}."
if [ "${current}" = "${target}" ] && [ "${force}" = 0 ]; then
	say "the pins already name ${target}. Use --force to run the steps again."
	echo "current ${target}"
	exit 0
fi

if ! git diff --quiet HEAD -- "${pin_files[@]}"; then
	git diff --stat HEAD -- "${pin_files[@]}" >&2
	die "the files above have uncommitted changes. Commit or discard them first."
fi

armed=0
old_gitlink="$(git ls-files -s modules/wazuh | awk '{print $2}')"
restore() {
	say "a step failed. Restoring the pin files."
	git checkout HEAD -- "${pin_files[@]}"
	if [ -n "${old_gitlink}" ]; then
		git update-index --cacheinfo "160000,${old_gitlink},modules/wazuh"
	fi
}
armed=1
trap 'rc=$?; if [ "${rc}" != 0 ] && [ "${armed}" = 1 ]; then restore; fi' EXIT
trap 'say "interrupted."; exit 1' INT TERM

say "moving from ${current} to ${target}."

# 2. Read the upstream values for the tag.
wazuh_rev="$(tag_commit wazuh/wazuh "v${target}")" || die "wazuh/wazuh has no tag v${target}."
makefile="$(curl -sS --fail -L --retry 2 "https://raw.githubusercontent.com/wazuh/wazuh/${wazuh_rev}/src/Makefile")" ||
	die "cannot download src/Makefile at v${target}."
deps_version="$(sed -n 's/^DEPS_VERSION[ ]*[?:]*=[ ]*\([0-9][0-9]*\)[ ]*$/\1/p' <<<"${makefile}" | head -n1)"
http_rev="$(sed -n 's/^HTTP_REQUEST_BRANCH[ ]*[?:]*=[ ]*\([0-9a-f]\{40\}\)[ ]*$/\1/p' <<<"${makefile}" | head -n1)"
[ -n "${deps_version}" ] || die "cannot read DEPS_VERSION from src/Makefile at v${target}."
[ -n "${http_rev}" ] || die "cannot read a commit from HTTP_REQUEST_BRANCH in src/Makefile at v${target}."
say "wazuh rev ${wazuh_rev}, DEPS_VERSION ${deps_version}, HTTP_REQUEST_BRANCH ${http_rev}."

# 3. Hash the GitHub sources.
say "hashing the GitHub sources."
wazuh_sri="$(unpacked_sri "https://github.com/wazuh/wazuh/archive/${wazuh_rev}.tar.gz")"
http_sri="$(unpacked_sri "https://github.com/wazuh/wazuh-http-request/archive/${http_rev}.tar.gz")"
bpf_sri="$(flat_sri "https://raw.githubusercontent.com/wazuh/wazuh/v${target}/src/syscheckd/src/ebpf/src/modern.bpf.c")"
for v in "${wazuh_sri}" "${http_sri}" "${bpf_sri}"; do
	[[ "${v}" =~ ^sha256-[A-Za-z0-9+/]{43}=$ ]] || die "a GitHub source hash is empty or malformed: '${v}'."
done

# 4. Write pkgs/common/default.nix. The server prefetch reads dependencyVersion
#    from it, so this comes before the package prefetch scripts.
set_top "${common}" version "${target}"
set_top "${common}" dependencyVersion "${deps_version}"
set_top "${common}" wazuhRev "${wazuh_rev}"
set_after "${common}" 'rev = wazuhRev;' sha256 "${wazuh_sri}"
set_after "${common}" 'repo = "wazuh-http-request";' rev "${http_rev}"
set_after "${common}" "rev = \"${http_rev}\";" sha256 "${http_sri}"
set_after "${common}" 'modern.bpf.c";' hash "${bpf_sri}"

# 5. The qa-integration-framework tag for the test VM.
if qa_rev="$(tag_commit wazuh/qa-integration-framework "v${target}")"; then
	qa_sri="$(unpacked_sri "https://github.com/wazuh/qa-integration-framework/archive/${qa_rev}.tar.gz")"
	[[ "${qa_sri}" =~ ^sha256-[A-Za-z0-9+/]{43}=$ ]] || die "the qa-integration-framework hash is malformed: '${qa_sri}'."
	set_top "${testing}" version "${target}"
	set_after "${testing}" 'rev = "v${version}";' hash "${qa_sri}"
else
	say "wazuh/qa-integration-framework has no tag v${target}. ${testing} is unchanged."
fi

# 6. Agent and server dependency archives from packages.wazuh.com.
say "hashing the agent dependency archives."
DEPS_VERSION="${deps_version}" WAZUH_VERSION="${target}" HTTP_REQUEST_REV="${http_rev}" \
	./pkgs/dependencies/prefetch-external-dependencies.sh >/dev/null
say "hashing the server dependency archives."
./pkgs/wazuh-server/prefetch-dependencies.sh

# 7. Indexer and dashboard packages.
for component in indexer dashboard; do
	manifest="pkgs/wazuh-${component}/source.json"
	jq --arg v "${target}" --arg r "${package_revision}" '.version = $v | .revision = $r' \
		"${manifest}" >"${manifest}.tmp"
	mv "${manifest}.tmp" "${manifest}"
done
say "hashing the indexer and dashboard packages."
./pkgs/wazuh-indexer/prefetch.sh

# 8. The manager image for checks.enrollment.
if [ "${skip_manager_image}" = 0 ]; then
	set_top "${manager_nix}" version "${target}"
	arches=()
	for f in nixos/tests/common/wazuh-manager-image.*.json; do
		[ -e "${f}" ] || continue
		a="${f#nixos/tests/common/wazuh-manager-image.}"
		arches+=("${a%.json}")
	done
	[ "${#arches[@]}" -gt 0 ] || arches=(amd64)
	for a in "${arches[@]}"; do
		./nixos/tests/common/prefetch-manager-image.sh "${target}" "${a}"
	done
else
	say "--skip-manager-image: checks.enrollment still pins $(read_top "${manager_nix}" version)."
fi

# 9. The submodule commit. Only the gitlink is required. Move the checkout too
#    when the submodule is initialized.
git update-index --cacheinfo "160000,${wazuh_rev},modules/wazuh"
if [ -e modules/wazuh/.git ]; then
	if git -C modules/wazuh fetch -q --depth 1 origin "${wazuh_rev}" 2>/dev/null &&
		git -C modules/wazuh checkout -q "${wazuh_rev}"; then
		say "modules/wazuh is checked out at ${wazuh_rev}."
	else
		say "the modules/wazuh checkout did not move. Run: git submodule update modules/wazuh"
	fi
fi

# 10. Every edited Nix file must still parse.
for f in "${common}" "${testing}" "${manager_nix}" pkgs/dependencies/external_dependencies.nix; do
	nix-instantiate --parse "${f}" >/dev/null || die "${f} does not parse after the edit."
done

armed=0
git status --short -- "${pin_files[@]}" modules/wazuh >&2
say "done. Read 'git diff --cached modules/wazuh; git diff', then commit."
echo "changed ${current} ${target}"
