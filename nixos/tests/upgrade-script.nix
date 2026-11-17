# scripts/upgrade-wazuh.sh without a network.
#
# The script edits seven pin files and the submodule link, and it promises to
# restore all of them if a step fails. This check runs the real script in a
# git checkout of the pin files. curl, nix-prefetch-url and nix are stubs, so
# the check covers the argument handling, the guards before the first edit and
# the restore after a failed step. It does not cover a completed upgrade,
# because that needs the real archives.
#
# plant = "no-restore" removes the restore from the script. The check must
# fail with it. That shows that the failed step came after an edit.
{
  pkgs,
  plant ? null,
}:
let
  inherit (pkgs) lib;
  source = lib.fileset.toSource {
    root = ../..;
    fileset = lib.fileset.unions [
      ../../scripts
      ../../pkgs
      ./common
    ];
  };
  fakeRev = "1111111111111111111111111111111111111111";
  fakeHttpRev = "2222222222222222222222222222222222222222";
  oldLink = "3333333333333333333333333333333333333333";

  makefile = pkgs.writeText "Makefile" ''
    DEPS_VERSION = 99
    HTTP_REQUEST_BRANCH = ${fakeHttpRev}
    EXTERNAL_RES := openssl zlib cJSON
    ifeq (''${TARGET},server)
    	EXTERNAL_RES += $(CPYTHON) jemalloc
    endif
  '';

  # The stub answers what steps 2 and 3 ask for and refuses everything else.
  # The first refused request with a real consumer is the archive download in
  # step 6, after step 4 edited pkgs/common/default.nix.
  curl = pkgs.writeShellScriptBin "curl" ''
    output=""
    url=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        -o) output="$2"; shift 2 ;;
        -H | --retry | -w) shift 2 ;;
        -*) shift ;;
        *) url="$1"; shift ;;
      esac
    done
    echo "$url" >> "$CURL_LOG"
    answer() {
      if [ -n "$output" ]; then cat > "$output"; else cat; fi
    }
    case "$url" in
      https://api.github.com/repos/wazuh/wazuh/git/refs/tags/v9.9.9)
        echo '{"object":{"type":"commit","sha":"${fakeRev}"}}' | answer ;;
      https://raw.githubusercontent.com/wazuh/wazuh/${fakeRev}/src/Makefile)
        answer < "$MAKEFILE" ;;
      https://raw.githubusercontent.com/wazuh/wazuh/v9.9.9/src/syscheckd/src/ebpf/src/modern.bpf.c)
        echo 'int placeholder;' | answer ;;
      *)
        exit 22 ;;
    esac
  '';
  nixPrefetchUrl = pkgs.writeShellScriptBin "nix-prefetch-url" ''
    echo 0000000000000000000000000000000000000000000000000000
  '';
  nix = pkgs.writeShellScriptBin "nix" ''
    echo sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
  '';
in
pkgs.runCommand "wazuh-upgrade-script${lib.optionalString (plant != null) "-plant-${plant}"}"
  {
    nativeBuildInputs = [
      curl
      nixPrefetchUrl
      nix
      pkgs.git
      pkgs.jq
      pkgs.openssl
      pkgs.gnutar
      pkgs.gzip
      pkgs.gawk
      pkgs.gnused
      pkgs.findutils
    ];
    MAKEFILE = makefile;
  }
  ''
    export HOME="$TMPDIR/home"
    mkdir -p "$HOME"
    cp -R ${source} repo
    chmod -R u+w repo
    cd repo
    patchShebangs scripts pkgs nixos > /dev/null
    ${lib.optionalString (plant == "no-restore") ''
      sed -i 's|^\tgit checkout HEAD -- "''${pin_files\[@\]}"$|\ttrue|' scripts/upgrade-wazuh.sh
      if grep -q 'git checkout HEAD' scripts/upgrade-wazuh.sh; then exit 1; fi
    ''}
    mkdir -p modules/wazuh
    git init -q .
    git add -A
    git update-index --add --cacheinfo 160000,${oldLink},modules/wazuh
    git -c user.name=test -c user.email=test@example.invalid commit -q -m pins

    export CURL_LOG="$TMPDIR/curl.log"
    script=scripts/upgrade-wazuh.sh
    current="$(sed -n 's/^  version = "\([^"]*\)";$/\1/p' pkgs/common/default.nix)"
    [ -n "$current" ]

    fail() {
      echo "FAILED: $*" >&2
      echo "--- stdout" >&2; cat "$TMPDIR/stdout" >&2
      echo "--- stderr" >&2; cat "$TMPDIR/stderr" >&2
      exit 1
    }
    # run <expected exit code> <arguments>
    run() {
      local expected="$1" code=0
      shift
      : > "$CURL_LOG"
      bash "$script" "$@" > "$TMPDIR/stdout" 2> "$TMPDIR/stderr" || code=$?
      [ "$code" = "$expected" ] || fail "'$*' gave exit code $code, expected $expected"
    }
    unchanged() {
      git diff --quiet HEAD || fail "$1: the work tree differs from the commit"
      [ "$(git ls-files -s modules/wazuh | awk '{print $2}')" = ${oldLink} ] ||
        fail "$1: the submodule link moved"
    }
    no_request() {
      [ ! -s "$CURL_LOG" ] || fail "$1: the script made a request: $(cat "$CURL_LOG")"
    }

    echo "bad usage gives exit code 2 and changes nothing"
    run 2
    run 2 --no-such-option 9.9.9
    run 2 9.9.9 8.8.8
    run 2 9.9.9 --package-revision two
    run 2 9.9
    run 2 v9.9.9
    unchanged "bad usage"
    no_request "bad usage"

    echo "the current version is reported without a request"
    run 0 "$current"
    [ "$(tail -n1 "$TMPDIR/stdout")" = "current $current" ] || fail "no 'current' line"
    unchanged "current version"
    no_request "current version"

    echo "an uncommitted change in a pin file stops the script and survives"
    echo '# local note' >> pkgs/wazuh-indexer/source.json
    run 1 9.9.9
    grep -q 'uncommitted changes' "$TMPDIR/stderr" || fail "no message about uncommitted changes"
    [ "$(tail -n1 pkgs/wazuh-indexer/source.json)" = '# local note' ] ||
      fail "the script discarded an uncommitted change"
    no_request "uncommitted change"
    git checkout HEAD -- pkgs/wazuh-indexer/source.json

    echo "a tag that does not exist stops the script before an edit"
    run 1 9.9.8
    grep -q 'has no tag v9.9.8' "$TMPDIR/stderr" || fail "no message about the tag"
    unchanged "missing tag"

    echo "a Makefile without DEPS_VERSION stops the script before an edit"
    grep -v '^DEPS_VERSION' ${makefile} > "$TMPDIR/Makefile.bad"
    MAKEFILE="$TMPDIR/Makefile.bad" run 1 9.9.9
    grep -q 'cannot read DEPS_VERSION' "$TMPDIR/stderr" || fail "no message about DEPS_VERSION"
    unchanged "bad Makefile"

    echo "a failed step after the first edit restores every pin file"
    run 1 9.9.9
    grep -q 'moving from '"$current"' to 9.9.9' "$TMPDIR/stderr" || fail "the upgrade did not start"
    grep -q 'hashing the agent dependency archives' "$TMPDIR/stderr" ||
      fail "the script did not reach the step after the edit"
    grep -q 'Restoring the pin files' "$TMPDIR/stderr" || fail "no restore message"
    ! grep -q '^changed ' "$TMPDIR/stdout" || fail "the script reported a change"
    unchanged "failed step"

    touch "$out"
  ''
