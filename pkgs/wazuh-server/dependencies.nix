{ fetchurl, stdenv, dependencyVersion, lib }:
let
  manifestPath = ./dependency-hashes.json;
  hashes = if builtins.pathExists manifestPath then builtins.fromJSON (builtins.readFile manifestPath)
    else throw "Wazuh server dependency hashes missing: run pkgs/wazuh-server/prefetch-dependencies.sh on a host with packages.wazuh.com access";
  arch = if stdenv.hostPlatform.isx86_64 then "x86_64"
    else if stdenv.hostPlatform.isAarch64 then "arm64"
    else throw "Wazuh server supports x86_64-linux and aarch64-linux";
  # The manifest names the archives. prefetch-dependencies.sh writes one key per
  # manager-only name in src/Makefile, so a new upstream name needs no edit here.
  # The four names below come first in their old order, so the derivation
  # inputs do not change for the current manifest.
  known = [ "jemalloc" "flatbuffers" "simdjson" ];
  others = lib.filter (n: !(lib.elem n known) && !(lib.hasPrefix "cpython_" n)) (builtins.attrNames hashes);
  names = [ "cpython_${arch}" ] ++ lib.filter (n: hashes ? ${n}) known ++ others;
in
map (name: fetchurl {
  url = "https://packages.wazuh.com/deps/${dependencyVersion}/libraries/sources/${name}.tar.gz";
  hash = hashes.${name};
}) names
