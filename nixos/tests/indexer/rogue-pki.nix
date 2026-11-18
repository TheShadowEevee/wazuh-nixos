# A CA that the test PKI does not trust, and one client certificate from it.
# The certificate copies the admin subject of nixos/tests/common/pki.nix, so
# only the CA check can tell it apart from the real admin certificate.
#
# This is separate from common/pki.nix: a change there changes every check.
# Do not use these keys outside tests. They are in the world-readable store.
{ pkgs }:
let
  out = pkgs.runCommand "wazuh-test-rogue-pki" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir -p $out
    cd $out
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -subj "/OU=Wazuh/O=Wazuh/CN=wazuh-test-rogue-ca" \
      -keyout ca.key -out ca.pem
    openssl req -newkey rsa:2048 -nodes \
      -subj "/OU=Wazuh/O=Wazuh/CN=admin" \
      -keyout admin.rsa.key -out admin.csr
    printf 'extendedKeyUsage=clientAuth\n' > admin.ext
    openssl x509 -req -in admin.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
      -days 3650 -extfile admin.ext -out admin.pem
    openssl pkcs8 -topk8 -nocrypt -in admin.rsa.key -out admin.key
    openssl verify -CAfile ca.pem admin.pem
    rm ca.key admin.rsa.key admin.csr admin.ext
  '';
in
{
  ca = "${out}/ca.pem";
  admin = {
    cert = "${out}/admin.pem";
    key = "${out}/admin.key";
  };
}
