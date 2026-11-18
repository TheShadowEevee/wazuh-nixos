# plant: null for the check. A name from plants below builds the same test
# with one gap planted, to show that a subtest fails on it:
#
#   nix build --impure --expr '(import ./nixos/tests/indexer {
#     pkgs = import <nixpkgs> { }; plant = "tls"; })'
{ pkgs, plant ? null }:
let
  inherit (pkgs) lib;
  pki = import ../common/pki.nix { inherit pkgs; };
  rogue = import ./rogue-pki.nix { inherit pkgs; };
  fixture = import ./fixture.nix { inherit pkgs pki; };
  inherit (fixture) rotated;
  # Each plant breaks one property that one subtest asserts.
  plants = {
    # The trust store also holds the rogue CA.
    tls.services.wazuh-indexer.tls.ca = lib.mkForce (toString (pkgs.runCommand "ca-with-rogue.pem" { } ''
      cat ${pki.ca} ${rogue.ca} > $out
    ''));
    # A restart of the indexer no longer reruns securityadmin. Three links
    # each rerun it: partOf and requires stop it with the indexer, and the
    # indexer's wants starts it again. partOf alone did not plant the gap.
    # The unit still starts once at boot, from multi-user.target.
    revert.systemd.services = {
      wazuh-indexer-security.wantedBy = [ "multi-user.target" ];
      wazuh-indexer-security.partOf = lib.mkForce [ ];
      wazuh-indexer-security.requires = lib.mkForce [ ];
      wazuh-indexer.wants = lib.mkForce [ "network-online.target" ];
    };
    # The data directory does not survive a reboot.
    reboot.virtualisation.fileSystems."/var/lib/wazuh-indexer" = {
      device = "tmpfs";
      fsType = "tmpfs";
    };
  };
in
assert plant == null || plants ? ${plant};
pkgs.testers.runNixOSTest {
  name = "wazuh-indexer" + lib.optionalString (plant != null) "-plant-${plant}";
  nodes.indexer = { lib, ... }: {
    imports = [ fixture.module ] ++ lib.optional (plant != null) plants.${plant};
    # Specific LAN address, not wildcard: admin must still reach hostname
    # loopback, while clients can reach the explicitly selected interface.
    networking.interfaces.eth1.ipv4.addresses = lib.mkForce [ { address = "192.168.1.10"; prefixLength = 24; } ];
    services.wazuh-indexer.listenAddress = lib.mkForce "192.168.1.10";
    environment.systemPackages = [ pkgs.curl pkgs.jq pkgs.python3 ];
  };
  # A second isolated indexer exercises the production loopback defaults. The
  # test driver's generated LAN host mapping is replaced with NixOS's normal
  # local hostname mapping, so this specifically catches 127.0.0.1-only binds.
  nodes.indexer2 = { lib, ... }: {
    imports = [ (import ./fixture.nix { inherit pkgs pki; nodeName = "indexer2"; defaultListen = true; }).module ];
    networking.hosts = lib.mkForce {
      "127.0.0.2" = [ "indexer2" ];
      "127.0.0.1" = [ "localhost" ];
      "::1" = [ "localhost" ];
    };
    environment.systemPackages = [ pkgs.curl pkgs.jq ];
    # The admin hash lives in a mutable runtime file, as with a secret
    # manager, so the test can rotate it. Seeded once per boot.
    services.wazuh-indexer.users.admin.passwordHashFile = lib.mkForce "/run/secrets/indexer-admin-hash";
    system.activationScripts.indexer-admin-hash = ''
      [ -e /run/secrets/indexer-admin-hash ] || install -D -m400 ${fixture.secrets}/hash /run/secrets/indexer-admin-hash
    '';
  };
  testScript = ''
    start_all()
    indexer2.wait_until_succeeds("systemctl is-active wazuh-indexer-security.service", timeout=900)
    # securityadmin can finish before the HTTP authentication backend has
    # loaded its configuration. Wait for an authenticated request on each
    # independent node before asserting its bind behavior.
    indexer2.wait_until_succeeds("curl --fail --silent --show-error --connect-timeout 3 --max-time 10 --cacert ${pki.ca} -u 'admin:Test-password-42!' https://indexer2:9200", timeout=120)
    indexer2.succeed("curl --fail --silent --cacert ${pki.ca} --resolve indexer2:9200:127.0.0.1 -u 'admin:Test-password-42!' https://indexer2:9200")
    indexer.fail("curl --connect-timeout 3 --fail --silent --cacert ${pki.ca} -u 'admin:Test-password-42!' https://indexer2:9200")
    indexer.wait_for_unit("wazuh-indexer.service")
    indexer.wait_until_succeeds("systemctl is-active wazuh-indexer-security.service", timeout=900)
    indexer2.wait_until_succeeds("curl --fail --silent --show-error --connect-timeout 3 --max-time 10 --cacert ${pki.ca} --resolve indexer:9200:192.168.1.10 -u 'admin:Test-password-42!' https://indexer:9200", timeout=120)
    base = "curl --fail --silent --show-error --cacert ${pki.ca} -u 'admin:Test-password-42!'"
    indexer.wait_until_succeeds(base + " 'https://indexer:9200/_cluster/health?wait_for_status=yellow&timeout=5s' | jq -e '.status == \"yellow\" or .status == \"green\"'")
    indexer.succeed(base + " -H 'Content-Type: application/json' -XPUT 'https://indexer:9200/nixos-test/_doc/1?refresh=true' -d '{\"message\":\"persistent\"}'")
    indexer.succeed("systemctl restart wazuh-indexer")
    indexer.wait_until_succeeds("systemctl is-active wazuh-indexer-security.service", timeout=900)
    indexer.wait_until_succeeds(base + " https://indexer:9200/nixos-test/_doc/1 | jq -e '._source.message == \"persistent\"'")
    indexer.fail("curl --fail --silent --cacert ${pki.wrongCa} -u 'admin:Test-password-42!' https://indexer:9200")
    indexer.fail("curl --fail --silent --cacert ${pki.ca} -u admin:wrong https://indexer:9200")
    indexer.fail("curl --fail --silent --cacert ${pki.ca} -u admin:admin https://indexer:9200")
    indexer.succeed("test $(stat -c %a /run/wazuh-indexer/node.key) = 600")
    indexer.fail("sudo -u nobody cat /run/wazuh-indexer/node.key")
    indexer.succeed("test $(systemctl show wazuh-indexer -p User --value) = wazuh-indexer")
    indexer.succeed("test $(systemctl show wazuh-indexer -p ProtectSystem --value) = strict")

    old = "Test-password-42!"
    new = "Rotated-password-43!"
    def admin(password):
        return f"curl --fail --silent --cacert ${pki.ca} -u 'admin:{password}' https://indexer2:9200"
    security = "wazuh-indexer-security.service"

    with subtest("a rotated hash file takes effect when the security unit reruns"):
        indexer2.succeed("install -m400 ${rotated}/hash /run/secrets/indexer-admin-hash")
        indexer2.succeed(f"systemctl restart {security}")
        indexer2.wait_until_succeeds(admin(new), timeout=120)
        indexer2.fail(admin(old))

    with subtest("an invalid hash fails the unit and leaves the active users alone"):
        indexer2.succeed("printf not-a-bcrypt-hash > /run/secrets/indexer-admin-hash")
        indexer2.fail(f"systemctl restart {security}")
        indexer2.succeed(f"journalctl -u {security} | grep -q 'Invalid bcrypt credential for indexer user'")
        # Neither the bad value nor the active hash reaches the journal.
        indexer2.fail(f"journalctl -u {security} | grep -q -F not-a-bcrypt-hash")
        indexer2.fail(f"journalctl -u {security} | grep -q -F \"$(cat ${rotated}/hash)\"")
        indexer2.succeed(admin(new))
        indexer2.fail(admin(old))

    with subtest("a valid hash file recovers through Restart=on-failure, without a manual start"):
        indexer2.succeed("install -m400 ${fixture.secrets}/hash /run/secrets/indexer-admin-hash")
        indexer2.wait_until_succeeds(f"systemctl is-active {security}", timeout=900)
        indexer2.succeed(f"test $(systemctl show -p NRestarts --value {security}) -gt 0")
        indexer2.wait_until_succeeds(admin(old), timeout=120)
        indexer2.fail(admin(new))

    def tls(port, *extra):
        answer = indexer.succeed(
            "python3 ${./tls-probe.py} 192.168.1.10 " + str(port) + " indexer ${pki.ca} " + " ".join(extra)
        ).strip()
        print(f"tls-probe {port} {' '.join(extra)}: {answer}")
        return answer

    with subtest("the indexer refuses client certificates from another CA, and transport clients without one"):
        rogue = "${rogue.admin.cert} ${rogue.admin.key}"
        node = "${pki.indexer.cert} ${pki.indexer.key}"
        admin_cert = "${pki.admin.cert} ${pki.admin.key}"
        # Positive controls: the probe reaches both ports, and each port
        # accepts a client certificate from the test CA.
        answer = tls(9300, node)
        assert answer == "accepted silence", f"9300, node certificate: {answer}"
        answer = tls(9200, "--http")
        assert answer.startswith("accepted HTTP/1.1 401"), f"9200, no certificate: {answer}"
        answer = tls(9200, admin_cert, "--http")
        assert answer.startswith("accepted HTTP/1.1 "), f"9200, admin certificate: {answer}"
        # Transport requires a certificate. HTTP makes it optional, so a
        # client with no certificate gets the 401 above, not a TLS error.
        answer = tls(9300)
        assert answer.startswith("refused "), f"9300, no certificate: {answer}"
        answer = tls(9300, rogue)
        assert answer.startswith("refused "), f"9300, rogue certificate: {answer}"
        answer = tls(9200, rogue, "--http")
        assert answer.startswith("refused "), f"9200, rogue certificate: {answer}"
        # The handshake fails before the password counts.
        indexer.fail("curl --fail --silent --cacert ${pki.ca} --cert ${rogue.admin.cert} --key ${rogue.admin.key} -u 'admin:Test-password-42!' https://indexer:9200")

    # The security REST API rejects weak passwords (score-based validation),
    # so this one has no dictionary words.
    api_user = "curl --fail --silent --cacert ${pki.ca} -u 'api-user:Qx7-Vm2#Lp9!Rt4z' https://indexer:9200/_plugins/_security/authinfo"

    with subtest("a user added through the security API is gone after an indexer restart"):
        # README: the security unit reapplies the declared users on each
        # restart and overwrites changes made through the security API. The
        # admin certificate is the only REST API admin in this module.
        # No --fail: on an error, the body says why.
        answer = indexer.succeed(
            "curl --silent --show-error --write-out ' %{http_code}' --cacert ${pki.ca} --cert ${pki.admin.cert} --key ${pki.admin.key}"
            + " -H 'Content-Type: application/json' -XPUT https://indexer:9200/_plugins/_security/api/internalusers/api-user"
            + " -d '{\"password\":\"Qx7-Vm2#Lp9!Rt4z\"}'"
        ).strip()
        assert answer.endswith(" 200") or answer.endswith(" 201"), f"PUT internalusers/api-user: {answer}"
        indexer.wait_until_succeeds(api_user, timeout=60)
        invocation = indexer.succeed(f"systemctl show -p InvocationID --value {security}").strip()
        indexer.succeed("systemctl restart wazuh-indexer")
        # A failed request during the restart proves nothing. Wait for a new
        # run of the security unit, then for the restarted node to answer.
        rerun = indexer.execute(
            "timeout 600 sh -c 'until test \"$(systemctl show -p InvocationID --value " + security + ")\" != " + invocation
            + " && systemctl is-active --quiet " + security + "; do sleep 2; done'"
        )[0] == 0
        indexer.wait_until_succeeds(base + " https://indexer:9200", timeout=300)
        indexer.fail(api_user)
        assert rerun, "the security unit did not run again after the indexer restart"

    with subtest("a document and the declared users survive a reboot of the indexer VM"):
        indexer.succeed(base + " -H 'Content-Type: application/json' -XPUT 'https://indexer:9200/nixos-reboot/_doc/1?refresh=true' -d '{\"message\":\"before reboot\"}'")
        indexer.shutdown()
        indexer.start()
        indexer.wait_for_unit("wazuh-indexer.service", timeout=900)
        indexer.wait_until_succeeds(f"systemctl is-active {security}", timeout=900)
        indexer.wait_until_succeeds(base + " https://indexer:9200", timeout=300)
        indexer.wait_until_succeeds(base + " https://indexer:9200/nixos-reboot/_doc/1 | jq -e '._source.message == \"before reboot\"'", timeout=300)
        indexer.succeed(base + " https://indexer:9200/nixos-test/_doc/1 | jq -e '._source.message == \"persistent\"'")
        indexer.fail(api_user)
        indexer.fail("curl --fail --silent --cacert ${pki.ca} -u admin:admin https://indexer:9200")
  '';
}
