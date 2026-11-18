# plant: null for the check. A name from plants below builds the same test
# with one gap planted, to show that a subtest fails on it. See
# nixos/tests/indexer/default.nix for the command.
{ pkgs, plant ? null }:
let
  inherit (pkgs) lib;
  # Each plant breaks one property that one subtest asserts.
  plants = {
    # The dashboard serves plain HTTP on its port.
    http.systemd.services.wazuh-dashboard.preStart = lib.mkAfter ''
      python3 - <<'EOF'
      import json, pathlib
      path = pathlib.Path("/run/wazuh-dashboard/opensearch_dashboards.yml")
      settings = json.loads(path.read_text())
      settings["server.ssl.enabled"] = False
      path.write_text(json.dumps(settings))
      EOF
    '';
    # /api/status answers without a valid login.
    auth.services.wazuh-dashboard.settings."opensearch_security.auth.unauthenticated_routes" = [ "/api/status" ];
  };
  pki = import ../common/pki.nix { inherit pkgs; };
  fixture = import ../indexer/fixture.nix { inherit pkgs pki; };
  dashboardPackage = pkgs.callPackage ../../../pkgs/wazuh-dashboard { };
  managerUser = pkgs.writeText "test-manager-user" "wazuh-wui";
in
assert plant == null || plants ? ${plant};
pkgs.testers.runNixOSTest {
  name = "wazuh-dashboard" + lib.optionalString (plant != null) "-plant-${plant}";
  nodes = {
    indexer = { lib, ... }: {
      imports = [ fixture.module ];
      environment.systemPackages = [ pkgs.curl ];
      # Mutable runtime hash, as with a secret manager, so the test can
      # rotate the kibanaserver password. Seeded once per boot.
      services.wazuh-indexer.users.kibanaserver.passwordHashFile = lib.mkForce "/run/secrets/kibanaserver-hash";
      system.activationScripts.kibanaserver-hash = ''
        [ -e /run/secrets/kibanaserver-hash ] || install -D -m400 ${fixture.secrets}/hash /run/secrets/kibanaserver-hash
      '';
    };
    server = { ... }: {
      networking.firewall.allowedTCPPorts = [ 55000 ];
      systemd.services.test-api = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python ${./api.py} ${pki.server.cert} ${pki.server.key}";
      };
    };
    dashboard = { ... }: {
      imports = [ ../../wazuh-dashboard ] ++ lib.optional (plant != null) plants.${plant};
      virtualisation.memorySize = 2048;
      environment.systemPackages = [ pkgs.curl pkgs.jq pkgs.findutils ];
      system.activationScripts.kibanaserver-password = ''
        [ -e /run/secrets/kibanaserver-password ] || install -D -m400 ${fixture.secrets}/password /run/secrets/kibanaserver-password
      '';
      services.wazuh-dashboard = {
        enable = true;
        package = dashboardPackage;
        listenAddress = "0.0.0.0";
        tls = { certificate = pki.dashboard.cert; key = pki.dashboard.key; };
        indexer = {
          hosts = [ "https://indexer:9200" ];
          ca = pki.ca;
          usernameFile = "${fixture.secrets}/kibanaserver";
          passwordFile = "/run/secrets/kibanaserver-password";
        };
        managers = [ {
          url = "https://server";
          ca = pki.ca;
          usernameFile = "${managerUser}";
          passwordFile = "${fixture.secrets}/password";
        } ];
      };
    };
  };
  testScript = ''
    import time
    start_all()
    indexer.wait_until_succeeds("systemctl is-active wazuh-indexer-security.service", timeout=900)
    server.wait_for_unit("test-api.service")
    dashboard.wait_for_unit("wazuh-dashboard.service")
    dashboard.wait_for_open_port(5601)
    http_code = "curl --silent --output /dev/null --max-time 10 --write-out '%{http_code}' "

    with subtest("plain HTTP on the dashboard port gets no HTTP answer"):
        # Wait until the listener answers either scheme, so that neither
        # assertion below can pass on a listener that is not up yet.
        https = http_code + "--cacert ${pki.ca} https://dashboard:5601/api/status"
        plain = http_code + "http://dashboard:5601/api/status"
        dashboard.wait_until_succeeds(f"test \"$({https})$({plain})\" != 000000", timeout=600)
        # The TLS listener closes on a plain request: curl reports 000. A
        # redirect to HTTPS would also be safe, but this module has none.
        answer = dashboard.succeed(plain + " || true").strip()
        assert answer == "000", f"plain HTTP got status {answer}"
        # Positive control: the same listener answers HTTPS, with any status.
        answer = dashboard.succeed(https + " || true").strip()
        assert answer != "000", "HTTPS got no answer"

    dashboard.wait_until_succeeds("curl --fail --silent --cacert ${pki.ca} https://dashboard:5601/api/status -u 'admin:Test-password-42!' | jq -e '.status.overall.state == \"green\"'", timeout=600)

    with subtest("the dashboard refuses a wrong password"):
        status = http_code + "--cacert ${pki.ca} https://dashboard:5601/api/status"
        answer = dashboard.succeed(status + " -u 'admin:Wrong-password-1!'").strip()
        assert answer == "401", f"/api/status, wrong password: {answer}"
        answer = dashboard.succeed(status).strip()
        assert answer != "200", f"/api/status, no credentials: {answer}"
        answer = dashboard.succeed(status + " -u 'admin:Test-password-42!'").strip()
        assert answer == "200", f"/api/status, right password: {answer}"
        login = http_code + "--cacert ${pki.ca} -H 'osd-xsrf: true' -H 'Content-Type: application/json' https://dashboard:5601/auth/login -d "
        answer = dashboard.succeed(login + "'{\"username\":\"admin\",\"password\":\"Wrong-password-1!\"}'").strip()
        assert answer == "401", f"/auth/login, wrong password: {answer}"
        answer = dashboard.succeed(login + "'{\"username\":\"admin\",\"password\":\"Test-password-42!\"}'").strip()
        assert answer == "200", f"/auth/login, right password: {answer}"

    dashboard.wait_until_succeeds("curl --fail --silent --cacert ${pki.ca} -u 'admin:Test-password-42!' -H 'osd-xsrf: true' -H 'Content-Type: application/json' -d '{\"id\":\"manager-0\"}' https://dashboard:5601/api/check-stored-api | jq -e '.statusCode == 200 and .data.cluster_info.manager == \"server\"'", timeout=240)
    dashboard.fail("curl --fail --silent --cacert ${pki.wrongCa} https://dashboard:5601/api/status")
    dashboard.succeed("test $(stat -c %a /run/wazuh-dashboard/opensearch_dashboards.yml) = 600")
    dashboard.succeed("jq -e '.\"opensearch.requestTimeout\" == 120000' /run/wazuh-dashboard/opensearch_dashboards.yml")
    dashboard.fail("sudo -u nobody cat /run/wazuh-dashboard/opensearch_dashboards.yml")
    client = dashboard.succeed("find ${dashboardPackage}/share/wazuh-dashboard/plugins -path '*/server/services/server-api-client.js'").strip()
    node = "${dashboardPackage}/share/wazuh-dashboard/node/bin/node"
    probe = node + " ${./manager-tls.cjs} " + client
    dashboard.succeed("NODE_EXTRA_CA_CERTS=${pki.ca} " + probe + " success")
    dashboard.succeed("NODE_EXTRA_CA_CERTS=${pki.wrongCa} " + probe + " untrusted")
    dashboard.succeed("env -u NODE_EXTRA_CA_CERTS " + probe + " untrusted")
    dashboard.succeed("systemctl restart wazuh-dashboard")
    dashboard.wait_for_open_port(5601)
    dashboard.wait_until_succeeds("curl --fail --silent --cacert ${pki.ca} https://dashboard:5601/api/status -u 'admin:Test-password-42!' | jq -e '.status.overall.state == \"green\"'", timeout=600)

    with subtest("a rotated kibanaserver password reaches the dashboard on restart"):
        kibana = "curl --fail --silent --cacert ${pki.ca} -u 'kibanaserver:{}' https://indexer:9200"
        indexer.succeed("install -m400 ${fixture.rotated}/hash /run/secrets/kibanaserver-hash")
        indexer.succeed("systemctl restart wazuh-indexer-security.service")
        indexer.wait_until_succeeds(kibana.format("Rotated-password-43!"), timeout=120)
        indexer.fail(kibana.format("Test-password-42!"))

        # Stale credential. While it cannot authenticate, the dashboard never
        # becomes ready, and /api/status answers in plain text, not JSON.
        # Positive proof: the indexer logs a failed kibanaserver login from
        # the restarted process. Bounded negative: no 200 for a full minute.
        dashboard.succeed("systemctl restart wazuh-dashboard")
        dashboard.wait_for_open_port(5601)
        # Mark the journal only now: before the restart, the old process also
        # held the stale password and its failures would match too. A cursor
        # is an exact boundary, a timestamp has one-second resolution.
        shown = indexer.succeed("journalctl -u wazuh-indexer -n 1 --show-cursor").strip().splitlines()[-1]
        assert shown.startswith("-- cursor: "), shown
        cursor = shown.removeprefix("-- cursor: ")
        indexer.wait_until_succeeds(f"journalctl -u wazuh-indexer --after-cursor '{cursor}' | grep -q 'Authentication finally failed for kibanaserver'", timeout=300)
        code = "curl --silent --output /dev/null --write-out '%{http_code}' --cacert ${pki.ca} -u 'admin:Test-password-42!' https://dashboard:5601/api/status"
        stale_codes = set()
        for _ in range(12):
            answer = dashboard.succeed(code).strip()
            stale_codes.add(answer)
            assert answer != "200", "dashboard status answered 200 with a stale kibanaserver password"
            time.sleep(5)
        print(f"status codes with the stale password: {sorted(stale_codes)}")

        dashboard.succeed("install -m400 ${fixture.rotated}/password /run/secrets/kibanaserver-password")
        dashboard.succeed("systemctl restart wazuh-dashboard")
        dashboard.succeed("jq -e '.\"opensearch.password\" == \"Rotated-password-43!\"' /run/wazuh-dashboard/opensearch_dashboards.yml")
        dashboard.wait_for_open_port(5601)
        # The old password no longer authenticates on the indexer, so green
        # means the dashboard connects with the new one.
        dashboard.wait_until_succeeds("curl --fail --silent --cacert ${pki.ca} https://dashboard:5601/api/status -u 'admin:Test-password-42!' | jq -e '.status.overall.state == \"green\"'", timeout=600)
  '';
}
