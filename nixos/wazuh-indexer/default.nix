{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkEnableOption mkOption types;
  cfg = config.services.wazuh-indexer;
  home = "${cfg.package}/share/wazuh-indexer";
  runtime = "/run/wazuh-indexer";
  fileOption =
    description:
    mkOption {
      type = types.str;
      inherit description;
    };
  requestedAddresses = lib.toList cfg.listenAddress;
  # NixOS resolves its own hostname to 127.0.0.2. Keep this loopback binding
  # even for an explicit LAN bind, so the admin connection verifies that DNS
  # name without requiring a private IP SAN or disabling hostname checks.
  bindAddresses = lib.unique (
    requestedAddresses ++ lib.optional (!(builtins.elem "0.0.0.0" requestedAddresses)) "127.0.0.2"
  );
  roles = lib.recursiveUpdate {
    "_meta" = {
      "type" = "rolesmapping";
      "config_version" = 2;
    };
    "all_access" = {
      "reserved" = true;
      "hidden" = false;
      "backend_roles" = [
        "admin"
      ];
      "hosts" = [ ];
      "users" = [ ];
      "and_backend_roles" = [ ];
    };
    "own_index" = {
      "reserved" = false;
      "hidden" = false;
      "backend_roles" = [ ];
      "hosts" = [ ];
      "users" = [
        "*"
      ];
      "and_backend_roles" = [ ];
    };
    "logstash" = {
      "reserved" = false;
      "hidden" = false;
      "backend_roles" = [
        "logstash"
      ];
      "hosts" = [ ];
      "users" = [ ];
      "and_backend_roles" = [ ];
    };
    "readall" = {
      "reserved" = true;
      "hidden" = false;
      "backend_roles" = [
        "readall"
      ];
      "hosts" = [ ];
      "users" = [ ];
      "and_backend_roles" = [ ];
    };
    "manage_snapshots" = {
      "reserved" = true;
      "hidden" = false;
      "backend_roles" = [
        "snapshotrestore"
      ];
      "hosts" = [ ];
      "users" = [ ];
      "and_backend_roles" = [ ];
    };
    "kibana_server" = {
      "reserved" = true;
      "hidden" = false;
      "backend_roles" = [ ];
      "hosts" = [ ];
      "users" = [
        "kibanaserver"
      ];
      "and_backend_roles" = [ ];
    };
    "kibana_user" = {
      "reserved" = false;
      "hidden" = false;
      "backend_roles" = [
        "kibanauser"
      ];
      "hosts" = [ ];
      "users" = [ ];
      "and_backend_roles" = [ ];
    };
    "manage_wazuh_index" = {
      "reserved" = true;
      "hidden" = false;
      "backend_roles" = [ ];
      "hosts" = [ ];
      "users" = [
        "kibanaserver"
      ];
      "and_backend_roles" = [ ];
    };
  } cfg.roles;
  generatedRoles = pkgs.writeText "roles_mapping.yml" (builtins.toJSON roles);
  settings =
    cfg.settings
    // {
      "network.host" = bindAddresses;
      "http.port" = cfg.port;
      "transport.port" = cfg.transportPort;
      "node.name" = cfg.nodeName;
      "cluster.name" = cfg.clusterName;
      "path.data" = "/var/lib/wazuh-indexer";
      "path.logs" = "/var/log/wazuh-indexer";
      "plugins.security.ssl.http.enabled" = true;
      "plugins.security.ssl.http.pemcert_filepath" = "node.pem";
      "plugins.security.ssl.http.pemkey_filepath" = "node.key";
      "plugins.security.ssl.http.pemtrustedcas_filepath" = "ca.pem";
      "plugins.security.ssl.transport.pemcert_filepath" = "node.pem";
      "plugins.security.ssl.transport.pemkey_filepath" = "node.key";
      "plugins.security.ssl.transport.pemtrustedcas_filepath" = "ca.pem";
      "plugins.security.ssl.transport.enforce_hostname_verification" = true;
      "plugins.security.authcz.admin_dn" = cfg.admin.distinguishedNames;
      "plugins.security.nodes_dn" = cfg.nodeDistinguishedNames;
      "plugins.security.allow_default_init_securityindex" = false;
      "compatibility.override_main_response_version" = true;
    }
    // lib.optionalAttrs cfg.singleNode { "discovery.type" = "single-node"; };
  generated = pkgs.writeText "opensearch.yml" (builtins.toJSON settings);
  securitySettings = {
    "_meta" = {
      "type" = "config";
      "config_version" = 2;
    };
    "config" = {
      "dynamic" = {
        "http" = cfg.securitySettings.http;
        "authc" = lib.listToAttrs (
          lib.imap0 (
            i: domain:
            lib.nameValuePair "${toString i}_auth_domain" (
              lib.recursiveUpdate domain {
                http_authenticator.config.idp.metadata_file = "metadata_${toString i}.xml";
              }
            )
          ) cfg.securitySettings.authc
        );
        "authz" = cfg.securitySettings.authz;
      };
    };
  };
  generatedSecuritySettings = pkgs.writeText "config.yml" (builtins.toJSON securitySettings);
  userNames = builtins.attrNames cfg.users;
  usersSpec = pkgs.writeText "indexer-users.json" (
    builtins.toJSON (
      lib.imap0 (i: name: {
        inherit name;
        credential = "user-${toString i}";
        backend_roles = cfg.users.${name}.backendRoles;
      }) userNames
    )
  );
  credentials = [
    "ca:${cfg.tls.ca}"
    "certificate:${cfg.tls.certificate}"
    "key:${cfg.tls.key}"
  ];
  hardening = {
    NoNewPrivileges = true;
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = true;
    PrivateDevices = true;
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectControlGroups = true;
    RestrictSUIDSGID = true;
    CapabilityBoundingSet = "";
    UMask = "0077";
  };
in
{
  options.services.wazuh-indexer = {
    enable = mkEnableOption "the Wazuh indexer";
    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ../../pkgs/wazuh-indexer { };
      defaultText = lib.literalExpression "pkgs.callPackage ../../pkgs/wazuh-indexer { }";
    };
    listenAddress = mkOption {
      type = types.either types.str (types.listOf types.str);
      default = [
        "127.0.0.1"
        "127.0.0.2"
      ];
      description = "Bind addresses. Defaults cover localhost and the NixOS hostname loopback address. The module also retains 127.0.0.2 for explicit interface binds, so securityadmin can verify the node hostname. A 0.0.0.0 wildcard already covers it.";
    };
    port = mkOption {
      type = types.port;
      default = 9200;
    };
    transportPort = mkOption {
      type = types.port;
      default = 9300;
    };
    openFirewall = mkEnableOption "the indexer HTTP firewall port (transport remains explicit)";
    nodeName = mkOption {
      type = types.str;
      default = config.networking.hostName;
    };
    clusterName = mkOption {
      type = types.str;
      default = "wazuh-cluster";
    };
    singleNode = mkOption {
      type = types.bool;
      default = true;
      description = "Use single-node discovery. For clusters disable this and configure discovery in settings.";
    };
    heapSize = mkOption {
      type = types.strMatching "[1-9][0-9]*[mgMG]";
      default = "1g";
    };
    nodeDistinguishedNames = mkOption {
      type = types.listOf types.str;
      description = "Exact trusted node certificate subject DNs.";
    };
    tls = {
      ca = fileOption "Runtime CA certificate file.";
      certificate = fileOption "Runtime node certificate file with a DNS SAN matching nodeName.";
      key = fileOption "Runtime unencrypted PKCS#8 private key; keep outside the Nix store.";
    };
    admin = {
      certificate = fileOption "Runtime securityadmin client certificate.";
      key = fileOption "Runtime securityadmin PKCS#8 private key; never passed to the indexer daemon.";
      distinguishedNames = mkOption {
        type = types.listOf types.str;
        description = "Exact admin certificate subject DNs.";
      };
      host = mkOption {
        type = types.str;
        default = cfg.nodeName;
        description = "DNS name used by securityadmin; must match the node certificate SAN.";
      };
    };
    users = mkOption {
      default = { };
      description = "Declarative internal users. Reapplied on restart; upstream demo users are excluded.";
      type = types.attrsOf (
        types.submodule {
          options = {
            passwordHashFile = fileOption "Runtime file containing a bcrypt password hash.";
            backendRoles = mkOption {
              type = types.listOf types.str;
              default = [ ];
            };
          };
        }
      );
    };
    roles = mkOption {
      default = { };
      description = "List of Authentication Domains";
      type = types.attrsOf (
        types.submodule {
          options = {
            reserved = mkOption {
              type = types.bool;
              default = true;
            };
            hidden = mkOption {
              type = types.bool;
              default = false;
            };
            backend_roles = mkOption {
              type = types.listOf types.str;
              default = [ ];
            };
            hosts = mkOption {
              type = types.listOf types.str;
              default = [ ];
            };
            users = mkOption {
              type = types.listOf types.str;
              default = [ ];
            };
            and_backend_roles = mkOption {
              type = types.listOf types.str;
              default = [ ];
            };
          };
        }
      );
    };
    settings = mkOption {
      type = types.attrsOf types.anything;
      default = { };
      description = "Additional OpenSearch settings. Module-owned TLS, state paths and endpoints take precedence.";
    };
    securitySettings = {
      # TODO: make properly configurable
      http = mkOption {
        type = types.attrsOf types.anything;
        default = { };
        description = "HTTP OpenSearch Security settings.";
      };
      authc = mkOption {
        default = { };
        description = "List of Authentication Domains";
        type = types.listOf (
          types.submodule {
            options = {
              http_enabled = mkOption {
                type = types.bool;
                default = true;
              };
              transport_enabled = mkOption {
                type = types.bool;
                default = true;
              };
              order = mkOption {
                type = types.int;
                default = "0";
              };
              http_authenticator = mkOption {
                type = types.submodule {
                  options = {
                    type = mkOption {
                      type = types.strMatching "(kerberos|basic|saml|proxy|jwt|clientcert|ldap)";
                      default = "basic";
                    };
                    challenge = mkOption {
                      type = types.bool;
                      default = true;
                    };
                    config = mkOption {
                      type = types.submodule {
                        options = {
                          # Kerberos
                          krb_debug = mkOption {
                            type = types.bool;
                            default = false;
                          };
                          strip_realm_from_principal = mkOption {
                            type = types.bool;
                            default = true;
                          };
                          # SAML
                          idp = {
                            metadata_file = mkOption {
                              type = types.str;
                              description = "SAML Metadata File provided by SAML Provider";
                              default = "";
                            };
                            entity_id = mkOption {
                              type = types.str;
                              default = "";
                            };
                          };
                          sp = {
                            entity_id = mkOption {
                              type = types.str;
                              default = "";
                            };
                          };
                          kibana_url = mkOption {
                            type = types.str;
                            default = "";
                          };
                          roles_key = mkOption {
                            type = types.str;
                            default = "Roles";
                          };
                          #exchange_key_file = fileOption "64 Character Generated Exchange Key File";
                          exchange_key_file = mkOption {
                            type = types.str;
                            description = "64 Character Generated Exchange Key File";
                            default = "";
                          };
                          # Proxy
                          user_header = mkOption {
                            type = types.str;
                            default = "x-proxy-user";
                          };
                          roles_header = mkOption {
                            type = types.str;
                            default = "x-proxy-roles";
                          };
                          # JWT
                          #signing_key_file = fileOption "Base64 encoded HMAC key or public RSA/ECDSA pem key";
                          signing_key_file = mkOption {
                            type = types.str;
                            description = "Base64 encoded HMAC key or public RSA/ECDSA pem key";
                            default = "";
                          };
                          jwt_header = mkOption {
                            type = types.str;
                            default = "Authorization";
                          };
                          jwt_url_parameter = mkOption {
                            type = types.str;
                            default = "";
                          };
                          jwt_clock_skew_tolerance_seconds = mkOption {
                            type = types.str;
                            default = "30";
                          };
                          # roles_key is used again (first used in SAML) here
                          subject_key = mkOption {
                            type = types.str;
                            default = "";
                          };
                          # ClientCert
                          username_attribute = mkOption {
                            type = types.str;
                            default = "cn";
                          };
                          # LDAP
                          enable_ssl = mkOption {
                            type = types.bool;
                            default = false;
                          };
                          enable_start_tls = mkOption {
                            type = types.bool;
                            default = false;
                          };
                          enable_ssl_client_auth = mkOption {
                            type = types.bool;
                            default = false;
                          };
                          verify_hostnames = mkOption {
                            type = types.bool;
                            default = true;
                          };
                          hosts = mkOption {
                            type = types.listOf types.str;
                            default = [ "localhost:8389" ];
                          };
                          bind_dn = mkOption {
                            type = types.str;
                            default = "";
                          };
                          #passwordFile = fileOption "Password File for LDAP Bind DN";
                          passwordFile = mkOption {
                            type = types.str;
                            description = "Password File for LDAP Bind DN";
                            default = "";
                          };
                          userbase = mkOption {
                            type = types.str;
                            default = "ou=people,dc=example,dc=com";
                          };
                          usersearch = mkOption {
                            type = types.str;
                            default = "(sAMAccountName={0})";
                          };
                          # username_attribute is used again (first used in ClientCert) here
                        };
                      };
                    };
                  };
                };
              };
              authentication_backend = mkOption {
                type = types.submodule {
                  options = {
                    type = mkOption {
                      type = types.strMatching "(ldap|intern|noop)";
                      default = "basic";
                    };
                    config = mkOption {
                      type = types.submodule {
                        options = {
                          # LDAP
                          enable_ssl = mkOption {
                            type = types.bool;
                            default = false;
                          };
                          enable_start_tls = mkOption {
                            type = types.bool;
                            default = false;
                          };
                          enable_ssl_client_auth = mkOption {
                            type = types.bool;
                            default = false;
                          };
                          verify_hostnames = mkOption {
                            type = types.bool;
                            default = true;
                          };
                          hosts = mkOption {
                            type = types.listOf types.str;
                            default = [ "localhost:8389" ];
                          };
                          bind_dn = mkOption {
                            type = types.str;
                            default = "";
                          };
                          #passwordFile = fileOption "Password File for LDAP Bind DN";
                          passwordFile = mkOption {
                            type = types.str;
                            description = "Password File for LDAP Bind DN";
                            default = "";
                          };
                          userbase = mkOption {
                            type = types.str;
                            default = "ou=people,dc=example,dc=com";
                          };
                          usersearch = mkOption {
                            type = types.str;
                            default = "(sAMAccountName={0})";
                          };
                          username_attribute = mkOption {
                            type = types.str;
                            default = "";
                          };
                        };
                      };
                    };
                  };
                };
                default = {
                  type = "noop";
                };
              };
            };
          }
        );
      };
      # TODO: make properly configurable
      authz = mkOption {
        type = types.attrsOf types.anything;
        default = { };
        description = "Authz (Authorization) OpenSearch Security settings.";
      };
    };
  };
  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.users != { };
        message = "wazuh-indexer.users must contain explicit users; demo passwords are never installed.";
      }
      {
        assertion = cfg.nodeDistinguishedNames != [ ] && cfg.admin.distinguishedNames != [ ];
        message = "wazuh-indexer requires trusted node and admin certificate DNs.";
      }
    ];
    users.groups.wazuh-indexer = { };
    users.users.wazuh-indexer = {
      isSystemUser = true;
      group = "wazuh-indexer";
    };
    boot.kernel.sysctl."vm.max_map_count" = lib.mkForce 262144;
    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];
    systemd.services.wazuh-indexer = {
      description = "Wazuh indexer";
      wantedBy = [ "multi-user.target" ];
      wants = [
        "network-online.target"
        "wazuh-indexer-security.service"
      ];
      after = [ "network-online.target" ];
      path = [
        pkgs.coreutils
        pkgs.gnused
      ];
      environment = {
        OPENSEARCH_PATH_CONF = runtime;
        OPENSEARCH_TMPDIR = "/var/lib/wazuh-indexer/tmp";
      };
      preStart = lib.concatStringsSep "\n" (
        [
          ''
            cp -r ${home}/config/. ${runtime}/
            chmod -R u+w ${runtime}
            cp ${generated} ${runtime}/opensearch.yml
          ''
        ]
        ++ lib.concatLists (
          lib.imap0 (
            i: domain:
            let
              metadataFile = domain.http_authenticator.config.idp.metadata_file or "";
            in
            lib.optional (
              domain.http_authenticator != null && metadataFile != ""
            ) "cp ${lib.escapeShellArg metadataFile} ${runtime}/metadata_${toString i}.xml"
          ) cfg.securitySettings.authc
        )
        ++ [
          ''
            install -m600 "$CREDENTIALS_DIRECTORY/ca" ${runtime}/ca.pem
            install -m600 "$CREDENTIALS_DIRECTORY/certificate" ${runtime}/node.pem
            install -m600 "$CREDENTIALS_DIRECTORY/key" ${runtime}/node.key
            sed -i -e '/^-Xms/d' -e '/^-Xmx/d' \
              -e 's|/etc/wazuh-indexer|${runtime}|g' ${runtime}/jvm.options
            printf '\n-Xms${cfg.heapSize}\n-Xmx${cfg.heapSize}\n' >> ${runtime}/jvm.options
            mkdir -p /var/lib/wazuh-indexer/tmp
          ''
        ]
      );
      serviceConfig = hardening // {
        User = "wazuh-indexer";
        Group = "wazuh-indexer";
        ExecStart = "${cfg.package}/bin/wazuh-indexer";
        StateDirectory = "wazuh-indexer";
        LogsDirectory = "wazuh-indexer";
        RuntimeDirectory = "wazuh-indexer";
        RuntimeDirectoryMode = "0700";
        LoadCredential = credentials;
        LimitNOFILE = 65536;
        Restart = "on-failure";
        RestartSec = 5;
        TimeoutStartSec = 180;
      };
    };
    systemd.services.wazuh-indexer-security = {
      description = "Apply Wazuh indexer security configuration";
      unitConfig.StartLimitIntervalSec = 0;
      after = [ "wazuh-indexer.service" ];
      requires = [ "wazuh-indexer.service" ];
      partOf = [ "wazuh-indexer.service" ];
      path = [
        pkgs.coreutils
        pkgs.python3
      ];
      # securityadmin exits at once when the port is closed, and each retry
      # starts a JVM that competes with the booting indexer. Wait for the
      # port first. TimeoutStartSec bounds the wait.
      script = ''
        until (exec 3<>/dev/tcp/${cfg.admin.host}/${toString cfg.port}) 2>/dev/null; do
          sleep 2
        done
        cp -r ${home}/config/opensearch-security/. /run/wazuh-indexer-security/
        chmod -R u+w /run/wazuh-indexer-security
        python3 ${./users.py} ${usersSpec} /run/wazuh-indexer-security/internal_users.yml
        python3 ${./domains.py} ${generatedSecuritySettings} /run/wazuh-indexer-security/config.yml
        cp ${generatedRoles} /run/wazuh-indexer-security
        exec ${cfg.package}/bin/wazuh-indexer-securityadmin \
          -h ${lib.escapeShellArg cfg.admin.host} -p ${toString cfg.port} \
          -cn ${lib.escapeShellArg cfg.clusterName} \
          -cacert "$CREDENTIALS_DIRECTORY/ca" \
          -cert "$CREDENTIALS_DIRECTORY/certificate" -key "$CREDENTIALS_DIRECTORY/key" \
          -cd /run/wazuh-indexer-security
      '';
      serviceConfig = hardening // {
        Type = "oneshot";
        DynamicUser = true;
        RemainAfterExit = true;
        RuntimeDirectory = "wazuh-indexer-security";
        RuntimeDirectoryMode = "0700";
        LoadCredential = [
          "ca:${cfg.tls.ca}"
          "certificate:${cfg.admin.certificate}"
          "key:${cfg.admin.key}"
        ]
        ++ lib.imap0 (i: name: "user-${toString i}:${cfg.users.${name}.passwordHashFile}") userNames
        ++ lib.imap0 (
          i: domain:
          if
            (securitySettings.config.dynamic.authc.${toString i + "_auth_domain"}.http_authenticator != null)
          then
            if
              (
                securitySettings.config.dynamic.authc.${toString i + "_auth_domain"}.http_authenticator.config.exchange_key_file
                != ""
              )
            then
              "${toString i}_auth_domain_exchange_key_file:${
                securitySettings.config.dynamic.authc.${toString i + "_auth_domain"}.http_authenticator.config.exchange_key_file
              }"
            else
              "/dev/null"
          else
            "/dev/null"
        ) cfg.securitySettings.authc
        ++ lib.imap0 (
          i: domain:
          if
            (securitySettings.config.dynamic.authc.${toString i + "_auth_domain"}.http_authenticator != null)
          then
            if
              (
                securitySettings.config.dynamic.authc.${toString i + "_auth_domain"}.http_authenticator.config.signing_key_file
                != ""
              )
            then
              "${toString i}_auth_domain_signing_key_file:${
                securitySettings.config.dynamic.authc.${toString i + "_auth_domain"}.http_authenticator.config.signing_key_file
              }"
            else
              "/dev/null"
          else
            "/dev/null"
        ) cfg.securitySettings.authc;
        Restart = "on-failure";
        RestartSec = 5;
        TimeoutStartSec = 600;
      };
    };
  };
}
