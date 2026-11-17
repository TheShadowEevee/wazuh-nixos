# Module assertions of the agent, independent of VM boot.
#
# The store-safety assertion rejects a configuration that enables a collector
# which writes its state beside its code. Each row below is one way to write
# such a configuration, or one configuration that must stay legal. A row that
# gives the wrong answer names itself in the build log.
{
  pkgs,
  nixpkgs,
  wazuhModule,
}:
let
  inherit (pkgs) lib;
  hostConfig =
    options:
    (nixpkgs.lib.nixosSystem {
      system = pkgs.stdenv.hostPlatform.system;
      modules = [
        wazuhModule
        {
          services.wazuh-agent = {
            enable = true;
            manager.host = "192.0.2.10";
          }
          // options;
          boot.loader.grub.enable = false;
          fileSystems."/" = {
            device = "none";
            fsType = "ext4";
          };
          system.stateVersion = "25.11";
        }
      ];
    }).config;

  # The assertion is found by its message, so that an unrelated failed
  # assertion cannot make a row pass.
  storeSafetyFails =
    options:
    lib.any (a: !a.assertion && lib.hasInfix "beside its code" a.message) (hostConfig options).assertions;

  wholeFile = body: ''
    <ossec_config>
      <client><server><address>192.0.2.10</address></server></client>
      ${body}
    </ossec_config>
  '';

  rejected = {
    wodle-aws-s3 = {
      extraConfig = ''<wodle name="aws-s3"><disabled>no</disabled></wodle>'';
    };
    wodle-azure-logs = {
      extraConfig = ''<wodle name="azure-logs"><disabled>no</disabled></wodle>'';
    };
    wodle-docker-listener = {
      extraConfig = ''<wodle name="docker-listener"><disabled>no</disabled></wodle>'';
    };
    wodle-single-quotes = {
      extraConfig = "<wodle name='aws-s3'><disabled>no</disabled></wodle>";
    };
    section-gcp-pubsub = {
      extraConfig = "<gcp-pubsub><enabled>yes</enabled></gcp-pubsub>";
    };
    section-gcp-bucket = {
      extraConfig = "<gcp-bucket><enabled>yes</enabled></gcp-bucket>";
    };
    section-gcp-bucket-newline = {
      extraConfig = "<gcp-bucket\n><enabled>yes</enabled></gcp-bucket>";
    };
    whole-file-wodle = {
      config = wholeFile ''<wodle name="azure-logs"><disabled>no</disabled></wodle>'';
    };
    whole-file-gcp-pubsub = {
      config = wholeFile "<gcp-pubsub><enabled>yes</enabled></gcp-pubsub>";
    };
    whole-file-gcp-bucket = {
      config = wholeFile "<gcp-bucket><enabled>yes</enabled></gcp-bucket>";
    };
  };

  accepted = {
    default = { };
    wodle-command = {
      extraConfig = ''<wodle name="command"><disabled>yes</disabled></wodle>'';
    };
    # The name as text is not the section.
    label-value = {
      extraConfig = ''<labels><label key="cloud">gcp-pubsub</label></labels>'';
    };
    # A longer tag name is a different section.
    longer-tag = {
      extraConfig = "<gcp-bucket-notes>x</gcp-bucket-notes>";
    };
  };

  wrong =
    lib.mapAttrsToList (name: _: "rejected.${name} was accepted") (
      lib.filterAttrs (_: options: !(storeSafetyFails options)) rejected
    )
    ++ lib.mapAttrsToList (name: _: "accepted.${name} was rejected") (
      lib.filterAttrs (_: storeSafetyFails) accepted
    );
in
pkgs.runCommand "wazuh-agent-eval"
  {
    wrong = lib.concatStringsSep "\n" wrong;
    rows = toString (lib.length (lib.attrNames rejected) + lib.length (lib.attrNames accepted));
  }
  ''
    if [ -n "$wrong" ]; then
      printf '%s\n' "$wrong" >&2
      exit 1
    fi
    echo "$rows rows gave the expected answer"
    touch "$out"
  ''
