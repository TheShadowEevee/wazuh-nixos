"""Render JSON (valid YAML) without placing secrets in the store."""
import json
import os
import pathlib
import sys

credentials = pathlib.Path(os.environ["CREDENTIALS_DIRECTORY"])
file = json.loads(pathlib.Path(sys.argv[1]).read_text())

domains = file["config"]["dynamic"]["authc"]

for name, domain in domains.items():
    config = domain["http_authenticator"]["config"]

    for key_type in ("exchange_key", "signing_key"):
        key_file = config.pop(f"{key_type}_file", None)

        if key_file:
            credential_file = credentials / f"{name}_{key_type}_file"
            config[key_type] = credential_file.read_text().rstrip("\r\n")

pathlib.Path(sys.argv[2]).write_text(
    json.dumps(file, indent=2) + "\n"
)
