"""Render JSON (valid YAML) without placing secrets in the store."""
import json
import os
import pathlib
import re
import sys

credentials = pathlib.Path(os.environ["CREDENTIALS_DIRECTORY"])
file = json.loads(pathlib.Path(sys.argv[1]).read_text())
domains = file["config"]["dynamic"]["authc"]
i = 0
for domain in domains:
    if domain["http_authenticator"]["config"]["exchange_key_file"] != null:
        domain["http_authenticator"]["config"]["exchange_key_file"] = (credentials / "domain-" + i + "-signing_key_file").read_text().rstrip("\r\n")
    if domain["http_authenticator"]["config"]["signing_key_file"] != null:
        domain["http_authenticator"]["config"]["signing_key_file"] = (credentials / "domain-" + i + "-signing_key_file").read_text().rstrip("\r\n")
    i += 1
file["config"]["dynamic"]["authc"] = domains
pathlib.Path(sys.argv[1]).write_text(json.dumps(file))
