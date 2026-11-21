#!/usr/bin/env python3
"""Main-developer processing and automatic public clearance publication.

Pass native verifier arguments after --, or use --case-directory to retry a
previous publication. Private requests/reports are never transmitted to RPC.
"""
import argparse
import hashlib
import http.client
import json
from pathlib import Path
import secrets
import stat
import subprocess
import time
import urllib.parse
import urllib.request


def rpc(endpoint, method, params, login=None):
    url = urllib.parse.urlsplit(endpoint)
    if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError("Use a daemon HTTP(S) address without embedded credentials")
    connection_type = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
    connection = connection_type(url.hostname, url.port, timeout=180)
    path = url.path.rstrip("/") + "/json_rpc"
    body = json.dumps({"jsonrpc": "2.0", "id": "audit-clearance", "method": method, "params": params}).encode()
    headers = {"Content-Type": "application/json", "Connection": "keep-alive"}
    try:
        connection.request("POST", path, body, headers)
        response = connection.getresponse()
        data = response.read(4 * 1024 * 1024 + 1)
        if response.status == 401 and login:
            challenge = response.getheader("WWW-Authenticate", "")
            if not challenge.startswith("Digest "):
                raise ValueError("Unsupported daemon authentication challenge")
            auth = urllib.request.parse_keqv_list(urllib.request.parse_http_list(challenge[7:]))
            if auth.get("algorithm", "MD5") != "MD5" or "auth" not in auth.get("qop", "").split(","):
                raise ValueError("Unsupported daemon digest authentication")
            username, password = login
            if any(c in username for c in '\r\n"\\'):
                raise ValueError("Invalid RPC username")
            nonce, realm, cnonce, nc = auth["nonce"], auth["realm"], secrets.token_hex(16), "00000001"
            if any(c in nonce + realm for c in '\r\n"\\'):
                raise ValueError("Invalid daemon digest challenge")
            digest = lambda text: hashlib.md5(text.encode()).hexdigest()
            answer = digest(f'{digest(f"{username}:{realm}:{password}")}:{nonce}:{nc}:{cnonce}:auth:{digest(f"POST:{path}")}')
            headers["Authorization"] = (f'Digest username="{username}", realm="{realm}", nonce="{nonce}", '
                f'uri="{path}", algorithm=MD5, response="{answer}", qop=auth, nc={nc}, cnonce="{cnonce}"')
            connection.request("POST", path, body, headers)
            response = connection.getresponse()
            data = response.read(4 * 1024 * 1024 + 1)
        if response.status != 200 or len(data) > 4 * 1024 * 1024:
            raise ValueError(f"Daemon RPC HTTP response {response.status}")
        result = json.loads(data)
        if "error" in result:
            raise ValueError(str(result["error"].get("message", "Daemon rejected clearance")))
        if result["result"].get("status", "OK") != "OK":
            raise ValueError("Daemon did not accept clearance")
        return result["result"]
    finally:
        connection.close()


def publish(case_directory, endpoint, login=None):
    path = case_directory / "clearances.public"
    with path.open("rb") as source:
        raw = source.read(256 * 1024 * 1024 + 1)
    if len(raw) > 256 * 1024 * 1024:
        raise ValueError("Public clearance manifest exceeds size limit")
    manifest = json.loads(raw)
    batches = manifest.get("batches", [])
    if manifest.get("version") != 4 or not isinstance(batches, list) or len(batches) > 5000:
        raise ValueError("Invalid public clearance manifest")
    for number, batch in enumerate(batches):
        if not isinstance(batch, str) or not batch or len(batch) > 2 * 256 * 1024:
            raise ValueError("Invalid public certificate batch size")
        bytes.fromhex(batch)
        for attempt in range(6):
            try:
                rpc(endpoint, "submit_audit_clearance", {"data": batch}, login)
                break
            except ValueError as error:
                if "busy; retry" not in str(error) or attempt == 5:
                    raise
                time.sleep(1)
        print(f"PUBLIC_CLEARANCE_SUBMITTED {number + 1}/{len(batches)}", flush=True)
    return len(batches)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--daemon-address", required=True)
    parser.add_argument("--verifier", type=Path, default=Path("build/audit/release/bin/salvium-audit-review"))
    parser.add_argument("--case-directory", type=Path, help="Publish/retry existing public certificates without reprocessing")
    parser.add_argument("--rpc-login-file", type=Path, help="Private file containing username:password")
    parser.add_argument("native_arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    native = args.native_arguments
    if native and native[0] == "--":
        native = native[1:]
    if native:
        if args.case_directory:
            parser.error("Choose native processing arguments or --case-directory")
        native_parser = argparse.ArgumentParser(add_help=False)
        native_parser.add_argument("--outdir", type=Path, required=True)
        native_parser.add_argument("--sign-key", type=Path, required=True)
        selected, _ = native_parser.parse_known_args(native)
        subprocess.run([str(args.verifier.resolve()), *native], check=True)
        directory = selected.outdir
    else:
        if not args.case_directory:
            parser.error("Supply native processing arguments after -- or --case-directory")
        directory = args.case_directory
    login = None
    if args.rpc_login_file:
        if stat.S_IMODE(args.rpc_login_file.stat().st_mode) & 0o077:
            parser.error("RPC login file must be accessible only by its owner")
        with args.rpc_login_file.open("rb") as source:
            raw = source.read(8193)
        if len(raw) > 8192 or b":" not in raw:
            parser.error("Invalid RPC login file")
        login = tuple(raw.decode().rstrip("\r\n").split(":", 1))
    count = publish(directory, args.daemon_address, login)
    print(f"PUBLICATION_COMPLETE batches={count}; wallets learn confirmed clearance on refresh; no import required")


if __name__ == "__main__":
    main()
