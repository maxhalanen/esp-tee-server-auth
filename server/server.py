#!/usr/bin/env python3
"""
ESP TEE Server Authentication — Server Script

The device auto-blinks an LED. The server signs an expected LED state and
sends it to the device. The device verifies the signature inside the TEE
using the server's hardcoded public key, then compares the expected state
against the actual GPIO level and responds MATCH or MISMATCH.

Protocol:
  1. Request a challenge nonce from the device (CMD_GET_CHALLENGE)
  2. Sign SHA-256(nonce || expected_state) with the server's ECDSA-P256 key
  3. Send: [CMD_CHECK_STATUS][expected_state][nonce][R||S signature]

The private key here corresponds to the public key hardcoded in:
  components/server_auth_service/server_auth_service.c

To rotate keys:
  1. Generate a new keypair (see instructions in server_auth_service.c)
  2. Update SERVER_PUBKEY_X / SERVER_PUBKEY_Y in server_auth_service.c
  3. Replace SERVER_PRIVATE_KEY_PEM below
  4. Rebuild and reflash

Requirements:
    pip install cryptography

Usage:
    python3 server.py <DEVICE_IP> <expected> [PORT]

    expected: on | off | tamper

Examples:
    python3 server.py 192.168.1.100 on
    python3 server.py 192.168.1.100 off
    python3 server.py 192.168.1.100 tamper   # signed with wrong key
"""

import socket
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization

# Protocol constants (must match device firmware)
CMD_GET_CHALLENGE = 0x00
CMD_CHECK_STATUS  = 0x01

NONCE_LEN = 32

# Server private key — keep this secret, never send to device
SERVER_PRIVATE_KEY_PEM = b"""
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgf4rurrsrEuBDPsgs
GEABtYlMxlw7bVtdqOLtuKFGTtKhRANCAAQcYg2BS2o/I9q3GYHyqlSF9/+QVFPF
1aw6rPiWJy9/BGf0VMY9yDBam2CQkB/p0FWjhLwhASTn8D2F6VYF+DFL
-----END PRIVATE KEY-----
"""


def load_key() -> ec.EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(
        SERVER_PRIVATE_KEY_PEM.strip(), password=None
    )


def get_challenge(host: str, port: int) -> bytes:
    """Request a 32-byte nonce from the device."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5.0)
        s.connect((host, port))
        s.sendall(bytes([CMD_GET_CHALLENGE]))
        data = b""
        while len(data) < NONCE_LEN:
            chunk = s.recv(NONCE_LEN - len(data))
            if not chunk:
                break
            data += chunk
    if len(data) != NONCE_LEN:
        raise RuntimeError(f"Expected {NONCE_LEN} byte nonce, got {len(data)}")
    return data


def sign_check(key: ec.EllipticCurvePrivateKey,
               nonce: bytes, expected_state: int) -> bytes:
    """Sign SHA-256(nonce || expected_state), return raw R||S (64 bytes)."""
    msg = nonce + bytes([expected_state])
    der_sig = key.sign(msg, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def send_check(host: str, port: int,
               expected_state: int, nonce: bytes, sig_rs: bytes) -> str:
    """Send [CMD_CHECK_STATUS][expected_state][nonce][sig] to the device."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5.0)
        s.connect((host, port))
        s.sendall(bytes([CMD_CHECK_STATUS, expected_state]) + nonce + sig_rs)
        return s.recv(256).decode("utf-8", errors="replace").strip()


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    host     = sys.argv[1]
    expected = sys.argv[2].lower()
    port     = int(sys.argv[3]) if len(sys.argv) > 3 else 3333

    if expected not in ("on", "off", "tamper"):
        print(f"Unknown argument '{expected}'. Use: on | off | tamper")
        sys.exit(1)

    key = load_key()
    print(f"[*] Connecting to {host}:{port}")

    print("[*] Requesting challenge nonce...")
    nonce = get_challenge(host, port)
    print(f"    Nonce: {nonce.hex()}")

    if expected == "tamper":
        print("\n[*] Sending check signed with WRONG key (tamper test)...")
        wrong_key = ec.generate_private_key(ec.SECP256R1())
        sig_rs = sign_check(wrong_key, nonce, 0x01)
        result = send_check(host, port, 0x01, nonce, sig_rs)
        print(f"    Device response: {result}")
    else:
        expected_byte = 0x01 if expected == "on" else 0x00
        print(f"\n[*] Asserting LED should be {expected.upper()}...")
        sig_rs = sign_check(key, nonce, expected_byte)
        result = send_check(host, port, expected_byte, nonce, sig_rs)
        print(f"    Device response: {result}")


if __name__ == "__main__":
    main()
