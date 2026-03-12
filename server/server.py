#!/usr/bin/env python3
"""
ESP TEE Server Authentication — Server Script (Symmetric HMAC-SHA256)

Mutual authentication using a shared secret:
  - Server MACs its command  → device verifies (server authenticated)
  - Device MACs its response → server verifies (device authenticated)

Protocol:
  1. Request a challenge nonce from the device (CMD_GET_CHALLENGE)
  2. Send: [CMD_CHECK_STATUS][expected_state][nonce][HMAC-SHA256(nonce||expected_state)]
  3. Receive: [1B result][32B HMAC-SHA256(nonce||result)]
  4. Verify the response MAC — confirms reply came from the device

The shared key here must match SHARED_KEY in:
  components/server_auth_service/server_auth_service.c

To rotate keys:
  1. Generate 32 random bytes:
       python3 -c "import os; print(os.urandom(32).hex())"
  2. Update SHARED_KEY in server_auth_service.c (as a C byte array)
  3. Update SHARED_KEY_HEX below
  4. Rebuild and reflash

Requirements:
    No third-party packages needed (uses stdlib hmac + hashlib)

Usage:
    python3 server.py <DEVICE_IP> <expected> [PORT]

    expected: on | off | tamper

Examples:
    python3 server.py 192.168.1.100 on
    python3 server.py 192.168.1.100 off
    python3 server.py 192.168.1.100 tamper   # signed with wrong key
"""

import hashlib
import hmac
import socket
import sys

# Protocol constants (must match device firmware)
CMD_GET_CHALLENGE = 0x00
CMD_CHECK_STATUS  = 0x01

NONCE_LEN = 32
MAC_LEN   = 32

# Shared secret — must match SHARED_KEY in server_auth_service.c
SHARED_KEY_HEX = "a37f2c8e51d49b6af03ec7824d19b52f8c6e0a73d845f19c2be754380dc6a91e"
SHARED_KEY = bytes.fromhex(SHARED_KEY_HEX)


def compute_mac(key: bytes, nonce: bytes, data_byte: int) -> bytes:
    """Compute HMAC-SHA256(nonce || data_byte, key)."""
    msg = nonce + bytes([data_byte])
    return hmac.new(key, msg, hashlib.sha256).digest()


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


def send_check(host: str, port: int,
               expected_state: int, nonce: bytes, mac: bytes) -> tuple[int, bytes]:
    """
    Send [CMD_CHECK_STATUS][expected_state][nonce][mac] to the device.
    Returns (result_byte, response_mac) or raises on error.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5.0)
        s.connect((host, port))
        s.sendall(bytes([CMD_CHECK_STATUS, expected_state]) + nonce + mac)

        response = b""
        while len(response) < 1 + MAC_LEN:
            chunk = s.recv(1 + MAC_LEN - len(response))
            if not chunk:
                break
            response += chunk

    # Error strings from device are shorter than 33 bytes or start with 'E'
    if len(response) < 1 + MAC_LEN or response[0:1] == b'E':
        raise RuntimeError(response.decode("utf-8", errors="replace").strip())

    result_byte = response[0]
    response_mac = response[1:1 + MAC_LEN]
    return result_byte, response_mac


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

    print(f"[*] Connecting to {host}:{port}")
    print("[*] Requesting challenge nonce...")
    nonce = get_challenge(host, port)
    print(f"    Nonce: {nonce.hex()}")

    if expected == "tamper":
        print("\n[*] Sending check with WRONG key (tamper test)...")
        wrong_key = bytes(32)  # all-zero key — will not match device
        mac = compute_mac(wrong_key, nonce, 0x01)
        try:
            result_byte, resp_mac = send_check(host, port, 0x01, nonce, mac)
            print(f"    WARNING: device accepted tampered MAC (result: {result_byte})")
        except RuntimeError as e:
            print(f"    Device rejected (expected): {e}")
    else:
        expected_byte = 0x01 if expected == "on" else 0x00
        mac = compute_mac(SHARED_KEY, nonce, expected_byte)
        print(f"\n[*] Asserting LED should be {expected.upper()}...")

        try:
            result_byte, resp_mac = send_check(host, port, expected_byte, nonce, mac)
        except RuntimeError as e:
            print(f"    Device error: {e}")
            sys.exit(1)

        result_str = "MATCH" if result_byte == 0x01 else "MISMATCH"
        print(f"    Device response: {result_str}")

        # Verify the response MAC — confirms reply came from the device
        expected_resp_mac = compute_mac(SHARED_KEY, nonce, result_byte)
        if hmac.compare_digest(resp_mac, expected_resp_mac):
            print("    Response MAC: VALID (confirmed from device)")
        else:
            print("    Response MAC: INVALID — response may be forged")


if __name__ == "__main__":
    main()
