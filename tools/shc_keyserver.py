#!/usr/bin/env python3
"""
SHC Remote Key Server

TCP server for the SHC remote key-split protocol.
Serves K_remote to authenticated binaries using the per-compilation
Feistel cipher parameters stored in the key database.

Usage:
    shc_keyserver.py --port 7843 --keys keys.json
    shc_keyserver.py --import script.sh.key --keys keys.json
"""

import argparse
import json
import os
import socketserver
import sys


# --- Feistel cipher (parameterized by per-compilation S-boxes/perm/rconst) ---

def rotl64(val: int, n: int) -> int:
    return ((val << n) | (val >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def fe_round_func(x: bytearray, rk: bytes, sboxes: list, perm: list):
    """Round function F(x[8], round_key[8]) -> modifies x in place."""
    for j in range(8):
        x[j] ^= rk[j]
    for j in range(8):
        x[j] = sboxes[j % 4][x[j]]
    tmp = bytearray(8)
    for j in range(8):
        tmp[j] = x[perm[j]]
    x[:] = tmp
    for j in range(8):
        x[j] = sboxes[(j + 2) % 4][x[j]]
    for j in range(7):
        x[j] ^= x[(j + 1) % 8]
    for j in range(7, 0, -1):
        x[j] ^= x[(j + 1) % 8]
    v = int.from_bytes(x, 'little')
    r1 = rotl64(v, 11)
    r2 = rotl64(v, 23)
    v ^= r1 ^ r2
    x[:] = v.to_bytes(8, 'little')


def fe_key_schedule(key: bytes, sboxes: list, rconsts: list, nrounds: int) -> list:
    """Key schedule: 32-byte key -> N x 8-byte round keys."""
    temp = bytearray(key)
    round_keys = []
    for i in range(nrounds):
        for j in range(8):
            temp[j] ^= rconsts[i][j]
        for j in range(32):
            temp[j] = sboxes[j % 4][temp[j]]
        temp = temp[7:] + temp[:7]
        for j in range(32):
            temp[j] ^= temp[(j + 13) % 32]
        for j in range(32):
            temp[j] = sboxes[(j + 2) % 4][temp[j]]
        rk = bytearray(8)
        for j in range(8):
            rk[j] = temp[j] ^ temp[j+8] ^ temp[j+16] ^ temp[j+24]
        round_keys.append(bytes(rk))
    return round_keys


def fe_encrypt_block(inp: bytes, round_keys: list, sboxes: list, perm: list) -> bytes:
    """Encrypt one 128-bit block using Feistel structure."""
    L = bytearray(inp[:8])
    R = bytearray(inp[8:16])
    for i in range(len(round_keys)):
        tmp = bytearray(R)
        fe_round_func(tmp, round_keys[i], sboxes, perm)
        for j in range(8):
            tmp[j] ^= L[j]
        L = bytearray(R)
        R = tmp
    return bytes(L) + bytes(R)


def fe_key_mix(key: bytearray, data: bytes, sboxes: list, perm: list,
               rconsts: list, nrounds: int):
    """Mix data into key, run avalanche. Returns (key, round_keys)."""
    for i in range(len(data)):
        key[i % 32] ^= data[i]
    round_keys = fe_key_schedule(bytes(key), sboxes, rconsts, nrounds)
    blk1 = bytes(range(16))
    blk2 = bytes(range(15, -1, -1))
    out1 = fe_encrypt_block(blk1, round_keys, sboxes, perm)
    out2 = fe_encrypt_block(blk2, round_keys, sboxes, perm)
    key[:16] = out1[:16]
    key[16:] = out2[:16]
    round_keys = fe_key_schedule(bytes(key), sboxes, rconsts, nrounds)
    return key, round_keys


def parse_cipher_params(entry: dict):
    """Parse cipher parameters from key database entry."""
    sboxes = []
    for s_hex in entry['sboxes']:
        sboxes.append([int(s_hex[i:i+2], 16) for i in range(0, len(s_hex), 2)])
    perm_hex = entry['perm']
    perm = [int(perm_hex[i:i+2], 16) for i in range(0, len(perm_hex), 2)]
    nrounds = entry['nrounds']
    rconst_hex = entry['rconst']
    rconsts = []
    for r in range(nrounds):
        rc = bytes(int(rconst_hex[r*16+j*2:r*16+j*2+2], 16) for j in range(8))
        rconsts.append(rc)
    return sboxes, perm, rconsts, nrounds


# --- Protocol implementation ---

def handle_request(data: bytes, keys_db: dict) -> bytes | None:
    """
    Handle a 32-byte request: binary_id[16] | client_nonce[16]
    Returns 160-byte response: server_nonce[16] | auth_tag[16] | encrypted_K_remote[128]
    """
    if len(data) != 32:
        return None

    binary_id = data[:16].hex()
    client_nonce = data[16:32]

    if binary_id not in keys_db:
        print(f"  Unknown binary_id: {binary_id}", flush=True)
        return None

    entry = keys_db[binary_id]
    k_remote = bytes.fromhex(entry['k_remote'])
    psk = bytes.fromhex(entry['psk'])

    if len(k_remote) != 128 or len(psk) != 32:
        print(f"  Invalid key data for {binary_id}", flush=True)
        return None

    sboxes, perm, rconsts, nrounds = parse_cipher_params(entry)

    # Generate server_nonce
    server_nonce = os.urandom(16)

    # session_key = FE_encrypt(client_nonce, key=psk) || FE_encrypt(server_nonce, key=psk)
    psk_key = bytearray(32)
    psk_key, psk_rkeys = fe_key_mix(psk_key, psk, sboxes, perm, rconsts, nrounds)
    session_key_part1 = fe_encrypt_block(client_nonce, psk_rkeys, sboxes, perm)
    session_key_part2 = fe_encrypt_block(server_nonce, psk_rkeys, sboxes, perm)
    session_key = session_key_part1 + session_key_part2

    # auth_tag = FE_encrypt(server_nonce, key=psk) with fresh key setup
    psk_key2 = bytearray(32)
    psk_key2, psk_rkeys2 = fe_key_mix(psk_key2, psk, sboxes, perm, rconsts, nrounds)
    auth_tag = fe_encrypt_block(server_nonce, psk_rkeys2, sboxes, perm)[:16]

    # Encrypt K_remote with session_key using CTR mode
    sk_key = bytearray(32)
    sk_key, sk_rkeys = fe_key_mix(sk_key, session_key, sboxes, perm, rconsts, nrounds)
    encrypted_kr = bytearray(k_remote)
    counter = 0
    buf_pos = 16
    buf = b''
    for i in range(128):
        if buf_pos >= 16:
            ctr_block = bytearray(16)
            ctr_block[0] = counter & 0xFF
            ctr_block[1] = (counter >> 8) & 0xFF
            ctr_block[2] = (counter >> 16) & 0xFF
            ctr_block[3] = (counter >> 24) & 0xFF
            counter += 1
            buf = fe_encrypt_block(bytes(ctr_block), sk_rkeys, sboxes, perm)
            buf_pos = 0
        encrypted_kr[i] ^= buf[buf_pos]
        buf_pos += 1

    return server_nonce + auth_tag + bytes(encrypted_kr)


class KeyHandler(socketserver.StreamRequestHandler):
    def handle(self):
        peer = self.client_address
        print(f"Connection from {peer[0]}:{peer[1]}", flush=True)
        try:
            data = b''
            while len(data) < 32:
                chunk = self.request.recv(32 - len(data))
                if not chunk:
                    print(f"  Connection closed prematurely", flush=True)
                    return
                data += chunk

            response = handle_request(data, self.server.keys_db)
            if response is None:
                print(f"  Request denied", flush=True)
                return

            self.request.sendall(response)
            print(f"  Key served successfully", flush=True)
        except Exception as e:
            print(f"  Error: {e}", flush=True)


class KeyServer(socketserver.TCPServer):
    allow_reuse_address = True

    def __init__(self, addr, handler, keys_db):
        self.keys_db = keys_db
        super().__init__(addr, handler)


def load_keys(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, 'r') as f:
        return json.load(f)


def save_keys(path: str, db: dict):
    with open(path, 'w') as f:
        json.dump(db, f, indent=2)
        f.write('\n')


def import_key(keyfile: str, dbpath: str):
    with open(keyfile, 'r') as f:
        entry = json.load(f)

    required = ['binary_id', 'k_remote', 'psk', 'sboxes', 'perm', 'rconst', 'nrounds']
    for k in required:
        if k not in entry:
            print(f"Error: missing '{k}' in {keyfile}", file=sys.stderr)
            sys.exit(1)

    db = load_keys(dbpath)
    bid = entry['binary_id']
    db[bid] = {
        'k_remote': entry['k_remote'],
        'psk': entry['psk'],
        'sboxes': entry['sboxes'],
        'perm': entry['perm'],
        'rconst': entry['rconst'],
        'nrounds': entry['nrounds'],
    }
    save_keys(dbpath, db)
    print(f"Imported binary_id {bid} into {dbpath}")


def main():
    parser = argparse.ArgumentParser(description='SHC Remote Key Server')
    parser.add_argument('--port', type=int, default=7843, help='TCP port (default: 7843)')
    parser.add_argument('--keys', required=True, help='JSON key database file')
    parser.add_argument('--import', dest='import_file', help='Import a .key file into the database')
    parser.add_argument('--bind', default='0.0.0.0', help='Bind address (default: 0.0.0.0)')
    args = parser.parse_args()

    if args.import_file:
        import_key(args.import_file, args.keys)
        return

    db = load_keys(args.keys)
    print(f"Loaded {len(db)} key(s) from {args.keys}", flush=True)

    server = KeyServer((args.bind, args.port), KeyHandler, db)
    print(f"Listening on {args.bind}:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down")
        server.shutdown()


if __name__ == '__main__':
    main()
