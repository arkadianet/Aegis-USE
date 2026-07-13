#!/usr/bin/env python3
"""Independent reference for Aegis generator/nullifier vectors.

Pure-Python RFC 9380 (expand_message_xmd/SHA-256, hash_to_field, SvdW)
plus minimal EC arithmetic on secp256k1 and secq256k1. This is the
EXTERNAL ORACLE for aegis-crypto: it self-checks against the official
RFC 9380 J.8.1/K.1 vectors, then emits
test-vectors/aegis/generators/v1.json, which the Rust implementation
must reproduce byte-for-byte.

Run:  python3 aegis_h2c_reference.py > ../generators/v1.json
"""
import hashlib
import json
import sys

# --- curve parameters ------------------------------------------------
P_SECP = 2**256 - 2**32 - 977                       # secp256k1 base field
N_SECP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
# secq256k1: same equation y^2 = x^3 + 7 over F_n (fields swapped).
CURVES = {
    "secp256k1": {"p": P_SECP, "a": 0, "b": 7},
    "secq256k1": {"p": N_SECP, "a": 0, "b": 7},
}

# --- RFC 9380 primitives ---------------------------------------------
def sha256(b):
    return hashlib.sha256(b).digest()

def strxor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def expand_message_xmd(msg, dst, length):
    ell = -(-length // 32)
    assert ell <= 255 and len(dst) <= 255
    dst_prime = dst + bytes([len(dst)])
    msg_prime = bytes(64) + msg + length.to_bytes(2, "big") + b"\x00" + dst_prime
    b0 = sha256(msg_prime)
    bs = [sha256(b0 + b"\x01" + dst_prime)]
    for i in range(2, ell + 1):
        bs.append(sha256(strxor(b0, bs[-1]) + bytes([i]) + dst_prime))
    return b"".join(bs)[:length]

def hash_to_field(msg, dst, p, count, ell=48):
    ub = expand_message_xmd(msg, dst, count * ell)
    return [int.from_bytes(ub[i * ell : (i + 1) * ell], "big") % p for i in range(count)]

def is_square(x, p):
    return x % p == 0 or pow(x, (p - 1) // 2, p) == 1

def sqrt_mod(x, p):
    """Tonelli–Shanks (works for p ≡ 1 mod 4; shortcut for 3 mod 4)."""
    x %= p
    if x == 0:
        return 0
    if p % 4 == 3:
        r = pow(x, (p + 1) // 4, p)
    else:
        q, s = p - 1, 0
        while q % 2 == 0:
            q //= 2
            s += 1
        z = 2
        while is_square(z, p):
            z += 1
        m, c, t, r = s, pow(z, q, p), pow(x, q, p), pow(x, (q + 1) // 2, p)
        while t != 1:
            i, t2 = 0, t
            while t2 != 1:
                t2 = t2 * t2 % p
                i += 1
            b = pow(c, 1 << (m - i - 1), p)
            m, c, t, r = i, b * b % p, t * b * b % p, r * b % p
    assert r * r % p == x % p
    return r

def sgn0(x):
    return x & 1

# --- SvdW (RFC 9380 §6.6.1 + H.1) -------------------------------------
def g_of(x, a, b, p):
    return (pow(x, 3, p) + a * x + b) % p

def find_z_svdw(p, a, b):
    ctr = 1
    while True:
        for z in (ctr, p - ctr):
            gz = g_of(z, a, b, p)
            if gz == 0:
                continue
            h = -(3 * z * z + 4 * a) * pow(4 * gz, -1, p) % p
            if h == 0 or not is_square(h, p):
                continue
            if is_square(gz, p) or is_square(g_of(-z * pow(2, -1, p) % p, a, b, p), p):
                return z
        ctr += 1

def svdw_constants(p, a, b):
    z = find_z_svdw(p, a, b)
    gz = g_of(z, a, b, p)
    t = (3 * z * z + 4 * a) % p
    c1 = gz
    c2 = -z * pow(2, -1, p) % p
    c3 = sqrt_mod(-gz * t % p, p)
    if sgn0(c3):
        c3 = p - c3
    c4 = -4 * gz * pow(t, -1, p) % p
    return z, c1, c2, c3, c4

def svdw_map(u, p, a, b, consts):
    z, c1, c2, c3, c4 = consts
    tv1 = u * u % p * c1 % p
    tv2 = (1 + tv1) % p
    tv1 = (1 - tv1) % p
    prod = tv1 * tv2 % p
    tv3 = pow(prod, -1, p) if prod else 0
    tv4 = u * tv1 % p * tv3 % p * c3 % p
    x1 = (c2 - tv4) % p
    x2 = (c2 + tv4) % p
    x3 = (pow(tv2 * tv2 % p * tv3 % p, 2, p) * c4 + z) % p
    if is_square(g_of(x1, a, b, p), p):
        x = x1
    elif is_square(g_of(x2, a, b, p), p):
        x = x2
    else:
        x = x3
    y = sqrt_mod(g_of(x, a, b, p), p)
    if sgn0(u) != sgn0(y):
        y = p - y
    return x, y

# --- EC arithmetic (affine, short Weierstrass) --------------------------
INF = None

def ec_add(pt1, pt2, p):
    if pt1 is INF:
        return pt2
    if pt2 is INF:
        return pt1
    (x1, y1), (x2, y2) = pt1, pt2
    if x1 == x2 and (y1 + y2) % p == 0:
        return INF
    if pt1 == pt2:
        lam = 3 * x1 * x1 * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    return x3, (lam * (x1 - x3) - y1) % p

def ec_mul(k, pt, p):
    acc = INF
    while k:
        if k & 1:
            acc = ec_add(acc, pt, p)
        pt = ec_add(pt, pt, p)
        k >>= 1
    return acc

def hash_to_curve(msg, dst, curve):
    p, a, b = curve["p"], curve["a"], curve["b"]
    consts = svdw_constants(p, a, b)
    u0, u1 = hash_to_field(msg, dst, p, 2)
    return ec_add(svdw_map(u0, p, a, b, consts), svdw_map(u1, p, a, b, consts), p)

# --- self-check vs official RFC 9380 vectors ---------------------------
def self_check():
    # K.1 expand_message_xmd, SHA-256, len 0x20
    xmd_dst = b"QUUX-V01-CS02-with-expander-SHA256-128"
    assert expand_message_xmd(b"", xmd_dst, 0x20) == bytes.fromhex(
        "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235"
    )
    assert expand_message_xmd(b"abc", xmd_dst, 0x20) == bytes.fromhex(
        "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615"
    )
    # J.8.1 hash_to_field u-values
    dst = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_"
    u = hash_to_field(b"", dst, P_SECP, 2)
    assert u[0] == 0x6B0F9910DD2BA71C78F2EE9F04D73B5F4C5F7FC773A701ABEA1E573CAB002FB3
    assert u[1] == 0x1AE6C212E08FE1A5937F6202F929A2CC8EF4EE5B9782DB68B0D5799FD8F09E16
    u = hash_to_field(b"abc", dst, P_SECP, 2)
    assert u[0] == 0x128AAB5D3679A1F7601E3BDF94CED1F43E491F544767E18A4873F397B08A2B61
    assert u[1] == 0x5897B65DA3B595A813D0FDCC75C895DC531BE76A03518B044DAAA0F2E4689E00

# --- vector emission ----------------------------------------------------
GENERATORS = [
    ("G_value", "secp256k1", "aegis:gen:v1:G_value"),
    ("G_PRF", "secp256k1", "aegis:gen:v1:G_PRF"),
    ("H_even", "secp256k1", "aegis:gen:v1:H_even"),
    ("G", "secq256k1", "aegis:gen:v1:G"),
    ("H_odd", "secq256k1", "aegis:gen:v1:H_odd"),
    ("empty_leaf", "secp256k1", "aegis:empty-leaf:v1"),
]

def h32(n):
    return format(n, "064x")

def main():
    self_check()
    out = {
        "version": "v1",
        "seed": "aegis:gen:v1",
        "map": "RFC 9380 SvdW, expand_message_xmd/SHA-256, k=128, L=48, msg=empty, DST=domain tag",
        "curves": {},
        "generators": [],
    }
    for name, curve in CURVES.items():
        z = find_z_svdw(curve["p"], curve["a"], curve["b"])
        out["curves"][name] = {"svdw_z": h32(z)}
    for name, curve_name, dst in GENERATORS:
        x, y = hash_to_curve(b"", dst.encode(), CURVES[curve_name])
        out["generators"].append(
            {"name": name, "curve": curve_name, "dst": dst, "x": h32(x), "y": h32(y)}
        )
    # nullifier vector: nf = (nk + rho)^-1 * G on secq256k1 (scalars mod P_SECP)
    g_odd = next(g for g in out["generators"] if g["name"] == "G")
    g_pt = (int(g_odd["x"], 16), int(g_odd["y"], 16))
    nk = 0x3333333333333333333333333333333333333333333333333333333333333333
    rho = 0x4444444444444444444444444444444444444444444444444444444444444444
    inv = pow((nk + rho) % P_SECP, -1, P_SECP)
    nf = ec_mul(inv, g_pt, N_SECP)
    out["nullifier_vector"] = {
        "nk": h32(nk), "rho": h32(rho), "nf_x": h32(nf[0]), "nf_y": h32(nf[1]),
    }
    # rho derivations (H_ρ = hash_to_field count=1 into E_odd scalar field = P_SECP)
    box_id = bytes([0xAA] * 32)
    rho_pm = hash_to_field(box_id, b"aegis:rho:pegmint:v1", P_SECP, 1)[0]
    cb_msg = (1).to_bytes(8, "big") + b"aegis-dev"
    rho_cb = hash_to_field(cb_msg, b"aegis:rho:coinbase:v1", P_SECP, 1)[0]
    # transfer rho seeds from a consumed nullifier's 32-byte x-extract
    rho_tx = hash_to_field(bytes.fromhex(h32(nf[0])), b"aegis:rho:transfer:v1", P_SECP, 1)[0]
    out["rho_vectors"] = {
        "pegmint_boxid_aa32": h32(rho_pm),
        "coinbase_h1_aegis_dev": h32(rho_cb),
        "transfer_from_nf_x": h32(rho_tx),
    }
    # note commitment vector: cm = v*G_value + tag*G_PRF + blind*H_even on secp
    def gen_pt(name):
        g = next(g for g in out["generators"] if g["name"] == name)
        return int(g["x"], 16), int(g["y"], 16)
    v = 1000
    tag = 0x1111111111111111111111111111111111111111111111111111111111111111
    blind = 0x2222222222222222222222222222222222222222222222222222222222222222
    cm = ec_add(
        ec_add(
            ec_mul(v, gen_pt("G_value"), P_SECP),
            ec_mul(tag, gen_pt("G_PRF"), P_SECP),
            P_SECP,
        ),
        ec_mul(blind, gen_pt("H_even"), P_SECP),
        P_SECP,
    )
    out["note_cm_vector"] = {
        "value": v, "tag": h32(tag), "blinding": h32(blind),
        "cm_x": h32(cm[0]), "cm_y": h32(cm[1]),
    }
    json.dump(out, sys.stdout, indent=2)
    print()

if __name__ == "__main__":
    main()
