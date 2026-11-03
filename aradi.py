"""
Reference implementation of the ARADI block cipher (Greene, Motley, Weeks,
IACR ePrint 2024/1240), together with the helper maps needed by the
differential fault attack (DFA) simulation.

State: four 32-bit words (w, x, y, z); w is the most significant word.
Key:   eight 32-bit words K0..K7 (K0 is the least significant word of the
       256-bit key as printed in the specification's test vector).

All functions are pure; the module keeps no mutable global state, so it is
safe to call from several processes or threads.
"""
from __future__ import annotations

from typing import List, Sequence, Tuple

MASK32 = 0xFFFFFFFF
MASK16 = 0xFFFF
NUM_ROUNDS = 16

# Rotation constants (a_j, b_j, c_j) of the linear layer L_j, j = 0..3.
LIN_A = (11, 10, 9, 8)
LIN_B = (8, 9, 4, 9)
LIN_C = (14, 11, 14, 7)

State = Tuple[int, int, int, int]
KeyState = List[int]


def rotl16(v: int, r: int) -> int:
    r %= 16
    return ((v << r) | (v >> (16 - r))) & MASK16


def rotl32(v: int, r: int) -> int:
    r %= 32
    return ((v << r) | (v >> (32 - r))) & MASK32


# ---------------------------------------------------------------------------
# S-box layer
# ---------------------------------------------------------------------------
def sbox_layer(w: int, x: int, y: int, z: int) -> State:
    """Bit-sliced S-box: four Toffoli steps, applied to all 32 columns."""
    x ^= w & y
    z ^= x & y
    y ^= w & z
    w ^= x & z
    return w, x, y, z


def sbox_layer_inv(w: int, x: int, y: int, z: int) -> State:
    """Inverse of sbox_layer (undo the Toffoli steps in reverse order)."""
    w ^= x & z
    y ^= w & z
    z ^= x & y
    x ^= w & y
    return w, x, y, z


def sbox4(v: int) -> int:
    """The 4-bit S-box on an integer v = (w<<3)|(x<<2)|(y<<1)|z."""
    w, x, y, z = (v >> 3) & 1, (v >> 2) & 1, (v >> 1) & 1, v & 1
    w, x, y, z = sbox_layer(w, x, y, z)
    return (w << 3) | (x << 2) | (y << 1) | z


SBOX = tuple(sbox4(v) for v in range(16))
SBOX_INV = tuple(SBOX.index(v) for v in range(16))


# ---------------------------------------------------------------------------
# Linear layer
# ---------------------------------------------------------------------------
def linear_map(j: int, v: int) -> int:
    """L_j on one 32-bit word v = u || l (u upper 16 bits, l lower 16 bits).

    upper' = u ^ (u <<< a_j) ^ (l <<< c_j)
    lower' = l ^ (l <<< a_j) ^ (u <<< b_j)
    """
    u = (v >> 16) & MASK16
    l = v & MASK16
    a, b, c = LIN_A[j], LIN_B[j], LIN_C[j]
    up = u ^ rotl16(u, a) ^ rotl16(l, c)
    lo = l ^ rotl16(l, a) ^ rotl16(u, b)
    return (up << 16) | lo


def linear_layer(j: int, w: int, x: int, y: int, z: int) -> State:
    return linear_map(j, w), linear_map(j, x), linear_map(j, y), linear_map(j, z)


# ---------------------------------------------------------------------------
# Key schedule
# ---------------------------------------------------------------------------
def m0(x: int, y: int) -> Tuple[int, int]:
    x1 = rotl32(x, 1) ^ y
    y1 = rotl32(y, 3) ^ x1
    return x1 & MASK32, y1 & MASK32


def m1(x: int, y: int) -> Tuple[int, int]:
    x1 = rotl32(x, 9) ^ y
    y1 = rotl32(y, 28) ^ x1
    return x1 & MASK32, y1 & MASK32


def m0_inv(x1: int, y1: int) -> Tuple[int, int]:
    y = rotl32(y1 ^ x1, 32 - 3)
    x = rotl32(x1 ^ y, 32 - 1)
    return x, y


def m1_inv(x1: int, y1: int) -> Tuple[int, int]:
    y = rotl32(y1 ^ x1, 32 - 28)
    x = rotl32(x1 ^ y, 32 - 9)
    return x, y


def key_update(k: Sequence[int], i: int) -> KeyState:
    """One key-schedule step i (0 <= i <= 15): K^{i} -> K^{i+1}."""
    k = list(k)
    k[0], k[1] = m0(k[0], k[1])
    k[2], k[3] = m1(k[2], k[3])
    k[4], k[5] = m0(k[4], k[5])
    k[6], k[7] = m1(k[6], k[7])
    if i % 2 == 0:
        k[1], k[2] = k[2], k[1]
        k[5], k[6] = k[6], k[5]
    else:
        k[1], k[4] = k[4], k[1]
        k[3], k[6] = k[6], k[3]
    k[7] ^= i
    return k


def key_update_inv(k: Sequence[int], i: int) -> KeyState:
    """Inverse of key_update(., i): K^{i+1} -> K^{i}."""
    k = list(k)
    k[7] ^= i
    if i % 2 == 0:
        k[1], k[2] = k[2], k[1]
        k[5], k[6] = k[6], k[5]
    else:
        k[1], k[4] = k[4], k[1]
        k[3], k[6] = k[6], k[3]
    k[0], k[1] = m0_inv(k[0], k[1])
    k[2], k[3] = m1_inv(k[2], k[3])
    k[4], k[5] = m0_inv(k[4], k[5])
    k[6], k[7] = m1_inv(k[6], k[7])
    return k


def round_key_from_state(k: Sequence[int], i: int) -> State:
    """Round key k_i taken from key state K^i (even i: words 0..3, odd: 4..7)."""
    if i % 2 == 0:
        return k[0], k[1], k[2], k[3]
    return k[4], k[5], k[6], k[7]


def expand_key(master: Sequence[int]) -> Tuple[List[State], List[KeyState]]:
    """Return (round_keys[0..16], key_states[0..16])."""
    assert len(master) == 8
    states = [list(master)]
    rks = [round_key_from_state(master, 0)]
    k = list(master)
    for i in range(NUM_ROUNDS):
        k = key_update(k, i)
        states.append(list(k))
        rks.append(round_key_from_state(k, i + 1))
    return rks, states


def master_from_key_state(k_state: Sequence[int], i: int) -> KeyState:
    """Invert the key schedule from key state K^i back to K^0."""
    k = list(k_state)
    for step in range(i - 1, -1, -1):
        k = key_update_inv(k, step)
    return k


# ---------------------------------------------------------------------------
# Encryption / decryption with optional fault injection
# ---------------------------------------------------------------------------
def xor_state(s: State, k: State) -> State:
    return s[0] ^ k[0], s[1] ^ k[1], s[2] ^ k[2], s[3] ^ k[3]


def encrypt(pt: State, rks: Sequence[State], fault: Tuple[int, int, int] | None = None,
            return_trace: bool = False):
    """Encrypt one block.

    rks[i] is the round key XORed at the start of round i+1 (rks[0] is the
    pre-whitening key, rks[16] the final key).  Round i (1..16) is
    tau_{k_i} o Lambda_i o pi applied to the state S^{i-1}; S^0 = pt ^ k_0.

    fault = (round_index r, word_index, delta): XOR `delta` into word
    `word_index` (0=w,1=x,2=y,3=z) of the state S^{r-1}, i.e. at the start of
    round r (before the S-box of round r).  r in 1..16.

    If return_trace is True the list [S^0, S^1, ..., S^16] is returned.
    """
    s = xor_state(pt, rks[0])
    trace = [s] if return_trace else None
    for r in range(1, NUM_ROUNDS + 1):
        if fault is not None and fault[0] == r:
            lst = list(s)
            lst[fault[1]] ^= fault[2]
            s = tuple(lst)  # type: ignore[assignment]
        s = sbox_layer(*s)
        s = linear_layer((r - 1) % 4, *s)
        s = xor_state(s, rks[r])
        if return_trace:
            trace.append(s)
    return trace if return_trace else s


def decrypt(ct: State, rks: Sequence[State]) -> State:
    s = ct
    for r in range(NUM_ROUNDS, 0, -1):
        s = xor_state(s, rks[r])
        s = linear_layer((r - 1) % 4, *s)  # L_j is an involution
        s = sbox_layer_inv(*s)
    return xor_state(s, rks[0])


def decrypt_one_round(ct: State, rk: State, r: int) -> State:
    """Undo round r (1..16) given its round key: returns S^{r-1}."""
    s = xor_state(ct, rk)
    s = linear_layer((r - 1) % 4, *s)
    return sbox_layer_inv(*s)


# ---------------------------------------------------------------------------
# Self test
# ---------------------------------------------------------------------------
# Test vector 1 of the specification (key printed as K7 .. K0).
TV_KEY = [0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C,
          0x13121110, 0x17161514, 0x1B1A1918, 0x1F1E1D1C]
TV_PT = (0, 0, 0, 0)
TV_CT = (0x3F09ABF4, 0x00E3BD74, 0x03260DEF, 0xB7C53912)


def self_test() -> None:
    rks, states = expand_key(TV_KEY)
    ct = encrypt(TV_PT, rks)
    assert ct == TV_CT, f"test vector mismatch: {[hex(v) for v in ct]}"
    assert decrypt(ct, rks) == TV_PT
    for j in range(4):
        for v in (0, 1, 0x80000000, 0x12345678, 0xFFFFFFFF, 0xDEADBEEF):
            assert linear_map(j, linear_map(j, v)) == v, "L_j is not an involution"
    for v in range(16):
        assert SBOX_INV[SBOX[v]] == v
    w, x, y, z = 0x0123, 0x4567, 0x89AB, 0xCDEF
    assert sbox_layer_inv(*sbox_layer(w, x, y, z)) == (w, x, y, z)
    assert master_from_key_state(states[16], 16) == TV_KEY
    for i in range(1, 17):
        assert key_update_inv(key_update(states[i - 1], i - 1), i - 1) == states[i - 1]


if __name__ == "__main__":
    self_test()
    print("ARADI self test passed (test vector 1, involutions, key schedule inverse).")
    print("SBOX     =", [f"{v:X}" for v in SBOX])
    print("SBOX_INV =", [f"{v:X}" for v in SBOX_INV])
