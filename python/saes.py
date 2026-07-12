"""
saes.py
------------------------------------------------------------
Implementasi Simplified AES (S-AES) dalam Python.

Tujuan file ini:
  1. Referensi silang untuk memverifikasi hasil aplikasi web
     (js/saes-core.js) dan perhitungan manual tulis tangan.
  2. Bisa dijalankan langsung dari terminal (CLI) sehingga mudah
     didemonstrasikan pada video penjelasan.

Struktur algoritma & tabel mengikuti spesifikasi pada modul tugas:
  - Blok data 16 bit -> state matrix 2x2 nibble
  - Kunci 16 bit -> K0, K1, K2 (via Key Expansion)
  - GF(2^4) dengan polinomial irredusibel x^4 + x + 1 (0x13)

Jalankan:
    python saes.py

lalu ikuti instruksi pada terminal (pilih mode Enkripsi/Dekripsi,
masukkan plaintext/ciphertext 16-bit dan kunci 16-bit).
------------------------------------------------------------
"""

from __future__ import annotations
from typing import List, Tuple

# ---------------------------------------------------------
# 1. Tabel referensi
# ---------------------------------------------------------
SBOX = [0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5,
        0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7]

INV_SBOX = [0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF,
            0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE]

RCON1 = [0x8, 0x0]   # 1000 0000 (0x80)
RCON2 = [0x3, 0x0]   # 0011 0000 (0x30)

MIX_MATRIX = [[1, 4], [4, 1]]
INV_MIX_MATRIX = [[9, 2], [2, 9]]

Nibbles = List[int]


# ---------------------------------------------------------
# 2. Utilitas bit / format
# ---------------------------------------------------------
def bits_to_nibbles(bits16: str) -> Nibbles:
    if len(bits16) != 16 or any(c not in "01" for c in bits16):
        raise ValueError("Input harus 16 digit biner (hanya 0/1).")
    return [int(bits16[i:i + 4], 2) for i in range(0, 16, 4)]


def nibbles_to_bits(nibbles: Nibbles) -> str:
    return "".join(f"{n:04b}" for n in nibbles)


def nibbles_to_hex(nibbles: Nibbles) -> str:
    return "".join(f"{n:X}" for n in nibbles)


def state_matrix_view(nibbles: Nibbles) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    # | n0 n2 |
    # | n1 n3 |
    return ((nibbles[0], nibbles[2]), (nibbles[1], nibbles[3]))


def print_state(nibbles: Nibbles, label: str = "") -> None:
    (a, b), (c, d) = state_matrix_view(nibbles)
    if label:
        print(f"  {label}")
    print(f"    | {a:X} {b:X} |      (bin) | {a:04b} {b:04b} |")
    print(f"    | {c:X} {d:X} |            | {c:04b} {d:04b} |")


# ---------------------------------------------------------
# 3. Aritmetika GF(2^4), polinomial x^4 + x + 1 (0x13)
# ---------------------------------------------------------
def gf_mult(a: int, b: int, verbose: bool = False) -> int:
    """Perkalian a*b pada GF(2^4) modulo x^4+x+1 (0x13)."""
    x, y, p = a & 0xF, b & 0xF, 0
    for i in range(4):
        bit = y & 1
        if bit:
            p ^= x
        carry = x & 0x8
        if verbose:
            print(f"      i={i}: x={x:X} bit_y={bit} carry={'ya' if carry else 'tidak'} -> p sementara={p & 0xF:X}")
        x <<= 1
        if carry:
            x ^= 0x13
        x &= 0xF
        y >>= 1
    return p & 0xF


# ---------------------------------------------------------
# 4. Key Expansion
# ---------------------------------------------------------
def xor_word(w1: List[int], w2: List[int]) -> List[int]:
    return [w1[0] ^ w2[0], w1[1] ^ w2[1]]


def rot_word(w: List[int]) -> List[int]:
    return [w[1], w[0]]


def sub_word(w: List[int]) -> List[int]:
    return [SBOX[w[0]], SBOX[w[1]]]


def key_expansion(key_bits: str, verbose: bool = True):
    k = bits_to_nibbles(key_bits)
    w0, w1 = [k[0], k[1]], [k[2], k[3]]

    rot_w1 = rot_word(w1)
    sub_rot_w1 = sub_word(rot_w1)
    g1 = xor_word(sub_rot_w1, RCON1)
    w2 = xor_word(w0, g1)
    w3 = xor_word(w2, w1)

    rot_w3 = rot_word(w3)
    sub_rot_w3 = sub_word(rot_w3)
    g2 = xor_word(sub_rot_w3, RCON2)
    w4 = xor_word(w2, g2)
    w5 = xor_word(w4, w3)

    K0, K1, K2 = w0 + w1, w2 + w3, w4 + w5

    if verbose:
        print("== KEY EXPANSION ==")
        print(f"  w0={w0}  w1={w1}")
        print(f"  RotWord(w1)={rot_w1}  SubWord(...)={sub_rot_w1}  RCON1={RCON1}  g1={g1}")
        print(f"  w2 = w0 XOR g1 = {w2}")
        print(f"  w3 = w2 XOR w1 = {w3}")
        print(f"  RotWord(w3)={rot_w3}  SubWord(...)={sub_rot_w3}  RCON2={RCON2}  g2={g2}")
        print(f"  w4 = w2 XOR g2 = {w4}")
        print(f"  w5 = w4 XOR w3 = {w5}")
        print(f"  K0 = {nibbles_to_hex(K0)}   K1 = {nibbles_to_hex(K1)}   K2 = {nibbles_to_hex(K2)}\n")

    return K0, K1, K2


# ---------------------------------------------------------
# 5. Transformasi lapis
# ---------------------------------------------------------
def add_round_key(state: Nibbles, round_key: Nibbles) -> Nibbles:
    return [s ^ k for s, k in zip(state, round_key)]


def sub_nibbles(state: Nibbles, box=SBOX) -> Nibbles:
    return [box[n] for n in state]


def shift_rows(state: Nibbles) -> Nibbles:
    # self-inverse: menukar n1 <-> n3
    return [state[0], state[3], state[2], state[1]]


def mix_columns(state: Nibbles, matrix=MIX_MATRIX, verbose: bool = True) -> Nibbles:
    col1 = [state[0], state[1]]
    col2 = [state[2], state[3]]

    def mul_col(col, tag):
        if verbose:
            print(f"    Kolom {tag} = {col}")
        m00 = gf_mult(matrix[0][0], col[0], verbose)
        m01 = gf_mult(matrix[0][1], col[1], verbose)
        out0 = m00 ^ m01
        m10 = gf_mult(matrix[1][0], col[0], verbose)
        m11 = gf_mult(matrix[1][1], col[1], verbose)
        out1 = m10 ^ m11
        if verbose:
            print(f"      -> out0 = {matrix[0][0]}*{col[0]:X} XOR {matrix[0][1]}*{col[1]:X} = {m00:X} XOR {m01:X} = {out0:X}")
            print(f"      -> out1 = {matrix[1][0]}*{col[0]:X} XOR {matrix[1][1]}*{col[1]:X} = {m10:X} XOR {m11:X} = {out1:X}")
        return out0, out1

    r10, r11 = mul_col(col1, 1)
    r20, r21 = mul_col(col2, 2)
    return [r10, r11, r20, r21]


# ---------------------------------------------------------
# 6. Enkripsi & Dekripsi
# ---------------------------------------------------------
def encrypt(plain_bits: str, key_bits: str, verbose: bool = True) -> Tuple[str, str]:
    K0, K1, K2 = key_expansion(key_bits, verbose)
    state = bits_to_nibbles(plain_bits)
    if verbose:
        print("== ENKRIPSI =="); print_state(state, "Plaintext (state awal)")

    state = add_round_key(state, K0)
    if verbose: print_state(state, "Setelah Initial AddRoundKey (K0)")

    # Round 1
    state = sub_nibbles(state, SBOX)
    if verbose: print_state(state, "Round 1 - Setelah SubNibbles")
    state = shift_rows(state)
    if verbose: print_state(state, "Round 1 - Setelah ShiftRows")
    if verbose: print("  MixColumns:")
    state = mix_columns(state, MIX_MATRIX, verbose)
    if verbose: print_state(state, "Round 1 - Setelah MixColumns")
    state = add_round_key(state, K1)
    if verbose: print_state(state, "Round 1 - Setelah AddRoundKey (K1)")

    # Round 2 (final)
    state = sub_nibbles(state, SBOX)
    if verbose: print_state(state, "Round 2 - Setelah SubNibbles")
    state = shift_rows(state)
    if verbose: print_state(state, "Round 2 - Setelah ShiftRows")
    state = add_round_key(state, K2)
    if verbose: print_state(state, "Round 2 - Setelah AddRoundKey (K2) [FINAL]")

    cipher_bits = nibbles_to_bits(state)
    cipher_hex = nibbles_to_hex(state)
    if verbose:
        print(f"\n  Ciphertext = {cipher_bits} (biner) = {cipher_hex} (hex)\n")
    return cipher_bits, cipher_hex


def decrypt(cipher_bits: str, key_bits: str, verbose: bool = True) -> Tuple[str, str]:
    K0, K1, K2 = key_expansion(key_bits, verbose)
    state = bits_to_nibbles(cipher_bits)
    if verbose:
        print("== DEKRIPSI =="); print_state(state, "Ciphertext (state awal)")

    state = add_round_key(state, K2)
    if verbose: print_state(state, "Setelah Initial AddRoundKey (K2)")

    # Inverse Round 1
    state = shift_rows(state)
    if verbose: print_state(state, "Inv Round 1 - Setelah InvShiftRows")
    state = sub_nibbles(state, INV_SBOX)
    if verbose: print_state(state, "Inv Round 1 - Setelah InvSubNibbles")
    state = add_round_key(state, K1)
    if verbose: print_state(state, "Inv Round 1 - Setelah AddRoundKey (K1)")
    if verbose: print("  InvMixColumns:")
    state = mix_columns(state, INV_MIX_MATRIX, verbose)
    if verbose: print_state(state, "Inv Round 1 - Setelah InvMixColumns")

    # Inverse Round 2
    state = shift_rows(state)
    if verbose: print_state(state, "Inv Round 2 - Setelah InvShiftRows")
    state = sub_nibbles(state, INV_SBOX)
    if verbose: print_state(state, "Inv Round 2 - Setelah InvSubNibbles")
    state = add_round_key(state, K0)
    if verbose: print_state(state, "Inv Round 2 - Setelah AddRoundKey (K0) [FINAL]")

    plain_bits = nibbles_to_bits(state)
    plain_hex = nibbles_to_hex(state)
    if verbose:
        print(f"\n  Plaintext = {plain_bits} (biner) = {plain_hex} (hex)\n")
    return plain_bits, plain_hex


# ---------------------------------------------------------
# 7. CLI sederhana
# ---------------------------------------------------------
def _prompt_bits16(label: str) -> str:
    while True:
        val = input(f"{label} (16 bit biner): ").strip()
        if len(val) == 16 and all(c in "01" for c in val):
            return val
        print("  -> Input tidak valid. Harus tepat 16 digit, hanya 0/1. Coba lagi.")


def main():
    print("=" * 60)
    print(" S-AES CLI — Simplified Advanced Encryption Standard")
    print("=" * 60)
    mode = ""
    while mode not in ("1", "2"):
        mode = input("Pilih mode: [1] Enkripsi  [2] Dekripsi -> ").strip()

    key_bits = _prompt_bits16("Kunci")
    if mode == "1":
        plain_bits = _prompt_bits16("Plaintext")
        encrypt(plain_bits, key_bits, verbose=True)
    else:
        cipher_bits = _prompt_bits16("Ciphertext")
        decrypt(cipher_bits, key_bits, verbose=True)


if __name__ == "__main__":
    main()
