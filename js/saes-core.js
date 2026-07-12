/**
 * saes-core.js
 * ------------------------------------------------------------
 * Implementasi inti algoritma Simplified AES (S-AES).
 * Mengikuti struktur baku S-AES (Schaefer & Waidner / Stallings):
 *   - Blok data   : 16 bit  -> state matrix 2x2 nibble
 *   - Kunci       : 16 bit  -> 3 subkunci (K0, K1, K2)
 *   - Field       : GF(2^4) dengan polinomial irredusibel x^4 + x + 1 (0x13)
 *
 * Modul ini murni logika (tidak menyentuh DOM) supaya:
 *   1. Mudah diuji terpisah dari tampilan (app.js).
 *   2. Bisa dijadikan referensi silang dengan python/saes.py.
 *
 * Setiap fungsi transformasi mengembalikan { state, log } sehingga
 * seluruh langkah perhitungan bisa ditampilkan di UI (kebutuhan D.2).
 * ------------------------------------------------------------ */

const SAES = (() => {

  // ---------------------------------------------------------
  // 1. Tabel referensi (D.3)
  // ---------------------------------------------------------
  // S-Box: index = nibble input, value = nibble output
  const SBOX =  [0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5,
                 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7];

  const INV_SBOX = [0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF,
                     0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE];

  // RCON1 = 1000 0000 -> nibble [0x8, 0x0]
  // RCON2 = 0011 0000 -> nibble [0x3, 0x0]
  const RCON1 = [0x8, 0x0];
  const RCON2 = [0x3, 0x0];

  // Matriks MixColumns  | 1 4 |      Matriks InvMixColumns | 9 2 |
  //                     | 4 1 |                             | 2 9 |
  const MIX_MATRIX = [[1, 4], [4, 1]];
  const INV_MIX_MATRIX = [[9, 2], [2, 9]];

  // ---------------------------------------------------------
  // 2. Utilitas bit / format
  // ---------------------------------------------------------
  const nib2bin = (n) => n.toString(2).padStart(4, '0');
  const nib2hex = (n) => n.toString(16).toUpperCase();

  // Ubah string biner 16-bit menjadi array 4 nibble [n0,n1,n2,n3]
  function bitsToNibbles(bits16) {
    const n = [];
    for (let i = 0; i < 4; i++) {
      n.push(parseInt(bits16.substr(i * 4, 4), 2));
    }
    return n;
  }

  // Ubah array 4 nibble menjadi string biner 16-bit
  function nibblesToBits(nibbles) {
    return nibbles.map(nib2bin).join('');
  }

  function nibblesToHex(nibbles) {
    return nibbles.map(nib2hex).join('');
  }

  // State disimpan sebagai array [n0,n1,n2,n3] yang merepresentasikan
  // matriks:  | n0  n2 |
  //           | n1  n3 |
  function stateMatrixView(nibbles) {
    return [[nibbles[0], nibbles[2]], [nibbles[1], nibbles[3]]];
  }

  // ---------------------------------------------------------
  // 3. Aritmetika GF(2^4), polinomial x^4 + x + 1 (0x13)
  // ---------------------------------------------------------
  function gfMultTrace(a, b) {
    // Perkalian a*b mod (x^4+x+1), sekaligus mengembalikan jejak
    // (trace) langkah "russian peasant multiplication" agar bisa
    // ditampilkan di UI (kebutuhan: "detail perhitungan perkalian GF").
    let x = a & 0xF, y = b & 0xF, p = 0;
    const steps = [];
    for (let i = 0; i < 4; i++) {
      const bit = y & 1;
      if (bit) p ^= x;
      const carry = x & 0x8;
      steps.push({
        i, x: nib2hex(x & 0xF), yBit: bit, carryReduce: !!carry,
        pAfter: nib2hex(p & 0xF)
      });
      x <<= 1;
      if (carry) x ^= 0x13; // reduksi modulo x^4+x+1
      x &= 0xF;
      y >>= 1;
    }
    return { result: p & 0xF, trace: steps };
  }

  function gfMult(a, b) {
    return gfMultTrace(a, b).result;
  }

  // ---------------------------------------------------------
  // 4. Key Expansion (D.2.a)
  // ---------------------------------------------------------
  function xorWord(w1, w2) {
    return [w1[0] ^ w2[0], w1[1] ^ w2[1]];
  }
  function rotWord(w) {
    return [w[1], w[0]];
  }
  function subWord(w) {
    return [SBOX[w[0]], SBOX[w[1]]];
  }

  function keyExpansion(key16bits) {
    const k = bitsToNibbles(key16bits); // [k0,k1,k2,k3]
    const w0 = [k[0], k[1]];
    const w1 = [k[2], k[3]];

    const rotW1 = rotWord(w1);
    const subRotW1 = subWord(rotW1);
    const g1 = xorWord(subRotW1, RCON1);
    const w2 = xorWord(w0, g1);
    const w3 = xorWord(w2, w1);

    const rotW3 = rotWord(w3);
    const subRotW3 = subWord(rotW3);
    const g2 = xorWord(subRotW3, RCON2);
    const w4 = xorWord(w2, g2);
    const w5 = xorWord(w4, w3);

    const K0 = [...w0, ...w1];
    const K1 = [...w2, ...w3];
    const K2 = [...w4, ...w5];

    const log = {
      w0, w1, rotW1, subRotW1, RCON1, g1, w2, w3,
      rotW3, subRotW3, RCON2, g2, w4, w5, K0, K1, K2
    };
    return { K0, K1, K2, log };
  }

  // ---------------------------------------------------------
  // 5. Transformasi lapis (D.2.b - D.2.d)
  // ---------------------------------------------------------
  function addRoundKey(state, roundKey) {
    return state.map((n, i) => n ^ roundKey[i]);
  }

  function subNibbles(state, box = SBOX) {
    return state.map((n) => box[n]);
  }

  // Menukar baris kedua matriks (n1 <-> n3). Operasi ini self-inverse.
  function shiftRows(state) {
    return [state[0], state[3], state[2], state[1]];
  }

  function mixColumns(state, matrix = MIX_MATRIX) {
    // Kolom 1: [n0, n1], Kolom 2: [n2, n3]
    const col1 = [state[0], state[1]];
    const col2 = [state[2], state[3]];

    const mulCol = (col) => {
      const m00 = gfMultTrace(matrix[0][0], col[0]);
      const m01 = gfMultTrace(matrix[0][1], col[1]);
      const m10 = gfMultTrace(matrix[1][0], col[0]);
      const m11 = gfMultTrace(matrix[1][1], col[1]);
      const out0 = m00.result ^ m01.result;
      const out1 = m10.result ^ m11.result;
      return { out0, out1, m00, m01, m10, m11 };
    };

    const r1 = mulCol(col1);
    const r2 = mulCol(col2);

    const newState = [r1.out0, r1.out1, r2.out0, r2.out1];
    return { state: newState, detail: { col1, col2, r1, r2, matrix } };
  }

  // ---------------------------------------------------------
  // 6. ENKRIPSI PENUH
  // ---------------------------------------------------------
  function encrypt(plainBits, keyBits) {
    const steps = [];
    const { K0, K1, K2, log: keLog } = keyExpansion(keyBits);
    steps.push({ type: 'keyExpansion', data: keLog });

    let state = bitsToNibbles(plainBits);
    steps.push({ type: 'input', label: 'Plaintext (state awal)', state: [...state] });

    // Initial AddRoundKey
    const beforeARK0 = [...state];
    state = addRoundKey(state, K0);
    steps.push({
      type: 'addRoundKey', round: 0, label: 'Initial AddRoundKey (K0)',
      before: beforeARK0, key: K0, after: [...state]
    });

    // ---- Round 1 ----
    let before = [...state];
    state = subNibbles(state, SBOX);
    steps.push({ type: 'subNibbles', round: 1, box: 'SBOX', before, after: [...state] });

    before = [...state];
    state = shiftRows(state);
    steps.push({ type: 'shiftRows', round: 1, before, after: [...state] });

    before = [...state];
    const mc1 = mixColumns(state, MIX_MATRIX);
    state = mc1.state;
    steps.push({ type: 'mixColumns', round: 1, before, after: [...state], detail: mc1.detail });

    before = [...state];
    state = addRoundKey(state, K1);
    steps.push({ type: 'addRoundKey', round: 1, label: 'AddRoundKey (K1)', before, key: K1, after: [...state] });

    // ---- Round 2 (final) ----
    before = [...state];
    state = subNibbles(state, SBOX);
    steps.push({ type: 'subNibbles', round: 2, box: 'SBOX', before, after: [...state] });

    before = [...state];
    state = shiftRows(state);
    steps.push({ type: 'shiftRows', round: 2, before, after: [...state] });

    before = [...state];
    state = addRoundKey(state, K2);
    steps.push({ type: 'addRoundKey', round: 2, label: 'AddRoundKey (K2) - Final', before, key: K2, after: [...state] });

    const cipherBits = nibblesToBits(state);
    const cipherHex = nibblesToHex(state);
    steps.push({ type: 'output', label: 'Ciphertext akhir', state: [...state], bits: cipherBits, hex: cipherHex });

    return { result: cipherBits, resultHex: cipherHex, K0, K1, K2, steps };
  }

  // ---------------------------------------------------------
  // 7. DEKRIPSI PENUH  (InvCipher, sesuai D.2.e)
  // ---------------------------------------------------------
  function decrypt(cipherBits, keyBits) {
    const steps = [];
    const { K0, K1, K2, log: keLog } = keyExpansion(keyBits);
    steps.push({ type: 'keyExpansion', data: keLog });

    let state = bitsToNibbles(cipherBits);
    steps.push({ type: 'input', label: 'Ciphertext (state awal)', state: [...state] });

    // Initial AddRoundKey dengan K2
    let before = [...state];
    state = addRoundKey(state, K2);
    steps.push({ type: 'addRoundKey', round: 0, label: 'Initial AddRoundKey (K2)', before, key: K2, after: [...state] });

    // ---- Inverse Round 1 ----
    before = [...state];
    state = shiftRows(state); // InvShiftRows == ShiftRows (self-inverse)
    steps.push({ type: 'invShiftRows', round: 1, before, after: [...state] });

    before = [...state];
    state = subNibbles(state, INV_SBOX);
    steps.push({ type: 'invSubNibbles', round: 1, box: 'INV_SBOX', before, after: [...state] });

    before = [...state];
    state = addRoundKey(state, K1);
    steps.push({ type: 'addRoundKey', round: 1, label: 'AddRoundKey (K1)', before, key: K1, after: [...state] });

    before = [...state];
    const imc = mixColumns(state, INV_MIX_MATRIX);
    state = imc.state;
    steps.push({ type: 'invMixColumns', round: 1, before, after: [...state], detail: imc.detail });

    // ---- Inverse Round 2 ----
    before = [...state];
    state = shiftRows(state);
    steps.push({ type: 'invShiftRows', round: 2, before, after: [...state] });

    before = [...state];
    state = subNibbles(state, INV_SBOX);
    steps.push({ type: 'invSubNibbles', round: 2, box: 'INV_SBOX', before, after: [...state] });

    before = [...state];
    state = addRoundKey(state, K0);
    steps.push({ type: 'addRoundKey', round: 2, label: 'AddRoundKey (K0) - Final', before, key: K0, after: [...state] });

    const plainBits = nibblesToBits(state);
    const plainHex = nibblesToHex(state);
    steps.push({ type: 'output', label: 'Plaintext akhir', state: [...state], bits: plainBits, hex: plainHex });

    return { result: plainBits, resultHex: plainHex, K0, K1, K2, steps };
  }

  // ---------------------------------------------------------
  // 8. Validasi input
  // ---------------------------------------------------------
  function isValidBits16(str) {
    return typeof str === 'string' && /^[01]{16}$/.test(str);
  }

  return {
    SBOX, INV_SBOX, RCON1, RCON2, MIX_MATRIX, INV_MIX_MATRIX,
    nib2bin, nib2hex, bitsToNibbles, nibblesToBits, nibblesToHex,
    stateMatrixView, gfMult, gfMultTrace,
    keyExpansion, addRoundKey, subNibbles, shiftRows, mixColumns,
    encrypt, decrypt, isValidBits16
  };
})();
