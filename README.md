# S-AES Simulator — Simplified Advanced Encryption Standard

Aplikasi web simulasi algoritma **S-AES (Simplified Advanced Encryption Standard)**, dibuat untuk Tugas Individu Mata Kuliah Kriptografi (Semester Genap 2025/2026). Aplikasi mendukung proses **enkripsi** dan **dekripsi** blok 16-bit dengan kunci 16-bit, lengkap dengan tampilan **langkah perhitungan** (Key Expansion, SubNibbles, ShiftRows, MixColumns, AddRoundKey) secara rinci di GF(2⁴).

> ⚠️ **Catatan penting:** Kode ini adalah *starting point*. Sesuai ketentuan akademik pada modul tugas, Anda wajib memahami, memodifikasi seperlunya, dan bisa menjelaskan setiap bagian kode (termasuk operasi GF(2⁴)) saat presentasi/konfirmasi dosen.

---

## 1. Struktur Folder

```
saes-webapp/
├── index.html          # Halaman utama aplikasi
├── css/
│   └── style.css        # Styling / tampilan
├── js/
│   ├── saes-core.js     # Logika inti algoritma S-AES (tanpa DOM)
│   └── app.js            # Penghubung form <-> algoritma, render langkah
├── python/
│   └── saes.py           # Implementasi Python (CLI) untuk cross-check
└── README.md
```

---

## 2. Menjalankan Aplikasi Web (Lokal)

Aplikasi ini **murni client-side** (HTML/CSS/JS), tidak butuh server backend/database, sehingga sangat mudah dijalankan maupun di-hosting.

### Cara termudah
1. Ekstrak folder `saes-webapp/`.
2. Klik dua kali file `index.html` — akan terbuka di browser default Anda.

### Menggunakan local server (disarankan, menghindari isu path browser)
Jika punya Python terinstall:
```bash
cd saes-webapp
python3 -m http.server 8000
```
Lalu buka `http://localhost:8000` di browser.

Atau dengan Node.js (`npx serve`):
```bash
cd saes-webapp
npx serve .
```

---

## 3. Cara Menggunakan Aplikasi

1. **Pilih mode**: Enkripsi atau Dekripsi (toggle di bagian atas form).
2. **Isi input**:
   - Jika mode **Enkripsi** → isi kolom *Plaintext* (16-bit biner) dan *Kunci* (16-bit biner).
   - Jika mode **Dekripsi** → isi kolom *Ciphertext* (16-bit biner) dan *Kunci* (16-bit biner).
   - Input hanya menerima karakter `0` dan `1`, harus tepat 16 digit. Selain itu akan muncul pesan error validasi.
3. Klik **Submit**. Aplikasi akan menampilkan:
   - **Hasil** (biner & heksadesimal) di panel Output.
   - **Langkah Perhitungan** lengkap: Key Expansion (w0–w5, K0/K1/K2), state matrix sebelum/sesudah setiap transformasi (SubNibbles, ShiftRows, MixColumns/InvMixColumns beserta detail perkalian GF(2⁴), AddRoundKey).
4. Klik tombol **Tampilkan/Sembunyikan Langkah Perhitungan** untuk toggle panel step-by-step.
5. Klik **Reset** untuk mengosongkan semua field dan mengulang dari awal.
6. Panel **Tabel Referensi** di bagian bawah menampilkan S-Box, Inverse S-Box, matriks MixColumns/InvMixColumns, dan konstanta RCON yang dipakai algoritma — selalu terlihat sebagai referensi.

### Contoh nilai uji (test vector standar S-AES)
| Field | Nilai biner | Hex |
|---|---|---|
| Plaintext | `0110111101101011` | 6F6B |
| Kunci | `1010011100111011` | A73B |
| Ciphertext (hasil) | `0000011100111000` | 0738 |

Gunakan nilai ini untuk memastikan aplikasi Anda menghasilkan output yang benar sebelum memakai nilai lain untuk perhitungan manual.

---

## 4. Menjalankan Versi Python (CLI) — untuk Cross-Check

File `python/saes.py` berisi implementasi S-AES yang identik secara logika dengan `js/saes-core.js`. Berguna untuk:
- Memverifikasi hasil aplikasi web dan perhitungan manual tulis tangan.
- Didemonstrasikan di video penjelasan (menunjukkan proses berjalan di terminal, baris demi baris).

Jalankan:
```bash
cd python
python3 saes.py
```
Ikuti instruksi di terminal: pilih mode (1 = Enkripsi, 2 = Dekripsi), lalu masukkan kunci dan plaintext/ciphertext 16-bit. Semua langkah perhitungan (Key Expansion, SubNibbles, ShiftRows, MixColumns/InvMixColumns beserta trace perkalian GF(2⁴), AddRoundKey) akan dicetak ke terminal.

Bisa juga dipakai langsung sebagai modul:
```python
from saes import encrypt, decrypt
cipher_bits, cipher_hex = encrypt("0110111101101011", "1010011100111011")
plain_bits, plain_hex = decrypt(cipher_bits, "1010011100111011")
```

---

## 5. Deploy ke Domain `.my.id`

Karena aplikasi ini statis (tidak butuh server Python/Node saat runtime — file `saes.py` hanya untuk CLI/cross-check lokal), Anda bisa deploy dengan opsi berikut:

- **GitHub Pages / Netlify / Vercel** (gratis) → arahkan *custom domain* `.my.id` Anda ke sana melalui DNS (CNAME/A record).
- **Shared hosting biasa** → upload isi folder `saes-webapp/` (khususnya `index.html`, `css/`, `js/`) ke `public_html` via FTP/cPanel File Manager.

Pastikan struktur folder (`css/`, `js/`) tetap sama persis dengan path yang direferensikan di `index.html`.

*(Sesuai permintaan, proses deploy dilakukan sendiri oleh mahasiswa.)*

---

## 6. Ringkasan Algoritma yang Diimplementasikan

- **Ukuran blok**: 16 bit → state matrix 2×2 nibble `[[n0,n2],[n1,n3]]`
- **Ukuran kunci**: 16 bit → 3 subkunci K0, K1, K2
- **Round**: 2 round + 1 initial AddRoundKey
- **Field**: GF(2⁴), polinomial irredusibel `x⁴ + x + 1` (0x13)
- **Enkripsi**: AddRoundKey(K0) → [SubNibbles → ShiftRows → MixColumns → AddRoundKey(K1)] → [SubNibbles → ShiftRows → AddRoundKey(K2)]
- **Dekripsi**: AddRoundKey(K2) → [InvShiftRows → InvSubNibbles → AddRoundKey(K1) → InvMixColumns] → [InvShiftRows → InvSubNibbles → AddRoundKey(K0)]

---

## 7. Lisensi / Penggunaan

Dibuat sebagai bahan belajar untuk Tugas Individu Mata Kuliah Kriptografi. Silakan dimodifikasi sesuai kebutuhan, namun pastikan Anda memahami setiap bagiannya sebelum dikumpulkan, sesuai ketentuan akademik pada modul tugas.
