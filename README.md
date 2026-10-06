# YOUR cardaMOM

Skrip Python untuk mengambil **29 kunci** dari native library `libcardamom.so`
di dalam paket MyXL — **sepenuhnya offline**: tanpa perangkat, tanpa root,
tanpa Frida.

Skrip membuka file `.xapk`, mengekstrak sertifikat penandatangan APK,
membaca literal terenkripsi dari 29 fungsi getter JNI `Cardamom_*` di `.rodata`,
lalu mendekripsinya dengan kunci yang diturunkan dari sertifikat tersebut.

## Cara kerja

1. **Buka `.xapk`** (struktur zip) → temukan APK di dalamnya.
   Juga menerima `.apk` tunggal, `.apks`, atau bundle `.apkmirror`.
2. **Ambil sertifikat penandatangan** dari APK — dari `META-INF/*.RSA`
   (via PKCS#7), atau fallback ke *APK Signing Block* v2/v3.
3. **Ekstrak `lib/<abi>/libcardamom.so`** dari salah satu APK
   (default ABI `arm64-v8a`, bisa diubah dengan `--abi`).
4. **Baca 29 simbol JNI** `Java_com_myxlultimate_core_spice_Cardamom_*`
   dari `.dynsym`, lalu temukan literal string masing-masing di `.rodata`
   lewat disassembly (capstone): pola `ADRP+ADD` / `ADR` / `ADRP+LDR`,
   divalidasi terhadap ukuran alokasi `operator new`.
5. **Dekripsi literal** dengan kunci turunan sertifikat:
   - `encryptionKey` = base64(DER sertifikat), tanpa newline
   - kunci AES-256 = `sha256hex(encryptionKey)[:32]`
   - IV = `sha256hex(encryptionKey[:10])[:16]`
   - AES/CBC/PKCS5Padding atas base64url(literal)
   - skrip otomatis mencoba 3 varian IV (`take(10)` / penuh / `[-10:]`)
     dan memakai varian yang membuka getter terbanyak.
6. **Tulis hasil** ke `.json` / `.txt` / `.env` dan tampilkan di layar.

## Kebutuhan

- Python 3.8+
- [`cryptography`](https://cryptography.io) (sertifikat, AES)
- [`capstone`](https://www.capstone-engine.org) (disassembly ARM64)

```bash
pip install cryptography capstone
```

## Pemakaian

```bash
python main.py 'myXL+-+XL,+PRIORITAS+&+HOME_9.6.0_APKPure.xapk'
```

```bash
# direktori keluaran & path JSON kustom
python main.py app.xapk --out hasil --json kunci.json

# APK tunggal + ABI lain + mode senyap
python main.py app.apk --out hasil --abi armeabi-v7a --quiet
```

### Opsi CLI

| Opsi | Default | Keterangan |
|---|---|---|
| `xapk` | *(wajib)* | Path ke `.xapk` / `.apk` / `.apks` |
| `--out` | `keys-dari-xapk` | Direktori keluaran |
| `--json` | `<out>/cardamom-keys.json` | Path khusus untuk file JSON |
| `--abi` | `arm64-v8a` | ABI `libcardamom.so` yang dipilih bila ada beberapa |
| `--quiet` | — | Hanya proses, tanpa tampilan di layar |

## Keluaran

Semua file ditulis dengan permission `0600` di dalam direktori `0700`:

- **`cardamom-keys.json`** — metadata (sumber xapk, sha256 `.so`, subjek &
  sha256 sertifikat, varian IV yang dipakai, jumlah getter terbuka) + daftar kunci.
- **`cardamom-keys.txt`** — format manusiawi: `getter` lalu nilainya di baris
  berindentasi.
- **`cardamom-keys.env`** — `NAMA_GETTER="nilai"` (nama diubah ke
  UPPER_SNAKE_CASE), siap di-`source`.

Contoh tampilan layar:

```
IV dipakai  : encode(key).take(10)  (29/29 getter terbuka)

getter                                     nilai
getApiKey                                  sk-xxxxx...
```

Getter yang gagal didekripsi ditandai `(gagal)` di layar dan `null` di JSON.

## Struktur proyek

```
.
├── main.py      # skrip ekstraktor
└── README.md
```

## Catatan & batasan

- Skrip mengasumsikan simbol JNI diawali `Java_com_myxlultimate_core_spice_Cardamom_`
  dan literal berada di `.rodata` — bila versi aplikasi mengubah layout ini,
  pola pemuatan literal di `getter_literals()` perlu disesuaikan.
- Bila sertifikat tidak ditemukan di APK mana pun, skrip berhenti dengan pesan
  `tidak menemukan sertifikat penandatangan di APK mana pun`.
- Gunakan untuk riset keamanan / analisis pada aplikasi yang berhak Anda analisis.
