#!/usr/bin/env python3
"""main.py — ambil SEMUA kunci MyXL (29 getter Cardamom) langsung dari file .xapk.

Pemakaian:
    python main.py \
        'myXL+-+XL,+PRIORITAS+&+HOME_9.6.0_APKPure.xapk' [--out keys-dari-xapk] [--json kunci.json]

Yang dilakukan (semuanya offline, tanpa perangkat, tanpa root, tanpa frida):
  1. buka .xapk (zip) -> temukan APK di dalamnya
  2. ambil sertifikat penandatangan dari APK (META-INF/*.RSA via PKCS#7, atau APK Signing Block v2/v3)
  3. temukan lib<abi>/libcardamom.so di salah satu APK, lalu ekstrak
  4. baca 29 simbol JNI Java_com_myxlultimate_core_spice_Cardamom_* dan literalnya di .rodata
     (pola ADRP+ADD / ADR / ADRP+LDR, divalidasi dengan ukuran operator_new)
  5. buka literal itu dengan kunci turunan sertifikat:
        encryptionKey = base64(DER sertifikat) tanpa newline
        kunci AES-256  = sha256hex(encryptionKey)[:32]      iv = sha256hex(encryptionKey.take(10))[:16]
        AES/CBC/PKCS5Padding atas base64url(literal)
  6. tulis hasil ke .json / .txt / .env dan tampilkan di layar

Catatan: file .xapk/.apks/.apkmirror bundle semuanya struktur zip yang sama; skrip ini juga
menerima .apk tunggal.
"""
import argparse
import base64
import datetime
import hashlib
import io
import json
import os
import re
import struct
import sys
import zipfile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
except ImportError:
    sys.exit("butuh capstone: uv run --no-project --with capstone --with cryptography python main.py ...")

SO_NAME = "libcardamom.so"
SYM_PREFIX = "Java_com_myxlultimate_core_spice_Cardamom_"
APK_SIG_MAGIC = b"APK Sig Block 42"
V2_ID, V3_ID = 0x7109871A, 0xF05368C0


# ---------------------------------------------------------------- sertifikat

def cert_from_v1(apk_bytes):
    try:
        z = zipfile.ZipFile(io.BytesIO(apk_bytes))
    except Exception:
        return None, None
    for n in z.namelist():
        if re.match(r"META-INF/.*\.(RSA|DSA|EC)$", n, re.I):
            try:
                certs = load_der_pkcs7_certificates(z.read(n))
                if certs:
                    return certs[0], n
            except Exception:
                continue
    return None, None


def cert_from_signing_block(apk_bytes):
    i = apk_bytes.rfind(APK_SIG_MAGIC)
    if i < 0:
        return None, None
    end = i + len(APK_SIG_MAGIC)
    size2 = struct.unpack_from("<Q", apk_bytes, end - 24)[0]
    start = end - 8 - size2
    if struct.unpack_from("<Q", apk_bytes, start)[0] != size2:
        return None, None
    p, limit = start + 8, end - 24
    while p < limit:
        pair_len = struct.unpack_from("<Q", apk_bytes, p)[0]
        pid = struct.unpack_from("<I", apk_bytes, p + 8)[0]
        val = apk_bytes[p + 12: p + 8 + pair_len]
        if pid in (V2_ID, V3_ID):
            try:
                sd_len = struct.unpack_from("<I", val, 4)[0]
                sd = val[8: 8 + sd_len]
                q = 4
                q += 4 + struct.unpack_from("<I", sd, q)[0]          # lewati digests
                certs_len = struct.unpack_from("<I", sd, q)[0]
                certs = sd[q + 4: q + 4 + certs_len]
                c_len = struct.unpack_from("<I", certs, 0)[0]
                from cryptography import x509
                return x509.load_der_x509_certificate(certs[4: 4 + c_len]), f"signing block v2/v3 ({pid:#x})"
            except Exception:
                pass
        p += 8 + pair_len
    return None, None


# ---------------------------------------------------------------- ELF + disasm

def elf_sections(data):
    if data[:4] != b"\x7fELF" or data[4] != 2:
        raise ValueError("bukan ELF64")
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    raw = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name, typ, flags, addr, off, size = struct.unpack_from("<IIQQQQ", data, o)
        raw.append(dict(name_off=name, type=typ, addr=addr, off=off, size=size))
    strtab = raw[e_shstrndx]
    for s in raw:
        p = strtab["off"] + s["name_off"]
        s["name"] = data[p:data.index(b"\x00", p)].decode("utf-8", "replace")
    return {s["name"]: s for s in raw}


def dyn_java_symbols(data, secs, prefix):
    dynsym, dynstr = secs.get(".dynsym"), secs.get(".dynstr")
    if not dynsym or not dynstr:
        return {}
    out = {}
    n = dynsym["size"] // 24
    for i in range(n):
        o = dynsym["off"] + i * 24
        st_name, st_info, _other, _shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", data, o)
        p = dynstr["off"] + st_name
        end = data.index(b"\x00", p)
        nm = data[p:end].decode("utf-8", "replace")
        if nm.startswith(prefix):
            out[nm] = (st_value, st_size)
    return out


def getter_literals(data, secs, syms):
    """Kembalikan {nama_getter: (alamat, literal)} mengikuti pola pemuatan literal."""
    text, rodata = secs[".text"], secs[".rodata"]
    ro_lo, ro_hi = rodata["addr"], rodata["addr"] + rodata["size"]

    def cstr(va):
        if not (ro_lo <= va < ro_hi):
            return None
        o = rodata["off"] + (va - rodata["addr"])
        try:
            e = data.index(b"\x00", o)
        except ValueError:
            return None
        try:
            return data[o:e].decode("utf-8")
        except UnicodeDecodeError:
            return None

    def qword(va):
        for s in secs.values():
            if s["addr"] <= va < s["addr"] + s["size"]:
                o = s["off"] + (va - s["addr"])
                if o + 8 <= len(data):
                    return struct.unpack_from("<Q", data, o)[0]
        return None

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    result = {}
    for name, (addr, size) in sorted(syms.items(), key=lambda kv: kv[1][0]):
        code = data[text["off"] + (addr - text["addr"]): text["off"] + (addr - text["addr"]) + size]
        insns = list(md.disasm(code, addr))
        alloc = None
        for j, i in enumerate(insns):
            m = re.match(r"^w0, #(0x[0-9a-f]+|\d+)$", i.op_str)
            if i.mnemonic == "mov" and m and j + 1 < len(insns) and insns[j + 1].mnemonic == "bl":
                alloc = int(m.group(1), 0)
        cands, adrp = [], None
        for i in insns:
            m = re.search(r"#(0x[0-9a-f]+|\d+)", i.op_str)
            if i.mnemonic == "adrp":
                parts = i.op_str.split(",")
                adrp = (parts[0].strip(), int(parts[1].strip().lstrip("#"), 0)) if len(parts) > 1 else None
            elif i.mnemonic == "adr" and m:
                t = cstr(int(m.group(1), 0))
                if t:
                    cands.append((int(m.group(1), 0), t))
            elif i.mnemonic == "add" and adrp and m and i.op_str.split(",")[0].strip() == adrp[0]:
                va = adrp[1] + int(m.group(1), 0)
                t = cstr(va)
                if t:
                    cands.append((va, t))
            elif i.mnemonic == "ldr" and adrp and m:
                mm = re.search(r"\[(\S+?)(?:,\s*#(0x[0-9a-f]+|\d+))?\]", i.op_str)
                if mm and mm.group(1) == adrp[0]:
                    tgt = qword(adrp[1] + (int(mm.group(2), 0) if mm.group(2) else 0))
                    if tgt:
                        t = cstr(tgt)
                        if t:
                            cands.append((tgt, t))
        uniq = []
        for va, t in cands:
            if all(t != u[1] for u in uniq):
                uniq.append((va, t))
        if not uniq:
            continue
        fit = [c for c in uniq if alloc and alloc - 24 <= len(c[1]) + 1 <= alloc + 1]
        result[name.replace(SYM_PREFIX, "")] = (fit or uniq)[0]
    return result


# ---------------------------------------------------------------- kripto

def sha256hex(s):
    return hashlib.sha256(s.encode()).hexdigest()


def decrypt_literal(literal, iv_str, enc_key):
    key = sha256hex(enc_key)[:32].encode()
    iv = sha256hex(iv_str)[:16].encode()
    s = literal.strip()
    try:
        ct = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except Exception:
        try:
            ct = base64.b64decode(s + "=" * (-len(s) % 4))
        except Exception:
            return None
    if len(ct) % 16:
        return None
    try:
        d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        pt = d.update(ct) + d.finalize()
    except Exception:
        return None
    n = pt[-1]
    if 1 <= n <= 16 and pt[-n:] == bytes([n]) * n:
        pt = pt[:-n]
    try:
        return pt.decode("utf-8")
    except UnicodeDecodeError:
        return None


# ---------------------------------------------------------------- utama

def process(xapk, outdir, json_path, abi_pref="arm64-v8a", quiet=False):
    z = zipfile.ZipFile(xapk)
    inner = [(i.filename, z.read(i.filename)) for i in z.infolist() if i.filename.lower().endswith(".apk")]
    if not inner:                                    # .apk tunggal
        with open(xapk, "rb") as fh:
            inner = [(os.path.basename(xapk), fh.read())]
    if not quiet:
        print(f"xapk        : {xapk}")
        print(f"APK di dalam: {', '.join(n for n, _ in inner)}")

    # 1. sertifikat
    cert, src = None, None
    for name, data in inner:
        cert, src = cert_from_v1(data)
        if cert is None:
            cert, src = cert_from_signing_block(data)
        if cert is not None:
            src = f"{name} :: {src}"
            break
    if cert is None:
        raise SystemExit("tidak menemukan sertifikat penandatangan di APK mana pun")
    der = cert.public_bytes(Encoding.DER)
    enc_key = base64.b64encode(der).decode().replace("\n", "")

    # 2. libcardamom.so (pilih ABI yang diminta bila ada)
    so_bytes, so_from = None, None
    found = []
    for name, data in inner:
        try:
            zz = zipfile.ZipFile(io.BytesIO(data))
        except Exception:
            continue
        for n in zz.namelist():
            if n.endswith(SO_NAME):
                found.append((name, n, zz.read(n)))
    if not found:
        raise SystemExit(f"{SO_NAME} tidak ditemukan di APK mana pun")
    found.sort(key=lambda t: 0 if f"/{abi_pref}/" in t[1] else 1)
    so_from, so_path, so_bytes = found[0]

    if not quiet:
        print(f"sertifikat  : {src}")
        print(f"subjek      : {cert.subject.rfc4514_string()}")
        print(f"sha256 cert : {hashlib.sha256(der).hexdigest()}")
        print(f"libcardamom : {so_path} dari {so_from} ({len(so_bytes):,} byte, "
              f"sha256 {hashlib.sha256(so_bytes).hexdigest()[:16]}…)")

    # 3. simbol + literal
    secs = elf_sections(so_bytes)
    syms = dyn_java_symbols(so_bytes, secs, SYM_PREFIX)
    lits = getter_literals(so_bytes, secs, syms)

    # 4. dekripsi; pilih varian IV terbaik
    variants = [
        ("encode(key).take(10)", enc_key[:10]),
        ("encode(key) penuh", enc_key),
        ("encode(key)[-10:]", enc_key[-10:]),
    ]
    best = None
    for label, iv_str in variants:
        pairs = [(g, decrypt_literal(v, iv_str, enc_key)) for g, (_a, v) in lits.items()]
        good = sum(1 for _g, p in pairs if p)
        if best is None or good > best[1]:
            best = (label, good, pairs, iv_str)
    iv_label, good, pairs, iv_str = best
    keys = [dict(getter=g, value=p) for g, p in sorted(pairs)]

    # 5. keluaran
    meta = dict(
        source_xapk=os.path.abspath(xapk),
        source_apk=so_from,
        so_path=so_path,
        so_sha256=hashlib.sha256(so_bytes).hexdigest(),
        so_size=len(so_bytes),
        cert_source=src,
        cert_subject=cert.subject.rfc4514_string(),
        cert_sha256=hashlib.sha256(der).hexdigest(),
        iv_variant=iv_label,
        getters_found=len(lits),
        decrypted=good,
        extracted_at=datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
    )

    if not quiet:
        print(f"IV dipakai  : {iv_label}  ({good}/{len(lits)} getter terbuka)")
        print(f"\n{'getter':42} {'nilai'}")
        for k in keys:
            v = k["value"] or "(gagal)"
            print(f"{k['getter']:42} {v if len(v) <= 96 else v[:93] + '...'}")

    if outdir:
        os.makedirs(outdir, exist_ok=True)
        os.chmod(outdir, 0o700)
        jp = json_path or os.path.join(outdir, "cardamom-keys.json")
        with open(jp, "w") as fh:
            json.dump(dict(meta=meta, keys=keys), fh, indent=2)
        with open(os.path.join(outdir, "cardamom-keys.txt"), "w") as fh:
            fh.write(f"# sumber : {meta['source_xapk']}\n# .so    : {meta['so_path']} "
                     f"(sha256 {meta['so_sha256']})\n# cert   : {meta['cert_subject']} "
                     f"(sha256 {meta['cert_sha256']})\n# iv     : {meta['iv_variant']}\n\n")
            for k in keys:
                fh.write(f"{k['getter']}\n    {k['value']}\n\n")
        with open(os.path.join(outdir, "cardamom-keys.env"), "w") as fh:
            fh.write(f"# sha256 {so_path}: {meta['so_sha256']}\n")
            for k in keys:
                fh.write(f'{re.sub(r"[^A-Za-z0-9]", "_", k["getter"]).upper()}="{k["value"]}"\n')
        for f in ("cardamom-keys.json", "cardamom-keys.txt", "cardamom-keys.env"):
            p = os.path.join(outdir, f)
            if os.path.exists(p):
                os.chmod(p, 0o600)
        if not quiet:
            print(f"\ndisimpan    : {jp}")
    return meta, keys


def main():
    ap = argparse.ArgumentParser(description="Ambil semua kunci MyXL dari file .xapk")
    ap.add_argument("xapk")
    ap.add_argument("--out", default="keys-dari-xapk", help="direktori keluaran (default: keys-dari-xapk)")
    ap.add_argument("--json", dest="json_path", default=None, help="path khusus untuk JSON")
    ap.add_argument("--abi", default="arm64-v8a")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()
    process(a.xapk, a.out, a.json_path, a.abi, a.quiet)
    return 0


if __name__ == "__main__":
    sys.exit(main())
