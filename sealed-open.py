#!/usr/bin/env python3
# sealed-open: opens a Sealed vault copy (a ".sealedvault" folder, or a .zip of one) with its recovery key, without the Sealed app.
#
#   python3 sealed-open.py "Sealed Vault.sealedvault" "Opened vault"
#
# It asks for the recovery key (the input is not shown), says whether the key opens the copy, then writes every photo, video,
# document, note and record as an ordinary file, stacks as folders, and a Report.txt of what it could not open.
# Needs Python 3.8+ and the "cryptography" package (pip install cryptography). No account, no network.
#
# The format is "Sealed: encryption and key handling", section 17 (and sections 2, 4, 6, 15 and Appendix A).
# MIT License. Copyright (c) 2026 Loopware. See README.md next to this file for the full text.

import argparse
import datetime
import getpass
import hashlib
import hmac
import io
import json
import os
import struct
import sys
import unicodedata
import zipfile

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:
    sys.exit("sealed-open needs the 'cryptography' package: python3 -m pip install cryptography")

VERSION = "1"
MANIFEST = "manifest.sealed"
BLOBS = "blobs"
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
REFERENCE_EPOCH = 978307200  # 2001-01-01 00:00:00 UTC, the zero of every date (section 8)


class Refused(Exception):
    pass


# ---------------------------------------------------------------------------------------------------------------- reading the copy

class Folder:
    """A .sealedvault folder, or a .zip that holds one (at its top or one folder down)."""

    def __init__(self, path):
        self.zip = None
        if os.path.isdir(path):
            if not os.path.isfile(os.path.join(path, MANIFEST)):
                inner = [d for d in os.listdir(path) if os.path.isfile(os.path.join(path, d, MANIFEST))]
                if len(inner) != 1:
                    raise Refused("there is no %s in this folder: pick the .sealedvault folder itself" % MANIFEST)
                path = os.path.join(path, inner[0])
            self.root = path
        elif zipfile.is_zipfile(path):
            self.zip = zipfile.ZipFile(path)
            names = [n for n in self.zip.namelist() if n == MANIFEST or n.endswith("/" + MANIFEST)]
            names = [n for n in names if "__MACOSX" not in n]
            if len(names) != 1:
                raise Refused("the zip holds %d copies of a vault (one is needed)" % len(names))
            self.root = names[0][: -len(MANIFEST)]
        else:
            raise Refused("not a folder or a zip: %s" % path)

    def read(self, name):
        if self.zip:
            return self.zip.read(self.root + name)
        with open(os.path.join(self.root, name), "rb") as f:
            return f.read()

    def open(self, name):
        if self.zip:
            return self.zip.open(self.root + name)
        return open(os.path.join(self.root, name), "rb")

    def has(self, name):
        if self.zip:
            try:
                self.zip.getinfo(self.root + name)
                return True
            except KeyError:
                return False
        return os.path.isfile(os.path.join(self.root, name))

    def placeholder(self, name):
        """iCloud Drive keeps a file it has not downloaded as ".<name>.icloud"."""
        head, _, tail = name.rpartition("/")
        return self.has((head + "/" if head else "") + "." + tail + ".icloud")


# ------------------------------------------------------------------------------------------------------------------ the key (6, 15)

def phrase_bytes(text):
    """Section 6.1: upper case (full Unicode mapping), letters and digits only, the aliases, 5 bits a character."""
    cleaned = [c for c in text.upper() if c.isascii() and c.isalnum()]
    bits = value = 0
    out = bytearray()
    for c in cleaned:
        c = {"O": "0", "I": "1", "L": "1"}.get(c, c)
        if c not in ALPHABET:
            raise Refused("the recovery key has a letter that is not in it (%s)" % c)
        value = (value << 5) | ALPHABET.index(c)
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((value >> bits) & 0xFF)
    return bytes(out)


def read_phrase(text):
    """Returns ("v1", K) or ("v2", R_n)."""
    raw = phrase_bytes(text)
    if len(raw) == 34:
        if hashlib.sha256(raw[:32]).digest()[:2] != raw[32:]:
            raise Refused("the recovery key has a typo (its check does not fit)")
        return "v1", raw[:32]
    if len(raw) == 37 and raw[0] == 2:
        if hashlib.sha256(raw[:33]).digest()[:4] != raw[33:]:
            raise Refused("the recovery key has a typo (its check does not fit)")
        return "v2", raw[1:33]
    raise Refused("that is not a whole recovery key (it has 11 or 12 groups of five)")


def hkdf_recovery_key(k, n):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"sealed.recovery.v2.salt",
                info=b"sealed.recovery.v2" + struct.pack(">I", n)).derive(k)


def open_envelope(envelope, r):
    if len(envelope) != 70 or envelope[:4] != b"BBKE" or envelope[4] != 1 or envelope[5] != 1:
        raise Refused("the copy's recovery envelope is damaged")
    n = struct.unpack(">I", envelope[6:10])[0]
    if n == 0:
        raise Refused("the copy's recovery envelope is damaged")
    try:
        k = AESGCM(r).decrypt(envelope[10:22], envelope[22:], b"sealed.envelope.v1" + bytes([1]) + envelope[6:10])
    except InvalidTag:
        raise Refused("this recovery key does not open this copy (another vault's key, or one that was replaced)")
    if len(k) != 32 or not hmac.compare_digest(hkdf_recovery_key(k, n), r):
        raise Refused("this recovery key does not open this copy")
    return k


def key_check(k):
    return hmac.new(k, b"sealed.recovery.keycheck.v1", hashlib.sha256).digest()


# ----------------------------------------------------------------------------------------------------------------- the manifest (17)

def read_header(manifest):
    if len(manifest) < 39 or manifest[:4] != b"BBOV":
        raise Refused("%s is not the manifest of a Sealed vault copy" % MANIFEST)
    if manifest[4] != 1:
        raise Refused("this copy was made by a newer Sealed (format version %d); get a newer reader" % manifest[4])
    envelope_len = struct.unpack(">H", manifest[37:39])[0]
    if envelope_len not in (0, 70) or len(manifest) < 39 + envelope_len + 28:
        raise Refused("%s is damaged" % MANIFEST)
    header = manifest[: 39 + envelope_len]
    return header, manifest[5:37], manifest[39: 39 + envelope_len] or None


def vault_key(phrase, header, check, envelope):
    kind, raw = read_phrase(phrase)
    if kind == "v1":
        k = raw
    else:
        if envelope is None:
            raise Refused("this copy's vault has a recovery key of 11 groups; the key typed has 12")
        k = open_envelope(envelope, raw)
    if not hmac.compare_digest(key_check(k), check):
        raise Refused("this recovery key is not this vault's")
    return k


def open_body(manifest, header, k):
    sealed = manifest[len(header):]
    try:
        body = AESGCM(k).decrypt(sealed[:12], sealed[12:], b"sealed.openvault.v1" + header)
    except InvalidTag:
        raise Refused("the key is right, but %s is damaged" % MANIFEST)
    try:
        doc = json.loads(body.decode("utf-8"))
        for key in ("items", "notes", "records", "stacks"):
            if not isinstance(doc[key], list) or not all(isinstance(x, dict) and isinstance(x.get("id"), str) for x in doc[key]):
                raise ValueError(key)
        if not all(isinstance(x.get("inCopy"), bool) for x in doc["items"]):
            raise ValueError("inCopy")
    except (ValueError, KeyError, UnicodeDecodeError):
        raise Refused("the key is right, but %s is not what it should hold" % MANIFEST)
    return doc


# ------------------------------------------------------------------------------------------------------------------- blobs (section 4)

def read_exact(f, n):
    data = f.read(n)
    if len(data) != n:
        raise Refused("the file ends early")
    return data


def blob_stream(f, k, write):
    """Section 4, streaming: every chunk verified in its place, the last one marked last."""
    if read_exact(f, 4) != b"BBXV" or read_exact(f, 1) != b"\x01":
        raise Refused("not a Sealed file")
    dek_len = struct.unpack(">H", read_exact(f, 2))[0]
    if dek_len != 60:
        raise Refused("damaged header")
    wrapped = read_exact(f, 60)
    try:
        dek = AESGCM(k).decrypt(wrapped[:12], wrapped[12:], None)
    except InvalidTag:
        raise Refused("its file key does not open with this vault's key")
    if len(dek) != 32:
        raise Refused("damaged file key")
    chunk_size = struct.unpack(">I", read_exact(f, 4))[0]
    if not 1 <= chunk_size <= 4194304:
        raise Refused("damaged chunk size")
    aes = AESGCM(dek)
    index = 0
    length = f.read(4)
    if len(length) != 4:
        raise Refused("no content")
    while True:
        sealed_len = struct.unpack(">I", length)[0]
        if not 16 <= sealed_len <= chunk_size + 16:
            raise Refused("damaged chunk")
        sealed = read_exact(f, sealed_len)
        following = f.read(4)
        if following and len(following) != 4:
            raise Refused("the file ends inside a chunk")
        last = not following
        nonce = struct.pack(">Q", index) + b"\x00\x00\x00" + (b"\x01" if last else b"\x00")
        try:
            write(aes.decrypt(nonce, sealed, None))
        except InvalidTag:
            raise Refused("the file is damaged or incomplete")
        if last:
            return
        index += 1
        length = following


# ---------------------------------------------------------------------------------------------------------------------- file names

FORBIDDEN = set('/\\:*?"<>|')
RESERVED = {"CON", "PRN", "AUX", "NUL"} | {"COM%d" % i for i in range(1, 10)} | {"LPT%d" % i for i in range(1, 10)}
MIME_EXTENSIONS = {
    "image/jpeg": "jpg", "image/heic": "heic", "image/heif": "heif", "image/png": "png", "image/gif": "gif", "image/webp": "webp",
    "image/tiff": "tiff", "image/bmp": "bmp", "video/quicktime": "mov", "video/mp4": "mp4", "video/x-m4v": "m4v",
    "audio/mp4": "m4a", "audio/x-m4a": "m4a", "audio/mpeg": "mp3", "audio/wav": "wav", "audio/aac": "aac",
    "application/pdf": "pdf", "text/plain": "txt", "application/zip": "zip", "text/csv": "csv", "text/html": "html",
}


def safe_name(name, fallback="Untitled"):
    """A name a file system takes on macOS, Windows and Linux; never a path."""
    name = unicodedata.normalize("NFC", name or "")
    name = "".join("_" if (c in FORBIDDEN or ord(c) < 32 or ord(c) == 127) else c for c in name).strip()
    name = name.lstrip(".").rstrip(". ")
    if not name:
        name = fallback
    stem = name.split(".")[0].upper()
    if stem in RESERVED:
        name = "_" + name
    while len(name.encode("utf-8")) > 120:
        name = name[:-1]
    return name


def item_file_name(item):
    name = item.get("fileName")
    if not name:
        base = item.get("name") or "Untitled"
        ext = MIME_EXTENSIONS.get(str(item.get("mimeType", "")).lower())
        if ext and not base.lower().endswith("." + ext):
            base = base + "." + ext
        name = base
    return safe_name(name)


class Writer:
    """Writes into the output folder; two things with one name in one folder become "name (2).ext"."""

    def __init__(self, root):
        self.root = root
        self.taken = {}

    def path(self, folder, name):
        os.makedirs(os.path.join(self.root, folder), exist_ok=True)
        taken = self.taken.setdefault(folder, set())
        stem, dot, ext = name.rpartition(".")
        if not dot or not stem:
            stem, ext = name, ""
        candidate, n = name, 1
        while candidate.lower() in taken or os.path.exists(os.path.join(self.root, folder, candidate)):
            n += 1
            candidate = "%s (%d)%s" % (stem, n, "." + ext if ext else "")
        taken.add(candidate.lower())
        return os.path.join(folder, candidate)


def when(seconds):
    if not isinstance(seconds, (int, float)):
        return None
    return REFERENCE_EPOCH + seconds


# ------------------------------------------------------------------------------------------------------------------- notes and records

def rtfd_files(data):
    """A note's rich text is flattened RTFD (Apple's serialized file wrapper): 'rtfd', 0, 3, the number of entries, their names,
    their lengths, then each entry as kind (1) and length and bytes. Returns {name: bytes} without the '.' entry, or None."""
    try:
        if data[:4] != b"rtfd":
            return None
        _, _, count = struct.unpack_from("<III", data, 4)
        if count > 10000:
            return None
        offset = 16
        names = []
        for _ in range(count):
            (length,) = struct.unpack_from("<I", data, offset)
            offset += 4
            names.append(data[offset: offset + length].decode("utf-8"))
            offset += length
        lengths = struct.unpack_from("<%dI" % count, data, offset)
        offset += 4 * count
        files = {}
        for name, length in zip(names, lengths):
            kind, size = struct.unpack_from("<II", data, offset)
            if name != "." and kind == 1 and "/" not in name and not name.startswith(".."):
                files[name] = data[offset + 8: offset + 8 + size]
            offset += length
        return files if "TXT.rtf" in files else None
    except (struct.error, UnicodeDecodeError):
        return None


RECORD_TYPES = {"login": "Login", "totp": "Two-factor code", "card": "Card", "bankAccount": "Bank account", "idDocument": "ID",
                "wifi": "Wi-Fi", "recoveryCode": "Recovery codes", "licenseKey": "License key", "contact": "Contact",
                "custom": "Record"}
RECORD_FIELDS = [("username", "Username"), ("password", "Password"), ("website", "Website"), ("cardNumber", "Card number"),
                 ("expirationDate", "Expires"), ("cvv", "Security code"), ("accountNumber", "Account number"),
                 ("wifiSecurity", "Wi-Fi security"), ("company", "Company"), ("phone", "Phone"), ("email", "Email"),
                 ("address", "Address"), ("notes", "Notes")]


def record_text(record):
    kind = RECORD_TYPES.get(record.get("recordTypeRaw"), "Record")
    lines = [record.get("title") or kind, "Type: " + kind]
    fields = record.get("payload") or {}
    for key, label in RECORD_FIELDS:
        value = fields.get(key)
        if isinstance(value, str) and value:
            lines.append("%s: %s" % (label, value))
    for field in fields.get("customFields") or []:
        if isinstance(field, dict) and field.get("value"):
            lines.append("%s: %s" % (field.get("label") or "Field", field.get("value")))
    tags = [t for t in fields.get("tags") or [] if isinstance(t, str)]
    if tags:
        lines.append("Tags: " + ", ".join(tags))
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------------------------------------------------------- opening

def stack_paths(stacks):
    """Each stack's folder: its parents' names, then its own (a cycle or a missing parent ends the chain)."""
    by_id = {s.get("id"): s for s in stacks if isinstance(s, dict)}
    paths = {}
    for sid in by_id:
        parts, seen, current = [], set(), by_id[sid]
        while current is not None and current.get("id") not in seen:
            seen.add(current.get("id"))
            parts.insert(0, safe_name(current.get("name"), "Stack"))
            current = by_id.get(current.get("parentID"))
        paths[sid] = os.path.join(*parts)
    return paths


def folder_for(entry, paths):
    for sid in entry.get("albumIds") or []:
        if sid in paths:
            return paths[sid]
    return ""


def open_vault(source, phrase, output, report_json=None, out=print):
    folder = Folder(source)
    manifest = folder.read(MANIFEST)
    header, check, envelope = read_header(manifest)
    k = vault_key(phrase, header, check, envelope)
    out("The recovery key opens this vault.")
    doc = open_body(manifest, header, k)
    saved = when(doc.get("savedAt"))
    if saved:
        out("Saved by Sealed on %s." % datetime.datetime.fromtimestamp(saved).strftime("%Y-%m-%d %H:%M"))

    os.makedirs(output, exist_ok=True)
    writer = Writer(output)
    paths = stack_paths(doc["stacks"])
    report = {"files": [], "notOpened": [], "onlyInICloudBackup": [], "missing": []}
    counts = {"items": 0, "notes": 0, "records": 0}

    for item in doc["items"]:
        if not isinstance(item, dict):
            continue
        label = item.get("name") or item.get("id") or "an item"
        blob = item.get("encryptedFileName")
        if not item.get("inCopy"):
            report["onlyInICloudBackup"].append(label)
            continue
        if not isinstance(blob, str) or not blob[:1].isalnum() or not all(c.isascii() and (c.isalnum() or c in "._-") for c in blob):
            report["notOpened"].append("%s: its file name is not one Sealed makes" % label)
            continue
        name = BLOBS + "/" + blob
        if not folder.has(name):
            why = "iCloud Drive has not downloaded it to this computer yet" if folder.placeholder(name) else "its file is missing"
            report["missing"].append("%s: %s" % (label, why))
            continue
        relative = writer.path(folder_for(item, paths), item_file_name(item))
        target = os.path.join(output, relative)
        try:
            with folder.open(name) as f, open(target + ".part", "wb") as w:
                blob_stream(f, k, w.write)
            os.replace(target + ".part", target)
        except Refused as e:
            os.remove(target + ".part")
            report["notOpened"].append("%s: %s" % (label, e))
            continue
        stamp = when(item.get("originalCreationDate")) or when(item.get("createdAt"))
        if stamp:
            os.utime(target, (stamp, stamp))
        counts["items"] += 1
        report["files"].append({"id": item.get("id"), "kind": "item", "path": relative})

    for note in doc["notes"]:
        if not isinstance(note, dict):
            continue
        title = safe_name(note.get("title") or (note.get("body") or "").split("\n")[0][:60], "Untitled note")
        where = folder_for(note, paths)
        text_path = writer.path(where, title + ".txt")
        with open(os.path.join(output, text_path), "w", encoding="utf-8", newline="\n") as f:
            f.write(note.get("body") or "")
        entry = {"id": note.get("id"), "kind": "note", "path": text_path}
        rich = note.get("rtfd")
        if isinstance(rich, str) and rich:
            import base64
            files = rtfd_files(base64.b64decode(rich))
            if files and len(files) == 1:
                rich_path = writer.path(where, title + ".rtf")
                with open(os.path.join(output, rich_path), "wb") as f:
                    f.write(files["TXT.rtf"])
                entry["rich"] = rich_path
            elif files:
                rich_path = writer.path(where, title + ".rtfd")
                os.makedirs(os.path.join(output, rich_path), exist_ok=True)
                for name, data in files.items():
                    with open(os.path.join(output, rich_path, safe_name(name)), "wb") as f:
                        f.write(data)
                entry["rich"] = rich_path
        stamp = when(note.get("updatedAt"))
        if stamp:
            os.utime(os.path.join(output, text_path), (stamp, stamp))
        counts["notes"] += 1
        report["files"].append(entry)

    records = [r for r in doc["records"] if isinstance(r, dict)]
    for record in records:
        title = safe_name(record.get("title") or RECORD_TYPES.get(record.get("recordTypeRaw"), "Record"))
        relative = writer.path(folder_for(record, paths), title + ".txt")
        with open(os.path.join(output, relative), "w", encoding="utf-8", newline="\n") as f:
            f.write(record_text(record))
        counts["records"] += 1
        report["files"].append({"id": record.get("id"), "kind": "record", "path": relative})
    if records:
        with open(os.path.join(output, writer.path("", "Records.json")), "w", encoding="utf-8") as f:
            json.dump(records, f, ensure_ascii=False, indent=2)

    lines = ["Opened with sealed-open %s." % VERSION,
             "%d files, %d notes, %d records." % (counts["items"], counts["notes"], counts["records"])]
    for key, title in (("onlyInICloudBackup", "Only in the iCloud backup (Space Saver), not in this copy"),
                       ("missing", "Missing from this copy"), ("notOpened", "Could not be opened")):
        if report[key]:
            lines.append("")
            lines.append("%s (%d):" % (title, len(report[key])))
            lines.extend("  " + str(x) for x in report[key])
    with open(os.path.join(output, writer.path("", "Report.txt")), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    for line in lines[1:]:
        out(line)
    if report_json:
        with open(report_json, "w", encoding="utf-8") as f:
            json.dump(dict(report, counts=counts), f, ensure_ascii=False, indent=2)
    return counts, report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Open a Sealed vault copy (.sealedvault folder or .zip) with its recovery key.")
    parser.add_argument("copy", help="the .sealedvault folder, or a .zip of it")
    parser.add_argument("output", nargs="?", help="where to write the files (default: 'Opened vault' next to the copy)")
    parser.add_argument("--phrase-stdin", action="store_true", help="read the recovery key from standard input (for scripts)")
    parser.add_argument("--report-json", help="also write what was written, as JSON, to this file")
    args = parser.parse_args(argv)
    output = args.output or os.path.join(os.path.dirname(os.path.abspath(args.copy)), "Opened vault")
    if os.path.exists(output) and os.listdir(output):
        print("The output folder is not empty: %s" % output)
        return 2
    try:
        phrase = sys.stdin.readline() if args.phrase_stdin else getpass.getpass("Recovery key (not shown): ")
        open_vault(args.copy, phrase, output, args.report_json)
    except Refused as e:
        print("Not opened: %s." % e)
        return 1
    except OSError as e:
        print("Could not read or write a file: %s" % e)
        return 1
    print("Done: %s" % output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
