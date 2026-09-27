#!/usr/bin/env python3
"""Phigros 4.0.0 Android local PlayerPrefs XML, lossless round-trip.

Usage: python phigros_save_crypto.py [-d | -e] INPUT.xml [OUTPUT.xml]
Default operation is decrypt. Requires: python -m pip install pycryptodome
The decrypted XML is a marked analysis file, not a game-ready save.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import quote, unquote
from xml.sax.saxutils import escape

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError as exc:
    raise SystemExit("Missing dependency. Install it with: python -m pip install pycryptodome") from exc

KEY_SOURCE = b"Phigros.enc.j57vnvr8wlZssXM7eWpa"
IV_SOURCE = b"Q4zHm5vUEMJJ3iS9"
ROOT_MARKER = b"phigros_research_count"
ENTRY_MARKER = b"phigros_research_v1"
STRING_RE = re.compile(rb"(?P<opening><string\b[^>]*)(?P<close>>)(?P<body>.*?)</string>", re.DOTALL)
NAME_RE = re.compile(rb"\bname\s*=\s*(?P<quote>['\"])(?P<value>.*?)(?P=quote)", re.DOTALL)
ENTRY_META_RE = re.compile(rb" phigros_research_v1=\"(?P<data>[A-Za-z0-9_=-]+)\"")
ROOT_META_RE = re.compile(rb" phigros_research_count=\"(?P<count>[0-9]+)\"")
MAP_RE = re.compile(rb"<map\b[^>]*>")


class SaveFormatError(ValueError):
    """Malformed, incompatible or unexpectedly edited analysis XML."""


def reverse_bits(value: int) -> int:
    return int(f"{value:08b}"[::-1], 2)


def loop_reverse_xor(source: bytes) -> bytes:
    return bytes(source[(i + 1) % len(source)] ^ reverse_bits(value)
                 for i, value in enumerate(source))


KEY = loop_reverse_xor(KEY_SOURCE)
IV = loop_reverse_xor(IV_SOURCE)


def encrypt_text(text: str) -> str:
    ciphertext = AES.new(KEY, AES.MODE_CBC, IV).encrypt(pad(text.encode("utf-8"), 16))
    return base64.b64encode(ciphertext).decode("ascii")


def decrypt_text(text: str) -> str:
    try:
        ciphertext = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SaveFormatError("Invalid Base64 ciphertext") from exc
    if not ciphertext or len(ciphertext) % 16:
        raise SaveFormatError("AES ciphertext must be nonempty and a multiple of 16 bytes")
    try:
        plaintext = unpad(AES.new(KEY, AES.MODE_CBC, IV).decrypt(ciphertext), 16)
        return plaintext.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise SaveFormatError("AES/PKCS#7/UTF-8 decoding failed") from exc


def _xml_escape(text: str, *, attribute: bool) -> bytes:
    extra = {'"': "&quot;", "'": "&apos;"} if attribute else {}
    text = escape(text, extra)
    # Attribute line breaks are normalized by XML parsers unless written as entities.
    if attribute:
        text = text.replace("\r", "&#13;").replace("\n", "&#10;").replace("\t", "&#9;")
    else:
        text = text.replace("\r", "&#13;")
    return text.encode("utf-8")


def _xml_root(raw: bytes) -> ET.Element:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise SaveFormatError("Input is not valid XML") from exc
    if root.tag != "map":
        raise SaveFormatError("Expected a <map> PlayerPrefs root element")
    return root


def _digest(name: str, value: str) -> str:
    encoded = json.dumps([name, value], ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _encode_meta(name_raw: bytes, value_raw: bytes, name: str, value: str) -> bytes:
    item = [base64.b64encode(name_raw).decode("ascii"),
            base64.b64encode(value_raw).decode("ascii"), _digest(name, value)]
    return base64.urlsafe_b64encode(json.dumps(item, separators=(",", ":")).encode("ascii"))


def _decode_meta(marker: bytes) -> tuple[bytes, bytes, str]:
    try:
        item = json.loads(base64.urlsafe_b64decode(marker))
        if not isinstance(item, list) or len(item) != 3:
            raise ValueError("bad marker shape")
        name_raw = base64.b64decode(item[0], validate=True)
        value_raw = base64.b64decode(item[1], validate=True)
        fingerprint = item[2]
        if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise ValueError("bad marker hash")
        return name_raw, value_raw, fingerprint
    except (ValueError, TypeError, binascii.Error, UnicodeDecodeError) as exc:
        raise SaveFormatError("Research metadata is damaged; cannot safely re-encrypt") from exc


def _replace_name(opening: bytes, new_name: bytes) -> bytes:
    match = NAME_RE.search(opening)
    if match is None:
        raise SaveFormatError("<string> is missing a name attribute")
    start, end = match.span("value")
    return opening[:start] + new_name + opening[end:]


def _parse_entry(opening: bytes, body: bytes) -> tuple[str, str]:
    try:
        element = ET.fromstring(opening + b">" + body + b"</string>")
    except ET.ParseError as exc:
        raise SaveFormatError("Unsupported <string> XML structure") from exc
    if "name" not in element.attrib:
        raise SaveFormatError("<string> is missing a name attribute")
    return element.attrib["name"], element.text or ""


def _transform_entries(raw: bytes, *, decrypt: bool) -> tuple[bytes, int]:
    root = _xml_root(raw)
    matches = list(STRING_RE.finditer(raw))
    if len(matches) != sum(1 for element in root.iter("string")):
        raise SaveFormatError("Unsupported <string> layout; stopped to avoid damaging the XML")
    pieces: list[bytes] = []
    previous = 0
    count = 0
    for match in matches:
        pieces.append(raw[previous:match.start()])
        opening, body = match.group("opening"), match.group("body")
        original_name_raw_match = NAME_RE.search(opening)
        if original_name_raw_match is None:
            raise SaveFormatError("<string> is missing a name attribute")
        if decrypt:
            if ENTRY_MARKER in opening:
                raise SaveFormatError("Input appears to be an already-decrypted analysis XML")
            name, value = _parse_entry(opening, body)
            try:
                plain_name = decrypt_text(unquote(name))
                plain_value = decrypt_text(unquote(value))
            except SaveFormatError:
                pieces.append(match.group(0))  # Preserve unrelated preferences byte-for-byte.
            else:
                marker = _encode_meta(original_name_raw_match.group("value"), body,
                                      plain_name, plain_value)
                new_opening = _replace_name(opening, _xml_escape(plain_name, attribute=True))
                new_opening += b' ' + ENTRY_MARKER + b'="' + marker + b'"'
                pieces.append(new_opening + b">" + _xml_escape(plain_value, attribute=False)
                              + b"</string>")
                count += 1
        else:
            metadata = ENTRY_META_RE.search(opening)
            if metadata is None:
                pieces.append(match.group(0))
            else:
                plain_name, plain_value = _parse_entry(opening, body)
                name_raw, value_raw, fingerprint = _decode_meta(metadata.group("data"))
                if _digest(plain_name, plain_value) == fingerprint:
                    # No semantic edit: use the original ciphertext spelling exactly.
                    new_name, new_value = name_raw, value_raw
                else:
                    new_name = quote(encrypt_text(plain_name), safe="").encode("ascii")
                    new_value = quote(encrypt_text(plain_value), safe="").encode("ascii")
                new_opening = opening[:metadata.start()] + opening[metadata.end():]
                pieces.append(_replace_name(new_opening, new_name) + b">" + new_value
                              + b"</string>")
                count += 1
        previous = match.end()
    pieces.append(raw[previous:])
    return b"".join(pieces), count


def decrypt_prefs(source: Path, target: Path) -> int:
    _safe_output(source, target)
    raw = source.read_bytes()
    if ROOT_MARKER in raw:
        raise SaveFormatError("Input appears to be an already-decrypted analysis XML")
    output, count = _transform_entries(raw, decrypt=True)
    if count == 0:
        raise SaveFormatError("No decryptable local entries found; check the file and game version")
    root_tag = MAP_RE.search(output)
    if root_tag is None:
        raise SaveFormatError("Missing <map> root element")
    mark = b' ' + ROOT_MARKER + b'="' + str(count).encode("ascii") + b'"'
    output = output[:root_tag.end() - 1] + mark + output[root_tag.end() - 1:]
    _xml_root(output)
    target.write_bytes(output)
    return count


def encrypt_prefs(source: Path, target: Path) -> int:
    _safe_output(source, target)
    raw = source.read_bytes()
    root_tag = MAP_RE.search(raw)
    if root_tag is None:
        raise SaveFormatError("Missing <map> root element")
    root_metadata = ROOT_META_RE.search(root_tag.group(0))
    if root_metadata is None:
        raise SaveFormatError("Input was not produced by this tool; decrypt it with -d first")
    expected = int(root_metadata.group("count"))
    output, count = _transform_entries(raw, decrypt=False)
    if count != expected:
        raise SaveFormatError(f"Research marker count mismatch: expected {expected}, found {count}")
    root_tag = MAP_RE.search(output)
    assert root_tag is not None
    marker = ROOT_META_RE.search(root_tag.group(0))
    assert marker is not None
    start = root_tag.start() + marker.start()
    end = root_tag.start() + marker.end()
    output = output[:start] + output[end:]
    _xml_root(output)
    target.write_bytes(output)
    return count


def _safe_output(source: Path, target: Path) -> None:
    if source.resolve() == target.resolve():
        raise SaveFormatError("Refusing to overwrite the input file")
    if target.exists():
        raise SaveFormatError(f"Output file already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Encrypt or decrypt Phigros 4.0.0 Android local PlayerPrefs XML")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("-d", "--decrypt", action="store_true", help="Decrypt (default)")
    mode.add_argument("-e", "--encrypt", action="store_true", help="Re-encrypt an analysis XML produced by this tool")
    parser.add_argument("input", type=Path, help="Input XML file")
    parser.add_argument("output", type=Path, nargs="?", help="Output XML file; if omitted, append .decrypted/.encrypted")
    args = parser.parse_args(argv)
    action = encrypt_prefs if args.encrypt else decrypt_prefs
    suffix = ".encrypted.xml" if args.encrypt else ".decrypted.xml"
    target = args.output or args.input.with_name(args.input.stem + suffix)
    try:
        count = action(args.input, target)
        print(f"Processed {count} encrypted entries; output: {target}")
        if args.encrypt:
            print("If the decrypted content was not changed, the rebuilt file should match the original byte-for-byte.")
        else:
            print("Warning: the decrypted XML contains plaintext and recovery metadata; do not import it into the game or share it.")
        return 0
    except (OSError, SaveFormatError) as exc:
        parser.exit(2, f"Error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
