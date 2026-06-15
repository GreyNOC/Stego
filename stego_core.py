from __future__ import annotations

import base64
import binascii
from contextlib import contextmanager
import hashlib
import hmac
import os
import tempfile
import traceback
import zlib
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from PIL import Image, UnidentifiedImageError

from stego_constants import (
    AES_GCM_NONCE_SIZE,
    AES_GCM_TAG_SIZE,
    AES_KEY_SIZE,
    CRC_SIZE,
    DEBUG_LOG,
    LEGACY_IMAGE_MAGIC,
    MAX_IMAGE_PIXELS,
    MAX_PAYLOAD_BYTES,
    MAX_SOURCE_FILE_BYTES,
    PBKDF2_ROUNDS,
    PROTECTED_IMAGE_MAGIC,
    SALT_SIZE,
    TEXT_ARMOR_PREFIX,
    TRAILER_LENGTH_SIZE,
)

# Bind Pillow's decompression-bomb limit to the project pixel cap so oversized
# images are rejected during decode rather than after a partial raster load.
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS


def format_bytes(value: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}" if unit != "B" else f"{value} B"
        size /= 1024
    return f"{value} B"


def validate_source_file(file_path: Path) -> None:
    if not file_path.is_file():
        raise ValueError("Source file does not exist or is not a regular file.")
    file_size = file_path.stat().st_size
    if file_size > MAX_SOURCE_FILE_BYTES:
        raise ValueError(
            f"File is too large ({format_bytes(file_size)}). "
            f"Limit is {format_bytes(MAX_SOURCE_FILE_BYTES)}."
        )


def validate_payload_size(payload: bytes) -> None:
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise ValueError(
            f"Payload is too large ({format_bytes(len(payload))}). "
            f"Limit is {format_bytes(MAX_PAYLOAD_BYTES)}."
        )


def validate_payload_file(file_path: Path) -> None:
    if not file_path.is_file():
        raise ValueError("Payload file does not exist or is not a regular file.")
    file_size = file_path.stat().st_size
    if file_size > MAX_PAYLOAD_BYTES:
        raise ValueError(
            f"Payload file is too large ({format_bytes(file_size)}). "
            f"Limit is {format_bytes(MAX_PAYLOAD_BYTES)}."
        )


def validate_image_limits(image: Image.Image) -> None:
    pixels = image.width * image.height
    if pixels > MAX_IMAGE_PIXELS:
        raise ValueError(f"Image is too large ({pixels:,} pixels). Limit is {MAX_IMAGE_PIXELS:,} pixels.")


@contextmanager
def atomic_output_path(output_path: Path):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        prefix=".greynoc-",
        suffix=".tmp",
        dir=output_path.parent,
        delete=False,
    ) as temp_file:
        temp_path = Path(temp_file.name)

    try:
        yield temp_path
        temp_path.replace(output_path)
    finally:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass


def open_image_safely(path: Path) -> Image.Image:
    """Open an image with bounded size and clean errors.

    Returns a detached copy so the caller can close the source handle safely.
    Raises ValueError for unidentified, corrupted, or oversized images.
    """
    try:
        with Image.open(path) as source:
            source.load()
            return source.copy()
    except UnidentifiedImageError as exc:
        raise ValueError("Invalid or unsupported image file.") from exc
    except Image.DecompressionBombError as exc:
        raise ValueError(
            f"Image exceeds the {MAX_IMAGE_PIXELS:,}-pixel safety limit."
        ) from exc
    except OSError as exc:
        raise ValueError("Image file is corrupted or unreadable.") from exc


def bytes_to_bits(data: bytes) -> list[int]:
    bits: list[int] = []
    for value in data:
        for shift in range(7, -1, -1):
            bits.append((value >> shift) & 1)
    return bits


def bits_to_bytes(bits: list[int]) -> bytes:
    if len(bits) % 8:
        raise ValueError("Bit count must be divisible by 8.")

    values = bytearray()
    for offset in range(0, len(bits), 8):
        value = 0
        for bit in bits[offset : offset + 8]:
            value = (value << 1) | bit
        values.append(value)
    return bytes(values)


def normalise_image(image: Image.Image) -> Image.Image:
    if image.mode in {"RGB", "RGBA"}:
        return image.copy()
    if "A" in image.getbands():
        return image.convert("RGBA")
    return image.convert("RGB")


def channel_index(bit_index: int, channel_count: int) -> int:
    pixel_index, rgb_channel = divmod(bit_index, 3)
    return pixel_index * channel_count + rgb_channel


def read_bits(raw: bytes, channel_count: int, bit_count: int) -> list[int]:
    capacity = len(raw) // channel_count * 3
    if bit_count > capacity:
        raise ValueError(f"Image only has capacity for {capacity} bits.")
    return [raw[channel_index(i, channel_count)] & 1 for i in range(bit_count)]


def read_bits_at_positions(raw: bytes, channel_count: int, positions: list[int]) -> list[int]:
    return [raw[channel_index(position, channel_count)] & 1 for position in positions]


def write_bits_at_positions(
    raw: bytearray,
    channel_count: int,
    positions: list[int],
    bits: list[int],
) -> None:
    for position, bit in zip(positions, bits):
        raw_index = channel_index(position, channel_count)
        raw[raw_index] = (raw[raw_index] & 0xFE) | bit


def build_legacy_image_packet(payload: bytes) -> bytes:
    return (
        LEGACY_IMAGE_MAGIC
        + len(payload).to_bytes(4, "big")
        + payload
        + zlib.crc32(payload).to_bytes(CRC_SIZE, "big")
    )


def derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("Password is required for this payload.")
    return PBKDF2(
        password.encode("utf-8"),
        salt,
        dkLen=AES_KEY_SIZE,
        count=PBKDF2_ROUNDS,
        hmac_hash_module=SHA256,
    )


def encrypt_payload(payload: bytes, password: str) -> tuple[bytes, bytes, bytes]:
    salt = get_random_bytes(SALT_SIZE)
    nonce = get_random_bytes(AES_GCM_NONCE_SIZE)
    key = derive_key(password, salt)
    return salt, nonce, encrypt_payload_with_key(payload, key, nonce)


def encrypt_payload_with_key(payload: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(payload)
    return ciphertext + tag


def decrypt_payload_with_key(encrypted_payload: bytes, key: bytes, nonce: bytes) -> bytes:
    if len(encrypted_payload) < AES_GCM_TAG_SIZE:
        raise ValueError("Encrypted payload is incomplete.")
    ciphertext = encrypted_payload[:-AES_GCM_TAG_SIZE]
    tag = encrypted_payload[-AES_GCM_TAG_SIZE:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise ValueError("Password is wrong or payload was modified.") from exc


def decrypt_payload(encrypted_payload: bytes, password: str, salt: bytes, nonce: bytes) -> bytes:
    key = derive_key(password, salt)
    return decrypt_payload_with_key(encrypted_payload, key, nonce)


def random_positions(
    capacity: int,
    count: int,
    key: bytes,
    context: bytes,
    salt: bytes = b"",
    exclude: set[int] | None = None,
) -> list[int]:
    if count > capacity:
        raise ValueError(f"Image only has capacity for {capacity} bits.")

    used = set(exclude or set())
    positions: list[int] = []
    if count + len(used) > capacity:
        raise ValueError(f"Image only has capacity for {capacity - len(used)} available bits.")

    counter = 0
    while len(positions) < count:
        block = hmac.new(
            key,
            b"GreyNOC position map\x00" + context + b"\x00" + salt + counter.to_bytes(8, "big"),
            hashlib.sha256,
        ).digest()
        counter += 1
        for offset in range(0, len(block), 8):
            if len(positions) >= count:
                break
            position = int.from_bytes(block[offset : offset + 8], "big") % capacity
            if position in used:
                continue
            used.add(position)
            positions.append(position)
    return positions


def fixed_header_positions(bit_count: int) -> list[int]:
    return list(range(bit_count))


def build_protected_image_header(salt: bytes, nonce: bytes, encrypted_size: int) -> bytes:
    return PROTECTED_IMAGE_MAGIC + b"\x01" + salt + nonce + encrypted_size.to_bytes(4, "big")


def parse_protected_image_header(header: bytes) -> tuple[bytes, bytes, int]:
    if not header.startswith(PROTECTED_IMAGE_MAGIC):
        raise ValueError("No password-protected GreyNOC image payload was found.")
    offset = len(PROTECTED_IMAGE_MAGIC)
    flags = header[offset]
    offset += 1
    if flags != 1:
        raise ValueError("Unsupported GreyNOC image payload version.")
    salt = header[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = header[offset : offset + AES_GCM_NONCE_SIZE]
    offset += AES_GCM_NONCE_SIZE
    encrypted_size = int.from_bytes(header[offset : offset + 4], "big")
    return salt, nonce, encrypted_size


def build_protected_trailer_footer(salt: bytes, nonce: bytes, encrypted_size: int, magic: bytes) -> bytes:
    return salt + nonce + encrypted_size.to_bytes(TRAILER_LENGTH_SIZE, "big") + magic


def format_payload(payload: bytes) -> tuple[str, str]:
    return payload.hex(" ").upper(), payload.decode("utf-8", errors="replace")


def parse_hex(value: str) -> bytes:
    compact = "".join(value.split())
    if not compact:
        raise ValueError("Hex payload is empty.")
    if len(compact) % 2:
        raise ValueError("Hex payload must have an even number of digits.")
    try:
        return bytes.fromhex(compact)
    except ValueError as exc:
        raise ValueError("Hex payload contains non-hex characters.") from exc


def encrypt_payload_to_text(payload: bytes, password: str) -> str:
    validate_payload_size(payload)
    salt, nonce, encrypted_payload = encrypt_payload(payload, password)
    blob = salt + nonce + encrypted_payload
    encoded = base64.urlsafe_b64encode(blob).decode("ascii").rstrip("=")
    return f"{TEXT_ARMOR_PREFIX}{encoded}"


def parse_encrypted_text(value: str) -> tuple[bytes, bytes, bytes]:
    text = value.strip()
    if not text:
        raise ValueError("Encrypted text is empty.")

    upper_text = text.upper()
    prefix = TEXT_ARMOR_PREFIX.upper()
    has_armor = upper_text.startswith(prefix)
    if has_armor:
        text = text[len(TEXT_ARMOR_PREFIX) :]

    compact = "".join(text.split())
    if not compact:
        raise ValueError("Encrypted text is empty.")

    if not has_armor and len(compact) % 2 == 0 and all(char in "0123456789abcdefABCDEF" for char in compact):
        blob = bytes.fromhex(compact)
    else:
        padded = compact + ("=" * (-len(compact) % 4))
        try:
            blob = base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
        except (binascii.Error, UnicodeEncodeError) as exc:
            raise ValueError("Encrypted text must be GreyNOC text, base64, or hex.") from exc

    minimum_size = SALT_SIZE + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE
    if len(blob) < minimum_size:
        raise ValueError("Encrypted text is incomplete.")

    salt = blob[:SALT_SIZE]
    nonce_start = SALT_SIZE
    nonce_end = nonce_start + AES_GCM_NONCE_SIZE
    nonce = blob[nonce_start:nonce_end]
    encrypted_payload = blob[nonce_end:]
    if len(encrypted_payload) > MAX_PAYLOAD_BYTES + AES_GCM_TAG_SIZE:
        raise ValueError("Encrypted text is larger than this app allows.")

    return salt, nonce, encrypted_payload


def decrypt_text_input(value: str, password: str) -> tuple[str, str]:
    salt, nonce, encrypted_payload = parse_encrypted_text(value)
    payload = decrypt_payload(encrypted_payload, password, salt, nonce)
    return format_payload(payload)


_TRUTHY_DEBUG_VALUES = frozenset({"1", "true", "yes", "on"})


def _debug_logging_enabled() -> bool:
    # Whitelist truthy values so unexpected casing (e.g. "FALSE", "OFF") never
    # silently enables logging — the prior blacklist treated any unknown string
    # as "on", which was the wrong default for a security-sensitive opt-in.
    return os.environ.get("GREYNOC_DEBUG", "").strip().lower() in _TRUTHY_DEBUG_VALUES


def log_exception() -> None:
    if not _debug_logging_enabled():
        return
    try:
        with DEBUG_LOG.open("a", encoding="utf-8") as log:
            log.write("\n--- GreyNOC Stego Studio error ---\n")
            traceback.print_exc(file=log)
    except Exception:
        pass


def log_traceback_text(traceback_text: str) -> None:
    if not _debug_logging_enabled():
        return
    try:
        with DEBUG_LOG.open("a", encoding="utf-8") as log:
            log.write("\n--- GreyNOC Stego Studio error ---\n")
            log.write(traceback_text)
            if not traceback_text.endswith("\n"):
                log.write("\n")
    except Exception:
        pass
