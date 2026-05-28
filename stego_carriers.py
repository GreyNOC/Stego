from __future__ import annotations

import zlib
from pathlib import Path

from Crypto.Random import get_random_bytes
from PIL import Image

from stego_constants import (
    AES_GCM_NONCE_SIZE,
    AES_GCM_TAG_SIZE,
    CRC_SIZE,
    IMAGE_EXTS,
    LEGACY_IMAGE_HEADER_SIZE,
    LEGACY_IMAGE_MAGIC,
    LEGACY_TRAILER_MAGIC,
    MAX_IMAGE_STEGO_RATIO,
    MAX_PAYLOAD_BYTES,
    PDF_EXTS,
    PROTECTED_IMAGE_HEADER_SIZE,
    PROTECTED_TRAILER_MAGIC,
    SALT_SIZE,
    TRAILER_LENGTH_SIZE,
    TRAILER_SCAN_LIMIT,
    VIDEO_EXTS,
)
from stego_core import (
    bits_to_bytes,
    build_legacy_image_packet,
    build_protected_image_header,
    build_protected_trailer_footer,
    bytes_to_bits,
    decrypt_payload,
    decrypt_payload_with_key,
    derive_key,
    encrypt_payload,
    encrypt_payload_with_key,
    fixed_header_positions,
    format_bytes,
    format_payload,
    normalise_image,
    parse_protected_image_header,
    random_positions,
    read_bits,
    read_bits_at_positions,
    validate_image_limits,
    validate_payload_size,
    validate_source_file,
    write_bits_at_positions,
)


def suffix(path: Path) -> str:
    return path.suffix.lower()


def is_image_file(path: Path) -> bool:
    return suffix(path) in IMAGE_EXTS


def is_video_file(path: Path) -> bool:
    return suffix(path) in VIDEO_EXTS


def is_pdf_file(path: Path) -> bool:
    return suffix(path) in PDF_EXTS


def can_open_as_image(path: Path) -> bool:
    if is_pdf_file(path) or is_video_file(path):
        return False
    try:
        validate_source_file(path)
    except Exception:
        return False
    try:
        with Image.open(path) as image:
            image.verify()
        return True
    except Exception:
        return False


def carrier_label(path: Path) -> str:
    if is_pdf_file(path):
        return "PDF trailer carrier"
    if is_video_file(path):
        return "video trailer carrier"
    if can_open_as_image(path):
        return "pixel LSB image carrier"
    return "file trailer carrier"


def suggested_output_path(input_path: Path) -> Path:
    if is_image_file(input_path):
        return input_path.with_name(f"{input_path.stem}_stego.png")
    return input_path.with_name(f"{input_path.stem}_stego{input_path.suffix}")


def normalized_output_path(input_path: Path, requested_output_path: Path) -> Path:
    if can_open_as_image(input_path):
        return requested_output_path.with_suffix(".png")
    return requested_output_path


def extract_protected_image_payload(image_path: Path, password: str) -> tuple[str, str]:
    validate_source_file(image_path)
    with Image.open(image_path) as source:
        image = normalise_image(source)
        validate_image_limits(image)

    channel_count = len(image.getbands())
    raw = image.tobytes()
    capacity = image.width * image.height * 3
    header_positions = fixed_header_positions(PROTECTED_IMAGE_HEADER_SIZE * 8)
    header = bits_to_bytes(read_bits_at_positions(raw, channel_count, header_positions))
    salt, nonce, encrypted_size = parse_protected_image_header(header)
    if encrypted_size > MAX_PAYLOAD_BYTES + AES_GCM_TAG_SIZE:
        raise ValueError("Encrypted payload is larger than this app allows.")

    key = derive_key(password, salt)
    encrypted_positions = random_positions(
        capacity,
        encrypted_size * 8,
        key,
        b"image-payload-v3",
        salt,
        exclude=set(header_positions),
    )
    encrypted_payload = bits_to_bytes(read_bits_at_positions(raw, channel_count, encrypted_positions))
    payload = decrypt_payload_with_key(encrypted_payload, key, nonce)
    return format_payload(payload)


def extract_legacy_image_payload(image_path: Path) -> tuple[str, str]:
    validate_source_file(image_path)
    with Image.open(image_path) as source:
        image = normalise_image(source)
        validate_image_limits(image)

    channel_count = len(image.getbands())
    raw = image.tobytes()

    header = bits_to_bytes(read_bits(raw, channel_count, LEGACY_IMAGE_HEADER_SIZE * 8))
    if not header.startswith(LEGACY_IMAGE_MAGIC):
        raise ValueError("No GreyNOC payload was found in this image.")

    payload_size = int.from_bytes(header[len(LEGACY_IMAGE_MAGIC) : LEGACY_IMAGE_HEADER_SIZE], "big")
    if payload_size > MAX_PAYLOAD_BYTES:
        raise ValueError("Payload is larger than this app allows.")

    packet_size = LEGACY_IMAGE_HEADER_SIZE + payload_size + CRC_SIZE
    packet = bits_to_bytes(read_bits(raw, channel_count, packet_size * 8))

    payload_start = LEGACY_IMAGE_HEADER_SIZE
    payload_end = payload_start + payload_size
    payload = packet[payload_start:payload_end]
    expected_crc = int.from_bytes(packet[payload_end : payload_end + CRC_SIZE], "big")
    actual_crc = zlib.crc32(payload)
    if actual_crc != expected_crc:
        raise ValueError("Payload checksum did not match.")

    return format_payload(payload)


def extract_protected_trailer_payload(file_path: Path, password: str) -> tuple[str, str]:
    validate_source_file(file_path)
    file_size = file_path.stat().st_size
    scan_size = min(file_size, TRAILER_SCAN_LIMIT)

    with file_path.open("rb") as file:
        file.seek(file_size - scan_size)
        tail = file.read(scan_size)

    magic_index = tail.rfind(PROTECTED_TRAILER_MAGIC)
    if magic_index < 0:
        raise ValueError("No password-protected GreyNOC file payload was found in this carrier.")

    absolute_magic_index = file_size - scan_size + magic_index
    length_start = absolute_magic_index - TRAILER_LENGTH_SIZE
    nonce_start = length_start - AES_GCM_NONCE_SIZE
    salt_start = nonce_start - SALT_SIZE
    if salt_start < 0:
        raise ValueError("Password-protected file payload is incomplete.")

    with file_path.open("rb") as file:
        file.seek(salt_start)
        salt = file.read(SALT_SIZE)
        nonce = file.read(AES_GCM_NONCE_SIZE)
        encrypted_size = int.from_bytes(file.read(TRAILER_LENGTH_SIZE), "big")
        if encrypted_size > MAX_PAYLOAD_BYTES + AES_GCM_TAG_SIZE:
            raise ValueError("Encrypted payload is larger than this app allows.")
        encrypted_start = salt_start - encrypted_size
        if encrypted_start < 0:
            raise ValueError("Password-protected file payload length is invalid.")

        file.seek(encrypted_start)
        encrypted_payload = file.read(encrypted_size)

    payload = decrypt_payload(encrypted_payload, password, salt, nonce)
    return format_payload(payload)


def extract_legacy_trailer_payload(file_path: Path) -> tuple[str, str]:
    validate_source_file(file_path)
    file_size = file_path.stat().st_size
    scan_size = min(file_size, TRAILER_SCAN_LIMIT)

    with file_path.open("rb") as file:
        file.seek(file_size - scan_size)
        tail = file.read(scan_size)

    magic_index = tail.rfind(LEGACY_TRAILER_MAGIC)
    if magic_index < 0:
        raise ValueError("No GreyNOC file payload was found in this carrier.")

    absolute_magic_index = file_size - scan_size + magic_index
    length_start = absolute_magic_index - TRAILER_LENGTH_SIZE
    crc_start = length_start - CRC_SIZE
    if length_start < 0 or crc_start < 0:
        raise ValueError("GreyNOC file payload is incomplete.")

    with file_path.open("rb") as file:
        file.seek(length_start)
        payload_size = int.from_bytes(file.read(TRAILER_LENGTH_SIZE), "big")
        if payload_size > MAX_PAYLOAD_BYTES:
            raise ValueError("Payload is larger than this app allows.")
        payload_start = crc_start - payload_size
        if payload_start < 0:
            raise ValueError("GreyNOC file payload length is invalid.")

        file.seek(payload_start)
        payload = file.read(payload_size)
        expected_crc = int.from_bytes(file.read(CRC_SIZE), "big")

    actual_crc = zlib.crc32(payload)
    if actual_crc != expected_crc:
        raise ValueError("File payload checksum did not match.")

    return format_payload(payload)


def embed_legacy_image_payload(input_path: Path, output_path: Path, payload: bytes) -> None:
    validate_payload_size(payload)
    validate_source_file(input_path)

    packet = build_legacy_image_packet(payload)
    bits = bytes_to_bits(packet)

    with Image.open(input_path) as source:
        image = normalise_image(source)
        validate_image_limits(image)

    channel_count = len(image.getbands())
    capacity = image.width * image.height * 3
    if len(bits) > capacity:
        max_payload_bytes = max(0, capacity // 8 - LEGACY_IMAGE_HEADER_SIZE - CRC_SIZE)
        raise ValueError(f"Image is too small. Maximum payload is {max_payload_bytes} bytes.")
    if len(bits) > int(capacity * MAX_IMAGE_STEGO_RATIO):
        max_payload_bytes = max(0, int(capacity * MAX_IMAGE_STEGO_RATIO) // 8 - LEGACY_IMAGE_HEADER_SIZE - CRC_SIZE)
        raise ValueError(f"Payload uses too much image capacity. Maximum payload is about {format_bytes(max_payload_bytes)}.")

    raw = bytearray(image.tobytes())
    for bit_index, bit in enumerate(bits):
        raw_index = bit_index // 3 * channel_count + bit_index % 3
        raw[raw_index] = (raw[raw_index] & 0xFE) | bit

    encoded = Image.frombytes(image.mode, image.size, bytes(raw))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    encoded.save(output_path, "PNG", optimize=True)


def embed_protected_image_payload(
    input_path: Path,
    output_path: Path,
    payload: bytes,
    password: str,
) -> None:
    validate_payload_size(payload)
    validate_source_file(input_path)

    salt = get_random_bytes(SALT_SIZE)
    nonce = get_random_bytes(AES_GCM_NONCE_SIZE)
    key = derive_key(password, salt)
    encrypted_payload = encrypt_payload_with_key(payload, key, nonce)
    header = build_protected_image_header(salt, nonce, len(encrypted_payload))
    header_bits = bytes_to_bits(header)
    encrypted_bits = bytes_to_bits(encrypted_payload)

    with Image.open(input_path) as source:
        image = normalise_image(source)
        validate_image_limits(image)

    channel_count = len(image.getbands())
    capacity = image.width * image.height * 3
    total_bits = len(header_bits) + len(encrypted_bits)
    if total_bits > capacity:
        max_payload_bytes = max(0, (capacity - len(header_bits)) // 8 - AES_GCM_TAG_SIZE)
        raise ValueError(f"Image is too small. Maximum encrypted payload is about {max_payload_bytes} bytes.")
    if total_bits > int(capacity * MAX_IMAGE_STEGO_RATIO):
        max_payload_bytes = max(0, int(capacity * MAX_IMAGE_STEGO_RATIO) // 8 - len(header) - AES_GCM_TAG_SIZE)
        raise ValueError(
            f"Payload uses too much image capacity. Maximum encrypted payload is about {format_bytes(max_payload_bytes)}."
        )

    header_positions = fixed_header_positions(len(header_bits))
    encrypted_positions = random_positions(
        capacity,
        len(encrypted_bits),
        key,
        b"image-payload-v3",
        salt,
        exclude=set(header_positions),
    )

    raw = bytearray(image.tobytes())
    write_bits_at_positions(raw, channel_count, header_positions, header_bits)
    write_bits_at_positions(raw, channel_count, encrypted_positions, encrypted_bits)

    encoded = Image.frombytes(image.mode, image.size, bytes(raw))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    encoded.save(output_path, "PNG", optimize=True)


def embed_legacy_trailer_payload(input_path: Path, output_path: Path, payload: bytes) -> None:
    validate_payload_size(payload)
    validate_source_file(input_path)
    if input_path.resolve() == output_path.resolve():
        raise ValueError("Choose a new output file so the source is not overwritten.")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with input_path.open("rb") as source, output_path.open("wb") as target:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            target.write(chunk)
        target.write(payload)
        target.write(zlib.crc32(payload).to_bytes(CRC_SIZE, "big"))
        target.write(len(payload).to_bytes(TRAILER_LENGTH_SIZE, "big"))
        target.write(LEGACY_TRAILER_MAGIC)


def embed_protected_trailer_payload(
    input_path: Path,
    output_path: Path,
    payload: bytes,
    password: str,
) -> None:
    validate_payload_size(payload)
    validate_source_file(input_path)
    if input_path.resolve() == output_path.resolve():
        raise ValueError("Choose a new output file so the source is not overwritten.")

    salt, nonce, encrypted_payload = encrypt_payload(payload, password)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with input_path.open("rb") as source, output_path.open("wb") as target:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            target.write(chunk)
        target.write(encrypted_payload)
        target.write(build_protected_trailer_footer(salt, nonce, len(encrypted_payload), PROTECTED_TRAILER_MAGIC))


def extract_from_file(file_path: Path, password: str = "") -> tuple[str, str, str]:
    validate_source_file(file_path)
    if can_open_as_image(file_path):
        if password:
            hex_value, message = extract_protected_image_payload(file_path, password)
            return hex_value, message, "Password image payload"

        try:
            hex_value, message = extract_legacy_image_payload(file_path)
            return hex_value, message, "Pixel LSB image payload"
        except Exception as pixel_error:
            try:
                hex_value, message = extract_legacy_trailer_payload(file_path)
                return hex_value, message, "File trailer payload"
            except Exception:
                raise pixel_error

    if password:
        hex_value, message = extract_protected_trailer_payload(file_path, password)
        return hex_value, message, "Password file trailer payload"

    try:
        hex_value, message = extract_legacy_trailer_payload(file_path)
        return hex_value, message, "File trailer payload"
    except Exception as trailer_error:
        raise ValueError(f"{trailer_error} If this file is password-protected, enter its password.") from trailer_error


def embed_for_file(
    input_path: Path,
    requested_output_path: Path,
    payload: bytes,
    password: str = "",
) -> tuple[str, Path]:
    validate_source_file(input_path)
    validate_payload_size(payload)
    output_path = normalized_output_path(input_path, requested_output_path)

    if can_open_as_image(input_path):
        if password:
            embed_protected_image_payload(input_path, output_path, payload, password)
            return "password-protected randomized PNG pixel LSB", output_path
        embed_legacy_image_payload(input_path, output_path, payload)
        return "clean PNG pixel LSB", output_path

    if password:
        embed_protected_trailer_payload(input_path, output_path, payload, password)
        return "password-protected file trailer", output_path
    embed_legacy_trailer_payload(input_path, output_path, payload)
    return "file trailer", output_path
