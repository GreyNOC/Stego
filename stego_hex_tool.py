from __future__ import annotations

import argparse
import zlib
from pathlib import Path

from PIL import Image, UnidentifiedImageError

from stego_constants import MAX_IMAGE_STEGO_RATIO, MAX_PAYLOAD_BYTES, MAX_SOURCE_FILE_BYTES
from stego_core import atomic_output_path, format_bytes, parse_hex


MAGIC = b"GNOCSTEG1"
HEADER_SIZE = len(MAGIC) + 4
CRC_SIZE = 4
MAX_IMAGE_PIXELS = 50_000_000

# Bind Pillow's decompression-bomb cap when this script is imported or run directly.
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS


def _validate_source_file(file_path: Path) -> None:
    if not file_path.is_file():
        raise ValueError("Source file does not exist or is not a regular file.")
    file_size = file_path.stat().st_size
    if file_size > MAX_SOURCE_FILE_BYTES:
        raise ValueError(
            f"File is too large ({format_bytes(file_size)}). "
            f"Limit is {format_bytes(MAX_SOURCE_FILE_BYTES)}."
        )


def _validate_payload_size(payload: bytes) -> None:
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise ValueError(
            f"Payload is too large ({format_bytes(len(payload))}). "
            f"Limit is {format_bytes(MAX_PAYLOAD_BYTES)}."
        )


def _validate_image_limits(image: Image.Image) -> None:
    pixels = image.width * image.height
    if pixels > MAX_IMAGE_PIXELS:
        raise ValueError(f"Image is too large ({pixels:,} pixels). Limit is {MAX_IMAGE_PIXELS:,} pixels.")


def _open_image(path: Path) -> Image.Image:
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


def _bytes_to_bits(data: bytes) -> list[int]:
    bits: list[int] = []
    for value in data:
        for shift in range(7, -1, -1):
            bits.append((value >> shift) & 1)
    return bits


def _bits_to_bytes(bits: list[int]) -> bytes:
    if len(bits) % 8:
        raise ValueError("Bit count must be divisible by 8")

    values = bytearray()
    for offset in range(0, len(bits), 8):
        value = 0
        for bit in bits[offset : offset + 8]:
            value = (value << 1) | bit
        values.append(value)
    return bytes(values)


def _normalise_image(image: Image.Image) -> Image.Image:
    if image.mode in {"RGB", "RGBA"}:
        return image.copy()
    if "A" in image.getbands():
        return image.convert("RGBA")
    return image.convert("RGB")


def _channel_index(bit_index: int, channel_count: int) -> int:
    pixel_index, rgb_channel = divmod(bit_index, 3)
    return pixel_index * channel_count + rgb_channel


def _read_bits(raw: bytes | bytearray, channel_count: int, bit_count: int) -> list[int]:
    capacity = len(raw) // channel_count * 3
    if bit_count > capacity:
        raise ValueError(f"Image only has capacity for {capacity} bits, need {bit_count}")
    return [raw[_channel_index(i, channel_count)] & 1 for i in range(bit_count)]


def embed_hex(input_path: Path, output_path: Path, hex_string: str) -> None:
    _validate_source_file(input_path)
    if input_path.resolve() == output_path.resolve():
        raise ValueError("Choose a new output file so the source image is not overwritten.")

    payload = parse_hex(hex_string)
    _validate_payload_size(payload)
    packet = (
        MAGIC
        + len(payload).to_bytes(4, "big")
        + payload
        + zlib.crc32(payload).to_bytes(4, "big")
    )
    bits = _bytes_to_bits(packet)

    image = _normalise_image(_open_image(input_path))
    _validate_image_limits(image)

    channel_count = len(image.getbands())
    capacity = image.width * image.height * 3
    if len(bits) > capacity:
        raise ValueError(f"Image only has capacity for {capacity} bits, need {len(bits)}")
    if len(bits) > int(capacity * MAX_IMAGE_STEGO_RATIO):
        max_payload_bytes = max(0, int(capacity * MAX_IMAGE_STEGO_RATIO) // 8 - HEADER_SIZE - CRC_SIZE)
        raise ValueError(f"Payload uses too much image capacity. Maximum payload is about {format_bytes(max_payload_bytes)}.")

    raw = bytearray(image.tobytes())
    for bit_index, bit in enumerate(bits):
        raw_index = _channel_index(bit_index, channel_count)
        raw[raw_index] = (raw[raw_index] & 0xFE) | bit

    encoded = Image.frombytes(image.mode, image.size, bytes(raw))
    with atomic_output_path(output_path) as temp_path:
        encoded.save(temp_path, "PNG")


def extract_hex(input_path: Path) -> tuple[str, str]:
    _validate_source_file(input_path)
    image = _normalise_image(_open_image(input_path))
    _validate_image_limits(image)

    channel_count = len(image.getbands())
    raw = image.tobytes()

    header = _bits_to_bytes(_read_bits(raw, channel_count, HEADER_SIZE * 8))
    if not header.startswith(MAGIC):
        raise ValueError("No GreyNOC stego payload found")

    payload_size = int.from_bytes(header[len(MAGIC) : HEADER_SIZE], "big")
    if payload_size > MAX_PAYLOAD_BYTES:
        raise ValueError("Payload is larger than this app allows.")
    packet_size = HEADER_SIZE + payload_size + CRC_SIZE
    packet = _bits_to_bytes(_read_bits(raw, channel_count, packet_size * 8))

    payload_start = HEADER_SIZE
    payload_end = payload_start + payload_size
    payload = packet[payload_start:payload_end]
    expected_crc = int.from_bytes(packet[payload_end : payload_end + CRC_SIZE], "big")
    actual_crc = zlib.crc32(payload)
    if actual_crc != expected_crc:
        raise ValueError(
            f"Checksum mismatch: expected {expected_crc:08x}, got {actual_crc:08x}"
        )

    return payload.hex(" ").upper(), payload.decode("utf-8", errors="replace")


def main() -> None:
    parser = argparse.ArgumentParser(description="Hide or extract a hex payload in a PNG.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    embed_parser = subparsers.add_parser("embed", help="Embed a hex payload")
    embed_parser.add_argument("--input", required=True, type=Path)
    embed_parser.add_argument("--output", required=True, type=Path)
    embed_parser.add_argument("--hex", required=True)

    extract_parser = subparsers.add_parser("extract", help="Extract a hex payload")
    extract_parser.add_argument("--input", required=True, type=Path)

    args = parser.parse_args()
    if args.command == "embed":
        embed_hex(args.input, args.output, args.hex)
        print(f"Wrote {args.output}")
        return

    hex_value, text_value = extract_hex(args.input)
    print(hex_value)
    print(text_value)


if __name__ == "__main__":
    main()
