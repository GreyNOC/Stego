from __future__ import annotations

from pathlib import Path


LEGACY_IMAGE_MAGIC = b"GNOCSTEG1"
PROTECTED_IMAGE_MAGIC = b"GNOCSTG3"
LEGACY_TRAILER_MAGIC = b"GNOCFILESTEG1"
PROTECTED_TRAILER_MAGIC = b"GNOCFILESTEG2"
TEXT_ARMOR_PREFIX = "GNOCENC1:"

CRC_SIZE = 4
TRAILER_LENGTH_SIZE = 8
TRAILER_SCAN_LIMIT = 64 * 1024 * 1024

AES_KEY_SIZE = 32
AES_GCM_TAG_SIZE = 16
AES_GCM_NONCE_SIZE = 12
SALT_SIZE = 16
PBKDF2_ROUNDS = 200_000

LEGACY_IMAGE_HEADER_SIZE = len(LEGACY_IMAGE_MAGIC) + 4
PROTECTED_IMAGE_HEADER_SIZE = (
    len(PROTECTED_IMAGE_MAGIC) + 1 + SALT_SIZE + AES_GCM_NONCE_SIZE + 4
)

MAX_SOURCE_FILE_BYTES = 512 * 1024 * 1024
MAX_PAYLOAD_BYTES = 5 * 1024 * 1024
MAX_IMAGE_PIXELS = 50_000_000
MAX_IMAGE_STEGO_RATIO = 0.25

DEBUG_LOG = Path(__file__).with_name("stego_debug.log")

IMAGE_EXTS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".bmp",
    ".gif",
    ".tif",
    ".tiff",
    ".webp",
    ".ico",
    ".tga",
    ".ppm",
    ".pgm",
    ".pbm",
    ".pnm",
    ".dib",
    ".avif",
}

VIDEO_EXTS = {
    ".mp4",
    ".mov",
    ".avi",
    ".mkv",
    ".webm",
    ".wmv",
    ".m4v",
    ".mpg",
    ".mpeg",
    ".3gp",
}

PDF_EXTS = {".pdf"}

MEDIA_FILETYPES = [
    (
        "Supported media",
        "*.png *.jpg *.jpeg *.bmp *.gif *.tif *.tiff *.webp *.ico *.tga *.avif "
        "*.mp4 *.mov *.avi *.mkv *.webm *.wmv *.m4v *.mpg *.mpeg *.3gp *.pdf",
    ),
    ("Images", "*.png *.jpg *.jpeg *.bmp *.gif *.tif *.tiff *.webp *.ico *.tga *.avif"),
    ("Videos", "*.mp4 *.mov *.avi *.mkv *.webm *.wmv *.m4v *.mpg *.mpeg *.3gp"),
    ("PDF", "*.pdf"),
    ("All files", "*.*"),
]
