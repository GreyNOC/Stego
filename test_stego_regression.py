from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from PIL import Image

import stego_core
from stego_carriers import embed_for_file, extract_from_file, normalized_output_path
from stego_constants import MAX_PAYLOAD_BYTES
from stego_core import (
    decrypt_text_input,
    encrypt_payload_to_text,
    open_image_safely,
    parse_encrypted_text,
    validate_payload_size,
)


PAYLOAD = b"Save the Humans."
PASSWORD = "GreyNOC-pass"


class StegoRegressionTests(unittest.TestCase):
    def make_source_image(self, path: Path) -> None:
        image = Image.new("RGB", (96, 96))
        pixels = image.load()
        for y in range(image.height):
            for x in range(image.width):
                pixels[x, y] = ((x * 3) % 256, (y * 5) % 256, ((x + y) * 7) % 256)
        image.save(path, "PNG")

    def test_protected_image_round_trip_and_wrong_password_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source.png"
            requested = root / "encoded.jpg"
            self.make_source_image(source)

            mode, output = embed_for_file(source, requested, PAYLOAD, PASSWORD)

            self.assertEqual(output, normalized_output_path(source, requested))
            self.assertEqual(output.suffix, ".png")
            self.assertIn("password-protected", mode)
            self.assertEqual(extract_from_file(output, PASSWORD)[1], PAYLOAD.decode())
            with self.assertRaises(ValueError):
                extract_from_file(output, "wrong-password")
            with self.assertRaises(ValueError):
                extract_from_file(output)

    def test_plain_legacy_requires_no_password(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source.png"
            output = root / "plain.png"
            self.make_source_image(source)

            embed_for_file(source, output, PAYLOAD, "")

            self.assertEqual(extract_from_file(output)[1], PAYLOAD.decode())
            with self.assertRaises(ValueError):
                extract_from_file(output, PASSWORD)

    def test_pdf_and_video_trailer_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pdf = root / "carrier.pdf"
            pdf.write_bytes(b"%PDF-1.4\n%test\n%%EOF\n")
            pdf_output = root / "carrier_stego.pdf"
            embed_for_file(pdf, pdf_output, PAYLOAD, PASSWORD)
            self.assertEqual(extract_from_file(pdf_output, PASSWORD)[1], PAYLOAD.decode())

            video = root / "carrier.mp4"
            video.write_bytes(b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom")
            video_output = root / "carrier_stego.mp4"
            embed_for_file(video, video_output, PAYLOAD, PASSWORD)
            self.assertEqual(extract_from_file(video_output, PASSWORD)[1], PAYLOAD.decode())

    def test_payload_size_limit(self) -> None:
        with self.assertRaises(ValueError):
            validate_payload_size(b"x" * (MAX_PAYLOAD_BYTES + 1))

    def test_text_decryption_engine_round_trips_and_rejects_wrong_password(self) -> None:
        encrypted_text = encrypt_payload_to_text(PAYLOAD, PASSWORD)

        self.assertTrue(encrypted_text.startswith("GNOCENC1:"))
        self.assertEqual(decrypt_text_input(encrypted_text, PASSWORD)[1], PAYLOAD.decode())
        with self.assertRaises(ValueError):
            decrypt_text_input(encrypted_text, "wrong-password")
        with self.assertRaises(ValueError):
            decrypt_text_input(encrypted_text, "")

    def test_text_decryption_accepts_raw_hex_container(self) -> None:
        encrypted_text = encrypt_payload_to_text(PAYLOAD, PASSWORD)
        salt, nonce, encrypted_payload = parse_encrypted_text(encrypted_text)
        raw_hex = (salt + nonce + encrypted_payload).hex()

        self.assertEqual(decrypt_text_input(raw_hex, PASSWORD)[1], PAYLOAD.decode())

    def test_corrupted_image_fails_with_clean_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            corrupted = Path(temp_dir) / "corrupted.png"
            corrupted.write_bytes(b"\x89PNG\r\n\x1a\nthis is not a real PNG payload")

            with self.assertRaises(ValueError) as ctx:
                open_image_safely(corrupted)
            self.assertNotIn("Traceback", str(ctx.exception))

            with self.assertRaises(ValueError):
                extract_from_file(corrupted, PASSWORD)

    def test_unsupported_binary_fails_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            blob = Path(temp_dir) / "random.bin"
            blob.write_bytes(b"\x00\x01\x02\x03not an image and no trailer either")

            with self.assertRaises(ValueError):
                extract_from_file(blob)

    def test_tampered_image_ciphertext_fails_authentication(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source.png"
            output = root / "encoded.png"
            self.make_source_image(source)
            embed_for_file(source, output, PAYLOAD, PASSWORD)

            data = bytearray(output.read_bytes())
            # Flip a bit deep in the file body so the GCM tag check fails.
            flip_index = len(data) - 1024
            data[flip_index] ^= 0x01
            output.write_bytes(bytes(data))

            with self.assertRaises(ValueError):
                extract_from_file(output, PASSWORD)

    def test_tampered_encrypted_text_fails_authentication(self) -> None:
        encrypted_text = encrypt_payload_to_text(PAYLOAD, PASSWORD)
        prefix, body = encrypted_text.split(":", 1)
        # Swap two characters in the armored body to corrupt the ciphertext + tag.
        tampered_body = body[:-3] + ("A" if body[-3] != "A" else "B") + body[-2:]
        tampered = f"{prefix}:{tampered_body}"

        with self.assertRaises(ValueError):
            decrypt_text_input(tampered, PASSWORD)

    def test_oversized_image_rejected_by_pillow_cap(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            image_path = root / "tiny.png"
            self.make_source_image(image_path)

            # Lower the cap below the test image so Pillow's decompression-bomb
            # guard fires during decode rather than after a partial load.
            with mock.patch.object(Image, "MAX_IMAGE_PIXELS", 16), \
                 mock.patch.object(stego_core, "MAX_IMAGE_PIXELS", 16):
                with self.assertRaises(ValueError) as ctx:
                    open_image_safely(image_path)
                self.assertIn("safety limit", str(ctx.exception))

    def test_debug_logging_is_off_by_default(self) -> None:
        import os

        log_path = stego_core.DEBUG_LOG
        size_before = log_path.stat().st_size if log_path.exists() else 0

        env = {k: v for k, v in os.environ.items() if k != "GREYNOC_DEBUG"}
        with mock.patch.dict(os.environ, env, clear=True):
            try:
                raise ValueError("synthetic error for logging test")
            except ValueError:
                stego_core.log_exception()

        size_after = log_path.stat().st_size if log_path.exists() else 0
        self.assertEqual(size_after, size_before)

    def test_image_embed_rejects_input_equals_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source.png"
            self.make_source_image(source)

            # Protected path
            with self.assertRaises(ValueError) as ctx:
                embed_for_file(source, source, PAYLOAD, PASSWORD)
            self.assertIn("overwritten", str(ctx.exception))

            # Legacy unprotected path
            with self.assertRaises(ValueError) as ctx:
                embed_for_file(source, source, PAYLOAD, "")
            self.assertIn("overwritten", str(ctx.exception))

            # Original still intact (no partial write)
            with Image.open(source) as image:
                self.assertEqual(image.size, (96, 96))

    def test_debug_logging_off_for_uppercase_false(self) -> None:
        """Regression: GREYNOC_DEBUG=FALSE previously enabled logging due to blacklist logic."""
        import os

        log_path = stego_core.DEBUG_LOG
        size_before = log_path.stat().st_size if log_path.exists() else 0

        for value in ("FALSE", "False", "off", "no", "anything-else", "0", ""):
            env = {**{k: v for k, v in os.environ.items()}, "GREYNOC_DEBUG": value}
            with mock.patch.dict(os.environ, env, clear=True):
                try:
                    raise ValueError("synthetic")
                except ValueError:
                    stego_core.log_exception()

        size_after = log_path.stat().st_size if log_path.exists() else 0
        self.assertEqual(size_after, size_before, "log was written for a non-truthy GREYNOC_DEBUG value")

    def test_debug_logging_on_for_truthy_values(self) -> None:
        import os

        with tempfile.TemporaryDirectory() as temp_dir:
            for value in ("1", "true", "TRUE", "yes", "Yes", "on", "ON"):
                redirected = Path(temp_dir) / f"log_{value}.log"
                env = {**{k: v for k, v in os.environ.items()}, "GREYNOC_DEBUG": value}
                with mock.patch.dict(os.environ, env, clear=True), \
                     mock.patch.object(stego_core, "DEBUG_LOG", redirected):
                    try:
                        raise ValueError("synthetic")
                    except ValueError:
                        stego_core.log_exception()
                self.assertTrue(redirected.exists(), f"log not written for GREYNOC_DEBUG={value!r}")
                self.assertGreater(redirected.stat().st_size, 0)

    def test_debug_logging_writes_when_env_flag_set(self) -> None:
        import os

        with tempfile.TemporaryDirectory() as temp_dir:
            redirected = Path(temp_dir) / "stego_debug.log"
            env = {**{k: v for k, v in os.environ.items()}, "GREYNOC_DEBUG": "1"}
            with mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch.object(stego_core, "DEBUG_LOG", redirected):
                try:
                    raise ValueError("synthetic error for logging test")
                except ValueError:
                    stego_core.log_exception()

            self.assertTrue(redirected.exists())
            self.assertGreater(redirected.stat().st_size, 0)

    def test_linux_cli_round_trips_payloads(self) -> None:
        repo_root = Path(__file__).resolve().parent
        cli = repo_root / "greynoc_stego_cli.py"

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source.png"
            output = root / "encoded.png"
            self.make_source_image(source)

            inject = subprocess.run(
                [
                    sys.executable,
                    str(cli),
                    "inject",
                    str(source),
                    "--output",
                    str(output),
                    "--password",
                    PASSWORD,
                    "--text",
                    PAYLOAD.decode(),
                ],
                cwd=repo_root,
                text=True,
                capture_output=True,
                check=True,
            )
            self.assertIn("Wrote:", inject.stdout)
            self.assertTrue(output.exists())

            extract = subprocess.run(
                [
                    sys.executable,
                    str(cli),
                    "extract",
                    str(output),
                    "--password",
                    PASSWORD,
                    "--format",
                    "text",
                ],
                cwd=repo_root,
                text=True,
                capture_output=True,
                check=True,
            )
            self.assertIn(PAYLOAD.decode(), extract.stdout)

            encrypted = subprocess.run(
                [
                    sys.executable,
                    str(cli),
                    "encrypt-text",
                    "--password",
                    PASSWORD,
                    "--text",
                    PAYLOAD.decode(),
                ],
                cwd=repo_root,
                text=True,
                capture_output=True,
                check=True,
            ).stdout.strip()
            self.assertTrue(encrypted.startswith("GNOCENC1:"))

            decrypted = subprocess.run(
                [
                    sys.executable,
                    str(cli),
                    "decrypt-text",
                    encrypted,
                    "--password",
                    PASSWORD,
                    "--format",
                    "text",
                ],
                cwd=repo_root,
                text=True,
                capture_output=True,
                check=True,
            )
            self.assertIn(PAYLOAD.decode(), decrypted.stdout)


if __name__ == "__main__":
    unittest.main()
