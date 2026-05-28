from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from PIL import Image

from stego_carriers import embed_for_file, extract_from_file, normalized_output_path
from stego_constants import MAX_PAYLOAD_BYTES
from stego_core import decrypt_text_input, encrypt_payload_to_text, parse_encrypted_text, validate_payload_size


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


if __name__ == "__main__":
    unittest.main()
