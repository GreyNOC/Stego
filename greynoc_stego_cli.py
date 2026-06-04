from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from stego_carriers import embed_for_file, extract_from_file, suggested_output_path
from stego_core import decrypt_text_input, encrypt_payload_to_text, parse_hex


def read_payload(args: argparse.Namespace) -> bytes:
    sources = [args.text is not None, args.hex is not None, args.file is not None]
    if sum(sources) != 1:
        raise ValueError("Choose exactly one payload source: --text, --hex, or --file.")

    if args.text is not None:
        return args.text.encode("utf-8")
    if args.hex is not None:
        return parse_hex(args.hex)
    return args.file.read_bytes()


def password_from_args(value: str | None, prompt: str) -> str:
    if value is not None:
        return value
    return getpass.getpass(prompt)


def cmd_inject(args: argparse.Namespace) -> int:
    payload = read_payload(args)
    password = password_from_args(args.password, "Password, blank for legacy unprotected payload: ")
    output_path = args.output or suggested_output_path(args.input)
    mode, final_output_path = embed_for_file(args.input, output_path, payload, password)
    print(f"Wrote: {final_output_path}")
    print(f"Mode: {mode}")
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    password = args.password or ""
    hex_value, text_value, mode = extract_from_file(args.input, password)
    print(f"Mode: {mode}")
    if args.format in {"text", "both"}:
        print(text_value)
    if args.format in {"hex", "both"}:
        if args.format == "both":
            print()
        print(hex_value)
    return 0


def cmd_encrypt_text(args: argparse.Namespace) -> int:
    payload = read_payload(args)
    password = password_from_args(args.password, "Password: ")
    print(encrypt_payload_to_text(payload, password))
    return 0


def cmd_decrypt_text(args: argparse.Namespace) -> int:
    password = password_from_args(args.password, "Password: ")
    hex_value, text_value = decrypt_text_input(args.value, password)
    if args.format in {"text", "both"}:
        print(text_value)
    if args.format in {"hex", "both"}:
        if args.format == "both":
            print()
        print(hex_value)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="greynoc-stego",
        description="GreyNOC Stego command-line tools for Linux and other shells.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    inject_parser = subparsers.add_parser("inject", help="Hide a payload in an image, PDF, video, or file.")
    inject_parser.add_argument("input", type=Path, help="Carrier file to encode.")
    inject_parser.add_argument("-o", "--output", type=Path, help="Output path. Defaults beside the input file.")
    inject_parser.add_argument("--password", help="Password for protected payloads. Empty means legacy unprotected.")
    inject_parser.add_argument("--text", help="UTF-8 text payload.")
    inject_parser.add_argument("--hex", help="Hex payload.")
    inject_parser.add_argument("--file", type=Path, help="File whose bytes become the payload.")
    inject_parser.set_defaults(func=cmd_inject)

    extract_parser = subparsers.add_parser("extract", help="Extract a payload from a carrier file.")
    extract_parser.add_argument("input", type=Path, help="Encoded carrier file.")
    extract_parser.add_argument("--password", help="Password for protected payloads.")
    extract_parser.add_argument("--format", choices=("text", "hex", "both"), default="both")
    extract_parser.set_defaults(func=cmd_extract)

    encrypt_parser = subparsers.add_parser("encrypt-text", help="Create a GreyNOC encrypted text container.")
    encrypt_parser.add_argument("--password", help="Password for the encrypted text.")
    encrypt_parser.add_argument("--text", help="UTF-8 text payload.")
    encrypt_parser.add_argument("--hex", help="Hex payload.")
    encrypt_parser.add_argument("--file", type=Path, help="File whose bytes become the payload.")
    encrypt_parser.set_defaults(func=cmd_encrypt_text)

    decrypt_parser = subparsers.add_parser("decrypt-text", help="Decrypt a GreyNOC encrypted text container.")
    decrypt_parser.add_argument("value", help="GreyNOC text, base64, or hex encrypted container.")
    decrypt_parser.add_argument("--password", help="Password for the encrypted text.")
    decrypt_parser.add_argument("--format", choices=("text", "hex", "both"), default="both")
    decrypt_parser.set_defaults(func=cmd_decrypt_text)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
