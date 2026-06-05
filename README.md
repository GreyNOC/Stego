# GreyNOC Stego Studio

Steganography toolkit for hiding encrypted payloads inside image, PDF, and video carriers.

- **Desktop app** (`greynoc_stego_extractor_app.pyw`) — Tkinter UI for inject / extract / decrypt-text flows on Windows.
- **CLI** (`greynoc_stego_cli.py` plus the POSIX `greynoc-stego` launcher) — same operations from a shell on Linux or macOS.

## What it does

- **Inject:** embed an arbitrary byte payload (UTF-8 text, hex, or a file) into a carrier. Images use a PNG pixel-LSB encoding; PDFs and videos use a length-prefixed trailer.
- **Extract:** recover the payload from a previously injected carrier.
- **Encrypt-text / Decrypt-text:** produce or read a portable `GNOCENC1:` armored container without a carrier file.

Password-protected payloads use **AES-256-GCM** (authenticated) with a **PBKDF2-HMAC-SHA256** key derived from the password (200,000 iterations, 16-byte random salt, 12-byte random nonce). Wrong passwords and any modification of the ciphertext fail the GCM tag check and surface as `Password is wrong or payload was modified.`

## Supported carrier formats

- **Images (PNG-output pixel-LSB):** PNG, JPG/JPEG, BMP, GIF, TIFF, WebP, ICO, TGA, PPM/PGM/PBM/PNM, DIB, AVIF (input only; output is always re-encoded as PNG).
- **PDF:** `.pdf` via trailer carrier.
- **Video:** `.mp4`, `.mov`, `.avi`, `.mkv`, `.webm`, `.wmv`, `.m4v`, `.mpg`, `.mpeg`, `.3gp` via trailer carrier.

### Safety limits

- Maximum source file size: **512 MB**
- Maximum payload size: **5 MB**
- Maximum image pixels: **50,000,000** (bound to Pillow's decompression-bomb guard at module load)
- Maximum image stego ratio: **25%** of pixel capacity

Images that exceed the pixel cap, are corrupted, or are not a recognised image format are rejected with a clean error rather than a stack trace.

## Install

```sh
python -m pip install -r requirements.txt
```

For development and security tooling:

```sh
python -m pip install -r requirements-dev.txt
```

## Run

Desktop (Windows):

```sh
python greynoc_stego_extractor_app.pyw
```

CLI:

```sh
# Inject a UTF-8 message into a PNG
python greynoc_stego_cli.py inject input.png --text "secret" --password "pw" --output out.png

# Extract from a carrier
python greynoc_stego_cli.py extract out.png --password "pw" --format text

# Create / read a portable encrypted-text container
python greynoc_stego_cli.py encrypt-text --password "pw" --text "secret"
python greynoc_stego_cli.py decrypt-text "GNOCENC1:..." --password "pw" --format text
```

POSIX shell:

```sh
./greynoc-stego inject input.png --text "secret" --password "pw" --output out.png
./greynoc-stego extract out.png --password "pw" --format text
```

## Test

```sh
python -m unittest discover -v -s . -p "test_*.py"
```

CI also runs `pip-audit` and `python -m compileall .` on every push and pull request via `.github/workflows/security.yml`.

## Security notes

- **Passwords are never logged.** Status messages report only payload byte counts and operation modes, never the password or plaintext.
- **`--password` on the CLI is visible to other users on the host** via process listings (`ps auxe`, `/proc/<pid>/cmdline`, Windows Task Manager command-line column). On shared hosts, omit `--password` and let the CLI prompt you with `getpass` instead. The desktop app reads passwords from a masked `Entry` field, so it is not subject to this exposure.
- **Debug logging is opt-in.** The desktop app no longer writes `stego_debug.log` by default. Set `GREYNOC_DEBUG=1` (or `true`, `yes`, `on`) in the environment if you need to capture tracebacks for a bug report — then delete the log when done. Any other value, including unset, keeps logging off.
- **Authenticated decryption.** GCM tag verification happens before plaintext is returned, so a tampered carrier or wrong password fails fast without leaking partial decryption output.
- **Use unique, strong passwords.** Reusing the same password across carriers does not weaken any single payload (each gets its own random salt and nonce), but a compromised password compromises every carrier protected by it. There is no recovery if you forget the password.
- **Do not paste decrypted plaintext, hex output, or carrier files into bug reports or public issues.** Reproduce with throw-away test data instead — see [SECURITY.md](SECURITY.md).

## Project layout

```
stego_core.py        AES-GCM + PBKDF2, image-open helper, bit packing
stego_carriers.py    PNG-LSB and trailer carriers for images / PDF / video
stego_constants.py   Magic bytes, format sizes, safety caps
stego_hex_tool.py    Standalone legacy hex-payload utility
greynoc_stego_extractor_app.pyw   Tkinter desktop app
greynoc_stego_cli.py / greynoc-stego   Cross-platform CLI
test_stego_regression.py   Unit / regression / authentication tests
```

## License and reporting

See [SECURITY.md](SECURITY.md) for vulnerability disclosure.
