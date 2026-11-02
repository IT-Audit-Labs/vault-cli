# vault-cli

Offline decryptor for [CisoView Vault](https://vault.itauditlabs.com) export packs.

When everything is down — Azure, Cloudflare, your identity provider — this tool decrypts your emergency export packs locally. No network required.

## Install

Download the latest binary from [Releases](https://github.com/IT-Audit-Labs/vault-cli/releases) for your platform:

| Platform | Binary |
|----------|--------|
| macOS (Apple Silicon) | `vault-cli-darwin-arm64` |
| macOS (Intel) | `vault-cli-darwin-amd64` |
| Windows | `vault-cli-windows-amd64.exe` |
| Linux | `vault-cli-linux-amd64` |

Or build from source:

```bash
go install github.com/IT-Audit-Labs/vault-cli@latest
```

## Usage

```bash
# Decrypt an export pack (prompts for passphrase)
vault-cli decrypt export-2026-04-23.zip.enc

# Decrypt to a specific directory
vault-cli decrypt export-2026-04-23.zip.enc -o ./recovery/

# Print version
vault-cli version
```

The passphrase is the one you set when creating the export pack in the Vault UI. It is never stored anywhere — if you lose it, the export cannot be decrypted.

## How It Works

1. Reads the encrypted `.enc` file
2. Prompts for your passphrase (hidden input, no echo)
3. Derives the decryption key using **Argon2id** (m=19456, t=3, p=1)
4. Decrypts with **AES-256-GCM**
5. Extracts the ZIP contents to the output directory

## Wire Format

```
salt(16 bytes) | iv(12 bytes) | ciphertext(AES-256-GCM)
```

- Salt: 16 random bytes for Argon2id
- IV: 12 random bytes for AES-GCM
- Ciphertext: AES-256-GCM encrypted ZIP with 16-byte auth tag appended

## Security

- Argon2id parameters are hardcoded to match the Vault server exactly
- Passphrase is read from terminal with echo disabled
- ZIP extraction prevents path traversal (zip slip protection)
- Per-file extraction limit: 100MB (zip bomb protection)
- No network calls — fully offline

## Build from Source

```bash
git clone https://github.com/IT-Audit-Labs/vault-cli.git
cd vault-cli
go test ./...
go build -o vault-cli .
```

### Cross-compile

```bash
GOOS=darwin  GOARCH=arm64 go build -o dist/vault-cli-darwin-arm64 .
GOOS=darwin  GOARCH=amd64 go build -o dist/vault-cli-darwin-amd64 .
GOOS=linux   GOARCH=amd64 go build -o dist/vault-cli-linux-amd64 .
GOOS=windows GOARCH=amd64 go build -o dist/vault-cli-windows-amd64.exe .
```

## License

Proprietary — IT Audit Labs. Distributed to CisoView Vault customers.

### Dependency verification

Build with Go 1.26.10 or newer. Before release, run `go test -race ./...`,
`go vet ./...`, `go mod verify`, and
`go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...`.
The fixed Argon2id compatibility vector was captured with the previous dependency
version and verified unchanged after updating; cipher parameters remain unchanged. ZIP destination checks now validate local
paths and use rooted filesystem operations, so the default output directory (`.`) accepts valid files while parent
traversal remains rejected. A synthetic encrypted ZIP is recovered through the
actual CLI in tests; wrong passphrases must leave no output. The remaining module-level OpenPGP advisory is not in this
application's imported packages (it uses Argon2id, not OpenPGP).
Cross-compilation does not establish runtime acceptance on Windows or Linux.
Do not merge, publish binaries or release without maintainer approval.

ZIP extraction now uses one `os.Root` handle for directory creation and file
writes. Existing file/directory symlinks cannot redirect extraction outside the
selected output directory. Relative symlinks that remain inside are supported;
absolute symlinks are rejected even when they point inside. Recover into a clean
directory or use relative internal links. This protection does not isolate hard
links, bind mounts or device files, and does not change the non-ZIP raw-output
branch or the existing 100MB-per-entry handling.
