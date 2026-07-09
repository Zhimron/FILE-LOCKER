# Python File Locker

This project locks files, images, videos, and folders by encrypting them with authenticated encryption. After locking, the original item is removed and the `.locked` file cannot be opened normally by image viewers, video players, or File Explorer.

New locked files use the v2 format:

- Argon2id memory-hard password derivation.
- AES-256-GCM by default, with optional ChaCha20-Poly1305.
- Encrypted metadata, including original filename and timestamps.
- Optional password + key-file authentication.
- Optional compression before encryption.
- Encrypted SHA-256 footer verification before restored files are written into place.
- Legacy v1 `.locked` files can still be opened, unlocked, and migrated.

## Run From Source

```powershell
py -m pip install -r requirements.txt
```

Start the command-line menu:

```powershell
py main.py
```

Start the desktop app:

```powershell
py locker_app.py
```

## Build An App For Another Windows System

Create a standalone `.exe` and a shareable `.zip`:

```powershell
powershell -ExecutionPolicy Bypass -File .\build_app.ps1
```

After it finishes, send this file to the other computer:

```text
dist\PythonFileLocker-Windows.zip
```

On the other computer, unzip it and run:

```text
PythonFileLocker.exe
```

The other computer does not need Python installed.

## Commands

Lock a file:

```powershell
py main.py lock "D:\Photos\image.jpg" --password "use at least twelve chars"
```

Lock a folder:

```powershell
py main.py lock "D:\Videos" --password "use at least twelve chars"
```

Lock with a key file, compression, and ChaCha20-Poly1305:

```powershell
py main.py lock "D:\Videos\clip.mp4" --password "use at least twelve chars" --key-file "D:\keys\locker.key" --compress --cipher chacha20-poly1305
```

Open or play a locked item without permanently unlocking it:

```powershell
py main.py open "D:\Photos\image.jpg.locked"
```

Restore a locked item permanently:

```powershell
py main.py unlock "D:\Photos\image.jpg.locked"
```

Show locked file information:

```powershell
py main.py info "D:\Photos\image.jpg.locked"
```

Migrate an old v1 locked file to the current v2 format:

```powershell
py main.py migrate "D:\Photos\old-image.jpg.locked" --password "use at least twelve chars"
```

## Important notes

- Remember your password. The project cannot recover it.
- New passwords must be at least 12 characters by default. You can tune policy with `--min-password-length`, `--require-upper`, `--require-lower`, `--require-digit`, and `--require-symbol`.
- If you use `--key-file`, both the password and the same key file are required to open or unlock the item.
- Locking removes the original file or folder only after encryption succeeds.
- The `open` command decrypts to a temporary folder, launches the default app, then deletes the temporary copy after you press Enter.
- `--secure-delete` performs a best-effort overwrite before removing original files. This is not reliable on SSDs, journaling filesystems, cloud sync folders, snapshots, backups, or drives with wear leveling.
- Legacy v1 files used PBKDF2 and visible metadata. Use `migrate` to rewrite them with encrypted v2 metadata and Argon2id.
