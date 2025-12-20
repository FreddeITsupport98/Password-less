# Password-less

Opinionated, **idempotent** helper script to enable passwordless `sudo` (and optionally polkit) for a single user on Linux.

This repository provides:

- `setup-passwordless-fb.sh` – a robust helper script that:
  - Configures **passwordless sudo** for a single user via `/etc/sudoers.d/…`
  - Optionally also configures **polkit** to always approve actions for that user
  - Can also ensure `/etc/sudoers` itself contains a `NOPASSWD` entry for the user
  - Is **safe** by design: uses `visudo` for syntax validation and makes backups before replacing system files
  - Is **idempotent**: re-running the script does **not** keep appending duplicate lines

## ⚠️ Security Warning

This script gives the target user essentially **root-equivalent power without any password prompt**.

- The target user can run **any command** as root with `sudo` without being asked for a password.
- If polkit configuration is enabled (default), that user will also get **automatic approval** for polkit-controlled actions (e.g. graphical administrative actions).

You should:

- Only use this on **systems you control** and fully trust the target user.
- Understand the implications for **security, auditing, and multi-user setups**.
- Prefer using this on **personal machines**, labs, VMs, or development environments, not shared production systems.

Use at your own risk.

---

## Features

- Works with common Linux distros (supports `apt`, `dnf`, `yum`, `pacman`, `zypper`, `apk`)
- Detects the **target user** automatically (the user running the script), or allows `--user USER`
- Configures:
  - `/etc/sudoers.d/<user>-passwordless` with:
    - `<user> ALL=(ALL:ALL) NOPASSWD: ALL`
    - `Defaults:<user> !authenticate`
  - (Optionally) `/etc/sudoers` itself to include the same `NOPASSWD` line
  - (Optionally) a polkit rule in `/etc/polkit-1/rules.d/00-allow-<user>-everything.rules`
- Idempotent:
  - Checks if config already matches the desired state before writing
  - Avoids **duplicating** lines or re-appending the same comment blocks
- Safety:
  - Uses `visudo` to validate **temporary files** before installing them
  - Backs up existing files with timestamped `.bak.<timestamp>` suffix when overwriting (only when `--force` is used)
  - Refuses to do unsafe things by default (e.g. doesn’t overwrite existing config unless you explicitly ask it to)

---

## Requirements

- A Linux system with:
  - `sudo` installed and available
  - A functional `visudo` binary
- A user account with:
  - Existing `sudo` rights (can run `sudo` with password at least once)
- Optional (for polkit integration):
  - A polkit installation (`polkit` / `policykit-1`)
  - `pkcheck` / `pkaction` binaries

The script will:

- Detect and optionally install missing dependencies (if you allow it)
- Detect the package manager among:
  - `apt`, `dnf`, `yum`, `pacman`, `zypper`, `apk`

---

## Installation

Clone this repo, or just copy the script to somewhere in your home directory and make it executable:

```bash
git clone https://github.com/<your-username>/Password-less.git
cd Password-less
chmod +x setup-passwordless-fb.sh
```

> You can also rename `setup-passwordless-fb.sh` to something else; the name is not special except for logging/comments.

---

## Usage

Basic usage:

```bash
./setup-passwordless-fb.sh [--user USER] [--sudo-only] [--no-install] [--yes] [--force] [--dry-run]
```

### Options

- `--user USER`  
  Target username (must already exist).  
  If omitted, the script uses the user who is invoking the script:

  ```bash
  TARGET_USER = $(id -un)
  ```

- `--sudo-only`  
  Only configure **passwordless sudo**.  
  Skip polkit rule creation.

- `--no-install`  
  Do **not** attempt to install missing dependencies (e.g. `polkit`).  
  If dependencies are missing, the script will abort and ask you to install them yourself.

- `--yes`  
  Non-interactive mode. Assume “yes” to prompts where applicable.

- `--force`  
  Allow overwriting existing `/etc/sudoers.d` and polkit rule files for this user **and** `/etc/sudoers` (where relevant).  
  Before overwriting, the script creates a backup: e.g. `/etc/sudoers.bak.20250101-123456`.

- `--dry-run`  
  Show what would be done, **without** actually writing any files.  
  Useful to review changes before applying them.

- `--restore`  
  Restore the latest backups for `/etc/sudoers`, `/etc/sudoers.d/<user>-passwordless`, and `/etc/polkit-1/rules.d/00-allow-<user>-everything.rules` (if they exist).  
  Useful for rolling back changes made by this script.

- `--verify-only` / `--verify`  
  Run verification checks only: confirm that passwordless sudo works for the target user, and (if not using `--sudo-only`) run a best-effort polkit sanity check.  
  Makes no configuration changes.

- `-h`, `--help`  
  Print usage and exit.

---

## What the Script Actually Does

### 1. Sanity Checks

- Refuses to run as `root`:

  ```bash
  if [[ "$(id -u)" -eq 0 ]]; then
    die "Do not run as root. Run as the target user with sudo access."
  fi
  ```

- Determines `TARGET_USER`:
  - If `--user` is provided: validates that user exists (`getent passwd`).
  - Otherwise: `TARGET_USER="$(id -un)"`.
- Refuses to operate on `root` as target user:

  ```bash
  if [[ "$TARGET_USER" == "root" ]]; then
    die "Refusing to configure passwordless access for root."
  fi
  ```

- Ensures `sudo` is installed and available, then refreshes sudo credentials:

  ```bash
  sudo -v
  ```

### 2. Dependency Check and Install (Optional)

- Checks for `sudo` and, if polkit is not disabled by `--sudo-only`, checks presence of `pkcheck` or `pkaction` as a proxy for polkit.
- If dependencies are missing:
  - If `--no-install` is set: aborts with an error and tells you what to install.
  - Otherwise:
    - Detects package manager (`apt`, `dnf`, `yum`, `pacman`, `zypper`, `apk`).
    - Asks you for confirmation (unless `--yes` is set).
    - Installs required packages (e.g. `sudo`, `policykit-1`, `polkit`).

### 3. Configure `/etc/sudoers.d/<user>-passwordless`

- Creates a small sudoers snippet in a temp file, e.g.:

  ```text
  <user> ALL=(ALL:ALL) NOPASSWD: ALL
  Defaults:<user> !authenticate
  ```

- Validates this temp file with:

  ```bash
  sudo visudo -c -f "$SUDOERS_TMP"
  ```

- Compares with existing `/etc/sudoers.d/<user>-passwordless` (if any):
  - If identical, it logs “already configured” and **does not** overwrite.
  - If different, it backs up the old file (if `--force` is used) and installs the new one with correct permissions (`0440`, owned by `root:root`).

- After installation, it validates the **entire** sudoers configuration with:

  ```bash
  sudo visudo -c
  ```

### 4. Verify Passwordless `sudo`

- Runs a simple check as the target user:

  ```bash
  sudo -u "$TARGET_USER" -H bash -lc 'sudo -n true'
  ```

- If that command fails, the script aborts and tells you to inspect the files.

### 5. Ensure `/etc/sudoers` Itself Has `NOPASSWD` For the User

In addition to using `/etc/sudoers.d`, the script can ensure the main `/etc/sudoers` file contains a line:

```text
<TARGET_USER> ALL=(ALL:ALL) NOPASSWD: ALL
```

**How it does this safely:**

1. Copies `/etc/sudoers` to a temp file.
2. Checks if a matching `NOPASSWD` line already exists (supports small formatting differences):

   ```bash
   sudo grep -Eq "^${TARGET_USER}[[:space:]]+ALL=\(ALL(:ALL)?\)[[:space:]]+NOPASSWD:?[[:space:]]+ALL" "$tmp"
   ```

3. Also checks for the marker comment from a previous run, to avoid re-adding the same block:

   ```bash
   # Added by <script-name> for passwordless sudo for <user>
   ```

4. If neither is present, it appends:

   ```text
   # Added by <script-name> for passwordless sudo for <user>
   <user> ALL=(ALL:ALL) NOPASSWD: ALL
   ```

5. Validates the modified sudoers (using `visudo -c -f <temp>`).
6. Backs up the original `/etc/sudoers` (if `--force` is used).
7. Installs the new validated file with strict permissions (`0440`, `root:root`).

This means you can re-run the script multiple times and **it won’t keep appending new lines**.

### 6. (Optional) Configure Polkit Rule

Unless `--sudo-only` is passed, the script attempts to create a polkit rule which grants the target user unconditional approval:

- Writes `/etc/polkit-1/rules.d/00-allow-<user>-everything.rules` similar to:

  ```javascript
  // Generated by setup-passwordless-fb.sh
  // WARNING: This approves all polkit actions for "<user>".
  polkit.addRule(function(action, subject) {
    if (subject.user === "<user>") {
      return polkit.Result.YES;
    }
  });
  ```

- Ensures the directory `/etc/polkit-1/rules.d` exists.
- Checks if the existing rule (if any) is identical; if so, it does not overwrite.
- Otherwise, backs up the old one (if `--force` is used) and installs the new rule.
- Attempts to restart polkit (best effort), using either `systemctl` or `service`.

### 7. Polkit Sanity Check (Best Effort)

If `pkcheck` is available, the script runs a small, non-fatal sanity check to ensure polkit is at least responsive.  
This doesn’t guarantee everything is configured, but can catch obvious issues.

---

## Typical Usage Examples

### A. Make the current user passwordless for sudo (sudo-only)

```bash
cd /path/to/Password-less
./setup-passwordless-fb.sh --sudo-only --yes --force
```

- Targets the current user (`id -un`).
- Configures `/etc/sudoers.d/<user>-passwordless`.
- Ensures `/etc/sudoers` itself has a `NOPASSWD` line for `<user>`.
- Skips polkit rules.
- Doesn’t ask interactive questions (`--yes`).
- Allows overwriting existing config with backups (`--force`).

### B. Make a specific user passwordless (with polkit)

```bash
./setup-passwordless-fb.sh --user alice --yes --force
```

- Targets `alice`.
- Configures both `sudoers.d` and `/etc/sudoers`.
- Also sets polkit rule for `alice`.
- Non-interactive and allows overwrites with backups.

### C. Preview Changes (Dry Run)

```bash
./setup-passwordless-fb.sh --user alice --sudo-only --dry-run
```

- Shows what would be written/changed.
- Does **not** actually write anything.

---

## Idempotency

You can run the script **multiple times** without it:

- Adding duplicate `NOPASSWD` lines to `/etc/sudoers`.
- Re-creating the same drop-in under `/etc/sudoers.d`.
- Re-installing identical polkit rule files.

It detects:

- Matching contents in `/etc/sudoers.d/<user>-passwordless`.
- Existing `NOPASSWD` lines in `/etc/sudoers` with minor format variations.
- Its own marker comment in `/etc/sudoers`.
- Identical contents in `/etc/polkit-1/rules.d/00-allow-<user>-everything.rules`.

When things are already configured, it logs info like:

```text
[info] Sudoers already configured (... is identical); skipping install.
[info] Main sudoers already has a NOPASSWD line for <user>; skipping.
[info] Polkit rule already configured (... is identical); skipping install/restart.
```

---

## Undo / Revert

To undo the configuration for a given user `<user>`:

1. Remove the sudoers drop-in:

   ```bash
   sudo rm -f /etc/sudoers.d/${user}-passwordless
   ```

2. Edit `/etc/sudoers` via `visudo` and remove the block:

   ```text
   # Added by setup-passwordless-fb.sh for passwordless sudo for <user>
   <user> ALL=(ALL:ALL) NOPASSWD: ALL
   ```

   Then validate via:

   ```bash
   sudo visudo -c
   ```

3. Remove the polkit rule (if created):

   ```bash
   sudo rm -f /etc/polkit-1/rules.d/00-allow-${user}-everything.rules
   ```

4. Optionally restart polkit or reboot.

If you used `--force`, backups like `"/etc/sudoers.bak.<timestamp>"` will exist.  ￼
You can restore them manually if needed:

```bash
sudo cp /etc/sudoers.bak.<timestamp> /etc/sudoers
sudo chown root:root /etc/sudoers
sudo chmod 0440 /etc/sudoers
sudo visudo -c
```

---

## Troubleshooting

### `sudo` still asks for a password

- Check that the drop-in file exists and is correct:

  ```bash
  sudo cat /etc/sudoers.d/${USER}-passwordless
  ```

- Check combined config validity:

  ```bash
  sudo visudo -c
  ```

- Make sure there are no conflicting entries for that user or group in `/etc/sudoers` or other files in `/etc/sudoers.d/`.

### `sudo` works, but polkit prompts still appear

- Ensure you did **not** run with `--sudo-only`.
- Check that the polkit rule file exists:

  ```bash
  sudo ls -l /etc/polkit-1/rules.d/
  sudo cat /etc/polkit-1/rules.d/00-allow-${USER}-everything.rules
  ```

- Some distros ship **polkit >= 124**, where JavaScript rules may be disabled.  
  In such cases, this script will warn you, but the rule might still not be honored.

### The script refuses to overwrite files

- If it says something like:

  ```text
  Refusing to overwrite existing /etc/sudoers.d/... Re-run with --force
  ```

  then re-run the script with `--force` to allow overwriting (with backups).

---

## Contributing

Contributions are welcome:

- Support for more distros or package managers
- Handling more polkit configurations (especially for newer polkit versions)
- Better detection of edge cases in sudoers layouts

Please open issues or pull requests on the repo.

---

## License

Choose and state your license here, for example:

- MIT
- GPLv3
- Apache-2.0
