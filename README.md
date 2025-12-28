# Password-less

Opinionated, **idempotent** helper script to enable passwordless `sudo` (and optionally polkit) for a single user on Linux.

This repository provides:

- `setup-passwordless-fb.sh` – a robust helper script that:
  - Configures **passwordless sudo** for a single user via `/etc/sudoers.d/…`
  - Optionally also configures **polkit** to always approve actions for that user
  - Can also ensure `/etc/sudoers` itself contains a `NOPASSWD` entry for the user
  - Is **safe** by design: uses `visudo` for syntax validation and makes backups before replacing system files
  - Is **idempotent**: re-running the script does **not** keep appending duplicate lines

## ⚠️ Security Warnings & Disclaimer

**You must read this entire README (including all warnings and option descriptions) before running `setup-passwordless-fb.sh`. If you choose to run the script without fully understanding this document, you accept that any damage, data loss, or security compromise is entirely your responsibility.**

This script gives the target user essentially **root-equivalent power without any password prompt** and may also add them to highly privileged system groups (such as `root`, `disk`, `shadow`, and `kmem`).

- The target user can run **any command** as root with `sudo` without being asked for a password.
- If polkit configuration is enabled (default), that user will also get **automatic approval** for polkit-controlled actions (e.g. graphical administrative actions).
- If group membership is modified, the target user may gain **direct access to disks, kernel interfaces, and sensitive files (including password hashes)** even *without* `sudo`.

### You must assume:

- **Full system compromise** is possible if this user account is ever abused or compromised.
- Local malware running as that user can trivially escalate to **full root**.
- Traditional protections such as `sudo` password prompts and some polkit dialogs will no longer provide meaningful defense.

### High‑risk behaviors and options (read this first)

In addition to configuring passwordless sudo and (optionally) polkit, this script can:

- Add the target user to **highly privileged system groups** such as `root`, `disk`, `wheel`, `systemd-journal`, `network`, `video`, `audio`, `input`, `render`, `kvm`, `tty`, `tape`, `shadow`, `kmem`, and `adm`.  
  This can give the user **direct access to raw disks, password hashes, kernel interfaces and system configuration**, even **without** using `sudo`.
- Optionally **relax mandatory access controls (MAC)** when `--relax-mac` is used, by stopping AppArmor (if present) and attempting to switch SELinux to **permissive** mode.  
  This removes an important layer of defense on top of normal Unix permissions and sudo.
- Optionally configure polkit so that the user receives **automatic approval for all polkit actions** (no graphical confirmation dialogs).
- Optionally (with `--full-file-permissions`) run a recursive ACL change equivalent to:

  ```bash
  sudo setfacl -R -m u:<TARGET_USER>:rwx /
  ```

  This grants the target user **read/write/execute** permissions on almost everything under `/` that supports ACLs.  
  In practice this is a **filesystem-wide superuser** grant that is **more invasive and harder to undo than passwordless sudo itself**.

These options are **off by default**, but if you enable them you should assume that the machine is effectively **permanently and irreversibly weakened** from a security standpoint.  
Do **not** enable them on any machine where you care about multi‑user isolation, strong security boundaries, or reliable long‑term integrity.

### Recommended extra precautions

Before using this script, **read and understand** all of the following:

1. **Single-user, non-critical systems only**  
   Use this only on machines where you are the **sole user** and there is no untrusted local user. Avoid production servers or shared multi-user systems.

2. **Physical and account security**  
   - Use a strong login passphrase for the target account and full disk encryption where possible.  
   - Lock your screen when unattended.  
   - Do not reuse the same password on other systems/services.

3. **Network and remote access**  
   - Be extremely careful enabling SSH or other remote access for this user.  
   - If you must, use key-based auth, disable password login, and restrict who can connect (firewall, `AllowUsers`, etc.).

4. **Limit browser and untrusted software risk**  
   - Treat running a web browser, email client, or untrusted binaries under this account as if you are running them as **root**.  
   - Avoid executing random scripts from the internet. Review them first.

5. **Backups and recovery**  
   - Keep known-good backups of `/etc/sudoers`, `/etc/sudoers.d/`, and any polkit rules.  
   - Consider creating a second, more restricted admin account you can fall back to.

6. **Log out / reboot after changes**  
   - After group membership changes, log out and back in (or reboot) to ensure group changes take effect and test carefully.

### Legal / warranty disclaimer

- This script and documentation are provided **“as is”**, **without any warranty** of any kind, express or implied.  
- **I am not the original author of this script** and make **no guarantees** about its safety, correctness, fitness for a particular purpose, or suitability for your environment.  
- You are solely responsible for **reviewing the code**, understanding what it does, and deciding whether it is appropriate to run on your systems.  
- By using this script, **you accept all risk**, including but not limited to data loss, security breaches, service outages, and legal or policy violations.

If you do not fully understand or accept these risks, **do not run this script**.

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
./setup-passwordless-fb.sh [--user USER] [--sudo-only] [--no-install] [--relax-mac] [--yes] [--force] [--dry-run]
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

- `--relax-mac`  
  **Dangerous, optional**: best-effort attempt to relax Mandatory Access Control (MAC) systems:
  - Stop the AppArmor service at runtime (if present).  
  - Set SELinux to **permissive** at runtime (if present).  
  This does **not** change UIDs/groups/sudoers, but it removes important enforcement layers, making any existing privileges more powerful.  
  The script will still prompt you for confirmation unless `--yes` is also provided.  
  In `--verify` mode, `--relax-mac` does **not** relax anything, but the script will always print a **detailed MAC status report** (AppArmor present/active, SELinux mode).

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

# Password-less Setup Script

This repository contains `setup-passwordless-fb.sh`, a helper script for configuring passwordless sudo (and, optionally, polkit) for a single user on Linux systems.

## WARNING: Extremely dangerous `--full-file-permissions` option

The script includes an **opt-in** flag named `--full-file-permissions`. When enabled, and after additional confirmation, the script runs the following command for the chosen target user:

```bash
sudo setfacl -R -m u:<TARGET_USER>:rwx /
```

This means:

- It applies **recursive** (`-R`) POSIX ACL changes starting at the root directory `/`.
- It grants the target user explicit **read, write, and execute** (`rwx`) permissions on **every file and directory that is reachable from `/` and supports ACLs**.
- This ACL grant is **additive** – it does not replace the existing owner/group/mode bits – it layers an additional access rule on top. In effect, the chosen user becomes able to read/modify/delete/execute almost anything on the system, regardless of traditional Unix permissions.

Because of the breadth and depth of this change, using `--full-file-permissions` is **much more invasive** than simply granting passwordless sudo.

### Why this is more dangerous than passwordless sudo

Passwordless sudo is already equivalent to giving a user full administrative control over the machine: they can run arbitrary commands as root, change system configuration, install software, access most data, etc. That said, sudo-based elevation is:

- **Transient and explicit**: the user must run `sudo <command>`, which is at least a clear, explicit action.
- **Policy-aware**: changes can be logged and restricted via sudoers policies.
- **Relatively reversible**: you can remove or tighten sudoers configuration and immediately affect future sudo behavior.

In contrast, recursively applying ACLs on `/`:

- **Silently rewrites the access model of the entire filesystem**. Existing security assumptions based on Unix owner/group/mode bits become invalid in subtle ways.
- **Persists across sessions and configuration changes**. Even if you later remove passwordless sudo or revoke group memberships, the ACL entries will remain until they are explicitly removed.
- **Applies to everything under `/`** that supports ACLs, including:
  - System binaries and libraries (e.g. `/usr/bin`, `/lib`, `/usr/lib`)
  - Configuration files under `/etc`
  - User homes under `/home`
  - Application data under `/var` and `/opt`
  - Potentially mounted filesystems beneath `/` (depending on how ACLs are handled by the underlying filesystem and mount options)

Once this ACL has been applied, the target user can:

- Modify or delete system binaries and libraries, making integrity checking and debugging much more difficult.
- Read and alter configuration for services they would not normally have access to.
- Read other users’ data under `/home` (unless specifically protected by other mechanisms such as encryption or separate mounts without ACLs).
- Tamper with logs, databases, and caches under `/var`.
- Plant or modify code in locations that other users or system services trust.

From a security perspective, this effectively turns the chosen user into a **superuser in the filesystem sense**, which can be even more chaotic than traditional sudo-based access.

### Practical risks and consequences

Using `--full-file-permissions` introduces several classes of risk:

1. **Accidental data loss or corruption**
   - Any command that the target user runs (even without `sudo`) now has the ability to write into locations that would normally be protected.
   - Mis-typed commands, erroneous scripts, or poorly tested tools can unintentionally overwrite or delete critical system files.
   - Automated tools, editors, or IDEs may suddenly "helpfully" rewrite files under `/etc`, `/usr`, or `/var` that they could not touch before.

2. **Security boundary collapse**
   - Traditional Unix permissions, which separate system data from user data, no longer provide meaningful protection against the target user.
   - Multi-user environments become effectively single-trust-domain from the perspective of that user: they can read or change almost anything other users store in normal locations.
   - Any compromise of the target user account (e.g. stolen credentials, malware, or remote exploit) becomes instantly catastrophic: the attacker does not even need to leverage sudo; they already have direct filesystem-level control.

3. **Difficult recovery**
   - ACLs are stored as extended attributes, not visible in plain `ls -l` output. Debugging "why can this user access this file?" becomes more complex.
   - Undoing a recursive ACL change on `/` is non-trivial. In theory, you could attempt the inverse operation (e.g. `setfacl -R -x u:<TARGET_USER> /`), but:
     - You must be sure of the exact ACL entries you added.
     - Other ACL-based changes made later might be entangled with these entries.
     - Some filesystems or mounts may handle ACL inheritance in unexpected ways.
   - In many real-world scenarios, the safest recovery path after such a broad ACL change is a **full system reinstall or bare-metal restore**.

4. **Interference with system tools and security software**
   - Backup tools, intrusion detection systems, and integrity checkers might misbehave or produce noisy reports because permissions no longer match expected baselines.
   - Certain security-sensitive services assume that some directories are only writable by root or a dedicated service account. Granting a regular user `rwx` may circumvent these assumptions in ways that are hard to audit.

### When (if ever) you should consider using `--full-file-permissions`

This option exists primarily for **very narrow, specialized, and short-lived scenarios**, for example:

- Disposable test environments where the machine can be thrown away and rebuilt at any time.
- Highly controlled lab setups where you intentionally want to model a "filesystem-compromised" environment.
- Personal single-user systems where you fully understand the impact and you are comfortable with potentially reinstalling if something goes wrong.

Even in these cases, there are usually **better alternatives**, such as:

- Using virtual machines or containers, and giving yourself full control inside the isolated guest/container instead of on the host.
- Mounting specific directories with permissive settings or separate ACLs, instead of modifying the entire root filesystem.
- Relying on passwordless sudo alone, which is already powerful but does not rewrite ACLs on every file.

### How to use it (and why you probably shouldn’t)

If you still decide to enable it, the typical usage is:

```bash
./setup-passwordless-fb.sh --user <your-username> --full-file-permissions
```

The script will:

1. Detect and validate the target user.
2. Configure passwordless sudo (and polkit, unless `--sudo-only` is passed).
3. Prompt you with clear warnings about the dangers of `--full-file-permissions`.
4. Ask for explicit confirmation **again** before running `setfacl -R -m u:<TARGET_USER>:rwx /`.

To see what would happen **without** making changes, you should always first run:

```bash
./setup-passwordless-fb.sh --user <your-username> --full-file-permissions --dry-run
```

This prints the commands that would be executed, including the ACL modification, but does not actually change anything.

### Undoing `--full-file-permissions`

There is **no simple, guaranteed-safe one-liner** to fully undo the effects of recursively granting `u:<TARGET_USER>:rwx` on `/`:

- You can attempt to remove the ACL entry with a matching recursive command, for example:

  ```bash
  sudo setfacl -R -x u:<TARGET_USER> /
  ```

  However, this assumes that **all** ACL entries for that user were created by this script and that no other legitimate ACLs have been added later.
- Some filesystems, mount points, or system directories may have their own ACL policies, inheritance rules, or may not support ACLs in a uniform way, making the exact end state hard to reason about.

For systems where you care about integrity and correctness, the most reliable way to fully revert is usually:

1. Back up essential data.
2. Reinstall or re-image the OS.
3. Restore user data from a known-good backup.

Because of this, you should treat `--full-file-permissions` as a **"nuclear" option**: once used, you should assume the machine’s security posture is permanently altered.

### Summary

- `--full-file-permissions` is **not** required for passwordless sudo or everyday administrative convenience.
- It performs a sweeping ACL change that effectively gives the chosen user root-like filesystem access everywhere under `/`.
- This is **highly dangerous**, hard to audit, and difficult to fully undo.
- You should avoid this option in any environment where security, multi-user isolation, or long-term system stability matters.

If you are not absolutely certain you understand all of the above, **do not use `--full-file-permissions`**.


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
