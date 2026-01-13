# Password-less

Opinionated, **idempotent** helper script to enable passwordless `sudo` (and optionally polkit) for a single user on Linux.

## Why passwordless sudo / su and what this script is for

This script exists for a very specific use case: a **single-user, personal or lab machine** where convenience matters more than strict isolation.

- I wanted a way to log into my normal account and have **full admin power immediately**, without constantly typing my password for every `sudo` or `su`.
- I also wanted this to be **repeatable and transparent**: instead of hand-editing `/etc/sudoers` or PAM files by trial and error on every new install, I can run one well-documented script.
- The script is designed to be **idempotent and self-checking**: it validates syntax with `visudo`, makes backups when overwriting, and avoids adding duplicate lines, so I can safely re-run it on my own systems.

Because of that, this project is **not** meant for multi-user servers, shared machines, or security-sensitive environments. It is explicitly an automation of "make this one user effectively root with no password prompts" for people (like me) who:

- Are comfortable accepting that **any compromise of that user account is a full system compromise**.
- Prefer fast, passwordless admin workflows on their own machines.
- Want the configuration to be auditable and reproducible instead of a pile of manual tweaks.

This repository provides:

- `setup-passwordless-fb.sh` – a robust helper script that:
  - Configures **passwordless sudo** for a single user via `/etc/sudoers.d/…`
  - Optionally also configures **polkit** to always approve actions for that user
  - Can also ensure `/etc/sudoers` itself contains a `NOPASSWD` entry for the user
  - (Best-effort) adjusts the **PAM `su` service** so that members of the `wheel` group can use `su` **without a password** on PAM-based Linux distros where a `su`/`su-l` service exists
  - Is **safe** by design: uses `visudo` for syntax validation and makes backups before replacing system files
  - Is **idempotent**: re-running the script does **not** keep appending duplicate lines or duplicating PAM `pam_wheel.so` entries

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
  The script will **only** add the user to groups that **actually exist** on the system (as returned by `getent group`). If you later install software that creates additional groups from this list and re-run the script, it will then add the user to those newly-present groups as well.
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
- **I am the original author of this script** and make **no guarantees** about its safety, correctness, fitness for a particular purpose, or suitability for your environment.  
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
  - `bash` available (e.g. `/bin/bash`); the script uses Bash-specific features and **must not** be run with `sh`, `dash`, or other non-Bash shells.
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
./setup-passwordless-fb.sh [--user USER] [--sudo-only] [--no-install] [--relax-mac] [--yes] [--force] [--dry-run] [--full-file-permissions] [--install-full-file-permissions-service] [--uninstall-full-file-permissions-service] [--all-groups] [--default-config]
```

> **Important:** This is a **Bash-only** script. Run it as `./setup-passwordless-fb.sh ...` or `bash setup-passwordless-fb.sh ...`. Do **not** run it with `sh`, `dash`, or `/bin/sh`, as that may cause errors like `unbound variable` or syntax errors.

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

- `--full-file-permissions`  
  **Nuclear option, experimental, NOT READY FOR NORMAL USE** and **ACL-only mode**: when you invoke the script with this flag (and not in `--restore`/`--verify`/`--install-...`/`--uninstall-...` modes), it skips the normal passwordless sudo/polkit/group/PAM configuration and runs **only** a recursive ACL grant equivalent to:

  ```bash
  setfacl -R -m u:<TARGET_USER>:rwx /
  ```

  Internally, the script now uses a `find` pipeline that **skips** several sensitive trees to reduce the chance of breaking core services:
  - Pseudo-filesystems: `/proc`, `/sys`, `/dev`, `/run`, `/boot/efi`, `/snap`  
  - Network stacks (best-effort, cross-distro):  
    - NetworkManager: `/etc/NetworkManager`, `/var/lib/NetworkManager`, `/usr/lib/NetworkManager`  
    - systemd-networkd: `/etc/systemd/network`, `/var/lib/systemd/network`  
    - connman: `/etc/connman`, `/var/lib/connman`  
    - wpa_supplicant: `/etc/wpa_supplicant`, `/var/lib/wpa_supplicant`  
    - wicked (SUSE): `/etc/wicked`, `/var/lib/wicked`

  Even with these exclusions, this feature is **experimental** and very likely to **permanently break** parts of your system (for example: networking, display manager, container runtimes, or system services whose permissions assumptions are violated by the ACLs). You should expect to need a **full reinstall or offline repair** after serious experimentation with this flag.

  The current implementation wraps the ACL pass in **extra confirmations**, logs detailed progress using `pv` (including an item count and approximate items/sec), and prints a concise summary at the end. A small sample of distinct `setfacl` errors (e.g. read-only filesystems, unsupported ACLs) is shown at the end so you can see what failed **without** being flooded by thousands of lines.  
  This mode is still **work in progress** and exists primarily for my own experimentation; treat it as an opt-in "I am trying to break my system on purpose" tool, not a supported configuration step.

- `--install-full-file-permissions-service`  
  Install a **systemd service + timer** (`passwordless-fb-fullacl.service` / `passwordless-fb-fullacl.timer`) that periodically re-applies `--full-file-permissions` in the background.  
  When you invoke the script with *only* this flag (no other modes like `--full-file-permissions`, `--restore`, `--verify`, etc.), it runs in a **"installer-only"** mode:
  - Asks for confirmation once.  
  - Writes/updates `/etc/passwordless-fb-fullacl.conf` (described in detail below).  
  - Generates/installs the systemd service + timer units.  
  - Runs `systemctl daemon-reload` and `systemctl enable --now passwordless-fb-fullacl.timer`.  
  - Exits without touching sudoers, polkit, groups, or anything else.

- `--uninstall-full-file-permissions-service`  
  Uninstall the periodic full-ACL reapply service/timer.  
  When used by itself, this also runs in an **exclusive uninstaller** mode:
  - Shows a confirmation prompt.  
  - Disables and stops `passwordless-fb-fullacl.timer` if it exists.  
  - Removes `passwordless-fb-fullacl.service`, `passwordless-fb-fullacl.timer`, and `/etc/passwordless-fb-fullacl.conf` (if present).  
  - Runs `systemctl daemon-reload`.  
  - Exits without modifying sudoers, polkit, or other configuration.

- `--default-config`  
  Reset `/etc/passwordless-fb-fullacl.conf` back to its **default template** and exit without touching sudoers, polkit, groups, or systemd units.  
  - Sets `ACL_TARGET_USER` to the current `TARGET_USER` (or `id -un` if unset).  
  - Sets `ACL_EXTRA_ARGS="--sudo-only --no-install --yes"`.  
  - Sets `ACL_ONCALENDAR="daily"`.  
  - Respects `--dry-run` (prints what it would do instead of writing).  
  - Also accepts the misspelled alias `--defualt-config` for convenience.

- `--all-groups`  
  **Extremely dangerous**: enumerate **every group** on the system via `getent group` and add the target user to all of them (except those they are already a member of).  
  This effectively removes almost all group-based isolation between the user and system services, daemons, and device nodes.  
  Use this only if you fully understand that it turns the user into a "member of everything" and are prepared to reinstall the system if something breaks.

- `--verify-pam-nullok`  
-  Historical option name, now wired to a **combined PAM + SSH empty-password audit** that **makes no changes**. It will:
-  - Scan `/etc/pam.d` for `auth` lines using `pam_unix` / `pam_unix.so` and detect:
-    - **bare `nullok` without `nullok_secure`** (local auth stacks that truly accept empty passwords), and
-    - `nullok_secure` (TTY-only empty passwords, e.g. console login).
-  - Inspect the effective SSH server configuration (preferring `sshd -T` when available, with a text fallback) to see whether `PermitEmptyPasswords yes` is active anywhere.
-  - Print a concise summary:
-    - `PAM Status: ...` (SAFE or RISK),
-    - `SSH Status: ...` (SAFE or RISK), and
-    - a final CRITICAL/WARNING/RESULT line explaining whether empty passwords are possible **locally**, **remotely**, or both.
-
-  This is the safest way to see whether your system’s overall auth stack (both PAM and SSH) could meaningfully honor an empty Unix password before you consider changing any passwords yourself.

- `--root-unlock`  
  **Extremely dangerous, KDE-focused, experimental**: run the script in a **standalone** "root desktop unlock" mode that tweaks only the **root** account, and then exits without touching normal passwordless sudo / polkit for other users. In this mode the script will:
  - Ensure the `root` account is a member of several desktop / device groups (`audio`, `video`, `input`, `render`, `tty`, etc.) so a root GUI session can see ALSA / PipeWire devices.  
  - Adjust `/etc/pulse/client.conf` so `autospawn = yes` and `allow-autospawn-for-root = yes`, and optionally unmute ALSA mixer channels using `amixer`, then persist ALSA volume with `alsactl store`.  
  - Bridge **root audio** to your regular desktop user’s PipeWire / PulseAudio server by exporting `PULSE_SERVER=unix:/run/user/<UID>/pulse/native` (and matching `XDG_RUNTIME_DIR` / `DBUS_SESSION_BUS_ADDRESS`) into `/root/.bashrc` and `/root/.profile` (and `/root/.zshrc` if it exists). In practice, this makes apps started as root talk to the *non-root* user’s sound server.  
  - Optionally detect if the **root account itself is locked** in `/etc/shadow` (password field begins with `!` or `*`) and, **only if you explicitly confirm**, run `passwd -u root` to unlock it so GUI/TTY root logins are possible. This is never done silently and is skipped entirely in `--dry-run` mode.  
  - Write a small state file at `/etc/passwordless-fb-root-unlock.state` so the changes can later be reverted with `--root-unlock-restore`.
  
  This mode is primarily designed and tested for **KDE Plasma + PipeWire** on single-user desktops. GNOME, XFCE, Hyprland, and other environments are **not tested** and may behave differently or break. Using `--root-unlock` implies you are comfortable running a full **root GUI session**, with all the risk that entails.

- `--root-unlock-restore`  
  Companion to `--root-unlock`: attempts to **undo** as many of the root desktop tweaks as possible using the state file and timestamped backups created by the unlock run. In particular it will:
  - Restore `/etc/pulse/client.conf` from the most recent `.bak.<timestamp>` backup (if present).  
  - Attempt to restore `/root/.config/pulse`, `/root/.config/pipewire`, and `/root/.local/state/wireplumber` from the latest `*.bak.<timestamp>` directories that `--root-unlock` moved aside.  
  - Restore the previous `linger` state for root (enable/disable), and the previous `systemctl` enable/active state for `pulseaudio.service`, *if* they were successfully recorded in the state file.  
  - Remove the `XDG_RUNTIME_DIR`, `DBUS_SESSION_BUS_ADDRESS`, and `PULSE_SERVER` exports (and their comments) from `/root/.bashrc`, `/root/.profile`, and `/root/.zshrc` if they were added by `--root-unlock`.  
  - Optionally remove root from any groups that `--root-unlock` recorded as newly added, returning root’s group membership as closely as possible to its prior state.
  
  Because this restore flow depends on the presence and correctness of `/etc/passwordless-fb-root-unlock.state` and backups from the unlock run, it is a **best-effort undo**, not a guarantee. You should still treat `--root-unlock` as a high-risk, hard-to-fully-revert operation.

#### Why `--all-groups` is especially dangerous

Adding the `--all-groups` flag to add your user to every group on the system is a classic case of **confused security boundaries**: it looks like a shortcut to "ultimate power", but it actually breaks how Linux separates services from users.

1. **You become the "victim" for service accounts**  
   Many daemons run under special accounts and groups (e.g. `www-data`, `nginx`, `mail`, `dbus`, `rpc`, etc.).  
   - If you join a web-server-related group and accidentally store files with group-write or group-read permissions, the web server may now be able to read or modify them.  
   - If that service is compromised, the attacker can pivot directly into your data, because you **bridged the gap** between a confined service and your personal files via group membership.

2. **The "nobody" / "nogroup" paradox**  
   Groups like `nobody` / `nogroup` are designed as **least-privilege sinks**. Some security checks treat them specially.  
   - Joining such groups can interact badly with mechanisms that expect only unprivileged, throwaway processes to be in them.  
   - You risk tripping logic that was never written with "a real interactive user in this group" in mind.

3. **Fighting the seat manager (audio/video and device groups)**  
   Modern Linux desktops use seat management (e.g. `systemd-logind`) to grant access to hardware devices (audio, video, input, GPUs, TTYs) dynamically to the **currently active session**.  
   - Hard-coding yourself into groups like `audio`, `video`, `render`, `kvm`, `tty`, `disk`, `tape`, etc. can confuse or override these mechanisms.  
   - This can lead to strange bugs such as other users on the same machine losing sound, display, or device access because your account "owns" those devices via group membership all the time.

4. **Unintended privilege-escalation backdoors**  
   Some groups are effectively **root aliases**:
   - `docker`, `lxd`, `libvirt` – can start privileged containers/VMs and break out; effectively root.
   - `shadow` – read access to password hashes.
   - `disk` – raw block device access (bypassing filesystem permissions entirely).
   - `kmem` – direct access to kernel memory on some systems.  
   By joining **every** group, you enable **all** of these escalation paths at once, plus many more subtle ones. This creates a permissions landscape that is extremely hard to audit or revert cleanly.

**Summary:**  
`--all-groups` is imprecise and noisy:

- It adds you to **dangerous groups** (which already gives you "root-alike" power).
- It also adds you to **service groups** (which weakens isolation without useful extra power).
- It pulls you into **legacy/system groups** where your presence may surprise or confuse both the OS and security tooling.

For most scenarios, a curated set of "supreme" groups (e.g. `root`, `disk`, `wheel`, `systemd-journal`, `network`, `video`, `audio`, `input`, `render`, `kvm`, `tty`, `tape`, `shadow`, `kmem`, `adm`) already yields near-total control while being somewhat more predictable and documented than `--all-groups`.

In addition, the script will (where a `su` PAM service is present – either directly in `/etc/pam.d/su` or `/etc/pam.d/su-l`, or via a vendor file in `/usr/lib/pam.d` that it copies into `/etc/pam.d`) adjust the PAM configuration so that users in the `wheel` group can run `su` **without a password** by adding the `trust` option to the `pam_wheel.so` line. This logic is designed to be **idempotent and cross‑distro friendly**:

- It first looks for an existing `pam_wheel.so` line and, if present, only adds `trust` (without duplicating the line).
- If no `pam_wheel.so` line exists, it inserts a single `auth     sufficient   pam_wheel.so use_uid trust group=wheel` line in a sensible place (typically after the `pam_rootok.so` auth line, or near the top of the file as a fallback).
- It only touches PAM configs when a `su`/`su-l` service file exists (either in `/etc/pam.d` or as a vendor file under `/usr/lib/pam.d`).

This makes `su` effectively passwordless for your admin user, on top of passwordless `sudo`, on most PAM-based Linux distributions where a `wheel` group is present.  
**Important:** this PAM change does **not** create or modify groups; it only changes how `su` authenticates users who are already members of `wheel`. On systems where `wheel` does not exist or is not used for admin access, you may need to adjust the PAM `group=` setting or create/assign the `wheel` group yourself.

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

Unless `--sudo-only` is passed, the script attempts to create a polkit rule which grants the target user unconditional approval. It also includes **tightened detection** for newer polkit versions where JavaScript rules may no longer be honored.

#### 6.1 Creating the rule

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

#### 6.2 Detecting when JS rules may be unsupported

Before writing or relying on the JS rule, the script:

- Uses `pkaction --version` to detect polkit versions **124+** (where upstream dropped JS rules).
- If a newer polkit is detected, it searches common rules directories such as:
  - `/etc/polkit-1/rules.d`
  - `/usr/share/polkit-1/rules.d`
  - `/usr/lib/polkit-1/rules.d`

  for `.rules` files that contain `polkit.addRule`. If any are found, it assumes JS rules are still supported by the distro.
- If **no** such JS rules are found, it marks JS rules as "maybe unsupported" and logs a warning. In this situation the script **does not** change your Unix password automatically. Instead, it advises you to:
-  - Run `--verify-pam-nullok` (or the standalone `pam-nullok-check.sh` helper) to see whether your PAM stack actually accepts empty passwords via `pam_unix nullok`.
-  - If, and only if, you fully understand the implications and your PAM stack is configured to honor empty passwords, you may choose to run `passwd -d <USER>` yourself to drop the local Unix password. This is always a **manual, explicit action**; the script will not run `passwd -d` for you.

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

### D. Install the periodic full-ACL systemd service only

If you want a background job that periodically re-applies `--full-file-permissions` for a user (for example after package updates or filesystem changes), you can install the **systemd service/timer** without running the rest of the setup:

```bash
./setup-passwordless-fb.sh --install-full-file-permissions-service
```

What this does:

- Prompts you with a clear warning that a periodic full-ACL job is being installed.
- Writes (or reuses) `/etc/passwordless-fb-fullacl.conf`, which controls the behavior of the timer + service. A freshly created default file looks like:

  ```ini
  # Environment for passwordless-fb-fullacl
  # User that should receive full-file-permissions ACLs.
  # Change this to a different user name if needed.
  ACL_TARGET_USER=<your-username>

  # Extra arguments passed to setup-passwordless-fb.sh when run from the service.
  # By default we avoid reinstalling anything and run non-interactively.
  ACL_EXTRA_ARGS="--sudo-only --no-install --yes"

  # How often to run the full-file-permissions service. This is copied directly
  # into the systemd timer's OnCalendar= setting. Examples:
  #   ACL_ONCALENDAR="daily"          # once per day (default)
  #   ACL_ONCALENDAR="hourly"         # every hour
  #   ACL_ONCALENDAR="Mon..Fri 02:00" # weekdays at 02:00
  ACL_ONCALENDAR="daily"
  ```

  - `ACL_TARGET_USER` – which user receives the ACLs. If unset, the installer resolves it to the invoking user and bakes that into the unit.
  - `ACL_EXTRA_ARGS` – extra arguments passed to the script when run from the service. If you remove this line, the installer safely defaults it back to `--sudo-only --no-install --yes` so the unit stays valid.
  - `ACL_ONCALENDAR` – systemd calendar expression controlling how often the job runs. If omitted, it falls back to `daily`.
- Creates `passwordless-fb-fullacl.service` that runs roughly:

  ```ini
  ExecStart=/usr/bin/env bash /path/to/setup-passwordless-fb.sh --user ACL_TARGET_USER --full-file-permissions ACL_EXTRA_ARGS
  ```

- Creates `passwordless-fb-fullacl.timer` that triggers the service according to `ACL_ONCALENDAR`.
- Reloads systemd units and immediately enables/starts the timer.

> The service uses the same `pv`-backed progress, runtime measurement, and ACL error sampling as the interactive `--full-file-permissions` run. It is still extremely dangerous and should only be used on machines where you fully accept the security and stability trade-offs.

### E. Uninstall the periodic full-ACL systemd service only

To remove the service/timer and its config without touching anything else:

```bash
./setup-passwordless-fb.sh --uninstall-full-file-permissions-service
```

This:

- Confirms with you interactively (unless `--yes` is also given).  
- Disables and stops the timer if it exists.  
- Deletes the service unit, timer unit, and `/etc/passwordless-fb-fullacl.conf` (if present).  
- Reloads systemd.

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

### PAM `nullok` vs `nullok_secure` and empty passwords

Modern Linux PAM stacks often control whether empty passwords are accepted via options on `pam_unix`:

- `nullok` – allows empty passwords for that auth stack (e.g. `system-auth`, `password-auth`).
- `nullok_secure` – allows empty passwords **only on secure TTYs** (e.g. local console), but not for GUI/SSH/other sessions.

This script uses a conservative heuristic:

- It considers the system to "accept empty passwords" **only** if it finds at least one `auth pam_unix(.so)` line that:
-  - Contains bare `nullok`, and
-  - Does **not** contain `nullok_secure` on the same line, and
-  - Is not commented out.
- The mere existence of `nullok_secure` in some other file (for example `/etc/pam.d/login`) does **not** cause a global failure; it is common to use `nullok_secure` for TTY logins while using bare `nullok` for other paths.

You can inspect this behavior in two ways:

- `./setup-passwordless-fb.sh --verify-pam-nullok` – runs the **unified PAM + SSH audit** embedded in the main script to:
-  - Print all relevant `pam_unix` lines in `/etc/pam.d` containing `nullok` or `nullok_secure`.
-  - Show a per-file summary of where **bare `nullok`** is present (empty passwords accepted) vs. where **`nullok_secure`** is present (TTY-only empty passwords).
-  - Inspect the effective SSH configuration (via `sshd -T` when possible, with a text fallback) to detect any `PermitEmptyPasswords yes` settings.
-  - Summarize results as `PAM Status`, `SSH Status`, and a final CRITICAL/WARNING/RESULT line.
-
- `sudo bash pam-nullok-check.sh` – standalone helper script with similar semantics focused primarily on PAM (with its own SSH awareness) that you can run independently of the full setup flow.

**Important:**

- The script no longer deletes Unix passwords automatically under any circumstances.  
- If you ever decide to remove your local password (e.g. `sudo passwd -d $USER`), you must:
-  - First use the tools above to confirm your PAM stack is truly configured to honor empty passwords in the contexts you care about.
-  - Then run `passwd -d` yourself, fully accepting the risk of lockout if your assessment is wrong.

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

When you run with `--full-file-permissions`, the script also:

- Detects and installs `pv` when needed (via your distro’s package manager) so that large ACL runs have a proper progress indicator.  
- Counts how many filesystem entries will be touched and prints a line such as:

  ```text
  [info] Found 234882 items. Starting ACL application with progress bar...
  ```

- Streams paths through `pv` with `-l` (line-based) and labels the stream `Applying ACLs`, so you see a live bar like:

  ```text
  Applying ACLs: [======>...]  45%  105,000 / 234,882  3.2k/s  00:35
  ```

- Measures runtime and prints a summary with an approximate throughput, e.g.:

  ```text
  [info] Successfully applied ACLs to approximately 234882 items in 42s (~5592 items/sec).
  ```

- Captures `setfacl` stderr into a temporary log, filters out the usual noisy lines (like operations on read-only or unsupported filesystems), and at the end prints **up to five unique error samples** such as:

  ```text
  [info] Sample of ACL errors (up to 5 unique messages):
  [acl-error] /sys/...: Operation not supported
  [acl-error] /run/...: Read-only file system
  ```

This gives you a clear sense of **how much** was processed, **how fast**, and **what kind of things failed**, without drowning you in raw error spam.

Because of the breadth and depth of this change, using `--full-file-permissions` is still **much more invasive** than simply granting passwordless sudo.

### Desktop notifications and progress UX for `--full-file-permissions`

On systems with a desktop session and `notify-send` available, the script also emits **desktop notifications** for full-ACL runs:

- When a `--full-file-permissions` run starts (either interactive or via the systemd service):
  - A notification such as: _"Applying recursive ACLs on / for <USER>. This may take a while and can affect many files."_
- When it finishes:
  - If it completed cleanly: _"ACL application on / for <USER> is complete. Full-file-permissions are now in effect."_
  - If there were errors: _"ACL application on / for <USER> finished with some errors. Check terminal output if you care about 100% coverage."_

The script best-effort targets the user’s graphical session (via the user’s D-Bus session bus) when running as root (e.g. from the systemd service). If no GUI or `notify-send` is available, these notifications are silently skipped.

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

If you find yourself needing this power repeatedly, consider pushing it into a **disposable VM** or container rather than your main OS, or at minimum using the **systemd timer** so you understand *when* ACLs are being refreshed instead of re-running the script manually in ad-hoc ways.

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


## Desktop Integration (KDE and PAM `su`)

In addition to sudoers and (optionally) polkit, the script makes a few desktop-related adjustments to align graphical tools with the passwordless setup.

### KDE `kdesu` / "Run as root" helper

On KDE/Plasma systems where `kwriteconfig5` is available and the desktop session is detected as KDE/Plasma, the script configures the `kdesu` helper to use `sudo` instead of `su`.

- This is done by writing to the `kdesurc` configuration using:
  - `kwriteconfig5 --file kdesurc --group super-user-command --key super-user-command sudo`
- Effect: graphical "Run as root" prompts will respect the same passwordless sudo configuration you have just set up, instead of asking for a separate `root` password.
- If `kwriteconfig5` is not present or the session is not KDE/Plasma, this step is skipped.

### PAM `su` integration for `wheel` users

As described earlier, the script also adjusts PAM configuration for `su`/`su-l` so that users in the `wheel` group can invoke `su` **without a password**, by adding the `trust` option to the `pam_wheel.so` line in a safe, idempotent way. This change only applies when a suitable PAM `su` service file exists and is copied into `/etc/pam.d` if necessary.

These integrations are optional and best-effort, but they help align **GUI tools** and the classic `su` command with the passwordless sudo configuration, so you don’t end up in a state where some tools recognize the passwordless setup and others still prompt unexpectedly.

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
