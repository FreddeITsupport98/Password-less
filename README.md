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
