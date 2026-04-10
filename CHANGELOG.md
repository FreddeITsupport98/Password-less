# Changelog
## Unreleased
### 2026-04-10 19:53:23Z
- Improved `gdebi-gtk` pkexec display-environment patching to support multiple unpatched argument layouts instead of a single strict block match.
- Added best-effort journal-based crash-signature detection for recent GDebi/pkexec GUI failures before evaluating patch application.
- Updated post-install syntax verification for `GDebiGtk.py` to run under `sudo`, avoiding false failures caused by root-owned Python bytecode cache paths.
### 2026-04-10 19:45:36Z
- Added smart detection for recent `polkit-agent-helper-1` permission failures using current-boot journal scanning.
- Added automatic ownership/mode repair for polkit helper binaries in common locations, enforcing `root:root` and `4755` when incorrect.
- Added a mount-options warning when `/` is `nosuid`, since that can still break setuid-based polkit helper behavior even after permission repair.
### 2026-04-04 19:37:39Z
- Added conditional auto-detection and auto-patching for the known `gdebi-gtk` pkexec display-environment crash path.
- Added safe guardrails for the patch flow: skip when already patched, skip on unsupported file layout, keep `.orig` backup, and register backup in the uninstall/restore manifest.
