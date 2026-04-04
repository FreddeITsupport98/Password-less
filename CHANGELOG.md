# Changelog
## Unreleased
### 2026-04-04 19:37:39Z
- Added conditional auto-detection and auto-patching for the known `gdebi-gtk` pkexec display-environment crash path.
- Added safe guardrails for the patch flow: skip when already patched, skip on unsupported file layout, keep `.orig` backup, and register backup in the uninstall/restore manifest.
