#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C
export LANG=C

log() { printf '%s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }

can_system_accept_empty_passwords() {
  # Heuristic check whether the PAM stack appears to allow empty passwords
  # via pam_unix.so with the "nullok" option.
  #
  # This does *not* guarantee a specific login path will accept an empty
  # password, but if we see no evidence of nullok at all, then running
  # "passwd -d" is much more likely to result in a locked / unusable
  # account instead of a truly passwordless one.

  # If pam_unix.so is only configured with nullok_secure, treat that as
  # effectively "no" for our purposes (it's typically limited to very
  # restricted TTYs).
  if grep -rEq '^[[:space:]]*auth.*pam_unix\.so.*nullok_secure' /etc/pam.d 2>/dev/null; then
    warn "[pam-nullok] Found pam_unix.so with nullok_secure in /etc/pam.d; treating system as NOT safe for empty passwords."
    return 1
  fi

  # Look for a pam_unix.so auth line with "nullok" (but not nullok_secure).
  local first_match
  first_match=$(grep -rEn '^[[:space:]]*auth.*pam_unix\\.so.*nullok(([^_[:alnum:]]|$))' /etc/pam.d 2>/dev/null | head -n1 || true)
  if [[ -n "$first_match" ]]; then
    log "[pam-nullok] Detected pam_unix.so with nullok on auth line: $first_match"
    return 0
  fi

  log "[pam-nullok] No pam_unix.so auth line with nullok found under /etc/pam.d; treating system as NOT safe for empty passwords."
  return 1
}

verify_pam_nullok_status() {
  log "[pam-nullok] Inspecting /etc/pam.d for pam_unix.so nullok / nullok_secure..."

  if grep -rEn '^[[:space:]]*auth.*pam_unix\.so.*nullok_secure' /etc/pam.d 2>/dev/null; then
    warn "[pam-nullok] Above lines show pam_unix.so with nullok_secure (treated as NOT safe for empty passwords)."
  else
    log "[pam-nullok] No pam_unix.so auth line with nullok_secure found."
  fi

  if grep -rEn '^[[:space:]]*auth.*pam_unix\.so.*nullok(([^_[:alnum:]]|$))' /etc/pam.d 2>/dev/null; then
    log "[pam-nullok] Above lines show pam_unix.so auth entries with nullok (without nullok_secure)."
  else
    log "[pam-nullok] No pam_unix.so auth line with bare nullok found."
  fi

  if can_system_accept_empty_passwords; then
    log "[pam-nullok] RESULT: can_system_accept_empty_passwords() -> YES (system appears willing to accept empty passwords via pam_unix nullok)."
    exit 0
  else
    log "[pam-nullok] RESULT: can_system_accept_empty_passwords() -> NO (system does NOT appear safe for empty passwords)."
    exit 1
  fi
}

verify_pam_nullok_status
