#!/usr/bin/env bash
set -euo pipefail

# Force stable locale for consistent parsing
export LC_ALL=C
export LANG=C

log()  { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }

# Recommend running as root so we can read all PAM/SSH configs.
if [[ $EUID -ne 0 ]]; then
  warn "This script should be run as root to ensure access to PAM and SSH configs."
fi

check_pam_nullok() {
  local pam_dir="/etc/pam.d"
  local found_nullok=0
  local nullok_files=()
  local secure_files=()

  log "Inspecting $pam_dir for pam_unix(.so) nullok / nullok_secure..."

  # Single-pass scan of all pam_unix auth lines. We consider the system to
  # "accept empty passwords" if we see at least one auth line that:
  #   - contains bare nullok, and
  #   - does NOT contain nullok_secure on the same line, and
  #   - is not commented out.
  while IFS=: read -r file line; do
    [[ -z "$line" ]] && continue

    # Ignore commented lines defensively.
    if [[ "$line" =~ ^[[:space:]]*# ]]; then
      continue
    fi

    # Track any use of nullok_secure (TTY-only empty passwords).
    if [[ "$line" =~ nullok_secure([^[:alnum:]_]|$) ]]; then
      warn "[pam-nullok] nullok_secure: $file: $line"
      secure_files+=("$file")
    fi

    # Track bare nullok without nullok_secure on the same line.
    if [[ "$line" =~ [[:space:]]nullok([^[:alnum:]_]|$) ]] && \
       [[ ! "$line" =~ nullok_secure([^[:alnum:]_]|$) ]]; then
      log "[pam-nullok] nullok:        $file: $line"
      nullok_files+=("$file")
      found_nullok=1
    fi
  done < <(grep -rE '^[[:space:]]*auth.*pam_unix(\.so)?' "$pam_dir" 2>/dev/null || true)

  if ((${#nullok_files[@]})); then
    log "[pam-nullok] SUMMARY: bare nullok (empty passwords accepted) seen in: $(IFS=,; echo "${nullok_files[*]}")"
  fi
  if ((${#secure_files[@]})); then
    warn "[pam-nullok] SUMMARY: nullok_secure (TTY-only empty passwords) seen in: $(IFS=,; echo "${secure_files[*]}")"
  fi

  if [[ "$found_nullok" -eq 1 ]]; then
    warn "[pam-nullok] PAM RISK: at least one auth pam_unix(.so) stack appears to accept empty passwords via bare nullok."
    return 1
  fi

  log "[pam-nullok] PAM SAFE: no auth pam_unix(.so) lines with bare nullok (without nullok_secure) were found. Empty passwords are likely rejected by PAM."
  return 0
}

check_sshd_empty_passwords() {
  # Best-effort inspection of sshd_config to see whether SSH would even
  # allow empty passwords. If PermitEmptyPasswords is explicitly set to
  # "yes" in any config snippet, we treat SSH as allowing empty passwords.
  local sshd_conf="/etc/ssh/sshd_config"
  local sshd_dir="/etc/ssh/sshd_config.d"
  local allows_empty=0

  if ! command -v sshd >/dev/null 2>&1 && [[ ! -f "$sshd_conf" && ! -d "$sshd_dir" ]]; then
    log "[ssh-nullok] OpenSSH server not detected; skipping SSH empty-password checks."
    return 0
  fi

  local line
  # Check main sshd_config
  if [[ -f "$sshd_conf" ]]; then
    while IFS= read -r line; do
      [[ "$line" =~ ^[[:space:]]*# ]] && continue
      if [[ "$line" =~ ^[[:space:]]*PermitEmptyPasswords[[:space:]]+yes([[:space:]]|$) ]]; then
        allows_empty=1
      fi
    done <"$sshd_conf"
  fi

  # Check any drop-in configs (Fedora and others often use these).
  if [[ -d "$sshd_dir" ]]; then
    local f
    for f in "$sshd_dir"/*.conf; do
      [[ -f "$f" ]] || continue
      while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        if [[ "$line" =~ ^[[:space:]]*PermitEmptyPasswords[[:space:]]+yes([[:space:]]|$) ]]; then
          allows_empty=1
        fi
      done <"$f"
    done
  fi

  if [[ "$allows_empty" -eq 1 ]]; then
    warn "[ssh-nullok] SSHD RISK: One or more sshd_config entries allow empty passwords (PermitEmptyPasswords yes)."
    return 1
  fi

  log "[ssh-nullok] SSHD SAFE: No explicit PermitEmptyPasswords yes found; SSH is unlikely to accept empty passwords."
  return 0
}

# Run the checks. Exit code semantics:
#   0 -> SAFE (no bare nullok in PAM, and SSH does not explicitly allow empty passwords)
#   1 -> RISK (PAM and/or SSH appear willing to accept empty passwords)
main() {
  local risk=0

  if ! check_pam_nullok; then
    risk=1
  fi
  if ! check_sshd_empty_passwords; then
    risk=1
  fi

  if [[ "$risk" -eq 1 ]]; then
    warn "[overall] RISK: At least one auth path (PAM and/or SSH) appears to accept empty passwords."
    return 1
  fi

  log "[overall] SAFE: Neither PAM nor SSH appear to accept empty passwords by default."
  return 0
}

if main; then
  exit 0
else
  exit 1
fi
