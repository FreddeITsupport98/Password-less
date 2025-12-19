#!/usr/bin/env bash
set -euo pipefail

# Passwordless sudo + polkit approval for a single user.
# WARNING: This grants root-equivalent power without authentication.
#
# Goals of this script:
# - Work across common distros (apt/dnf/pacman/zypper/apk)
# - Default to the current user, but allow targeting another existing user
# - Perform sanity checks + safe validation before writing system files
# - Avoid clobbering existing config unless explicitly forced

SCRIPT_NAME="$(basename "$0")"

usage() {
  cat <<'EOF'
Usage:
  setup-passwordless-fb.sh [--user USER] [--sudo-only] [--no-install] [--yes] [--force] [--dry-run]

Options:
  --user USER     Target USER (default: the invoking user running the script)
  --sudo-only     Only configure passwordless sudo (skip polkit)
  --no-install    Do not attempt to install missing dependencies
  --yes           Non-interactive: assume "yes" to prompts
  --force         Overwrite existing /etc/sudoers.d and polkit rule files for this user (backs up first)
  --dry-run       Print what would change, but do not write files
  -h, --help      Show this help

Notes:
  - Run as a normal user with sudo access (do NOT run as root).
  - Some distros ship polkit >= 124 where JavaScript rules are disabled/removed.
    In that case, this script will configure sudo but will only attempt polkit with a warning.
EOF
}

log() { printf '%s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

assume_yes=0
force=0
dry_run=0
sudo_only=0
no_install=0
TARGET_USER=""
POLKIT_TMP=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)
      [[ $# -ge 2 ]] || die "--user requires an argument"
      TARGET_USER="$2"
      shift 2
      ;;
    --sudo-only)
      sudo_only=1
      shift
      ;;
    --no-install)
      no_install=1
      shift
      ;;
    --yes)
      assume_yes=1
      shift
      ;;
    --force)
      force=1
      shift
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "Unknown argument: $1 (use --help)"
      ;;
  esac
done

confirm() {
  local prompt="$1"
  if [[ "$assume_yes" -eq 1 ]]; then
    return 0
  fi
  read -r -p "${prompt} [y/N]: " ans
  [[ "${ans}" == "y" || "${ans}" == "Y" ]]
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

files_identical_as_root() {
  # Compare two files, where either might require root to read.
  # Uses diff or cmp, whichever is available.
  local a="$1"
  local b="$2"

  if have_cmd diff; then
    sudo diff -q "$a" "$b" >/dev/null 2>&1
    return $?
  fi
  if have_cmd cmp; then
    sudo cmp -s "$a" "$b"
    return $?
  fi
  # If we can't compare, assume not identical so we fail safe.
  return 1
}

require_sudo() {
  have_cmd sudo || die "sudo not found. Install sudo and re-run (or run with --no-install after installing)."
  log "[sanity] Refreshing sudo timestamp (you may be prompted once)..."
  sudo -v
}

detect_pkg_mgr() {
  if have_cmd apt-get; then echo "apt"; return 0; fi
  if have_cmd dnf; then echo "dnf"; return 0; fi
  if have_cmd yum; then echo "yum"; return 0; fi
  if have_cmd pacman; then echo "pacman"; return 0; fi
  if have_cmd zypper; then echo "zypper"; return 0; fi
  if have_cmd apk; then echo "apk"; return 0; fi
  echo ""
}

install_deps_if_missing() {
  local missing=()

  # We cannot bootstrap sudo safely from a non-root context.
  if ! have_cmd sudo; then
    die "sudo not found. Install sudo (as root) and re-run this script as the target user."
  fi

  if [[ "$sudo_only" -eq 0 ]]; then
    # polkit tools are a decent proxy for polkit being present.
    (have_cmd pkcheck || have_cmd pkaction) || missing+=("polkit")
  fi

  if [[ "${#missing[@]}" -eq 0 ]]; then
    return 0
  fi

  if [[ "$no_install" -eq 1 ]]; then
    die "Missing dependencies: ${missing[*]}. Install them and re-run."
  fi

  local mgr
  mgr="$(detect_pkg_mgr)"
  [[ -n "$mgr" ]] || die "Missing dependencies: ${missing[*]}. Could not detect a supported package manager to install them."

  warn "Missing dependencies: ${missing[*]}"

  if ! confirm "Attempt to install missing dependencies via $mgr using sudo?"; then
    die "Aborted. Install dependencies manually and re-run."
  fi

  if [[ "$dry_run" -eq 1 ]]; then
    log "[dry-run] Would install via $mgr: ${missing[*]}"
    return 0
  fi

  case "$mgr" in
    apt)
      sudo apt-get update
      # Debian/Ubuntu package name is usually policykit-1.
      sudo apt-get install -y sudo policykit-1
      ;;
    dnf)
      sudo dnf install -y sudo polkit
      ;;
    yum)
      sudo yum install -y sudo polkit
      ;;
    pacman)
      sudo pacman -Sy --noconfirm sudo polkit
      ;;
    zypper)
      sudo zypper --non-interactive install sudo polkit
      ;;
    apk)
      sudo apk add sudo polkit
      ;;
    *)
      die "Unsupported package manager: $mgr"
      ;;
  esac
}

backup_if_exists() {
  local path="$1"
  if sudo test -e "$path"; then
    if [[ "$force" -ne 1 ]]; then
      die "Refusing to overwrite existing $path. Re-run with --force to overwrite (a backup will be created)."
    fi
    local ts
    ts="$(date +%Y%m%d-%H%M%S)"
    local bak="${path}.bak.${ts}"
    warn "Backing up existing $path -> $bak"
    if [[ "$dry_run" -eq 1 ]]; then
      log "[dry-run] Would backup $path to $bak"
    else
      sudo cp -a "$path" "$bak"
    fi
  fi
}

write_root_file() {
  local tmp="$1"
  local dest="$2"
  local mode="$3"

  backup_if_exists "$dest"

  if [[ "$dry_run" -eq 1 ]]; then
    log "[dry-run] Would install $dest (mode $mode)"
    return 0
  fi

  sudo install -o root -g root -m "$mode" "$tmp" "$dest"
}

find_visudo() {
  if have_cmd visudo; then
    command -v visudo
    return 0
  fi
  if [[ -x /usr/sbin/visudo ]]; then
    printf '%s\n' /usr/sbin/visudo
    return 0
  fi
  if [[ -x /sbin/visudo ]]; then
    printf '%s\n' /sbin/visudo
    return 0
  fi
  echo ""
}

js_escape_string() {
  # Escape backslashes and double quotes for inclusion in a JS "..." string.
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf '%s' "$s"
}

restart_polkit_best_effort() {
  # systemd is common but not universal.
  if have_cmd systemctl; then
    sudo systemctl restart polkit >/dev/null 2>&1 && return 0
    sudo systemctl restart polkit.service >/dev/null 2>&1 && return 0
  fi
  if have_cmd service; then
    sudo service polkit restart >/dev/null 2>&1 && return 0
  fi
  return 1
}

# --- Sanity checks ---
if [[ "$(id -u)" -eq 0 ]]; then
  die "Do not run as root. Run as the target user with sudo access."
fi

# Default target user is the current invoking user.
if [[ -z "$TARGET_USER" ]]; then
  TARGET_USER="$(id -un)"
fi

# Ensure target user exists.
getent passwd "$TARGET_USER" >/dev/null 2>&1 || die "Target user '$TARGET_USER' does not exist (getent passwd failed)."

# Hard stop if target is root.
if [[ "$TARGET_USER" == "root" ]]; then
  die "Refusing to configure passwordless access for root."
fi

install_deps_if_missing
require_sudo

VISUDO_BIN="$(find_visudo)"
[[ -n "$VISUDO_BIN" ]] || die "visudo not found. Install sudo/visudo and ensure it's available (often in /usr/sbin)."

log "[info] Target user: $TARGET_USER"

if [[ "$dry_run" -eq 0 ]]; then
  warn "This will grant '$TARGET_USER' root-equivalent access without a password."
  if ! confirm "Continue?"; then
    die "Aborted."
  fi
else
  warn "Dry run mode enabled; no changes will be written."
fi

# --- Configure sudoers drop-in ---
log "[1/3] Configuring passwordless sudo for $TARGET_USER..."
SUDOERS_TMP="$(mktemp)"
trap 'rm -f "$SUDOERS_TMP" "$POLKIT_TMP" 2>/dev/null || true' EXIT

cat >"$SUDOERS_TMP" <<EOF
${TARGET_USER} ALL=(ALL:ALL) NOPASSWD: ALL
Defaults:${TARGET_USER} !authenticate
EOF

SUDOERS_DEST="/etc/sudoers.d/${TARGET_USER}-passwordless"

sudoers_already_ok=0
if sudo test -e "$SUDOERS_DEST"; then
  if files_identical_as_root "$SUDOERS_TMP" "$SUDOERS_DEST"; then
    sudoers_already_ok=1
  fi
fi

# Validate syntax before installing.
# (If it's already installed and identical, we still validate the temp file to catch surprises.)
if [[ "$dry_run" -eq 1 ]]; then
  log "[dry-run] Would validate sudoers temp via: sudo $VISUDO_BIN -c -f $SUDOERS_TMP"
else
  sudo "$VISUDO_BIN" -c -f "$SUDOERS_TMP"
fi

if [[ "$sudoers_already_ok" -eq 1 ]]; then
  log "[info] Sudoers already configured ($SUDOERS_DEST is identical); skipping install."
else
  write_root_file "$SUDOERS_TMP" "$SUDOERS_DEST" 0440

  # Validate full sudoers config only if we changed something.
  if [[ "$dry_run" -eq 1 ]]; then
    log "[dry-run] Would validate full sudoers via: sudo $VISUDO_BIN -c"
  else
    sudo "$VISUDO_BIN" -c
  fi
fi

# Verify passwordless sudo works for the target user.
log "[2/3] Verifying passwordless sudo for $TARGET_USER..."
if [[ "$dry_run" -eq 1 ]]; then
  log "[dry-run] Would run: sudo -u $TARGET_USER -H bash -lc 'sudo -n true'"
else
  if sudo -u "$TARGET_USER" -H bash -lc 'sudo -n true' >/dev/null 2>&1; then
    log "OK: sudo is passwordless for $TARGET_USER."
  else
    die "sudo still requires a password for $TARGET_USER. Inspect $SUDOERS_DEST and /etc/sudoers.d/."
  fi
fi

# --- Configure polkit rule (optional) ---
if [[ "$sudo_only" -eq 1 ]]; then
  log "[3/3] Skipping polkit configuration (--sudo-only)."
  log "Done."
  exit 0
fi

log "[3/3] Configuring polkit rule for $TARGET_USER (best-effort)..."

# Detect polkit version if possible; warn if JS rules are likely unsupported.
if have_cmd pkaction; then
  if pkaction --version 2>/dev/null | grep -Eiq 'polkit(\s+|-)1(2[4-9]|[3-9][0-9])'; then
    warn "Your polkit appears to be >= 124; JavaScript rules may be disabled/unsupported. Continuing anyway."
  fi
fi

POLKIT_RULE_DIR="/etc/polkit-1/rules.d"
POLKIT_RULE_PATH="${POLKIT_RULE_DIR}/00-allow-${TARGET_USER}-everything.rules"
POLKIT_TMP="$(mktemp)"

u_js="$(js_escape_string "$TARGET_USER")"
cat >"$POLKIT_TMP" <<EOF
// Generated by $SCRIPT_NAME
// WARNING: This approves all polkit actions for "$u_js".
polkit.addRule(function(action, subject) {
  if (subject.user === "$u_js") {
    return polkit.Result.YES;
  }
});
EOF

if [[ "$dry_run" -eq 1 ]]; then
  log "[dry-run] Would ensure directory exists: $POLKIT_RULE_DIR"
else
  sudo mkdir -p "$POLKIT_RULE_DIR"
fi

polkit_rule_already_ok=0
if sudo test -e "$POLKIT_RULE_PATH"; then
  if files_identical_as_root "$POLKIT_TMP" "$POLKIT_RULE_PATH"; then
    polkit_rule_already_ok=1
  fi
fi

if [[ "$polkit_rule_already_ok" -eq 1 ]]; then
  log "[info] Polkit rule already configured ($POLKIT_RULE_PATH is identical); skipping install/restart."
else
  write_root_file "$POLKIT_TMP" "$POLKIT_RULE_PATH" 0644

  log "[info] Restarting polkit (best-effort)..."
  if [[ "$dry_run" -eq 1 ]]; then
    log "[dry-run] Would attempt to restart polkit"
  else
    if restart_polkit_best_effort; then
      :
    else
      warn "Could not restart polkit automatically. You may need to reboot or restart polkit manually."
    fi
  fi
fi

# Basic polkit check. This is not authoritative; it just avoids user interaction.
if have_cmd pkcheck; then
  log "[info] Running a basic pkcheck sanity check (may fail harmlessly if action-id isn't present)..."
  if [[ "$dry_run" -eq 1 ]]; then
    log "[dry-run] Would run pkcheck with --allow-user-interaction=false"
  else
    pkcheck --action-id org.freedesktop.policykit.exec --process $$ --allow-user-interaction=false >/dev/null 2>&1 || true
  fi
else
  warn "pkcheck not found; skipping polkit sanity check."
fi

log "Done."
log "To undo: remove $SUDOERS_DEST and $POLKIT_RULE_PATH (and any .bak.* backups you created)."
