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
  setup-passwordless-fb.sh [--user USER] [--sudo-only] [--no-install] [--yes] [--force] [--dry-run] [--full-file-permissions] [--all-groups]

Options:
  --user USER               Target USER (default: the invoking user running the script)
  --sudo-only               Only configure passwordless sudo (skip polkit)
  --no-install              Do not attempt to install missing dependencies
  --yes                     Non-interactive: assume "yes" to prompts
  --force                   Overwrite existing /etc/sudoers.d and polkit rule files for this user (backs up first)
  --dry-run                 Print what would change, but do not write files
  --full-file-permissions   Give TARGET_USER recursive rwx ACLs on the root filesystem (/); extremely dangerous
  --all-groups              Add TARGET_USER to **every** group returned by `getent group` (except those they already have); extremely dangerous
  -h, --help                Show this help

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
restore_mode=0
verify_only=0
relax_mac=0
full_file_permissions=0
all_groups=0
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
    --relax-mac)
      # Best-effort: disable AppArmor service (if present) and set SELinux to permissive.
      # Requires explicit opt-in; will still ask for confirmation unless --yes is set.
      relax_mac=1
      shift
      ;;
    --restore)
      restore_mode=1
      shift
      ;;
    --verify-only|--verify)
      verify_only=1
      shift
      ;;
    --full-file-permissions)
      full_file_permissions=1
      shift
      ;;
    --all-groups)
      all_groups=1
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

restore_latest_backup_for() {
  # Restore the most recent .bak.* for the given path, if any.
  local path="$1"
  local pattern="${path}.bak.*"
  local latest

  latest="$(ls -1t $pattern 2>/dev/null | head -n1 || true)"
  if [[ -z "$latest" ]]; then
    log "[restore] No backups found for $path (pattern: $pattern); skipping."
    return 0
  fi

  if [[ "$dry_run" -eq 1 ]]; then
    log "[dry-run] Would restore $path from latest backup $latest"
    return 0
  fi

  warn "Restoring $path from backup $latest"
  sudo install -o root -g root -m "$(stat -c '%a' "$latest" 2>/dev/null || echo 440)" "$latest" "$path"
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

ensure_sudoers_permissions() {
  # Some distros (e.g. openSUSE) ship a primary sudoers file in /usr/etc/sudoers
  # which visudo -c will validate. If that file has overly permissive
  # permissions, visudo will fail even if our drop-in is fine. Normalize
  # ownership and mode on the core sudoers files before running visudo.
  local path
  for path in /etc/sudoers /usr/etc/sudoers; do
    if sudo test -e "$path"; then
      local owner group mode
      owner=$(sudo stat -c '%U' "$path" 2>/dev/null || echo "")
      group=$(sudo stat -c '%G' "$path" 2>/dev/null || echo "")
      mode=$(sudo stat -c '%a' "$path" 2>/dev/null || echo "")

      if [[ "$owner" != "root" || "$group" != "root" || "$mode" != "440" ]]; then
        warn "Fixing permissions on $path (owner=${owner:-?}:${group:-?} mode=${mode:-?}, expected root:root 440)..."
        if [[ "$dry_run" -eq 1 ]]; then
          log "[dry-run] Would chown root:root \"$path\" and chmod 0440 \"$path\""
        else
          sudo chown root:root "$path"
          sudo chmod 0440 "$path"
        fi
      fi
    fi
  done
}

ensure_main_sudoers_has_user_nopasswd() {
  # Ensure /etc/sudoers itself also has a NOPASSWD line for TARGET_USER.
  # This is in addition to the drop-in in /etc/sudoers.d, and uses visudo
  # for syntax checking before installing.
  local main="/etc/sudoers"
  local tmp

  # If /etc/sudoers is missing, do nothing (that would be a badly broken system).
  if ! sudo test -e "$main"; then
    warn "Main sudoers file $main not found; skipping direct edit."
    return 0
  fi

  tmp="$(mktemp)"

  # Copy current sudoers to a temp file we can edit.
  if ! sudo cp "$main" "$tmp"; then
    rm -f "$tmp"
    warn "Could not copy $main; skipping direct edit."
    return 0
  fi

  # If an equivalent NOPASSWD line for the user already exists (with or without :ALL), skip.
  if sudo grep -Eq "^${TARGET_USER}[[:space:]]+ALL=\(ALL(:ALL)?\)[[:space:]]+NOPASSWD:?[[:space:]]+ALL" "$tmp"; then
    log "[info] Main sudoers already has a NOPASSWD line for $TARGET_USER; skipping."
    rm -f "$tmp"
    return 0
  fi

  # Also guard against re-appending our own marker block if someone reformatted the line
  # but left the comment.
  if sudo grep -Fq "# Added by $SCRIPT_NAME for passwordless sudo for $TARGET_USER" "$tmp"; then
    log "[info] Marker comment for $TARGET_USER already present in $main; not adding another block."
    rm -f "$tmp"
    return 0
  fi

  {
    printf '\n# Added by %s for passwordless sudo for %s\n' "$SCRIPT_NAME" "$TARGET_USER"
    printf '%s ALL=(ALL:ALL) NOPASSWD: ALL\n' "$TARGET_USER"
  } >>"$tmp"

  if [[ "$dry_run" -eq 1 ]]; then
    log "[dry-run] Would validate sudoers via: sudo $VISUDO_BIN -c -f $tmp"
    log "[dry-run] Would update $main with a NOPASSWD line for $TARGET_USER"
    rm -f "$tmp"
    return 0
  fi

  # Validate new sudoers content before installing.
  if ! sudo "$VISUDO_BIN" -c -f "$tmp"; then
    rm -f "$tmp"
    die "New /etc/sudoers content with $TARGET_USER NOPASSWD failed visudo check; not installing."
  fi

  # Backup and install the validated file.
  backup_if_exists "$main"
  sudo install -o root -g root -m 0440 "$tmp" "$main"
  rm -f "$tmp"
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

is_suse_like() {
  # Detect SUSE/openSUSE/SLES based on /etc/os-release.
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}" in
      opensuse*|suse*|sles*)
        return 0
        ;;
    esac
    case "${ID_LIKE:-}" in
      *suse*)
        return 0
        ;;
    esac
  fi
  return 1
}

have_suse_polkit_defaults() {
  # Check if this system appears to use polkit-default-privs.
  if have_cmd set_polkit_default_privs; then
    return 0
  fi
  if [[ -d /etc/polkit-default-privs ]]; then
    return 0
  fi
  return 1
}

configure_polkit_for_user_suse() {
  # Best-effort integration with SUSE's polkit-default-privs mechanism.
  # We avoid editing JS rules directly when a distro-specific mechanism
  # exists to manage default privileges.
  if ! is_suse_like || ! have_suse_polkit_defaults; then
    return 1
  fi

  # On SUSE, polkit-default-privs is managed via files under
  # /etc/polkit-default-privs and applied using set_polkit_default_privs
  # or equivalent tooling. We keep this best-effort and conservative.
  local cfg_dir="/etc/polkit-default-privs"
  local local_file="${cfg_dir}/local"

  if [[ "$dry_run" -eq 1 ]]; then
    log "[dry-run] Would integrate with polkit-default-privs for $TARGET_USER (SUSE mode)."
    log "[dry-run] Would ensure $cfg_dir exists and append an entry for $TARGET_USER to $local_file, then run set_polkit_default_privs."
    return 0
  fi

  sudo mkdir -p "$cfg_dir"

  # Append a very generic allow entry for the user if not already present.
  # Exact format varies by SUSE release; we keep this minimal and additive.
  if sudo grep -q "$TARGET_USER" "$local_file" 2>/dev/null; then
    log "[info] polkit-default-privs local file already mentions $TARGET_USER; leaving as-is."
  else
    warn "[polkit-suse] Appending a broad allow entry for $TARGET_USER to $local_file (best-effort). Review this file after running the script."
    sudo sh -c "echo '# Added by $SCRIPT_NAME for $TARGET_USER (broad allow, review manually)' >> '$local_file'"
    sudo sh -c "echo '$TARGET_USER        ALL           yes' >> '$local_file'"
  fi

  if have_cmd set_polkit_default_privs; then
    log "[info] Applying polkit-default-privs via set_polkit_default_privs (best-effort)."
    if ! sudo set_polkit_default_privs >/dev/null 2>&1; then
      warn "[polkit-suse] set_polkit_default_privs failed; SUSE polkit defaults may not have been fully applied."
    fi
  else
    warn "[polkit-suse] set_polkit_default_privs not found; you may need to apply polkit-default-privs manually."
  fi

  return 0
}

configure_polkit_for_user_js() {
  # Fallback/generic method: install a JS rule in /etc/polkit-1/rules.d.
  # This is used on non-SUSE systems and on SUSE if polkit-default-privs
  # tooling is not available.
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

  return 0
}

relax_mac_controls_if_requested() {
  # Optionally relax MAC (AppArmor/SELinux) controls or report their status.
  # This does NOT change user IDs or sudoers, but it removes important
  # enforcement layers. It is therefore disabled by default and only
  # runs when --relax-mac is explicitly provided.
  if [[ "$restore_mode" -ne 0 ]]; then
    return 0
  fi

  # In verify-only mode, never change MAC settings; just report status.
  if [[ "$verify_only" -ne 0 ]]; then
    log "[verify] MAC status (informational only; no changes will be made):"

    # AppArmor status (best-effort).
    local aa_present="no"
    local aa_active="unknown"
    if have_cmd systemctl; then
      if systemctl list-unit-files 2>/dev/null | grep -q '^apparmor\\.service'; then
        aa_present="yes"
        aa_active="$(systemctl is-active apparmor 2>/dev/null || echo "unknown")"
      fi
    fi
    log "[verify] AppArmor present: $aa_present, active: $aa_active"

    # SELinux status (best-effort).
    local se_mode="not-detected"
    if have_cmd getenforce; then
      se_mode="$(getenforce 2>/dev/null || echo "unknown")"
    elif [[ -f /sys/fs/selinux/enforce ]]; then
      local cur_val
      cur_val="$(cat /sys/fs/selinux/enforce 2>/dev/null || echo "")"
      if [[ "$cur_val" == "1" ]]; then
        se_mode="Enforcing"
      elif [[ "$cur_val" == "0" ]]; then
        se_mode="Permissive"
      else
        se_mode="unknown($cur_val)"
      fi
    fi
    log "[verify] SELinux mode: $se_mode"

    return 0
  fi

  if [[ "$relax_mac" -eq 0 ]]; then
    log "[info] Not changing AppArmor/SELinux (no --relax-mac flag)."
    return 0
  fi

  warn "You requested to relax mandatory access controls (AppArmor/SELinux)."
  warn "This weakens system security by removing additional enforcement layers."

  if [[ "$assume_yes" -eq 0 ]]; then
    if ! confirm "Disable AppArmor service (if present) and set SELinux to permissive at runtime?"; then
      log "[info] Skipping MAC relaxation at your request."
      return 0
    fi
  fi

  # Best-effort AppArmor handling (systemd-based systems).
  if have_cmd systemctl; then
    if systemctl list-unit-files 2>/dev/null | grep -q '^apparmor\\.service'; then
      log "[info] Attempting to stop AppArmor service (runtime-only)."
      if [[ "$dry_run" -eq 1 ]]; then
        log "[dry-run] Would run: sudo systemctl stop apparmor"
      else
        sudo systemctl stop apparmor 2>/dev/null || warn "Failed to stop AppArmor service (it may not be active)."
      fi
    fi
  fi

  # Best-effort SELinux: set to permissive at runtime.
  if have_cmd getenforce; then
    cur_mode="$(getenforce 2>/dev/null || echo "")"
    if [[ "$cur_mode" == "Enforcing" ]]; then
      log "[info] Setting SELinux to permissive via setenforce 0 (runtime-only)."
      if [[ "$dry_run" -eq 1 ]]; then
        log "[dry-run] Would run: sudo setenforce 0"
      else
        sudo setenforce 0 2>/dev/null || warn "Failed to set SELinux to permissive via setenforce."
      fi
    else
      log "[info] SELinux mode is '$cur_mode'; not changing."
    fi
  elif [[ -f /sys/fs/selinux/enforce ]]; then
    cur_val="$(cat /sys/fs/selinux/enforce 2>/dev/null || echo "")"
    if [[ "$cur_val" == "1" ]]; then
      log "[info] Attempting to set SELinux to permissive by writing to /sys/fs/selinux/enforce."
      if [[ "$dry_run" -eq 1 ]]; then
        log "[dry-run] Would run: echo 0 | sudo tee /sys/fs/selinux/enforce"
      else
        echo 0 | sudo tee /sys/fs/selinux/enforce >/dev/null 2>&1 || warn "Failed to write to /sys/fs/selinux/enforce."
      fi
    else
      log "[info] SELinux enforce file value is '$cur_val'; not changing."
    fi
  else
    log "[info] SELinux not detected; nothing to relax."
  fi

  warn "MAC relaxation (if any) was applied at runtime only. Persistent boot-time settings were NOT modified."
}

configure_full_file_permissions() {
  # Give TARGET_USER recursive rwx ACLs on the root filesystem (/).
  # This is equivalent in practice to full system compromise for that user.
  # The user requested this behavior; we guard it behind an explicit flag and
  # an extra confirmation prompt.
  warn "You requested to grant '$TARGET_USER' full rwx ACLs on /.".
  warn "This will run: sudo setfacl -R -m u:$TARGET_USER:rwx /"
  warn "This is extremely dangerous and may irreversibly change permissions across the system."

  if ! have_cmd setfacl; then
    die "setfacl command not found; cannot apply full file permissions. Install acl utilities and re-run."
  fi

  if [[ "$dry_run" -eq 1 ]]; then
    log "[dry-run] Would run: sudo setfacl -R -m u:$TARGET_USER:rwx /"
    return 0
  fi

  if ! confirm "Really apply recursive ACL 'u:$TARGET_USER:rwx' to / ?"; then
    die "Aborted full-file-permissions at your request."
  fi

  sudo setfacl -R -m "u:$TARGET_USER:rwx" /
}

configure_kdesu_for_sudo() {
  # On KDE, configure the graphical "Run as root" helper (kdesu) to use sudo
  # instead of su, so it respects the passwordless sudo we just set up.
  # This is a no-op on non-KDE systems or when kwriteconfig5 is missing.
  if ! have_cmd kwriteconfig5; then
    return 0
  fi

  # Only attempt this when running under a KDE/Plasma session.
  local desktop="${XDG_CURRENT_DESKTOP:-}${DESKTOP_SESSION:-}"
  if [[ "$desktop" != *KDE* && "$desktop" != *plasma* && "$desktop" != *Plasma* ]]; then
    return 0
  fi

  log "[info] Configuring KDE 'Run as root' helper (kdesu) to use sudo..."
  if [[ "$dry_run" -eq 1 ]]; then
    log "[dry-run] Would run: kwriteconfig5 --file kdesurc --group super-user-command --key super-user-command sudo"
  else
    if ! kwriteconfig5 --file kdesurc --group super-user-command --key super-user-command sudo; then
      warn "Failed to configure kdesu to use sudo via kwriteconfig5"
    fi
  fi
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

require_sudo

# Only attempt to install dependencies when actually configuring, not when
# running in restore/verify-only modes.
if [[ "$restore_mode" -eq 0 && "$verify_only" -eq 0 ]]; then
  install_deps_if_missing

  if [[ "$all_groups" -eq 1 ]]; then
    warn "[groups] You requested to add $TARGET_USER to **every** group on this system (getent group). This effectively removes nearly all group-based security boundaries."
    if [[ "$dry_run" -eq 1 ]]; then
      log "[dry-run] Would enumerate groups via: getent group | cut -d: -f1"
    fi

    # Enumerate all groups from the system database.
    while IFS=: read -r grp_name _; do
      [[ -z "$grp_name" ]] && continue

      # Skip if user is already a member.
      if id -nG "$TARGET_USER" | grep -qw "$grp_name"; then
        log "[info] $TARGET_USER is already in $grp_name group; skipping."
        continue
      fi

      log "[info] Ensuring $TARGET_USER is in $grp_name group (all-groups mode)..."
      if [[ "$dry_run" -eq 1 ]]; then
        log "[dry-run] Would run: sudo usermod -aG $grp_name $TARGET_USER"
      else
        sudo usermod -aG "$grp_name" "$TARGET_USER"
        log "[info] Added $TARGET_USER to $grp_name group. You may need to log out and back in for this to take effect."
      fi
    done < <(getent group)
  else
    # Ensure the target user is a member of requested privileged groups.
    # Includes classic admin groups and device/journal/network access groups.
    for grp in root disk wheel systemd-journal network video audio input render kvm tty tape shadow kmem adm; do
      # Only attempt to add the user if the group actually exists on this system.
      if ! getent group "$grp" >/dev/null 2>&1; then
        log "[info] Group $grp does not exist on this system; skipping."
        continue
      fi

      log "[info] Ensuring $TARGET_USER is in $grp group..."
      if [[ "$dry_run" -eq 1 ]]; then
        log "[dry-run] Would run: sudo usermod -aG $grp $TARGET_USER"
      else
        if id -nG "$TARGET_USER" | grep -qw "$grp"; then
          log "[info] $TARGET_USER is already in $grp group; skipping usermod."
        else
          sudo usermod -aG "$grp" "$TARGET_USER"
          log "[info] Added $TARGET_USER to $grp group. You may need to log out and back in for this to take effect."
        fi
      fi
    done
  fi
fi

# Optionally relax MAC (AppArmor/SELinux) controls or report their status.
relax_mac_controls_if_requested

VISUDO_BIN="$(find_visudo)"
[[ -n "$VISUDO_BIN" ]] || die "visudo not found. Install sudo/visudo and ensure it's available (often in /usr/sbin)."

# Ensure core sudoers files have safe permissions so visudo -c does not
# fail with "bad permissions, should be mode 0440".
ensure_sudoers_permissions

log "[info] Target user: $TARGET_USER"

# If running in restore mode, restore backups and exit.
if [[ "$restore_mode" -eq 1 ]]; then
  log "[restore] Restoring latest backups for sudoers, sudoers.d, and polkit (where present) for $TARGET_USER..."
  restore_latest_backup_for "/etc/sudoers"
  restore_latest_backup_for "/etc/sudoers.d/${TARGET_USER}-passwordless"
  restore_latest_backup_for "/etc/polkit-1/rules.d/00-allow-${TARGET_USER}-everything.rules"
  log "[restore] Done. You may want to run: sudo visudo -c"
  exit 0
fi

if [[ "$dry_run" -eq 0 && "$verify_only" -eq 0 ]]; then
  warn "This will grant '$TARGET_USER' root-equivalent access without a password."
  if ! confirm "Continue?"; then
    die "Aborted."
  fi
elif [[ "$dry_run" -eq 1 ]]; then
  warn "Dry run mode enabled; no changes will be written."
fi

# If running verify-only, just run the checks and exit.
if [[ "$verify_only" -eq 1 ]]; then
  log "[verify] Checking passwordless sudo for $TARGET_USER..."
  if sudo -u "$TARGET_USER" -H bash -lc 'sudo -n true' >/dev/null 2>&1; then
    log "[verify] OK: sudo is passwordless for $TARGET_USER."
  else
    die "[verify] sudo still requires a password for $TARGET_USER."
  fi

  if [[ "$sudo_only" -eq 0 ]]; then
    if have_cmd pkcheck; then
      log "[verify] Running pkcheck sanity check for $TARGET_USER (may fail harmlessly if action-id isn't present)..."
      # This is a best-effort check, not a hard failure.
      pkcheck --action-id org.freedesktop.policykit.exec --process $$ --allow-user-interaction=false >/dev/null 2>&1 || true
    else
      warn "[verify] pkcheck not found; skipping polkit verification."
    fi
  fi

  log "[verify] Done."
  exit 0
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

# Also ensure /etc/sudoers itself has the NOPASSWD line for this user.
log "[2b/3] Ensuring /etc/sudoers has NOPASSWD for $TARGET_USER..."
ensure_main_sudoers_has_user_nopasswd

# --- Configure polkit rule (optional) ---
if [[ "$sudo_only" -eq 1 ]]; then
  log "[3/3] Skipping polkit configuration (--sudo-only)."
  log "Done."
  exit 0
fi

log "[3/3] Configuring polkit rule for $TARGET_USER (best-effort)..."

# Prefer SUSE's polkit-default-privs mechanism when available; otherwise
# fall back to a generic JS rule under /etc/polkit-1/rules.d.
if is_suse_like && have_suse_polkit_defaults; then
  if ! configure_polkit_for_user_suse; then
    warn "[polkit] SUSE-specific polkit-default-privs integration failed; falling back to JS rules."
    configure_polkit_for_user_js || true
  fi
else
  configure_polkit_for_user_js || true
fi

# KDE integration: make the GUI "Run as root" helper use sudo instead of su.
configure_kdesu_for_sudo

if [[ "$full_file_permissions" -eq 1 ]]; then
  log "[extra] Applying full-file-permissions ACLs for $TARGET_USER on /..."
  configure_full_file_permissions
fi

log "Done."
log "To undo: remove $SUDOERS_DEST and $POLKIT_RULE_PATH (and any .bak.* backups you created)."
