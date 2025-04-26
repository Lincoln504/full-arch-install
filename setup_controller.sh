#!/usr/bin/env bash
# setup_controller.sh (v2.9 - Fix Network Role Service Check)
# Prepares the Ansible controller machine for an Arch Install using a SINGLE PLAYBOOK
# that orchestrates TWO LOGICAL STAGES (install + reboot + configure).
# Includes comprehensive verification checks within this script and the generated Ansible playbook.
# Includes installation and basic configuration for:
#   - Base System, NetworkManager, SSH, Avahi, Users, Sudo
#   - Swap files (primary/secondary)
#   - MicroSD mounting
#   - Firewall (nftables/ufw)
#   - Docker
#   - Sway DE (Waybar, Wofi, Foot, Alacritty, Mako, etc.)
#   - Theming (GTK Adwaita-dark default, Qt setup)
#   - Fonts (Fira Code)
#   - Autorotation (iio-sensor-proxy + script)
#   - Gestures (libinput-gestures)
#   - Wallpaper script (Unsplash + Pywal)
#   - Git Credential Manager (GCM) with cache store and GitHub credential pre-seeding
#   - VSCode
#   - Power Management (TLP)
#   - CPU Power Utils (cpupower)
#   - Media codecs (GStreamer, FFmpeg)
#   - Editors (Vim, Micro)
#   - XDG User Dirs
#   - Nautilus File Manager
#   - Autotiling for Sway
#   - Optional GUI tools (pavucontrol, tlpui, cpupower-gui)
# - Play 1 installs base via chroot, sets up users/keys/sudo, installs/enables Avahi,
#   creates a temporary first-boot script/service, runs handlers, syncs, triggers reboot.
# - Play 2 waits for connection, verifies core services, gathers facts, updates packages,
#   installs yay, installs extra packages (repo & AUR), verifies installations,
#   configures system, desktop, Git (including GCM), etc., verifies services, cleans up temp files.
# - Uses Ansible Vault for secrets (including optional GitHub credentials for GCM).
# - Copies user-provided config files.
# - Creates ansible.cfg to disable host key checking.
# - Creates a post-installation verification script (verify_installation.sh).
# - Provides detailed next steps including verification commands.

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
set -u
# Pipelines fail if any command fails, not just the last one.
set -o pipefail

# --- Configuration ---
PROJECT_DIR_NAME="ansible-arch-reboot" # Project directory name
PROJECT_DIR="${HOME}/${PROJECT_DIR_NAME}"
ANSIBLE_USER_ON_CONTROLLER=$(whoami) # User running this script
# Define default keys - user should verify/change in config.yml
DEFAULT_ROOT_SSH_KEY_FILE="${HOME}/.ssh/id_ed25519"
DEFAULT_USER_SSH_KEY_FILE="${HOME}/.ssh/id_ed25519_ldeen" # Example separate key

# Ansible collections required by the playbooks
REQUIRED_COLLECTIONS=(
  "community.general"
  "ansible.posix"
)

# User files to copy from the directory where this script is run
# Format: "Source Filename:Destination Path relative to Project Dir:Role Name (for logs)"
USER_FILES_TO_COPY=(
  "config:roles/desktop_sway/files/config:desktop_sway" # Sway config
  "libinput-gestures.conf:roles/desktop_sway/files/libinput-gestures.conf:desktop_sway" # Gesture config
  "wallpaper.sh:roles/desktop_sway/files/wallpaper.sh:desktop_sway" # Wallpaper script
  ".bashrc:roles/desktop_sway/files/.bashrc:desktop_sway" # Optional: User's bashrc
  "alacritty.yml:roles/desktop_sway/files/alacritty.yml:desktop_sway" # Optional: User's alacritty config
)

# --- Helper Functions ---
log_info() {  echo "==> [INFO] $1"; }
log_warn() {  echo "==> [WARN] $1" >&2; }
log_error() { echo "==> [ERROR] $1" >&2; exit 1; }
command_exists() { command -v "$1" >/dev/null 2>&1; }

# --- Verification Functions ---
validate_ssh_key() {
  local key_file="$1"
  log_info "Validating SSH key $key_file..."
  [ -f "$key_file" ] || log_error "SSH key $key_file missing!"
  # Check permissions - should be 600
  local perms
  perms=$(stat -c %a "$key_file")
  [ "$perms" = "600" ] || log_warn "Insecure permissions for $key_file (is $perms, should be 600)"
  # Validate key format
  ssh-keygen -l -f "$key_file" >/dev/null || log_error "Invalid SSH key format or unreadable: $key_file"
}

verify_project_structure() {
  log_info "Verifying project structure..."
  local critical_files=(
    "ansible.cfg"
    "inventory.ini"
    "install_and_configure.yml"
    "group_vars/all/config.yml.example"
    "group_vars/all/vault.yml.example" # Check example vault too
    "roles/base_system/tasks/main.yml" # Check at least one core role task file
    "roles/users/tasks/main.yml"       # Check users role (where GCM is added)
    "roles/network/tasks/main.yml"     # Check network role
    # Add more critical files/dirs if needed
  )
  local missing=0
  for file in "${critical_files[@]}"; do
    if [ ! -f "${PROJECT_DIR}/$file" ]; then
       log_warn "Missing critical project file: ${PROJECT_DIR}/$file"
       missing=1
    fi
  done
  [ $missing -eq 0 ] || log_error "Critical project structure files are missing. Setup failed."
}

verify_ssh_permissions() {
  local ssh_dir="${HOME}/.ssh"
  log_info "Verifying SSH directory and key permissions..."
  if [ ! -d "$ssh_dir" ]; then
      log_warn "SSH directory $ssh_dir does not exist. Skipping permission checks."
      return
  fi
  # Check .ssh directory permissions - should be 700
  local dir_perms
  dir_perms=$(stat -c %a "$ssh_dir")
  [ "$dir_perms" = "700" ] || log_warn ".ssh directory permissions are insecure (is $dir_perms, should be 700)"

  # Check permissions of files within .ssh - private keys should be 600
  find "$ssh_dir" -maxdepth 1 -type f -print0 | while IFS= read -r -d $'\0' key_file; do
      local key_perms
      key_perms=$(stat -c %a "$key_file")
      # Check if it looks like a private key (no standard extension or specific names)
      if [[ ! "$key_file" == *.pub ]] && [[ "$key_file" != *known_hosts* ]] && [[ "$key_file" != *config* ]] && [[ "$key_file" != *authorized_keys* ]]; then
          [ "$key_perms" = "600" ] || log_warn "Insecure permissions for potential private key $key_file (is $key_perms, should be 600)"
      # Public keys are often 644, authorized_keys 600, config 600 or 644, known_hosts 644 or 600
      elif [[ "$key_file" == *authorized_keys* ]] || [[ "$key_file" == *config* ]]; then
          [[ "$key_perms" == "600" || "$key_perms" == "644" ]] || log_warn "Unusual permissions for $key_file (is $key_perms)"
      elif [[ "$key_file" == *.pub ]] || [[ "$key_file" == *known_hosts* ]]; then
          [[ "$key_perms" == "644" || "$key_perms" == "600" ]] || log_warn "Unusual permissions for $key_file (is $key_perms)"
      fi
  done
}


# Function to create file with content, ensures parent directory exists
create_file_with_heredoc() {
    local file_path="$1"
    local parent_dir
    parent_dir=$(dirname "$file_path")
    mkdir -p "$parent_dir" || log_error "Failed to create directory ${parent_dir}"
    cat > "$file_path" || log_error "Failed to write heredoc to ${file_path}"
    log_info "Created/Updated: ${file_path}"
}


# --- Package Installation ---
# Detect package manager and install packages
install_packages() {
  local pm=''
  local install_cmd=''
  local packages_to_install=("$@")
  local pkgs_str="${packages_to_install[*]}"

  log_info "Detecting package manager..."
  if command_exists apt-get; then
    pm='apt'
    install_cmd='sudo apt-get update && sudo apt-get install -y'
  elif command_exists dnf; then
    pm='dnf'
    install_cmd='sudo dnf install -y'
  elif command_exists pacman; then
    pm='pacman'
    install_cmd='sudo pacman -Syu --noconfirm --needed'
  else
    log_error "Unsupported package manager. Please install packages manually: ${pkgs_str}"
  fi

  log_info "Using ${pm} to install required packages: ${pkgs_str}"
  if ! ${install_cmd} "${packages_to_install[@]}"; then
     log_error "Failed to install packages using ${pm}. Please install them manually."
  fi

  # Post-install verification for the specific packages just attempted
  log_info "Verifying installed packages: ${pkgs_str}"
  local verify_failed=0
  for pkg_base in "${packages_to_install[@]}"; do
      # Handle potential version specifiers for apt/dnf if needed, basic check here
      local pkg_to_check="$pkg_base"
      # Special case for openssh-client vs openssh-clients
      if [[ "$pkg_to_check" == "openssh-client" ]] && [[ "$pm" == "dnf" ]]; then
          pkg_to_check="openssh-clients"
      fi
      # Special case for python3-pip
      if [[ "$pkg_to_check" == "python3-pip" ]] && [[ "$pm" == "dnf" ]]; then
          pkg_to_check="python3-pip" # Often separate on Fedora/RHEL too
      fi
      # Special case for curl
      if [[ "$pkg_to_check" == "curl" ]] && [[ "$pm" == "dnf" ]]; then
          pkg_to_check="curl" # Usually just 'curl'
      fi

      local installed=0
      if [[ "$pm" == "pacman" ]]; then
        # pacman uses base package name even if version was specified for install
        pkg_to_check=$(pacman -Sg "$pkg_base" | awk '{print $2}' | head -n 1 || echo "$pkg_base") # Get base name if in group
        pacman -Qi "$pkg_to_check" >/dev/null 2>&1 && installed=1
      elif [[ "$pm" == "apt" ]]; then
        dpkg -s "$pkg_to_check" >/dev/null 2>&1 && installed=1
      elif [[ "$pm" == "dnf" ]]; then
         # dnf list installed might be slow, use rpm
         rpm -q "$pkg_to_check" >/dev/null 2>&1 && installed=1
      fi
      if [[ $installed -eq 0 ]]; then
          log_warn "Package '$pkg_to_check' verification failed using $pm!"
          verify_failed=1
      fi
  done
   [ $verify_failed -eq 0 ] || log_error "One or more packages failed verification after installation attempt."

}


# --- Main Execution ---

log_info "Starting Controller Setup for Single-Playbook Two-Stage Ansible Arch Install..."
log_info "Project will be created at: ${PROJECT_DIR}"

# Runtime Environment Checks
log_info "Verifying execution environment..."
if [ "$(id -u)" == "0" ]; then
    log_error "This script should not be run as root!"
fi
if grep -qi "arch" /etc/os-release; then
     log_warn "Running this setup script on Arch Linux itself. Ensure this is intended."
fi

if [ -d "${PROJECT_DIR}" ]; then
    read -p "Project directory ${PROJECT_DIR} already exists. Overwrite files? (y/N): " -r ov_response
    if [[ ! "$ov_response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        log_error "Aborted. Please remove or rename the existing directory first."
    fi
    log_warn "Existing project directory found. Files will be overwritten."
fi


# 1. Check Essential Commands & Dependencies (Git, SSH, Python, Pip, Curl)
log_info "Checking/Installing essential dependencies (git, ssh, python3, pip3, curl)..."
declare -A base_deps_map
base_deps_map=(
  [git]="git"
  [ssh]="openssh-client" # Package name varies (openssh-clients on RHEL/Fedora)
  [python3]="python3"
  [pip3]="python3-pip" # Package name varies (python3-pip on Debian/Ubuntu, python3-pip on RHEL/Fedora)
  [curl]="curl"
)
# Adjust package names based on detected PM if needed
if command_exists dnf || command_exists yum; then
    base_deps_map[ssh]="openssh-clients"
    base_deps_map[pip3]="python3-pip" # Confirming pip package name for dnf
    base_deps_map[curl]="curl"
fi
if command_exists apt-get; then
    base_deps_map[pip3]="python3-pip"
    base_deps_map[curl]="curl"
fi

needed_base_pkgs=()
for cmd in "${!base_deps_map[@]}"; do
  if ! command_exists "$cmd"; then
    needed_base_pkgs+=("${base_deps_map[$cmd]}")
  fi
done

if [ ${#needed_base_pkgs[@]} -gt 0 ]; then
  install_packages "${needed_base_pkgs[@]}"
fi

# Verify all base commands exist after potential installation
log_info "Verifying base commands are present..."
verify_failed=0 # Use local variable
for cmd in "${!base_deps_map[@]}"; do
   if ! command_exists "$cmd"; then
       log_warn "Command '$cmd' not found after installation attempt!"
       verify_failed=1
   fi
done
[ $verify_failed -eq 0 ] || log_error "One or more essential base commands are missing."
log_info "Base dependencies (git, ssh, python3, pip3, curl) are present."


# 2. Install passlib (for password_hash filter on controller if used)
log_info "Checking/Installing python3-passlib..."
if ! python3 -c "import passlib.hash" >/dev/null 2>&1; then
    log_warn "Python library 'passlib' not found. Attempting installation via pip..."
    # Try system-wide install first, then user install
    if sudo python3 -m pip install passlib; then
        log_info "passlib installed system-wide via pip."
    elif python3 -m pip install --user passlib; then
        log_info "passlib installed for user via pip."
        if [[ ":$PATH:" != *":${HOME}/.local/bin:"* ]]; then
             log_warn "User installation done. '~/.local/bin' might not be in your PATH."
             log_warn "You may need to add 'export PATH=\"\$HOME/.local/bin:\$PATH\"' to your ~/.bashrc or ~/.zshrc"
        fi
    else
        log_error "Failed to install passlib using pip. Needed for some Ansible password operations."
    fi
fi
# Verify passlib import after attempting install
python3 -c "import passlib.hash" >/dev/null 2>&1 || log_error "Python module 'passlib' check failed even after installation attempt."
log_info "Python library 'passlib' found."


# 3. Install Ansible Core
log_info "Checking/Installing Ansible Core..."
if ! command_exists ansible; then
   log_warn "Ansible not found. Attempting installation..."
   declare -A ansible_pkg_map
   ansible_pkg_map=( [apt]="ansible-core" [dnf]="ansible-core" [pacman]="ansible-core" )
   pm_detected='unknown' # Use local variable
   if command_exists apt-get; then pm_detected='apt'; elif command_exists dnf; then pm_detected='dnf'; elif command_exists pacman; then pm_detected='pacman'; fi

   if [[ "$pm_detected" != "unknown" ]]; then
       install_packages "${ansible_pkg_map[$pm_detected]}"
   else
      # Fallback to pip install if OS package manager fails or is unknown
      log_warn "OS package manager install failed or unsupported for ansible-core. Trying pip install..."
      if sudo python3 -m pip install ansible-core; then
          log_info "ansible-core installed system-wide via pip."
      elif python3 -m pip install --user ansible-core; then
          log_info "ansible-core installed for user via pip."
          if [[ ":$PATH:" != *":${HOME}/.local/bin:"* ]]; then
               log_warn "User installation done. '~/.local/bin' might not be in your PATH."
          fi
      else
          log_error "Failed to install ansible-core using pip."
      fi
   fi
fi
# Verify ansible command exists after potential install
command_exists ansible || log_error "Ansible command 'ansible' not found after installation attempt."
log_info "Ansible found: $(ansible --version | head -n 1)"


# 4. Install Ansible Collections
log_info "Checking/Installing required Ansible collections: ${REQUIRED_COLLECTIONS[*]}"
collection_install_failed=0
for collection in "${REQUIRED_COLLECTIONS[@]}"; do
    # Check if already installed first to avoid unnecessary attempts/warnings
    if ! ansible-galaxy collection list "${collection}" | grep -q "${collection}"; then
        log_info "Installing collection '${collection}'..."
        if ! ansible-galaxy collection install "${collection}"; then
            log_warn "Failed to install collection ${collection}. Attempting with sudo..."
            if ! sudo ansible-galaxy collection install "${collection}"; then
               log_error "Failed to install collection ${collection} even with sudo."
               collection_install_failed=1
            else
               log_info "Collection '${collection}' installed successfully with sudo."
            fi
        else
            log_info "Collection '${collection}' installed successfully."
        fi
    else
         log_info "Collection '${collection}' is already installed."
    fi
done

# Verify collections are installed after attempts
log_info "Verifying required Ansible collections are installed..."
verify_failed=0 # Use local variable
for collection in "${REQUIRED_COLLECTIONS[@]}"; do
    # Use precise grep to avoid matching substrings
    if ! ansible-galaxy collection list | grep -E "^\s*${collection//./\\.}\\s+" > /dev/null; then
        log_warn "Collection '${collection}' not found after installation attempt!"
        verify_failed=1
    fi
done
[ $verify_failed -eq 0 ] || log_error "One or more required Ansible collections failed installation or verification."
log_info "Required Ansible collections are present."


# 5. Check/Generate SSH Keypair(s) and Permissions
log_info "Checking SSH keys..."
# Root key
if [[ ! -f "${DEFAULT_ROOT_SSH_KEY_FILE}" ]]; then
  log_warn "ROOT SSH key file not found at ${DEFAULT_ROOT_SSH_KEY_FILE}."
  read -p "Generate new ROOT ed25519 SSH keypair now? (y/N): " -r response
  if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    log_info "Generating ROOT SSH keypair..."
    ssh-keygen -t ed25519 -f "${DEFAULT_ROOT_SSH_KEY_FILE}" -N "" || log_error "ssh-keygen failed."
    log_info "ROOT SSH keypair generated: ${DEFAULT_ROOT_SSH_KEY_FILE}.pub"
    log_info "Manually copy this PUBLIC key to /root/.ssh/authorized_keys on the LIVE ISO."
  else
    log_error "ROOT SSH key required. Generate manually at ${DEFAULT_ROOT_SSH_KEY_FILE} and re-run."
  fi
fi
validate_ssh_key "${DEFAULT_ROOT_SSH_KEY_FILE}" # Validate existing or newly generated key

# User key
if [[ ! -f "${DEFAULT_USER_SSH_KEY_FILE}" ]]; then
  log_warn "USER SSH key file not found at ${DEFAULT_USER_SSH_KEY_FILE}."
  read -p "Generate new USER ed25519 SSH keypair now? (y/N): " -r response
  if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    log_info "Generating USER SSH keypair..."
    ssh-keygen -t ed25519 -f "${DEFAULT_USER_SSH_KEY_FILE}" -N "" || log_error "ssh-keygen failed."
    log_info "USER SSH keypair generated: ${DEFAULT_USER_SSH_KEY_FILE}.pub"
    log_info "Ensure this public key content matches 'target_user_ssh_pub_key' in config.yml."
  else
    log_error "USER SSH key required for Stage 2. Generate manually at ${DEFAULT_USER_SSH_KEY_FILE} and re-run."
  fi
fi
validate_ssh_key "${DEFAULT_USER_SSH_KEY_FILE}" # Validate existing or newly generated key

# Verify general SSH directory and key permissions
verify_ssh_permissions


# --- Create Project Structure ---
log_info "Creating project structure in: ${PROJECT_DIR}"
mkdir -p "${PROJECT_DIR}"/{group_vars/all,vars,roles} # Create top levels

# Define roles for the two-stage playbook
ROLES=(
  "base_system"      # Role for Stage 1
  "common"           # Stage 2 role (updates, yay, essential tools)
  "network"          # Stage 2 role (verification)
  "users"            # Stage 2 role (verification, git config, GCM, xdg) # <-- GCM added here
  "swap"             # Stage 2 role
  "storage"          # Stage 2 role (microsd)
  "security"         # Stage 2 role (firewall)
  "docker"           # Stage 2 role (optional)
  "desktop_sway"     # Stage 2 role (sway, apps, theme, gestures, wallpaper, alacritty, bashrc)
)

log_info "Creating role skeletons..."
for role in "${ROLES[@]}"; do
  role_path="${PROJECT_DIR}/roles/${role}"
  mkdir -p "${role_path}"/{tasks,handlers,templates,files,vars,defaults,meta}
  # Create basic main.yml files if they don't exist
  for subdir in tasks handlers defaults vars meta; do
      main_file="${role_path}/${subdir}/main.yml"
      if [ ! -f "$main_file" ]; then
        echo "---" > "$main_file"
        echo "# ${subdir} for role ${role}" >> "$main_file"
      fi
  done
done
# Create files/templates dirs specifically needed by roles
mkdir -p "${PROJECT_DIR}/roles/base_system/templates"
mkdir -p "${PROJECT_DIR}/roles/security/templates"
mkdir -p "${PROJECT_DIR}/roles/desktop_sway/files"
mkdir -p "${PROJECT_DIR}/roles/desktop_sway/templates"
mkdir -p "${PROJECT_DIR}/roles/users/templates" # Keep this, might be useful later

log_info "Role directory structure created."

# --- Create Core Ansible Files ---

# ansible.cfg
log_info "Creating ansible.cfg..."
create_file_with_heredoc "${PROJECT_DIR}/ansible.cfg" << 'EOF'
# Ansible Configuration File for this Project
# Generated by setup_controller.sh

[defaults]
inventory = inventory.ini
retry_files_enabled = False
become = yes
# Increase timeout for potentially long-running tasks like GCM install script
timeout = 60

[ssh_connection]
ssh_args = -o ControlMaster=auto -o ControlPersist=60s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
pipelining = True
EOF

# .gitignore
log_info "Creating .gitignore..."
create_file_with_heredoc "${PROJECT_DIR}/.gitignore" << 'EOF'
# Ansible temporary files
*.retry
*.log
*~
*.bak

# Python virtual environment (if used)
.venv/
venv/
__pycache__/
*.pyc
*.pyo

# Configuration Variables (sensitive or environment-specific)
group_vars/all/config.yml
group_vars/all/vault.yml
vars/secrets.yml

# User-specific SSH keys if stored here (SHOULD NOT BE)
# *.key
# id_*

# OS generated files
.DS_Store
Thumbs.db
*.swp

# Terraform state files (if used alongside)
.terraform/
*.tfstate
*.tfstate.backup

# Cloned AUR repos (like yay)
yay/
*.pkg.tar.*
src/
pkg/

# Downloaded wallpapers
Pictures/Wallpapers/current_unsplash_wallpaper.jpg

# Git Credential Manager temporary files/logs (if any)
.gcm/
EOF

# inventory.ini
log_info "Creating inventory.ini..."
create_file_with_heredoc "${PROJECT_DIR}/inventory.ini" << 'EOF'
# Ansible Inventory File for Two-Stage Arch Linux Installation
# IMPORTANT: YOU MUST MANUALLY EDIT THE PLACEHOLDERS BELOW BEFORE RUNNING!

[arch_live]
# --- YOU MUST EDIT THIS SECTION ---
target_live ansible_host=X.X.X.X ansible_user=root ansible_private_key_file=~/.ssh/id_ed25519

[arch_configured]
# --- YOU MUST EDIT THIS SECTION ---
laptop ansible_host=arch-sway-laptop.local ansible_user=ldeen ansible_private_key_file=~/.ssh/id_ed25519_ldeen
EOF

# group_vars/all/config.yml.example
log_info "Creating group_vars/all/config.yml.example..."
create_file_with_heredoc "${PROJECT_DIR}/group_vars/all/config.yml.example" << 'EOF'
# Example Configuration for Two-Stage Ansible Arch Install (Uses Vault)
# Copy this file to 'group_vars/all/config.yml', fill in your specific values.

# --- Connection Settings ---
live_env_ssh_user: "root"
controller_root_private_key_file: "~/.ssh/id_ed25519"
target_user: "ldeen"
target_user_private_key_file: "~/.ssh/id_ed25519_ldeen"

# --- Target Disk and EXISTING Partition Usage (Stage 1) ---
# !! CRITICAL !! ENSURE THESE MATCH YOUR LAPTOP'S ACTUAL EXISTING PARTITIONS !!
target_disk: "/dev/mmcblk0"
target_existing_partitions:
  - device: "/dev/mmcblk0p1"
    filesystem: "vfat"
    mount_point: "/boot/efi"
  - device: "/dev/mmcblk0p3"
    filesystem: "ext4"
    mount_point: "/boot"
  - device: "/dev/mmcblk0p2"
    filesystem: "ext4"
    mount_point: "/"
filesystem_options:
  "/": "-L ROOT"
  "/boot": "-L BOOT"
  "/boot/efi": "-F 32 -n EFI"

# --- Wi-Fi Configuration ---
configure_wifi_in_stage1: true
wifi_ssid: "YourWifiNetworkName"

# --- MicroSD Card Configuration ---
use_microsd: true
microsd_partition_to_mount: "/dev/mmcblk1p1"
microsd_filesystem_type: "ext4"
microsd_mount_point: "/home/{{ target_user }}/MicroSD"

# --- Swap Files ---
create_primary_swap: true
primary_swap_path: "/swapfile"
primary_swap_size: "8G"
primary_swap_priority: -2
create_secondary_swap: true
secondary_swap_path_relative: "swapfile_sd"
secondary_swap_size: "10G"
secondary_swap_priority: 10
root_swappiness: 60

# --- Locale and Timezone ---
locale_lang: "en_US.UTF-8"
timezone: "America/Los_Angeles"
keymap: "us"

# --- Hostname ---
target_hostname: "arch-sway-laptop"

# --- Bootloader ---
boot_mode: "UEFI"
bootloader: "grub"
grub_bootloader_id: "GRUB"

# --- Base Packages (Stage 1) ---
base_packages:
  - base
  - linux
  - linux-firmware
  - base-devel
  - intel-ucode # OR amd-ucode
  - grub
  - efibootmgr
  - networkmanager
  - avahi
  - openssh
  - sudo
  - git
  - python
  - python-pip
  - python-passlib
  - reflector
  - man-db
  - man-pages
  - texinfo
  - vim

# --- Extra Packages (Stage 2) ---
# *** Ensure the chosen firewall package (nftables or ufw) is uncommented/listed here ***
# *** Ensure 'curl' is listed if using GCM install script ***
extra_packages:
  - sway
  - swaybg
  - swayidle
  - waybar
  - wofi
  - foot
  - alacritty
  - mako
  - grim
  - slurp
  - wl-clipboard
  - xdg-desktop-portal-wlr
  - xorg-xwayland
  - seatd
  - brightnessctl
  - playerctl
  - network-manager-applet
  - qt5-wayland
  - qt6-wayland
  - pipewire
  - pipewire-alsa
  - pipewire-pulse
  - wireplumber
  - pavucontrol
  - polkit
  - dconf
  - qt5ct
  - qt6ct
  - papirus-icon-theme
  - python-pywal
  - python-i3ipc
  - ttf-fira-code
  - noto-fonts
  - noto-fonts-emoji
  - ttf-font-awesome
  - firefox
  - htop
  - tmux
  - rsync
  - unzip
  - curl # Needed for GCM install script
  - wget
  - jq
  - micro # ADDED
  - nautilus
  - code
  - iio-sensor-proxy # If install_autorotation is true
  - docker          # If install_docker is true
  - docker-compose  # If install_docker is true
  - nftables        # If firewall_choice == 'nftables'
  # - ufw           # If firewall_choice == 'ufw'
  - tlp
  - cpupower
  - xdg-user-dirs
  - gstreamer
  - gst-plugins-good
  - gst-plugins-bad
  - gst-plugins-ugly
  - gst-libav
  - ffmpeg

# --- AUR Packages (Stage 2) ---
aur_packages:
  - yay
  - libinput-gestures
  # - git-credential-manager # No longer needed from AUR, installed via script
  - nwg-bar
  - adwaita-qt5-git
  - adwaita-qt6-git
  - autotiling
  # Optional GUI Tools (Uncomment to install)
  # - tlpui
  # - cpupower-gui

# --- User Configuration ---
target_user_shell: "/bin/bash"
target_user_groups: "wheel,input,video,audio,seat"
target_user_ssh_pub_key: "ssh-ed25519 AAAA... " # ssh public key string 
# --- Git Configuration ---
git_user_name: "Your Name"
git_user_email: "your.email@example.com"
# --- Git Credential Manager (GCM) ---
git_credential_manager_enabled: true # Set to true to install and configure GCM
# If true, you MUST provide vault_github_username and vault_github_password in vault.yml

# --- Feature Flags ---
install_docker: true
install_autorotation: true
firewall_choice: "nftables"

# --- Services to Enable (Stage 2) ---
enabled_services:
  - seatd.service
  - nftables.service      # If firewall_choice == 'nftables'
  # - ufw.service         # If firewall_choice == 'ufw'
  - iio-sensor-proxy.service # If install_autorotation is true
  - tlp.service

# --- Optional: Unsplash API Key ---
# unsplash_api_key: "{{ vault_unsplash_api_key | default('') }}"
unsplash_api_key: ""

# --- Theming ---
gtk_theme_name: "Adwaita-dark"
icon_theme_name: "Papirus-Dark"
cursor_theme_name: "Adwaita"

# --- Autorotation/Tablet Mode ---
touchscreen_identifier_pattern: "Touch"
EOF

# group_vars/all/vault.yml.example
log_info "Creating group_vars/all/vault.yml.example..."
create_file_with_heredoc "${PROJECT_DIR}/group_vars/all/vault.yml.example" << 'EOF'
# Example Vault File for Two-Stage Ansible Arch Install
# Create the real file using: ansible-vault create group_vars/all/vault.yml

# --- Hashed Passwords (REQUIRED) ---
# vault_root_password_hash: $6$salt$your_root_hash_here...
# vault_ldeen_password_hash: $6$salt$your_ldeen_hash_here...

# --- Wi-Fi Password (Required if configure_wifi_in_stage1: true) ---
# vault_wifi_password: "YourWifiPassword"

# --- GitHub Credentials for GCM (Required if git_credential_manager_enabled: true) ---
# vault_github_username: "YourGitHubUsername"
# vault_github_password: "YourGitHubPasswordOrPAT" # Use a Personal Access Token (PAT) if 2FA is enabled

# --- Optional Secrets ---
# vault_unsplash_api_key: "YOUR_UNSPLASH_KEY_HERE"
# vault_git_token: "YOUR_GIT_PAT_HERE" # Alternative token storage if not using GCM
EOF

# vars/ directory (Empty - Use group_vars)
log_info "Creating empty vars/ directory..."
mkdir -p "${PROJECT_DIR}/vars"

# Playbook: install_and_configure.yml
# Corrects the service state checks in pre_tasks
log_info "Creating install_and_configure.yml..."
create_file_with_heredoc "${PROJECT_DIR}/install_and_configure.yml" << 'EOF'
---
# Playbook to install and configure Arch Linux using a single execution
# Incorporates two logical stages with a reboot in between.
# Requires mDNS (.local) hostname resolution to work between stages.

# ---------------------------------------------------------------------
# Play 1: Base Installation (Runs on Live ISO as root)
# ---------------------------------------------------------------------
- name: Play 1 - Install Arch Linux Base System
  hosts: arch_live # Target group defined in inventory.ini for the Live ISO
  gather_facts: no # Facts not reliable/useful on live env initially
  pre_tasks:
    - name: Base | Verify Essential Variables (Play 1)
      ansible.builtin.assert:
        that:
          - target_disk is defined and target_disk | length > 0
          - target_existing_partitions is defined and target_existing_partitions | length >= 2
          - target_hostname is defined
          - locale_lang is defined
          - timezone is defined
          - keymap is defined
          - bootloader is defined
          - vault_root_password_hash is defined
          - vault_ldeen_password_hash is defined
          - controller_root_private_key_file is defined
          - target_user_ssh_pub_key is defined
          - base_packages is defined
          - target_user is defined
          - target_user_shell is defined
        fail_msg: "Required variables for Play 1 not defined/complete in group_vars/all/config.yml or vault.yml not loaded."
        quiet: yes
      tags: [always]
    - name: Base | Ensure Python is installed on Arch Live ISO (for Ansible modules)
      ansible.builtin.raw: pacman -Syu --noconfirm --needed python
      changed_when: false
      failed_when: false
      tags: [always]
  roles:
    - role: base_system
      tags: [always]

# ---------------------------------------------------------------------
# Play 2: System Configuration (Runs on Configured System as target_user)
# ---------------------------------------------------------------------
- name: Play 2 - Configure Arch Linux System
  hosts: arch_configured # Target group defined in inventory.ini (using .local hostname)
  gather_facts: no # <<< Explicitly disable automatic fact gathering
  pre_tasks:
    - name: Stage 2 | Verify Essential Variables (Play 2)
      ansible.builtin.assert:
        that:
          - target_user is defined
          - target_user_private_key_file is defined
          - target_user_groups is defined
          - extra_packages is defined
          - aur_packages is defined
          - firewall_choice is defined
          - enabled_services is defined
          - git_credential_manager_enabled is defined # Check GCM flag
          - (not (git_credential_manager_enabled | default(false) | bool)) or (vault_github_username is defined and vault_github_password is defined) # Check vault vars if GCM enabled
        fail_msg: "Required variables for Play 2 not defined/complete in group_vars/all/config.yml or vault.yml (check GCM settings)."
        quiet: yes
      tags: [always]
      delegate_to: localhost
    - name: Stage 2 | Wait for system to become reachable via SSH as target_user
      ansible.builtin.wait_for_connection:
        delay: 15
        timeout: 600
        sleep: 10
      tags: [always]
    - name: Stage 2 | Gather facts from the new system
      ansible.builtin.setup:
      tags: [always]
    - name: Stage 2 | Verify NetworkManager service is active on target
      ansible.builtin.systemd_service:
        name: NetworkManager.service
        state: started
      register: nm_service_status_stage2
      failed_when: nm_service_status_stage2.state != "started" # <-- Corrected check
      tags: [always]
      check_mode: no
    - name: Stage 2 | Verify SSH daemon (sshd) service is active on target
      ansible.builtin.systemd_service:
        name: sshd.service
        state: started
      register: sshd_service_status_stage2
      failed_when: sshd_service_status_stage2.state != "started" # <-- Corrected check
      tags: [always]
      check_mode: no

  roles:
    # *** Role Order Matters ***
    # Roles run first
    - role: common
      tags: [common]
    - role: network
      tags: [network]
    - role: users # Includes Git and GCM setup
      tags: [users]
    - role: storage
      when: use_microsd | default(false) | bool
      tags: [storage]
    - role: swap
      tags: [swap]
    - role: security
      tags: [security]
    - role: docker
      when: install_docker | default(false) | bool
      tags: [docker]
    - role: desktop_sway
      tags: [desktop_sway]

  tasks: # <<< Corrected Indentation
    # *** Tasks run AFTER roles ***
    # Install AUR packages AFTER yay is installed by common role
    - name: Stage 2 | Install AUR packages
      become: yes
      become_user: "{{ target_user }}" # Run yay as the target user
      community.general.pacman: # Use pacman module with yay provider
        name: "{{ aur_packages | default([]) }}"
        state: present
        executable: /usr/bin/yay # Specify yay executable
        extra_args: "--aur --needed --noconfirm" # Pass args to yay
      register: aur_install_result
      failed_when: aur_install_result.rc != 0 and 'already installed' not in aur_install_result.msg # Fail if error other than already installed
      when: aur_packages is defined and aur_packages | length > 0
      tags: [aur]

    # Verify AUR packages installed
    - name: Stage 2 | Verify AUR packages are installed
      become: yes # Check system packages
      ansible.builtin.command:
        cmd: "pacman -Qm {{ item }}" # Check if package exists in AUR db
      loop: "{{ aur_packages | default([]) }}"
      register: aur_check_result
      changed_when: false
      failed_when: aur_check_result.rc != 0 # Fail if pacman -Qm returns error (not found)
      when: aur_packages is defined and aur_packages | length > 0
      tags: [aur, verification]

  post_tasks: # <<< Corrected Indentation
    # *** Post tasks run last ***
    - name: Stage 2 | Enable system-wide services defined in config
      become: yes
      ansible.builtin.systemd_service:
        name: "{{ item }}"
        enabled: yes
        state: "{{ 'started' if item in ['docker.service', 'seatd.service', 'nftables.service', 'ufw.service', 'iio-sensor-proxy.service', 'tlp.service'] else omit }}"
      loop: "{{ enabled_services | default([]) }}"
      register: service_enable_result
      failed_when: service_enable_result.failed
      when: enabled_services is defined and enabled_services | length > 0
      tags: [always]
    - name: Stage 2 | Enable Docker service (conditional)
      become: yes
      ansible.builtin.systemd_service:
        name: docker.service
        enabled: yes
        state: started
      register: docker_enable_result
      failed_when: docker_enable_result.failed
      when: install_docker | default(false) | bool
      tags: [always]
    - name: Stage 2 | Gather service facts
      become: yes
      ansible.builtin.service_facts:
      tags: [always, verification]
    - name: Stage 2 | Verify required system services are running
      become: yes
      ansible.builtin.assert:
        that:
          - ansible_facts.services[item + ".service"] is defined
          - ansible_facts.services[item + ".service"].state == 'running' # Check for 'running' as reported by service_facts
        fail_msg: "Service {{ item }}.service is not running! State: {{ ansible_facts.services[item + '.service'].state | default('N/A') }}"
        quiet: yes
      loop:
        - NetworkManager
        - sshd
        - avahi-daemon
        - seatd
        - tlp
        - "{{ 'nftables' if firewall_choice == 'nftables' else ('ufw' if firewall_choice == 'ufw' else '') }}"
        - "{{ 'iio-sensor-proxy' if install_autorotation | default(false) | bool else '' }}"
        - "{{ 'docker' if install_docker | default(false) | bool else '' }}"
      when: item | length > 0 # Only check items that have a non-empty name
      tags: [always, verification]
    - name: Stage 2 | Clean up temporary first-boot Wi-Fi connection service
      become: yes
      when: configure_wifi_in_stage1 | default(false) | bool
      block:
        - name: Stage 2 | Disable and stop temporary first-boot service
          ansible.builtin.systemd_service:
            name: connect-wifi-first-boot.service
            enabled: no
            state: stopped
          failed_when: false
        - name: Stage 2 | Remove temporary first-boot service file
          ansible.builtin.file:
            path: /etc/systemd/system/connect-wifi-first-boot.service
            state: absent
        - name: Stage 2 | Remove temporary first-boot script file
          ansible.builtin.file:
            path: /usr/local/bin/connect-wifi-first-boot.sh
            state: absent
      tags: [always]
    - name: Stage 2 | Final message
      ansible.builtin.debug:
        msg: |
          ---------------------------------------------------------------------
          TWO-STAGE ANSIBLE RUN COMPLETE!

          >>> REVIEW & MANUAL STEPS REQUIRED NEXT <<<

          1. Log out and log back in as '{{ target_user }}' for group changes (e.g., Docker) to take effect.
          2. Verify network connection ('nmcli c s --active', 'ping google.com').
          3. Verify yay and AUR packages installed ('yay -Q | grep -E "{{ aur_packages | join('|') }}"').
          4. Verify Git config ('git config --global user.name', 'git config --global credential.helper', 'git config --global credential.credentialStore').
          5. **Verify GCM:** If enabled, try cloning a private GitHub repository using HTTPS. It should use the cached credentials without prompting:
             $ git clone https://github.com/YOUR_USERNAME/YOUR_PRIVATE_REPO.git
             (If it prompts, check GCM setup and vault variables).
          6. **Configure Autorotation:** Manually edit '/usr/local/bin/sway-autorotate.sh' and set the correct 'TABLET_MODE_SYSFS_PATH' for your hardware.
             $ sudo nano /usr/local/bin/sway-autorotate.sh
             $ systemctl --user restart sway-autorotate.service
          7. **Configure Qt Theming:** Run 'qt5ct' and 'qt6ct'. Select 'adwaita-dark' (or your preferred theme) and 'Papirus-Dark' icons. Apply and save.
          8. **Configure nwg-bar:** If you want the pop-up bar behavior, you'll need to manually configure nwg-bar and potentially bind it to a key in your Sway config. Refer to nwg-bar documentation.
          9. Check '~/.bashrc' and '~/.config/alacritty/alacritty.yml' were configured as expected.
          10. Start Sway: $ sway (from TTY after logging in as '{{ target_user }}')
          11. Test everything! (Swap, MicroSD mount, gestures, wallpaper, apps, power management, firewall rules, etc.)
          ---------------------------------------------------------------------
      tags: [always]
EOF


# --- Populate Role Tasks ---
log_info "Populating role tasks (tasks/main.yml)..."
# (Content of role tasks - Copied from previous versions, with network role fix)
# roles/base_system/tasks/main.yml
create_file_with_heredoc "${PROJECT_DIR}/roles/base_system/tasks/main.yml" << 'EOF'
---
# Tasks for installing the Arch Linux base system (Role: base_system) - Stage 1
- name: Base | Verify Essential Variables
  ansible.builtin.assert: { that: [target_disk is defined, target_existing_partitions is defined, target_hostname is defined, locale_lang is defined, timezone is defined, keymap is defined, bootloader is defined, vault_root_password_hash is defined, vault_ldeen_password_hash is defined, controller_root_private_key_file is defined, target_user_ssh_pub_key is defined, base_packages is defined, target_user is defined, target_user_shell is defined], fail_msg: "Required variables not defined/complete in group_vars/all/config.yml or vault.yml not loaded.", quiet: yes }
- name: Base | Check boot mode matches EFI requirement if specified
  ansible.builtin.stat: { path: /sys/firmware/efi/efivars }
  register: efi_check
  ignore_errors: yes
  when: boot_mode == 'UEFI'
- name: Base | Validate boot mode configuration vs reality
  ansible.builtin.fail: { msg: "Configured boot_mode 'UEFI' but EFI vars not found at /sys/firmware/efi/efivars." }
  when: boot_mode == 'UEFI' and not efi_check.stat.exists
- name: Base | Verify specified existing partitions exist on target disk
  ansible.builtin.stat: { path: "{{ item.device }}" }
  register: partition_stat_result
  loop: "{{ target_existing_partitions }}"
  loop_control: { label: "{{ item.device }}" }
  failed_when: not partition_stat_result.stat.exists or not partition_stat_result.stat.isblk
- name: Base | Unmount any existing mounts on target partitions (safety measure)
  ansible.posix.mount: { path: "{{ item.device }}", state: unmounted }
  loop: "{{ target_existing_partitions }}"
  loop_control: { label: "{{ item.device }}" }
  failed_when: false
- name: Base | Unmount any existing mounts within potential /mnt (safety measure)
  ansible.builtin.command: { cmd: "umount -R /mnt" }
  changed_when: false
  failed_when: false
- name: Base | Inform user about formatting existing partitions
  ansible.builtin.pause: { prompt: "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n!!! FORMATTING EXISTING PARTITIONS !!!\nThe next steps will REFORMAT the following EXISTING partitions on '{{ target_disk }}':\n{% for part in target_existing_partitions %}- Device: {{ part.device }}, Intended Mount: {{ part.mount_point }}, FS: {{ part.filesystem }}\n{% endfor %}ALL DATA on these partitions ({{ target_existing_partitions | map(attribute='device') | join(', ') }}) will be WIPED.\nPress Enter to continue, or Ctrl+C then 'A' to abort.\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", echo: yes }
- name: Base | Format non-EFI partitions
  community.general.filesystem: { device: "{{ item.device }}", fstype: "{{ item.filesystem }}", force: yes, opts: "{{ filesystem_options[item.mount_point] | default(omit) }}" }
  loop: "{{ target_existing_partitions }}"
  loop_control: { label: "{{ item.device }}" }
  when: item.filesystem not in ['vfat', 'linux-swap', 'none']
  register: format_result
  failed_when: format_result.failed
- name: Base | Format EFI partition (FAT32)
  community.general.filesystem: { device: "{{ item.device }}", fstype: "vfat", force: yes, opts: "{{ filesystem_options[item.mount_point] | default('-F 32') }}" }
  loop: "{{ target_existing_partitions }}"
  loop_control: { label: "{{ item.device }}" }
  when: item.filesystem == 'vfat'
  register: format_efi_result
  failed_when: format_efi_result.failed
- name: Base | Find root partition details from config
  ansible.builtin.set_fact: { root_part_info: "{{ target_existing_partitions | selectattr('mount_point', 'equalto', '/') | first }}" }
- name: Base | Mount root partition to /mnt
  ansible.posix.mount: { path: /mnt, src: "{{ root_part_info.device }}", fstype: "{{ root_part_info.filesystem }}", state: mounted }
  register: mount_root_result
  failed_when: mount_root_result.failed
- name: Base | Create other mount point directories within /mnt
  ansible.builtin.file: { path: "/mnt{{ item.mount_point }}", state: directory, mode: '0755' }
  loop: "{{ target_existing_partitions | sort(attribute='mount_point') }}"
  loop_control: { label: "{{ item.mount_point }}" }
  when: item.mount_point not in ['/', 'none'] and item.mount_point is defined
- name: Base | Mount other partitions within /mnt (sorted by path)
  ansible.posix.mount: { path: "/mnt{{ item.mount_point }}", src: "{{ item.device }}", fstype: "{{ item.filesystem }}", state: mounted, opts: "{{ 'defaults,noatime' if item.filesystem == 'ext4' else 'defaults' }}" }
  loop: "{{ target_existing_partitions | sort(attribute='mount_point') }}"
  loop_control: { label: "{{ item.mount_point }}" }
  when: item.mount_point not in ['/', 'none'] and item.mount_point is defined
  register: mount_other_result
  failed_when: mount_other_result.failed
- name: Base | Update mirrorlist before pacstrap
  ansible.builtin.command: { cmd: "pacman -Syy" }
  changed_when: false
  failed_when: false
- name: Base | Run pacstrap to install base system and essential packages
  ansible.builtin.command: { cmd: "pacstrap -K /mnt {{ base_packages | join(' ') }}" }
  register: pacstrap_result
  changed_when: true
  failed_when: pacstrap_result.rc != 0
- name: Base | Generate fstab using UUIDs
  ansible.builtin.command: { cmd: "genfstab -U /mnt" }
  register: genfstab_result
  changed_when: false
  failed_when: genfstab_result.rc != 0 or genfstab_result.stdout | length < 10
- name: Base | Write fstab to new system
  ansible.builtin.copy: { content: "{{ genfstab_result.stdout }}", dest: /mnt/etc/fstab, mode: '0644' }
  register: fstab_write_result
  failed_when: fstab_write_result.failed
- name: Base | Verify fstab content (basic check)
  ansible.builtin.assert: { that: ["'/' in genfstab_result.stdout", "'UUID=' in genfstab_result.stdout"], fail_msg: "Generated fstab appears incomplete or invalid.", quiet: yes }
- name: Base | Set hostname via chroot
  ansible.builtin.command: { cmd: "arch-chroot /mnt hostnamectl set-hostname {{ target_hostname }}" }
  changed_when: true
  register: set_hostname_result
  failed_when: set_hostname_result.rc != 0
- name: Base | Set timezone link via chroot
  ansible.builtin.command: { cmd: "arch-chroot /mnt ln -sf /usr/share/zoneinfo/{{ timezone }} /etc/localtime" }
  changed_when: true
  register: set_timezone_result
  failed_when: set_timezone_result.rc != 0
- name: Base | Set hardware clock via chroot
  ansible.builtin.command: { cmd: "arch-chroot /mnt hwclock --systohc" }
  changed_when: true
  register: set_hwclock_result
  failed_when: set_hwclock_result.rc != 0
- name: Base | Configure locale.gen via chroot
  ansible.builtin.lineinfile: { path: /mnt/etc/locale.gen, regexp: "^#\\s*({{ locale_lang }}\\s+UTF-8)", line: "\\1", backrefs: yes }
  register: locale_gen_change
  notify: Generate locale via chroot
  failed_when: locale_gen_change.failed
- name: Base | Flush handlers to run locale-gen before reboot
  ansible.builtin.meta: flush_handlers
- name: Base | Set default locale in locale.conf via chroot
  ansible.builtin.copy: { content: "LANG={{ locale_lang }}\n", dest: /mnt/etc/locale.conf, mode: '0644' }
  register: set_locale_conf_result
  failed_when: set_locale_conf_result.failed
- name: Base | Set console keymap in vconsole.conf via chroot
  ansible.builtin.copy: { content: "KEYMAP={{ keymap }}\n", dest: /mnt/etc/vconsole.conf, mode: '0644' }
  register: set_vconsole_result
  failed_when: set_vconsole_result.failed
- name: Base | Generate initramfs via chroot
  ansible.builtin.command: { cmd: "arch-chroot /mnt mkinitcpio -P" }
  changed_when: true
  register: mkinitcpio_result
  failed_when: mkinitcpio_result.rc != 0
- name: Base | Set root password using HASH from Vault via chroot
  ansible.builtin.command: { cmd: "arch-chroot /mnt usermod -p '{{ vault_root_password_hash }}' root" }
  changed_when: true
  no_log: true
  register: set_root_pass_result
  failed_when: set_root_pass_result.rc != 0
- name: Base | Get EFI mount point from config
  ansible.builtin.set_fact: { efi_mount_point_on_target: "{{ target_existing_partitions | selectattr('mount_point', 'equalto', '/boot/efi') | map(attribute='mount_point') | first | default('/boot/efi') }}" }
  when: bootloader == 'grub' and boot_mode == 'UEFI'
- name: Base | Install GRUB bootloader via chroot (UEFI)
  ansible.builtin.command: { cmd: "arch-chroot /mnt grub-install --target=x86_64-efi --efi-directory={{ efi_mount_point_on_target }} --bootloader-id={{ grub_bootloader_id | default('GRUB') }} --recheck" }
  changed_when: true
  when: bootloader == 'grub' and boot_mode == 'UEFI'
  register: grub_install_efi_result
  failed_when: grub_install_efi_result.rc != 0
- name: Base | Install GRUB bootloader via chroot (BIOS)
  ansible.builtin.command: { cmd: "arch-chroot /mnt grub-install --target=i386-pc {{ target_disk }} --recheck" }
  changed_when: true
  when: bootloader == 'grub' and boot_mode == 'BIOS'
  register: grub_install_bios_result
  failed_when: grub_install_bios_result.rc != 0
- name: Base | Generate GRUB configuration file via chroot
  ansible.builtin.command: { cmd: "arch-chroot /mnt grub-mkconfig -o /boot/grub/grub.cfg" }
  changed_when: true
  when: bootloader == 'grub'
  register: grub_mkconfig_result
  failed_when: grub_mkconfig_result.rc != 0
- name: Base | Set up temporary first-boot Wi-Fi connection service
  when: [configure_wifi_in_stage1 | default(false) | bool, wifi_ssid is defined, vault_wifi_password is defined]
  block:
    - name: Base | Ensure /usr/local/bin exists in chroot
      ansible.builtin.file: { path: /mnt/usr/local/bin, state: directory, mode: '0755', owner: root, group: root }
    - name: Base | Create first-boot Wi-Fi connection script in chroot
      ansible.builtin.copy: { dest: /mnt/usr/local/bin/connect-wifi-first-boot.sh, owner: root, group: root, mode: '0755', content: "#!/bin/bash\n# Set hostname, restart Avahi, connect Wi-Fi on first boot.\n/usr/bin/hostnamectl set-hostname {{ target_hostname }}\n/usr/bin/systemctl restart avahi-daemon.service || true\nsleep 15\n/usr/bin/nmcli device wifi connect '{{ wifi_ssid }}' password '{{ vault_wifi_password }}'\nexit 0" }
    - name: Base | Create systemd service file for first-boot Wi-Fi connection
      ansible.builtin.copy: { dest: /mnt/etc/systemd/system/connect-wifi-first-boot.service, owner: root, group: root, mode: '0644', content: "[Unit]\nDescription=Set hostname, restart Avahi, and connect WiFi on first boot\nWants=NetworkManager.service avahi-daemon.service\nAfter=NetworkManager.service avahi-daemon.service network.target\nBefore=network-online.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/local/bin/connect-wifi-first-boot.sh\n\n[Install]\nWantedBy=multi-user.target" }
    - name: Base | Enable temporary first-boot Wi-Fi service via chroot
      ansible.builtin.command: { cmd: "arch-chroot /mnt systemctl enable connect-wifi-first-boot.service" }
      changed_when: true
      register: enable_wifi_service_result
      failed_when: enable_wifi_service_result.rc != 0
- name: Base | Ensure NetworkManager is enabled via chroot
  ansible.builtin.command: { cmd: "arch-chroot /mnt systemctl enable NetworkManager.service" }
  changed_when: true
  register: enable_nm_result
  failed_when: enable_nm_result.rc != 0
- name: Base | Ensure SSH daemon is enabled via chroot
  ansible.builtin.command: { cmd: "arch-chroot /mnt systemctl enable sshd.service" }
  changed_when: true
  register: enable_sshd_result
  failed_when: enable_sshd_result.rc != 0
- name: Base | Ensure Avahi daemon is enabled via chroot
  ansible.builtin.command: { cmd: "arch-chroot /mnt systemctl enable avahi-daemon.service" }
  changed_when: true
  register: enable_avahi_result
  failed_when: enable_avahi_result.rc != 0
- name: Base | Create target user '{{ target_user }}' with wheel group via chroot
  ansible.builtin.command: { cmd: "arch-chroot /mnt useradd -m -U -G wheel -s {{ target_user_shell | default('/bin/bash') }} {{ target_user }}", creates: "/mnt/home/{{ target_user }}" }
  changed_when: true
  register: create_user_result
  failed_when: create_user_result.rc != 0 and 'already exists' not in create_user_result.stderr
- name: Base | Set target user password using HASH from Vault via chroot
  ansible.builtin.command: { cmd: "arch-chroot /mnt usermod -p '{{ vault_ldeen_password_hash }}' {{ target_user }}" }
  changed_when: true
  no_log: true
  register: set_user_pass_result
  failed_when: set_user_pass_result.rc != 0
- name: Base | Verify target user password field was updated in /etc/shadow
  ansible.builtin.command: { cmd: "arch-chroot /mnt awk -F: -v user={{ target_user }} '$1 == user {print $2}' /etc/shadow" }
  register: shadow_check
  changed_when: false
  failed_when: shadow_check.rc != 0 or shadow_check.stdout == "" or shadow_check.stdout.startswith('!') or shadow_check.stdout.startswith('*') or shadow_check.stdout != vault_ldeen_password_hash
  no_log: true
- name: Base | Ensure .ssh directory exists for root in new system
  ansible.builtin.file: { path: /mnt/root/.ssh, state: directory, owner: root, group: root, mode: '0700' }
- name: Base | Get absolute path to controller's root private key
  ansible.builtin.set_fact: { controller_root_private_key_abs: "{{ controller_root_private_key_file.replace('~', lookup('env', 'HOME')) }}" }
  delegate_to: localhost
  become: no
- name: Base | Construct path to controller's root public key
  ansible.builtin.set_fact: { controller_root_public_key_abs: "{{ controller_root_private_key_abs.replace('.pub','') + '.pub' }}" }
  delegate_to: localhost
  become: no
- name: Base | Verify controller root public key file exists
  ansible.builtin.stat: { path: "{{ controller_root_public_key_abs }}" }
  register: root_public_key_stat
  delegate_to: localhost
  become: no
- name: Base | Fail if controller root public key file not found
  ansible.builtin.fail: { msg: "Controller root public SSH key not found at {{ controller_root_public_key_abs }}. Cannot proceed." }
  when: not root_public_key_stat.stat.exists
  delegate_to: localhost
  become: no
- name: Base | Copy Controller's SSH public key for root login to new system
  ansible.posix.authorized_key: { user: root, key: "{{ lookup('file', controller_root_public_key_abs ) }}", path: /mnt/root/.ssh/authorized_keys, state: present, manage_dir: no }
- name: Base | Ensure .ssh directory exists for target user via chroot
  ansible.builtin.command: { cmd: "arch-chroot /mnt install -d -o {{ target_user }} -g {{ target_user }} -m 700 /home/{{ target_user }}/.ssh", creates: "/mnt/home/{{ target_user }}/.ssh" }
  changed_when: true
- name: Base | Ensure authorized_keys file exists for target user via chroot
  ansible.builtin.command: { cmd: "arch-chroot /mnt install -o {{ target_user }} -g {{ target_user }} -m 600 /dev/null /home/{{ target_user }}/.ssh/authorized_keys", creates: "/mnt/home/{{ target_user }}/.ssh/authorized_keys" }
  changed_when: true
- name: Base | Copy user's specified SSH public key content into file
  ansible.builtin.copy: { content: "{{ target_user_ssh_pub_key }}\n", dest: "/mnt/home/{{ target_user }}/.ssh/authorized_keys", mode: '0644' }
  when: target_user_ssh_pub_key is defined and target_user_ssh_pub_key | length > 10 and 'AAAA' in target_user_ssh_pub_key
- name: Base | Set correct ownership and permissions on user .ssh dir and contents via chroot
  ansible.builtin.shell: { cmd: "arch-chroot /mnt chown -R {{ target_user }}:{{ target_user }} /home/{{ target_user }}/.ssh && arch-chroot /mnt chmod 700 /home/{{ target_user }}/.ssh && arch-chroot /mnt chmod 600 /home/{{ target_user }}/.ssh/authorized_keys" }
  changed_when: true
  when: target_user_ssh_pub_key is defined and target_user_ssh_pub_key | length > 10 and 'AAAA' in target_user_ssh_pub_key
  register: set_user_ssh_perms_result
  failed_when: set_user_ssh_perms_result.rc != 0
- name: Base | Configure passwordless sudo for wheel group via chroot
  ansible.builtin.lineinfile: { path: /mnt/etc/sudoers, state: present, regexp: '^%wheel ALL=\(ALL:ALL\) NOPASSWD: ALL', line: '%wheel ALL=(ALL:ALL) NOPASSWD: ALL', validate: '/usr/sbin/visudo -cf %s' }
  register: sudoers_result
  failed_when: sudoers_result.failed
- name: Base | Sync filesystem buffers to disk
  ansible.builtin.command: sync
  changed_when: false
- name: Base | Reboot the machine (async)
  ansible.builtin.shell: "sleep 5 && reboot"
  async: 1
  poll: 0
  changed_when: true
EOF

# roles/base_system/handlers/main.yml
create_file_with_heredoc "${PROJECT_DIR}/roles/base_system/handlers/main.yml" << 'EOF'
---
# Handlers for role base_system
- name: Generate locale via chroot
  listen: "Generate locale via chroot"
  ansible.builtin.command: { cmd: "arch-chroot /mnt locale-gen" }
  changed_when: true
  register: locale_gen_handler_result
  failed_when: locale_gen_handler_result.rc != 0
EOF

# roles/common/tasks/main.yml
create_file_with_heredoc "${PROJECT_DIR}/roles/common/tasks/main.yml" << 'EOF'
---
# Common configuration tasks for the newly installed Arch system (Role: common) - Stage 2
- name: Common | Update pacman database
  become: yes
  ansible.builtin.pacman: { update_cache: yes }
  register: pacman_update_result
  failed_when: pacman_update_result.failed
- name: Common | Upgrade all system packages
  become: yes
  ansible.builtin.pacman: { upgrade: yes }
  register: pacman_upgrade_result
  failed_when: pacman_upgrade_result.failed
- name: Common | Install base development tools (ensure present)
  become: yes
  ansible.builtin.package: { name: base-devel, state: present }
  register: base_devel_result
  failed_when: base_devel_result.failed
- name: Common | Ensure git is installed (needed for yay and GCM)
  become: yes
  ansible.builtin.package: { name: git, state: present }
  register: git_install_result
  failed_when: git_install_result.failed
- name: Common | Check if yay is already installed
  ansible.builtin.command: which yay
  register: yay_check
  changed_when: false
  failed_when: false
  check_mode: no
- name: Common | Install yay AUR helper
  when: yay_check.rc != 0
  block:
    - name: Common | Create temporary build directory for yay
      become: yes
      become_user: "{{ target_user }}"
      ansible.builtin.tempfile: { state: directory, prefix: yay_build_ }
      register: yay_build_dir_result
    - name: Common | Clone yay repository from AUR into temp dir
      become: yes
      become_user: "{{ target_user }}"
      ansible.builtin.git: { repo: 'https://aur.archlinux.org/yay.git', dest: "{{ yay_build_dir_result.path }}", version: master }
      register: yay_clone_result
      failed_when: yay_clone_result.failed
    - name: Common | Build and install yay using makepkg
      become: yes
      become_user: "{{ target_user }}"
      ansible.builtin.command: { cmd: makepkg -si --noconfirm, chdir: "{{ yay_build_dir_result.path }}" }
      register: yay_makepkg_result
      failed_when: yay_makepkg_result.rc != 0
      when: yay_clone_result.changed
  always:
    - name: Common | Clean up yay build directory
      become: yes
      become_user: "{{ target_user }}"
      ansible.builtin.file: { path: "{{ yay_build_dir_result.path }}", state: absent }
      when: yay_build_dir_result.path is defined
- name: Common | Verify yay command is available after installation attempt
  ansible.builtin.command: which yay
  register: yay_check_after
  changed_when: false
  failed_when: yay_check_after.rc != 0
  check_mode: no
- name: Common | Install essential helper packages and Extra Packages from config
  become: yes
  ansible.builtin.package: { name: "{{ extra_packages | default([]) }}", state: present }
  register: extra_pkgs_result
  failed_when: extra_pkgs_result.failed
  when: extra_packages is defined and extra_packages | length > 0
- name: Common | Set kernel swappiness parameter via sysctl
  become: yes
  ansible.posix.sysctl: { name: vm.swappiness, value: "{{ root_swappiness | default(60) }}", sysctl_file: /etc/sysctl.d/99-swappiness.conf, state: present, reload: yes }
  register: sysctl_swappiness_result
  failed_when: sysctl_swappiness_result.failed
- name: Common | Verify kernel swappiness parameter is set correctly
  become: yes
  ansible.builtin.command: { cmd: "sysctl -n vm.swappiness" }
  register: swappiness_check_result
  changed_when: false
  failed_when: swappiness_check_result.rc != 0 or swappiness_check_result.stdout | int != (root_swappiness | default(60) | int)
  check_mode: no
EOF

# roles/users/tasks/main.yml
create_file_with_heredoc "${PROJECT_DIR}/roles/users/tasks/main.yml" << 'EOF'
---
# Tasks to verify/finalize user setup, Git, and Git Credential Manager (Role: users) - Stage 2
- name: Users | Verify essential user variables
  ansible.builtin.assert:
    that:
      - target_user is defined
      - vault_ldeen_password_hash is defined
      - vault_ldeen_password_hash is match('^\\$6\\$')
      - target_user_groups is defined
      - git_user_name is defined
      - git_user_email is defined
      - git_credential_manager_enabled is defined
      - (not (git_credential_manager_enabled | default(false) | bool)) or (vault_github_username is defined and vault_github_password is defined)
    fail_msg: "User config requires target_user, target_user_groups, git_user_name, git_user_email, git_credential_manager_enabled in config.yml and a valid vault_ldeen_password_hash (SHA512) in vault.yml. If GCM enabled, vault_github_username and vault_github_password are also required."
    quiet: yes
- name: Users | Determine final user groups including conditional docker group
  ansible.builtin.set_fact: { final_user_groups: "{{ (target_user_groups | default('wheel') | split(',')) + (['docker'] if install_docker | default(false) | bool else []) }}" }
- name: Users | Ensure target user '{{ target_user }}' exists and has correct groups
  become: yes
  ansible.builtin.user: { name: "{{ target_user }}", state: present, groups: "{{ final_user_groups | join(',') }}", append: yes }
  register: user_mod_result
  failed_when: user_mod_result.failed
- name: Users | Verify target user group membership
  become: yes
  ansible.builtin.command: { cmd: "groups {{ target_user }}" }
  register: user_groups_check
  changed_when: false
  failed_when: user_groups_check.rc != 0
  check_mode: no
- name: Users | Assert target user is in required groups
  ansible.builtin.assert: { that: [item in user_groups_check.stdout], fail_msg: "User '{{ target_user }}' is not a member of required group '{{ item }}'. Current groups: {{ user_groups_check.stdout }}", quiet: yes }
  loop: "{{ final_user_groups }}"
- name: Users | Verify target user password hash matches Vault
  become: yes
  ansible.builtin.command: { cmd: "getent shadow {{ target_user }}" }
  register: current_shadow_entry
  changed_when: false
  check_mode: no
  no_log: true
  failed_when: current_shadow_entry.rc != 0 or (current_shadow_entry.stdout | regex_replace('^[^:]+:') | regex_replace(':.*$') != vault_ldeen_password_hash)
- name: Users | Verify 'wheel' group members have passwordless sudo (check sudoers)
  become: yes
  ansible.builtin.lineinfile: { path: /etc/sudoers, state: present, regexp: '^%wheel ALL=\(ALL:ALL\) NOPASSWD: ALL', line: '%wheel ALL=(ALL:ALL) NOPASSWD: ALL', validate: '/usr/sbin/visudo -cf %s' }
  check_mode: yes
- name: Users | Verify user SSH key exists in authorized_keys
  ansible.builtin.stat: { path: "/home/{{ target_user }}/.ssh/authorized_keys" }
  register: user_auth_keys_stat
- name: Users | Check content of user authorized_keys (optional)
  become: yes
  ansible.builtin.slurp: { src: "/home/{{ target_user }}/.ssh/authorized_keys" }
  register: user_auth_keys_content
  when: user_auth_keys_stat.stat.exists
  check_mode: no
- name: Users | Assert user SSH key is present
  ansible.builtin.assert: { that: [user_auth_keys_stat.stat.exists, target_user_ssh_pub_key in (user_auth_keys_content.content | b64decode)], fail_msg: "Target user SSH key was not found or doesn't match config in /home/{{ target_user }}/.ssh/authorized_keys" }
  when: [target_user_ssh_pub_key is defined, user_auth_keys_stat.stat.exists, user_auth_keys_content.content is defined]
- name: Users | Configure Git global user name
  become: yes
  become_user: "{{ target_user }}"
  community.general.git_config:
    name: user.name
    scope: global
    value: "{{ git_user_name }}"
    state: present
  when: git_user_name | default('') | length > 0
- name: Users | Configure Git global user email
  become: yes
  become_user: "{{ target_user }}"
  community.general.git_config:
    name: user.email
    scope: global
    value: "{{ git_user_email }}"
    state: present
  when: git_user_email | default('') | length > 0

# --- Git Credential Manager (GCM) Setup ---
- name: Users | Install and Configure Git Credential Manager
  when: git_credential_manager_enabled | default(false) | bool
  become: yes
  become_user: "{{ target_user }}"
  block:
    - name: GCM | Check if GCM is already installed
      ansible.builtin.command: which git-credential-manager
      register: gcm_check
      failed_when: false
      changed_when: false
      check_mode: no
    - name: GCM | Install GCM using source helper script
      # Needs curl installed (should be handled by 'common' role or 'extra_packages')
      # Runs the script as the target user
      ansible.builtin.shell:
        cmd: "curl -L https://aka.ms/gcm/linux-install-source.sh | sh"
        warn: false # The script itself prints messages
      environment:
        # Ensure user's PATH is likely available if running via sudo/become
        PATH: "/home/{{ target_user }}/.local/bin:/usr/local/bin:/usr/bin:/bin"
      args:
        executable: /bin/bash
      register: gcm_install_result
      failed_when: gcm_install_result.rc != 0
      changed_when: "'Installing Git Credential Manager' in gcm_install_result.stdout"
      when: gcm_check.rc != 0 # Only run if GCM command not found
    - name: GCM | Verify GCM command is available after installation attempt
      ansible.builtin.command: which git-credential-manager
      register: gcm_check_after
      changed_when: false
      failed_when: gcm_check_after.rc != 0
      check_mode: no
    - name: GCM | Configure GCM system-wide for the user
      ansible.builtin.command:
        cmd: "git-credential-manager configure"
      environment:
        PATH: "/home/{{ target_user }}/.local/bin:/usr/local/bin:/usr/bin:/bin"
      register: gcm_configure_result
      # Configure might return non-zero if already configured, check stderr
      failed_when: gcm_configure_result.rc != 0 and 'already configured' not in gcm_configure_result.stderr | lower
      changed_when: "'Git Credential Manager has been configured successfully' in gcm_configure_result.stdout"
    - name: GCM | Set credential store to cache
      community.general.git_config:
        name: credential.credentialStore
        scope: global
        value: cache
        state: present
      register: gcm_set_store_result
      failed_when: gcm_set_store_result.failed
    - name: GCM | Pre-seed GitHub credentials into GCM cache store
      ansible.builtin.shell:
        # Use printf to format input for 'git-credential-manager store'
        # Keys: protocol, host, username, password. Ends with blank line.
        cmd: 'printf "protocol=https\nhost=github.com\nusername=%s\npassword=%s\n\n" "{{ vault_github_username }}" "{{ vault_github_password }}" | git-credential-manager store'
        warn: false # Avoid warning about using shell
      environment:
        PATH: "/home/{{ target_user }}/.local/bin:/usr/local/bin:/usr/bin:/bin"
      args:
        executable: /bin/bash
      register: gcm_store_result
      failed_when: gcm_store_result.rc != 0
      changed_when: true # Assume credentials updated/added
      no_log: true # IMPORTANT: Do not log the command or output containing the password

- name: Users | Verify GCM configuration (credentialStore setting)
  become: yes
  become_user: "{{ target_user }}"
  community.general.git_config:
    name: credential.credentialStore
    scope: global
  register: gcm_verify_store
  check_mode: no
  when: git_credential_manager_enabled | default(false) | bool
- name: Users | Assert GCM credential store is set to cache
  ansible.builtin.assert:
    that:
      - gcm_verify_store.value == 'cache'
    fail_msg: "Git credential.credentialStore is not set to 'cache'. Current value: {{ gcm_verify_store.value | default('Not Set') }}"
    quiet: yes
  when: git_credential_manager_enabled | default(false) | bool

# --- XDG User Directories ---
- name: Users | Run xdg-user-dirs-update to create standard directories
  become: yes
  become_user: "{{ target_user }}"
  ansible.builtin.command: { cmd: "xdg-user-dirs-update", creates: "/home/{{ target_user }}/Documents" }
  changed_when: true
  register: xdg_update_result
  failed_when: xdg_update_result.rc != 0 and 'No skeleton directory' not in xdg_update_result.stderr
- name: Users | Verify standard XDG directories exist
  ansible.builtin.stat: { path: "/home/{{ target_user }}/{{ item }}" }
  loop: [Desktop, Documents, Downloads, Music, Pictures, Public, Templates, Videos]
  register: xdg_dirs_stat
  failed_when: not xdg_dirs_stat.stat.exists or not xdg_dirs_stat.stat.isdir
EOF

# roles/swap/tasks/main.yml
create_file_with_heredoc "${PROJECT_DIR}/roles/swap/tasks/main.yml" << 'EOF'
---
# Tasks for Swap Files setup (Role: swap) - Stage 2
- name: Swap | Create primary swap file on root filesystem
  become: yes
  when: create_primary_swap | default(false) | bool
  block:
    - name: Swap | Ensure primary swap file exists with correct size (using fallocate)
      ansible.builtin.command: { cmd: "fallocate -l {{ primary_swap_size }} {{ primary_swap_path }}", creates: "{{ primary_swap_path }}" }
      register: fallocate_primary_result
      changed_when: fallocate_primary_result.rc == 0 and fallocate_primary_result.stdout is search('created')
      failed_when: fallocate_primary_result.rc != 0 and 'already exists' not in fallocate_primary_result.stderr
    - name: Swap | Verify primary swap file size and existence
      ansible.builtin.stat: { path: "{{ primary_swap_path }}" }
      register: primary_swap_stat
      failed_when: not primary_swap_stat.stat.exists or primary_swap_stat.stat.size != (primary_swap_size | human_to_bytes)
    - name: Swap | Set permissions for primary swap file
      ansible.builtin.file: { path: "{{ primary_swap_path }}", owner: root, group: root, mode: '0600' }
      register: primary_chmod_result
      failed_when: primary_chmod_result.failed
    - name: Swap | Check if primary path is already formatted as swap
      ansible.builtin.command: { cmd: "blkid -p -o value -s TYPE {{ primary_swap_path }}" }
      register: primary_blkid_result
      changed_when: false
      failed_when: false
    - name: Swap | Format primary swap file if not already formatted
      community.general.filesystem: { fstype: swap, device: "{{ primary_swap_path }}", force: no }
      register: primary_mkswap_result
      failed_when: primary_mkswap_result.failed
      when: "'swap' not in primary_blkid_result.stdout | default('')"
    - name: Swap | Add primary swap file to /etc/fstab
      ansible.posix.mount: { path: none, src: "{{ primary_swap_path }}", fstype: swap, opts: "sw,pri={{ primary_swap_priority | default('-2') }}", state: present }
      register: primary_fstab_result
      failed_when: primary_fstab_result.failed
    - name: Swap | Activate primary swapfile if not active
      ansible.builtin.command: { cmd: "swapon {{ primary_swap_path }}" }
      when: primary_swap_path not in ansible_facts.mounts | map(attribute='device') | list
      changed_when: true
      register: primary_swapon_result
      failed_when: primary_swapon_result.rc != 0
- name: Swap | Setup secondary swap file on MicroSD
  become: yes
  when: [create_secondary_swap | default(false) | bool, use_microsd | default(false) | bool]
  block:
    - name: Swap | Set secondary swap file path fact
      ansible.builtin.set_fact: { secondary_swap_file_path: "{{ microsd_mount_point }}/{{ secondary_swap_path_relative }}" }
    - name: Swap | Verify MicroSD mount point exists (dependency check)
      ansible.builtin.stat: { path: "{{ microsd_mount_point }}" }
      register: microsd_mountpoint_stat
    - name: Swap | Fail if MicroSD mount point doesn't exist
      ansible.builtin.fail: { msg: "MicroSD mount point '{{ microsd_mount_point }}' must exist before creating swapfile there." }
      when: not microsd_mountpoint_stat.stat.exists or not microsd_mountpoint_stat.stat.isdir
    - name: Swap | Ensure secondary swap file exists with correct size (using fallocate)
      ansible.builtin.command: { cmd: "fallocate -l {{ secondary_swap_size }} {{ secondary_swap_file_path }}", creates: "{{ secondary_swap_file_path }}" }
      register: fallocate_secondary_result
      changed_when: fallocate_secondary_result.rc == 0 and fallocate_secondary_result.stdout is search('created')
      failed_when: fallocate_secondary_result.rc != 0 and 'already exists' not in fallocate_secondary_result.stderr
    - name: Swap | Verify secondary swap file size and existence
      ansible.builtin.stat: { path: "{{ secondary_swap_file_path }}" }
      register: secondary_swap_stat
      failed_when: not secondary_swap_stat.stat.exists or secondary_swap_stat.stat.size != (secondary_swap_size | human_to_bytes)
    - name: Swap | Set permissions for secondary swap file
      ansible.builtin.file: { path: "{{ secondary_swap_file_path }}", owner: root, group: root, mode: '0600' }
      register: secondary_chmod_result
      failed_when: secondary_chmod_result.failed
    - name: Swap | Check if secondary path is already formatted as swap
      ansible.builtin.command: { cmd: "blkid -p -o value -s TYPE {{ secondary_swap_file_path }}" }
      register: secondary_blkid_result
      changed_when: false
      failed_when: false
    - name: Swap | Format secondary swap file if not already formatted
      community.general.filesystem: { fstype: swap, device: "{{ secondary_swap_file_path }}", force: no }
      register: secondary_mkswap_result
      failed_when: secondary_mkswap_result.failed
      when: "'swap' not in secondary_blkid_result.stdout | default('')"
    - name: Swap | Add secondary swap file to /etc/fstab
      ansible.posix.mount: { path: none, src: "{{ secondary_swap_file_path }}", fstype: swap, opts: "sw,pri={{ secondary_swap_priority | default('10') }}", state: present }
      register: secondary_fstab_result
      failed_when: secondary_fstab_result.failed
    - name: Swap | Activate secondary swapfile if not active
      ansible.builtin.command: { cmd: "swapon {{ secondary_swap_file_path }}" }
      when: secondary_swap_file_path not in ansible_facts.mounts | map(attribute='device') | list
      changed_when: true
      register: secondary_swapon_result
      failed_when: secondary_swapon_result.rc != 0
- name: Swap | Check active swap devices
  become: yes
  ansible.builtin.command: { cmd: swapon --show=NAME --noheadings }
  register: swapon_output
  changed_when: false
  check_mode: no
- name: Swap | Verify primary swap is active
  ansible.builtin.assert: { that: [primary_swap_path in swapon_output.stdout_lines], fail_msg: "Primary swap file {{ primary_swap_path }} does not appear to be active! Active swaps: {{ swapon_output.stdout_lines | join(', ') }}", quiet: yes }
  when: create_primary_swap | default(false) | bool
- name: Swap | Verify secondary swap is active
  ansible.builtin.assert: { that: [secondary_swap_file_path in swapon_output.stdout_lines], fail_msg: "Secondary swap file {{ secondary_swap_file_path }} does not appear to be active! Active swaps: {{ swapon_output.stdout_lines | join(', ') }}", quiet: yes }
  when: [create_secondary_swap | default(false) | bool, use_microsd | default(false) | bool]
EOF

# roles/storage/tasks/main.yml
create_file_with_heredoc "${PROJECT_DIR}/roles/storage/tasks/main.yml" << 'EOF'
---
# Tasks for mounting additional storage like MicroSD card (Role: storage) - Stage 2
- name: Storage | Get target user UID and GID
  ansible.builtin.getent: { database: passwd, key: "{{ target_user }}" }
  register: target_user_info_storage
  check_mode: no
  when: use_microsd | default(false) | bool
- name: Storage | Check if MicroSD partition device exists
  become: yes
  ansible.builtin.stat: { path: "{{ microsd_partition_to_mount }}" }
  register: microsd_partition_stat
  when: use_microsd | default(false) | bool
- name: Storage | Ensure MicroSD mount point directory exists
  become: yes
  ansible.builtin.file: { path: "{{ microsd_mount_point }}", state: directory, mode: '0755', owner: "{{ target_user }}", group: "{{ target_user_info_storage.ansible_facts.getent_passwd[target_user][3] }}" }
  register: create_mountpoint_result
  failed_when: create_mountpoint_result.failed
  when: [use_microsd | default(false) | bool, microsd_partition_stat.stat.exists | default(false), target_user_info_storage.ansible_facts.getent_passwd is defined]
- name: Storage | Ensure MicroSD is configured in fstab and mounted
  become: yes
  ansible.posix.mount: { src: "{{ microsd_partition_to_mount }}", path: "{{ microsd_mount_point }}", fstype: "{{ microsd_filesystem_type }}", opts: "defaults,nofail,noatime,x-systemd.device-timeout=10s", state: mounted }
  register: mount_microsd_result
  failed_when: mount_microsd_result.failed
  when: [use_microsd | default(false) | bool, microsd_partition_stat.stat.exists | default(false)]
- name: Storage | Verify MicroSD mount point is active
  become: yes
  ansible.builtin.command: { cmd: "mountpoint -q {{ microsd_mount_point }}" }
  register: mountpoint_check
  failed_when: mountpoint_check.rc != 0
  changed_when: false
  check_mode: no
  when: [use_microsd | default(false) | bool, microsd_partition_stat.stat.exists | default(false)]
EOF

# roles/network/tasks/main.yml (Corrected: Removed service_facts check)
create_file_with_heredoc "${PROJECT_DIR}/roles/network/tasks/main.yml" << 'EOF'
---
# Tasks to configure networking (Using NetworkManager) (Role: network) - Stage 2
- name: Network | Ensure NetworkManager package is installed
  become: yes
  ansible.builtin.package: { name: networkmanager, state: present }
  register: nm_pkg_result
  failed_when: nm_pkg_result.failed
- name: Network | Ensure NetworkManager service is enabled and running
  become: yes
  ansible.builtin.systemd_service: { name: NetworkManager.service, enabled: yes, state: started }
  register: nm_service_result
  failed_when: nm_service_result.failed
# Note: Verification that the service is running is implicitly done by the above task
# and explicitly checked using service_facts in the main playbook's post_tasks.
- name: Network | Get NetworkManager general status
  ansible.builtin.command: { cmd: nmcli -t -f STATE general status }
  register: nm_general_status
  changed_when: false
  failed_when: nm_general_status.rc != 0
  check_mode: no
- name: Network | Verify system has network connectivity (general state)
  ansible.builtin.assert: { that: ["'connected' in nm_general_status.stdout"], fail_msg: "NetworkManager general state is not 'connected'. Output: {{ nm_general_status.stdout }}", quiet: yes }
- name: Network | Get active network connections
  become: yes
  ansible.builtin.command:
    cmd: "nmcli -t -f NAME,DEVICE connection show --active" # Explicitly use cmd:
  register: nm_active_connections
  changed_when: false
  failed_when: nm_active_connections.rc != 0
  check_mode: no
- name: Network | Verify expected Wi-Fi connection is active
  ansible.builtin.assert: { that: [wifi_ssid in nm_active_connections.stdout], fail_msg: "Expected Wi-Fi connection '{{ wifi_ssid }}' not found in active connections. Active: {{ nm_active_connections.stdout | default('N/A') }}", quiet: yes }
  when: [configure_wifi_in_stage1 | default(false) | bool, wifi_ssid is defined]
EOF

# roles/network/handlers/main.yml
create_file_with_heredoc "${PROJECT_DIR}/roles/network/handlers/main.yml" << 'EOF'
---
# Handlers for network role
- name: Reload NetworkManager connections
  become: yes
  ansible.builtin.command: { cmd: nmcli connection reload }
  changed_when: false
  listen: "Reload NetworkManager connections"
- name: Restart NetworkManager
  become: yes
  ansible.builtin.systemd_service: { name: NetworkManager.service, state: restarted }
  listen: "Restart NetworkManager"
EOF

# roles/security/tasks/main.yml
create_file_with_heredoc "${PROJECT_DIR}/roles/security/tasks/main.yml" << 'EOF'
---
# Tasks for firewall setup (Role: security) - Stage 2
- name: Security | Determine firewall package name
  ansible.builtin.set_fact: { firewall_package_name: "{% if firewall_choice == 'nftables' %}nftables{% elif firewall_choice == 'ufw' %}ufw{% else %}''{% endif %}" }
  when: firewall_choice | default('none') != 'none'
- name: Security | Install chosen firewall package
  become: yes
  ansible.builtin.package: { name: "{{ firewall_package_name }}", state: present }
  register: firewall_pkg_result
  failed_when: firewall_pkg_result.failed
  when: firewall_choice | default('none') != 'none' and firewall_package_name | length > 0
- name: Security | Configure nftables rules
  become: yes
  ansible.builtin.template: { src: nftables.conf.j2, dest: /etc/nftables.conf, mode: '0644', owner: root, group: root, validate: /usr/sbin/nft -c -f %s }
  register: nftables_config_result
  failed_when: nftables_config_result.failed
  when: firewall_choice == 'nftables'
  notify: Reload nftables
- name: Security | Verify nftables SSH rule exists after reload
  become: yes
  ansible.builtin.command: { cmd: "nft list ruleset" }
  register: nftables_ruleset_check
  changed_when: false
  failed_when: nftables_ruleset_check.rc != 0 or 'tcp dport 22 accept' not in nftables_ruleset_check.stdout
  when: firewall_choice == 'nftables'
  check_mode: no
- name: Security | Configure UFW
  when: firewall_choice == 'ufw'
  become: yes
  block:
    - name: Security | Set UFW default policies
      community.general.ufw: { default: deny, direction: incoming }
      register: ufw_default_result
      failed_when: ufw_default_result.failed
    - name: Security | Allow SSH through UFW
      community.general.ufw: { rule: allow, port: '22', proto: tcp }
      register: ufw_allow_ssh_result
      failed_when: ufw_allow_ssh_result.failed
    - name: Security | Enable UFW
      community.general.ufw: { state: enabled }
      register: ufw_enable_result
      failed_when: ufw_enable_result.failed
  notify: Restart ufw
- name: Security | Verify UFW SSH rule exists after enable/restart
  become: yes
  ansible.builtin.command: { cmd: "ufw status verbose" }
  register: ufw_status_check
  changed_when: false
  failed_when: ufw_status_check.rc != 0 or '22/tcp' not in ufw_status_check.stdout or '(v6)' not in ufw_status_check.stdout or 'ALLOW IN' not in ufw_status_check.stdout
  when: firewall_choice == 'ufw'
  check_mode: no
EOF

# roles/security/templates/nftables.conf.j2
create_file_with_heredoc "${PROJECT_DIR}/roles/security/templates/nftables.conf.j2" << 'EOF'
#!/usr/sbin/nft -f
# Ansible Managed: Configure basic nftables ruleset
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority filter; policy drop;
    ct state {established, related} accept
    iifname lo accept
    ip protocol icmp accept comment "Allow IPv4 Ping"
    ip6 nexthdr ipv6-icmp accept comment "Allow IPv6 Ping"
    tcp dport 22 accept comment "Allow SSH"
    counter drop comment "Count and drop remaining packets"
  }
  chain forward {
    type filter hook forward priority filter; policy drop;
  }
  chain output {
    type filter hook output priority filter; policy accept;
  }
}
EOF

# roles/security/handlers/main.yml
create_file_with_heredoc "${PROJECT_DIR}/roles/security/handlers/main.yml" << 'EOF'
---
# Handlers for security role
- name: Reload nftables
  become: yes
  ansible.builtin.systemd_service: { name: nftables.service, state: reloaded }
  listen: "Reload nftables"
  when: firewall_choice == 'nftables'
- name: Restart ufw
  become: yes
  ansible.builtin.systemd_service: { name: ufw.service, state: restarted }
  listen: "Restart ufw"
  when: firewall_choice == 'ufw'
EOF

# roles/docker/tasks/main.yml
create_file_with_heredoc "${PROJECT_DIR}/roles/docker/tasks/main.yml" << 'EOF'
---
# Tasks to install Docker (Role: docker) - Stage 2
- name: Docker | Determine Docker package names
  ansible.builtin.set_fact: { docker_packages: ['docker', 'docker-compose'] }
- name: Docker | Install Docker packages
  become: yes
  ansible.builtin.package: { name: "{{ docker_packages }}", state: present }
  register: docker_pkg_result
  failed_when: docker_pkg_result.failed
- name: Docker | Ensure docker group exists
  become: yes
  ansible.builtin.group: { name: docker, state: present }
  register: docker_group_result
  failed_when: docker_group_result.failed
EOF

# roles/docker/handlers/main.yml
create_file_with_heredoc "${PROJECT_DIR}/roles/docker/handlers/main.yml" << 'EOF'
---
# Handlers for docker role
- name: Inform user about Docker group logout
  ansible.builtin.debug: { msg: "User '{{ target_user }}' added to the 'docker' group. User must log out and log back in for group membership to take effect." }
  listen: "Inform user about Docker group logout"
EOF

# roles/desktop_sway/tasks/main.yml
create_file_with_heredoc "${PROJECT_DIR}/roles/desktop_sway/tasks/main.yml" << 'EOF'
---
# Tasks to install and configure Sway environment (Role: desktop_sway) - Stage 2
- name: Sway | Get target user UID and GID
  ansible.builtin.getent: { database: passwd, key: "{{ target_user }}" }
  register: target_user_info
  check_mode: no
- name: Sway | Set DBUS environment variables for user tasks
  ansible.builtin.set_fact: { user_dbus_env: { DBUS_SESSION_BUS_ADDRESS: "unix:path=/run/user/{{ target_user_info.ansible_facts.getent_passwd[target_user][1] }}/bus", XDG_RUNTIME_DIR: "/run/user/{{ target_user_info.ansible_facts.getent_passwd[target_user][1] }}" } }
  when: target_user_info.ansible_facts.getent_passwd is defined and target_user in target_user_info.ansible_facts.getent_passwd
- name: Sway | Set GTK theme preference via gsettings
  ansible.builtin.command: { cmd: "runuser -l {{ target_user }} -c 'gsettings set org.gnome.desktop.interface gtk-theme \"{{ gtk_theme_name | default('Adwaita-dark') }}\"'" }
  register: gsettings_theme_result
  changed_when: false
  failed_when: gsettings_theme_result.rc != 0 and 'not found' not in gsettings_theme_result.stderr | lower and 'no such schema' not in gsettings_theme_result.stderr | lower
  environment: "{{ user_dbus_env | default({}) }}"
  when: target_user_info.ansible_facts.getent_passwd is defined
- name: Sway | Set GTK icon theme preference via gsettings
  ansible.builtin.command: { cmd: "runuser -l {{ target_user }} -c 'gsettings set org.gnome.desktop.interface icon-theme \"{{ icon_theme_name | default('Papirus-Dark') }}\"'" }
  register: gsettings_icon_result
  changed_when: false
  failed_when: gsettings_icon_result.rc != 0 and 'not found' not in gsettings_icon_result.stderr | lower and 'no such schema' not in gsettings_icon_result.stderr | lower
  environment: "{{ user_dbus_env | default({}) }}"
  when: target_user_info.ansible_facts.getent_passwd is defined
- name: Sway | Set GTK cursor theme preference via gsettings
  ansible.builtin.command: { cmd: "runuser -l {{ target_user }} -c 'gsettings set org.gnome.desktop.interface cursor-theme \"{{ cursor_theme_name | default('Adwaita') }}\"'" }
  register: gsettings_cursor_result
  changed_when: false
  failed_when: gsettings_cursor_result.rc != 0 and 'not found' not in gsettings_cursor_result.stderr | lower and 'no such schema' not in gsettings_cursor_result.stderr | lower
  environment: "{{ user_dbus_env | default({}) }}"
  when: target_user_info.ansible_facts.getent_passwd is defined
- name: Sway | Set QT_QPA_PLATFORMTHEME environment variable for Qt apps
  become: yes
  ansible.builtin.lineinfile: { path: /etc/environment, line: "QT_QPA_PLATFORMTHEME=qt5ct", create: yes, mode: '0644' }
  register: qt_env_result
  failed_when: qt_env_result.failed
- name: Sway | Ensure target user config directory exists
  ansible.builtin.file: { path: "/home/{{ target_user }}/.config", state: directory, owner: "{{ target_user }}", group: "{{ target_user_info.ansible_facts.getent_passwd[target_user][3] }}", mode: '0755' }
  when: target_user_info.ansible_facts.getent_passwd is defined
- name: Sway | Ensure user script directory exists
  ansible.builtin.file: { path: "/home/{{ target_user }}/.local/bin", state: directory, owner: "{{ target_user }}", group: "{{ target_user_info.ansible_facts.getent_passwd[target_user][3] }}", mode: '0755' }
  when: target_user_info.ansible_facts.getent_passwd is defined
- name: Sway | Copy user-provided Sway config file
  ansible.builtin.copy: { src: config, dest: "/home/{{ target_user }}/.config/sway/config", owner: "{{ target_user }}", group: "{{ target_user_info.ansible_facts.getent_passwd[target_user][3] }}", mode: '0644', directory_mode: '0755' }
  register: sway_config_copy_result
  failed_when: sway_config_copy_result.failed
  when: target_user_info.ansible_facts.getent_passwd is defined
- name: Sway | Verify Sway config file exists
  ansible.builtin.stat: { path: "/home/{{ target_user }}/.config/sway/config" }
  register: sway_config_stat
  failed_when: not sway_config_stat.stat.exists
  when: target_user_info.ansible_facts.getent_passwd is defined
- name: Sway | Copy user-provided libinput-gestures config file
  ansible.builtin.copy: { src: libinput-gestures.conf, dest: "/home/{{ target_user }}/.config/libinput-gestures/libinput-gestures.conf", owner: "{{ target_user }}", group: "{{ target_user_info.ansible_facts.getent_passwd[target_user][3] }}", mode: '0644', directory_mode: '0755' }
  register: gestures_config_copy_result
  failed_when: gestures_config_copy_result.failed
  when: target_user_info.ansible_facts.getent_passwd is defined
- name: Sway | Verify libinput-gestures config file exists
  ansible.builtin.stat: { path: "/home/{{ target_user }}/.config/libinput-gestures/libinput-gestures.conf" }
  register: gestures_config_stat
  failed_when: not gestures_config_stat.stat.exists
  when: target_user_info.ansible_facts.getent_passwd is defined
- name: Sway | Copy user-provided wallpaper script
  ansible.builtin.copy: { src: wallpaper.sh, dest: "/home/{{ target_user }}/.local/bin/wallpaper.sh", owner: "{{ target_user }}", group: "{{ target_user_info.ansible_facts.getent_passwd[target_user][3] }}", mode: '0755' }
  register: wallpaper_script_copy_result
  failed_when: wallpaper_script_copy_result.failed
  when: target_user_info.ansible_facts.getent_passwd is defined
- name: Sway | Verify wallpaper script exists and is executable
  ansible.builtin.stat: { path: "/home/{{ target_user }}/.local/bin/wallpaper.sh" }
  register: wallpaper_script_stat
  failed_when: not wallpaper_script_stat.stat.exists or wallpaper_script_stat.stat.mode != '0755'
  when: target_user_info.ansible_facts.getent_passwd is defined
- name: Sway | Set Unsplash API key in wallpaper script
  ansible.builtin.lineinfile: { path: "/home/{{ target_user }}/.local/bin/wallpaper.sh", regexp: '^ACCESS_KEY=".*"', line: 'ACCESS_KEY="{{ unsplash_api_key | default("") }}"', backrefs: yes, owner: "{{ target_user }}", group: "{{ target_user_info.ansible_facts.getent_passwd[target_user][3] }}" }
  when: unsplash_api_key is defined and target_user_info.ansible_facts.getent_passwd is defined
- name: Sway | Copy user-provided or default .bashrc
  ansible.builtin.copy: { src: .bashrc, dest: "/home/{{ target_user }}/.bashrc", owner: "{{ target_user }}", group: "{{ target_user_info.ansible_facts.getent_passwd[target_user][3] }}", mode: '0644' }
  register: bashrc_copy_result
  failed_when: bashrc_copy_result.failed
  when: target_user_info.ansible_facts.getent_passwd is defined
- name: Sway | Verify .bashrc file exists
  ansible.builtin.stat: { path: "/home/{{ target_user }}/.bashrc" }
  register: bashrc_stat
  failed_when: not bashrc_stat.stat.exists
  when: target_user_info.ansible_facts.getent_passwd is defined
- name: Sway | Copy user-provided or default Alacritty config
  ansible.builtin.template: { src: alacritty.yml.j2, dest: "/home/{{ target_user }}/.config/alacritty/alacritty.yml", owner: "{{ target_user }}", group: "{{ target_user_info.ansible_facts.getent_passwd[target_user][3] }}", mode: '0644', directory_mode: '0755' }
  register: alacritty_config_copy_result
  failed_when: alacritty_config_copy_result.failed
  when: target_user_info.ansible_facts.getent_passwd is defined
- name: Sway | Verify Alacritty config file exists
  ansible.builtin.stat: { path: "/home/{{ target_user }}/.config/alacritty/alacritty.yml" }
  register: alacritty_config_stat
  failed_when: not alacritty_config_stat.stat.exists
  when: target_user_info.ansible_facts.getent_passwd is defined
- name: Sway | Ensure /usr/local/bin exists
  become: yes
  ansible.builtin.file: { path: /usr/local/bin, state: directory, mode: '0755' }
  when: install_autorotation | default(false) | bool
- name: Sway | Copy autorotate script from template
  become: yes
  ansible.builtin.template: { src: sway-autorotate.sh.j2, dest: /usr/local/bin/sway-autorotate.sh, owner: root, group: root, mode: '0755' }
  register: autorotate_script_copy_result
  failed_when: autorotate_script_copy_result.failed
  when: install_autorotation | default(false) | bool
- name: Sway | Verify autorotate script exists and is executable
  become: yes
  ansible.builtin.stat: { path: "/usr/local/bin/sway-autorotate.sh" }
  register: autorotate_script_stat
  failed_when: not autorotate_script_stat.stat.exists or autorotate_script_stat.stat.mode != '0755'
  when: install_autorotation | default(false) | bool
- name: Sway | Ensure systemd user config directory exists
  ansible.builtin.file: { path: "/home/{{ target_user }}/.config/systemd/user", state: directory, owner: "{{ target_user }}", group: "{{ target_user_info.ansible_facts.getent_passwd[target_user][3] }}", mode: '0755' }
  when: target_user_info.ansible_facts.getent_passwd is defined
- name: Sway | Copy libinput-gestures systemd user service file
  ansible.builtin.copy: { src: libinput-gestures.service, dest: "/home/{{ target_user }}/.config/systemd/user/libinput-gestures.service", owner: "{{ target_user }}", group: "{{ target_user_info.ansible_facts.getent_passwd[target_user][3] }}", mode: '0644' }
  register: gestures_service_copy_result
  failed_when: gestures_service_copy_result.failed
  when: target_user_info.ansible_facts.getent_passwd is defined
- name: Sway | Copy sway-autorotate systemd user service file
  ansible.builtin.copy: { src: sway-autorotate.service, dest: "/home/{{ target_user }}/.config/systemd/user/sway-autorotate.service", owner: "{{ target_user }}", group: "{{ target_user_info.ansible_facts.getent_passwd[target_user][3] }}", mode: '0644' }
  register: autorotate_service_copy_result
  failed_when: autorotate_service_copy_result.failed
  when: install_autorotation | default(false) | bool and target_user_info.ansible_facts.getent_passwd is defined
- name: Sway | Enable and start systemd user services (best effort)
  ansible.builtin.systemd_service: { name: "{{ item }}", scope: user, enabled: yes, state: started }
  loop: [libinput-gestures.service, sway-autorotate.service]
  loop_control: { label: "{{ item }}" }
  when: [target_user_info.ansible_facts.getent_passwd is defined, item != 'sway-autorotate.service' or (install_autorotation | default(false) | bool)]
  become: yes
  become_user: "{{ target_user }}"
  environment: "{{ user_dbus_env | default({}) }}"
  register: user_service_result
  failed_when: user_service_result.rc != 0 and 'failed to connect to bus' not in user_service_result.msg | lower and 'does not exist' not in user_service_result.msg | lower and 'service is masked' not in user_service_result.msg | lower
- name: Sway | Verify systemd user services are enabled (best effort)
  ansible.builtin.command: { cmd: "runuser -l {{ target_user }} -c 'systemctl --user is-enabled {{ item }}'" }
  loop: [libinput-gestures.service, sway-autorotate.service]
  loop_control: { label: "{{ item }}" }
  register: user_service_enabled_check
  changed_when: false
  failed_when: user_service_enabled_check.rc != 0 and 'failed to connect to bus' not in user_service_enabled_check.stderr | lower and 'service is masked' not in user_service_enabled_check.stderr | lower
  when: [target_user_info.ansible_facts.getent_passwd is defined, item != 'sway-autorotate.service' or (install_autorotation | default(false) | bool)]
  check_mode: no
- name: Sway | Assert systemd user services are enabled where possible
  ansible.builtin.assert: { that: ["'enabled' in item.stdout or 'static' in item.stdout"], fail_msg: "User service {{ item.item }} is not enabled (or check failed due to DBUS). Status: {{ item.stdout | default('N/A') }}", quiet: yes }
  loop: "{{ user_service_enabled_check.results }}"
  when: item.rc == 0
EOF

# roles/desktop_sway templates and files (alacritty.yml.j2, sway-autorotate.sh.j2, libinput-gestures.service, sway-autorotate.service)
# These are copied verbatim from the v2.2 generation as they were not part of the user's provided verification snippets.
# Create alacritty.yml.j2 template
create_file_with_heredoc "${PROJECT_DIR}/roles/desktop_sway/templates/alacritty.yml.j2" << 'EOF'
# Ansible Managed: Basic Alacritty Configuration
font:
  normal: { family: Fira Code }
  bold: { family: Fira Code }
  italic: { family: Fira Code }
  bold_italic: { family: Fira Code }
  size: 10.0
colors:
  primary: { background: '0x282a36', foreground: '0xf8f8f2' }
  normal: { black: '0x000000', red: '0xff5555', green: '0x50fa7b', yellow: '0xf1fa8c', blue: '0xbd93f9', magenta: '0xff79c6', cyan: '0x8be9fd', white: '0xbfbfbf' }
  bright: { black: '0x4d4d4d', red: '0xff6e67', green: '0x5af78e', yellow: '0xf4f99d', blue: '0xcaa9fa', magenta: '0xff92d0', cyan: '0x9aedfe', white: '0xffffff' }
window: { padding: { x: 5, y: 5 } }
scrolling: { history: 10000 }
EOF

# Create sway-autorotate.sh.j2 template
create_file_with_heredoc "${PROJECT_DIR}/roles/desktop_sway/templates/sway-autorotate.sh.j2" << 'EOF'
#!/bin/bash
# Ansible Managed: Template for sway-autorotate.sh
# !! USER ADJUSTMENT REQUIRED on final system !!
TABLET_MODE_SYSFS_PATH="" # MUST be set manually post-install.
TOUCHSCREEN_IDENTIFIER_PATTERN="{{ touchscreen_identifier_pattern | default('Touch') }}"
KEYBOARD_IDENTIFIER_PATTERN="keyboard"
TOUCHPAD_IDENTIFIER_PATTERN="Touchpad"
DISPLAY_DEVICE_NAME_PATTERN="eDP|DP|HDMI-A"
TOUCHSCREEN_DEVICE="" KEYBOARD_DEVICE="" TOUCHPAD_DEVICE="" DISPLAY_DEVICE="" last_orientation="unknown" last_tablet_mode_state=-1
find_device() { local type="$1" input_or_output="$2" pattern="$3" query="" result="" swaymsg_path jq_path; swaymsg_path=$(command -v swaymsg); jq_path=$(command -v jq); if [ -z "$swaymsg_path" ] || [ -z "$jq_path" ]; then echo "Warning: swaymsg or jq not found." >&2; return 1; fi; if ! "$swaymsg_path" -t get_version > /dev/null 2>&1; then return 1; fi; if [ "$input_or_output" == "input" ]; then query='.[] | select(.type=="keyboard" or .type=="touchpad" or .type=="touch") | select(.identifier | test("'$pattern'"; "i")) | .identifier'; result=$("$swaymsg_path" -t get_inputs --raw | "$jq_path" -r "$query" | head -n 1); elif [ "$input_or_output" == "output" ]; then query_internal='.[] | select(.active==true and (.name | test("eDP"; "i"))) | .name'; result=$("$swaymsg_path" -t get_outputs --raw | "$jq_path" -r "$query_internal" | head -n 1); if [ -z "$result" ]; then query_any='.[] | select(.active==true) | select(.name | test("'$pattern'"; "i")) | .name'; result=$("$swaymsg_path" -t get_outputs --raw | "$jq_path" -r "$query_any" | head -n 1); fi; else echo "Warning: Invalid type '$input_or_output' for find_device." >&2; return 1; fi; if [ -z "$result" ]; then return 1; fi; echo "$result"; return 0; }
check_tablet_mode() { if [ -z "$TABLET_MODE_SYSFS_PATH" ] || [ ! -f "$TABLET_MODE_SYSFS_PATH" ]; then if [ "$last_tablet_mode_state" != 2 ]; then echo "$(date '+%Y-%m-%d %H:%M:%S') Info: Tablet mode sysfs path ('$TABLET_MODE_SYSFS_PATH') not valid or not set. Tablet mode detection disabled."; fi; return 2; fi; local state; state=$(cat "$TABLET_MODE_SYSFS_PATH" 2>/dev/null); if [ "$state" = "1" ]; then return 0; else return 1; fi; }
set_input_device_state() { local device_identifier="$1" state="$2" swaymsg_path timeout_path; swaymsg_path=$(command -v swaymsg); timeout_path=$(command -v timeout); if [ -z "$device_identifier" ] || [ -z "$swaymsg_path" ] || [ -z "$timeout_path" ]; then return; fi; if ! "$swaymsg_path" -t get_version > /dev/null 2>&1; then return; fi; echo "$(date '+%Y-%m-%d %H:%M:%S') Setting input device '$device_identifier' events to '$state'"; if ! "$timeout_path" 2s "$swaymsg_path" input "$device_identifier" events "$state"; then echo "$(date '+%Y-%m-%d %H:%M:%S') Error or timeout setting state for '$device_identifier'" >&2; fi; }
update_devices() { TOUCHSCREEN_DEVICE=$(find_device "input" "input" "$TOUCHSCREEN_IDENTIFIER_PATTERN"); KEYBOARD_DEVICE=$(find_device "input" "input" "$KEYBOARD_IDENTIFIER_PATTERN"); TOUCHPAD_DEVICE=$(find_device "input" "input" "$TOUCHPAD_IDENTIFIER_PATTERN"); DISPLAY_DEVICE=$(find_device "output" "output" "$DISPLAY_DEVICE_NAME_PATTERN"); }
update_devices
log_prefix="$(date '+%Y-%m-%d %H:%M:%S') [Autorotate]"; echo "$log_prefix Starting autorotate script..."; echo "$log_prefix Display Pattern: '$DISPLAY_DEVICE_NAME_PATTERN', Found: '${DISPLAY_DEVICE:-Not Found}'"; echo "$log_prefix Touchscreen Pattern: '$TOUCHSCREEN_IDENTIFIER_PATTERN', Found: '${TOUCHSCREEN_DEVICE:-Not Found}'"; echo "$log_prefix Keyboard Pattern: '$KEYBOARD_IDENTIFIER_PATTERN', Found: '${KEYBOARD_DEVICE:-Not Found}'"; echo "$log_prefix Touchpad Pattern: '$TOUCHPAD_IDENTIFIER_PATTERN', Found: '${TOUCHPAD_DEVICE:-Not Found}'"; echo "$log_prefix Tablet Mode Path: '${TABLET_MODE_SYSFS_PATH:-Not Set/Found}' (NEEDS CONFIGURATION MANUALLY!)"
monitor_sensor_path=$(command -v monitor-sensor); if [ -z "$monitor_sensor_path" ]; then echo "$log_prefix Error: monitor-sensor command not found." >&2; exit 1; fi
stdbuf -oL "$monitor_sensor_path" --accel | while IFS= read -r line; do swaymsg_path=$(command -v swaymsg); if [ -n "$swaymsg_path" ] && "$swaymsg_path" -t get_version > /dev/null 2>&1; then if [ -z "$DISPLAY_DEVICE" ] || [ -z "$TOUCHSCREEN_DEVICE" ] || [ -z "$KEYBOARD_DEVICE" ] || [ -z "$TOUCHPAD_DEVICE" ]; then echo "$log_prefix Retrying device discovery..."; update_devices; echo "$log_prefix Found Devices: Disp='${DISPLAY_DEVICE:-NF}', TS='${TOUCHSCREEN_DEVICE:-NF}', KB='${KEYBOARD_DEVICE:-NF}', TP='${TOUCHPAD_DEVICE:-NF}'"; fi; else DISPLAY_DEVICE="" TOUCHSCREEN_DEVICE="" KEYBOARD_DEVICE="" TOUCHPAD_DEVICE=""; sleep 5; continue; fi; check_tablet_mode; current_tablet_mode_state=$?; if [ "$current_tablet_mode_state" != "$last_tablet_mode_state" ]; then case "$current_tablet_mode_state" in 0) echo "$log_prefix Entering Tablet Mode: Disabling keyboard/touchpad."; set_input_device_state "$KEYBOARD_DEVICE" "disabled"; set_input_device_state "$TOUCHPAD_DEVICE" "disabled" ;; 1) echo "$log_prefix Entering Laptop Mode: Enabling keyboard/touchpad."; set_input_device_state "$KEYBOARD_DEVICE" "enabled"; set_input_device_state "$TOUCHPAD_DEVICE" "enabled" ;; 2) if [ "$last_tablet_mode_state" != 2 ]; then echo "$log_prefix Tablet mode detection disabled/failed: Ensuring keyboard/touchpad are enabled (default state)."; set_input_device_state "$KEYBOARD_DEVICE" "enabled"; set_input_device_state "$TOUCHPAD_DEVICE" "enabled"; fi ;; esac; last_tablet_mode_state=$current_tablet_mode_state; fi; orientation=$(echo "$line" | grep --line-buffered -oP 'Orientation changed: \K\S+'); if [ -n "$orientation" ] && [ "$orientation" != "$last_orientation" ]; then echo "$log_prefix Detected orientation: $orientation"; last_orientation="$orientation"; new_transform=""; case "$orientation" in "normal") new_transform="normal";; "left-up") new_transform="90";; "right-up") new_transform="270";; "bottom-up") new_transform="180";; *) echo "$log_prefix Unknown orientation: $orientation"; continue;; esac; if [ -n "$DISPLAY_DEVICE" ] && [ -n "$swaymsg_path" ]; then current_transform=$("$swaymsg_path" -t get_outputs --raw | jq -r --arg name "$DISPLAY_DEVICE" '.[] | select(.name==$name) | .transform // "unknown"'); if [ "$current_transform" != "$new_transform" ]; then echo "$log_prefix Applying transform '$new_transform' to display '$DISPLAY_DEVICE'"; if "$swaymsg_path" output "$DISPLAY_DEVICE" transform "$new_transform"; then if [ -n "$TOUCHSCREEN_DEVICE" ]; then echo "$log_prefix Mapping input '$TOUCHSCREEN_DEVICE' to output '$DISPLAY_DEVICE'"; sleep 0.5; "$swaymsg_path" input "$TOUCHSCREEN_DEVICE" map_to_output "$DISPLAY_DEVICE"; fi; else echo "$log_prefix Error applying transform with swaymsg." >&2; fi; elif [ -n "$TOUCHSCREEN_DEVICE" ]; then echo "$log_prefix Re-mapping input '$TOUCHSCREEN_DEVICE' to output '$DISPLAY_DEVICE' (transform unchanged)"; "$swaymsg_path" input "$TOUCHSCREEN_DEVICE" map_to_output "$DISPLAY_DEVICE"; fi; else echo "$log_prefix Display device unknown or swaymsg not found, cannot apply transform yet."; sleep 2; fi; fi; done
echo "$log_prefix Autorotate script exiting."
EOF

# Create libinput-gestures.service file
create_file_with_heredoc "${PROJECT_DIR}/roles/desktop_sway/files/libinput-gestures.service" << 'EOF'
[Unit]
Description=Libinput gestures daemon
After=graphical-session.target
[Service]
Type=simple
Environment="PATH=/usr/local/bin:/usr/bin:/bin:/home/{{ target_user }}/.local/bin"
ExecStart=/usr/bin/libinput-gestures-setup start
ExecStop=/usr/bin/libinput-gestures-setup stop
Restart=on-failure
[Install]
WantedBy=graphical-session.target
EOF

# Create sway-autorotate.service file
create_file_with_heredoc "${PROJECT_DIR}/roles/desktop_sway/files/sway-autorotate.service" << 'EOF'
[Unit]
Description=Sway automatic screen rotation and tablet mode script
After=sway-session.target iio-sensor-proxy.service graphical-session.target
BindsTo=sway-session.target graphical-session.target
[Service]
Type=simple
Environment="PATH=/usr/local/bin:/usr/bin:/bin:/home/{{ target_user }}/.local/bin"
ExecStart=/usr/local/bin/sway-autorotate.sh
Restart=on-failure
RestartSec=5
[Install]
WantedBy=sway-session.target graphical-session.target
EOF


# --- Copy User-Provided Files (From script execution directory) ---
log_info "Copying user-provided configuration files into roles..."
script_dir=$(pwd) # Directory where setup_controller.sh is run

copy_user_file() {
    local source_file_rel="$1"           # Source relative to script execution dir
    local dest_path="${PROJECT_DIR}/$2"  # Destination relative to project dir
    local role_name="$3"                 # Role name for logging
    local source_file="${script_dir}/${source_file_rel}"

    if [ ! -f "$source_file" ]; then
        log_warn "User file '${source_file_rel}' not found in '${script_dir}'. Skipping copy for role '${role_name}'."
        return # Skip if source file not found
    fi

    local dest_dir
    dest_dir=$(dirname "$dest_path")

    # Ensure destination directory exists within the role structure
    mkdir -p "$dest_dir" || log_error "Failed to create directory ${dest_dir}"
    # Copy the file
    cp "$source_file" "$dest_path" || log_error "Failed to copy ${source_file} to ${dest_path}"
    log_info "Copied '${source_file_rel}' -> '${dest_path}'"
}

# Copy files defined in USER_FILES_TO_COPY array
log_info "Attempting to copy user files specified in USER_FILES_TO_COPY array..."
for item in "${USER_FILES_TO_COPY[@]}"; do
    IFS=":" read -r src dest_rel role_name <<< "$item"
    copy_user_file "$src" "$dest_rel" "$role_name"
done

# --- Create Post-Install Verification Script ---
log_info "Creating post-installation verification script..."
create_file_with_heredoc "${PROJECT_DIR}/verify_installation.sh" << 'EOF'
#!/bin/bash
# Post-installation verification script
# Run this from within the project directory after the Ansible playbook completes.
# It checks basic system state. Some checks might require manual interpretation.

echo "=== System Verification Checklist ==="

# Load variables if config exists (best effort)
if [[ -f "group_vars/all/config.yml" ]]; then
    # Basic parsing - assumes simple key: value structure, won't handle complex YAML
    target_user=$(grep '^target_user:' group_vars/all/config.yml | sed 's/^target_user:\s*//' | tr -d '"'\'')
    target_hostname=$(grep '^target_hostname:' group_vars/all/config.yml | sed 's/^target_hostname:\s*//' | tr -d '"'\'')
    install_docker=$(grep '^install_docker:' group_vars/all/config.yml | sed 's/^install_docker:\s*//' | tr -d '"'\'')
    gcm_enabled=$(grep '^git_credential_manager_enabled:' group_vars/all/config.yml | sed 's/^git_credential_manager_enabled:\s*//' | tr -d '"'\'')
    microsd_mount_point=$(grep '^microsd_mount_point:' group_vars/all/config.yml | sed 's/^microsd_mount_point:\s*//' | tr -d '"'\'')
else
    echo "[WARN] config.yml not found, using defaults for verification (user='ldeen', host='arch-sway-laptop', docker=true, gcm=true)"
    target_user=${target_user:-ldeen}
    target_hostname=${target_hostname:-arch-sway-laptop}
    install_docker=${install_docker:-true}
    gcm_enabled=${gcm_enabled:-true}
    microsd_mount_point=${microsd_mount_point:-/home/${target_user}/MicroSD}
fi

echo "[INFO] Using target_user='$target_user', target_hostname='$target_hostname' for checks."

# --- Connectivity ---
echo "--- Network ---"
if ping -c 2 google.com >/dev/null 2>&1; then
    echo "[OK] Internet connectivity"
else
    echo "[FAIL] Internet connectivity check failed"
fi
if ping -c 1 "${target_hostname}.local" >/dev/null 2>&1; then
    echo "[OK] mDNS resolution for ${target_hostname}.local"
else
    echo "[WARN] mDNS resolution failed for ${target_hostname}.local (Ensure Avahi is running on target and resolvable from controller)"
fi

# --- System Services ---
echo "--- Services ---"
for service in NetworkManager sshd avahi-daemon seatd tlp; do
    # Check if service exists before checking status
    if systemctl list-unit-files "${service}.service" | grep -q "${service}.service"; then
        if systemctl is-active --quiet "$service"; then
            echo "[OK] Service $service active"
        else
            echo "[FAIL] Service $service not active"
        fi
    else
         echo "[INFO] Service $service not installed/found."
    fi
done
# Conditional service checks
# Add firewall, docker, iio-sensor-proxy checks here based on config vars if needed

# --- Swap ---
echo "--- Swap ---"
if swapon --show | grep -q '/swapfile'; then # Check for primary swapfile name
    echo "[OK] Primary swap active"
else
    echo "[FAIL] Primary swap not detected"
fi
# Add secondary swap check if configured

# --- Docker ---
echo "--- Docker ---"
if [[ "$install_docker" == "true" ]]; then
    if command -v docker >/dev/null 2>&1; then
        echo "[OK] Docker command found"
        if systemctl is-active --quiet docker; then
             echo "[OK] Docker service active"
        else
             echo "[FAIL] Docker service not active"
        fi
        if groups "$target_user" | grep -q '\bdocker\b'; then
            echo "[OK] User '$target_user' in docker group (logout/login may be needed)"
        else
            echo "[WARN] User '$target_user' NOT in docker group (logout/login required to use docker without sudo)"
        fi
    else
        echo "[FAIL] Docker command not found"
    fi
else
    echo "[INFO] Docker installation skipped."
fi

# --- Git & GCM ---
echo "--- Git & GCM ---"
if command -v git >/dev/null 2>&1; then
    echo "[OK] Git command found"
    if git config --global user.name >/dev/null 2>&1; then
        echo "[OK] Git user.name configured"
    else
        echo "[WARN] Git user.name not configured globally"
    fi
else
    echo "[FAIL] Git command not found"
fi
if [[ "$gcm_enabled" == "true" ]]; then
    if command -v git-credential-manager >/dev/null 2>&1; then
        echo "[OK] Git Credential Manager command found"
        gcm_store=$(git config --global credential.credentialStore)
        if [[ "$gcm_store" == "cache" ]]; then
            echo "[OK] GCM credentialStore configured to 'cache'"
        else
            echo "[FAIL] GCM credentialStore is NOT 'cache' (Current: '$gcm_store')"
        fi
        echo "[INFO] To fully test GCM, try cloning a private HTTPS repo: git clone https://github.com/..."
    else
        echo "[FAIL] Git Credential Manager command not found"
    fi
else
    echo "[INFO] GCM installation skipped."
fi


# --- Desktop Environment ---
echo "--- Desktop ---"
if command -v sway >/dev/null 2>&1; then
    echo "[OK] Sway command found"
else
    echo "[FAIL] Sway command not found"
fi
# Add checks for other DE components if needed (waybar, wofi, etc.)

# --- Filesystem Mounts ---
echo "--- Mounts ---"
if grep -q "${microsd_mount_point}" /proc/mounts; then # Check MicroSD mount if configured
    echo "[OK] MicroSD appears mounted at ${microsd_mount_point}"
else
    echo "[INFO] MicroSD mount point not active (or not configured)"
fi

echo "=== Verification Complete ==="
echo "Note: Some checks (like group membership) may require a logout/login on the target machine."
echo "Review warnings and failures carefully."
EOF
# Make the verification script executable
chmod +x "${PROJECT_DIR}/verify_installation.sh"
log_info "Created verification script: ${PROJECT_DIR}/verify_installation.sh"


# --- Final Instructions ---
# Verify project structure integrity before showing instructions
verify_project_structure

echo ""
echo "--------------------------------------------------"
log_info "Controller Setup Complete! Project created in: ${PROJECT_DIR}"
log_info "Ansible roles and playbook generated with enhanced verification, GCM setup, and service check fixes."
echo "--------------------------------------------------"
echo ""
log_info ">>> REVIEW & EXECUTION STEPS <<<"
echo ""
echo "  1. **REVIEW ANSIBLE ROLE TASKS:**"
echo "     ---> CRITICAL: Review the generated 'tasks/main.yml' file within EACH role directory."
echo "          (e.g., ${PROJECT_DIR}/roles/base_system/tasks/main.yml, common, users, desktop_sway, etc.)"
echo "     ---> Pay special attention to roles/users/tasks/main.yml for the new GCM setup."
echo "     ---> Ensure the tasks and verification steps match your specific needs and hardware."
echo ""
echo "  2. **Navigate to Project:**"
echo "     $ cd ${PROJECT_DIR}"
echo ""
echo "  3. **Provide User Config Files (Optional but Recommended):**"
echo "     ---> Place your custom 'config' (Sway), 'libinput-gestures.conf', 'wallpaper.sh', '.bashrc', 'alacritty.yml'"
echo "          in the *SAME DIRECTORY* where you ran this setup_controller.sh script."
echo "     ---> Re-run this script if you add/change these files after initial generation."
echo "     ---> **IMPORTANT**: Ensure your Sway 'config' file includes 'exec_always autotiling' if you want it enabled."
echo ""
echo "  4. **Configure Variables:**"
echo "     $ cp group_vars/all/config.yml.example group_vars/all/config.yml"
echo "     $ nano group_vars/all/config.yml"
echo "     ---> REVIEW AND SET ALL VALUES CAREFULLY! Especially:"
echo "          - controller_root_private_key_file, target_user_private_key_file paths"
echo "          - target_disk, target_existing_partitions (CRITICAL!)"
echo "          - configure_wifi_in_stage1, wifi_ssid"
echo "          - CPU Microcode package in base_packages (intel-ucode or amd-ucode)"
echo "          - target_user details, target_user_ssh_pub_key (MUST match target_user_private_key_file)"
echo "          - extra_packages (UNCOMMENT your chosen firewall package: nftables or ufw, ensure 'curl' is present if using GCM)"
echo "          - aur_packages lists (UNCOMMENT optional GUI tools like tlpui, cpupower-gui if desired)"
echo "          - target_hostname (MUST be resolvable via mDNS/Avahi from controller for Stage 2)"
echo "          - git_user_name, git_user_email"
echo "          - git_credential_manager_enabled (set to true or false)"
echo "          - use_microsd, microsd_* variables"
echo ""
echo "  5. **Configure Vault (Secrets):**"
echo "     a. Generate HASHED passwords for 'root' AND '{{ target_user }}':"
echo "        $ mkpasswd -m sha-512"
echo "        (Enter password when prompted, copy the resulting hash starting with \$6\$...)"
echo "        OR use Python:"
echo "        $ python3 -c 'import crypt; print(crypt.crypt(\"YOUR_PASSWORD_HERE\", crypt.mksalt(crypt.METHOD_SHA512)))'"
echo "     b. Create the Vault file (set a strong vault password!):"
echo "        $ ansible-vault create group_vars/all/vault.yml"
echo "     c. Add your HASHED passwords and Wi-Fi password (if using Wi-Fi pre-config) to the vault file."
echo "        >>> Use these EXACT variable names <<<"
echo "        vault_root_password_hash: \$6\$salt\$your_root_hash_here..."
echo "        vault_ldeen_password_hash: \$6\$salt\$your_ldeen_hash_here..."
echo "        vault_wifi_password: \"YourWifiPassword\" # Add this if configure_wifi_in_stage1: true"
echo "     d. **IF** git_credential_manager_enabled is true, add GitHub credentials:"
echo "        vault_github_username: \"YourGitHubUsername\""
echo "        vault_github_password: \"YourGitHubPasswordOrPAT\" # Use a Personal Access Token (PAT) if 2FA is enabled!"
echo "     e. Optional: Add Unsplash API Key:"
echo "        vault_unsplash_api_key: \"YOUR_KEY_HERE\" # Optional, if using wallpaper script"
echo ""
echo "  6. **Prepare Arch Live ISO:**"
echo "     ---> Boot target machine from Arch USB/Media."
echo "     ---> Connect to the network ('ip link', 'iwctl'/'nmtui', 'ping')."
echo "     ---> Find its IP address ('ip addr')."
echo "     ---> Manually copy your CONTROLLER's ROOT PUBLIC SSH key (corresponding to controller_root_private_key_file) to '/root/.ssh/authorized_keys' on the LIVE ISO."
echo "          # mkdir -p /root/.ssh && chmod 700 /root/.ssh"
echo "          # echo \"PASTE_ROOT_PUBLIC_KEY_HERE\" > /root/.ssh/authorized_keys"
echo "          # chmod 600 /root/.ssh/authorized_keys"
echo "     ---> Start sshd on the LIVE ISO: # systemctl start sshd"
echo ""
echo "  7. **Configure Inventory:**"
echo "     $ nano inventory.ini"
echo "     ---> ***CRITICAL*** Manually edit the placeholder values:"
echo "     ---> Under '[arch_live]', set 'ansible_host=' to the Live ISO's IP and 'ansible_private_key_file=' to the root private key path."
echo "     ---> Under '[arch_configured]', set 'ansible_host=' to the target hostname + .local, 'ansible_user=' to the target user, and 'ansible_private_key_file=' to the user private key path."
echo "     ---> ***CRITICAL*** Ensure your CONTROLLER machine can resolve '.local' hostnames (install/configure avahi-daemon, nss-mdns, check /etc/nsswitch.conf)."
echo "     ---> **VERIFY**: Run 'grep -E \"X\.X\.X\.X|arch-sway-laptop\.local\" inventory.ini'. This command should show NO output if you have correctly replaced the placeholders."
echo ""
echo "  8. **Pre-Flight Checks (Optional but Recommended):**"
echo "     ---> Validate Ansible syntax:"
echo "          $ ansible-playbook --syntax-check install_and_configure.yml --ask-vault-pass"
echo "     ---> Perform a dry run (no changes made):"
echo "          $ ansible-playbook --check --diff install_and_configure.yml --ask-vault-pass"
echo ""
echo "  9. **Run the Playbook:**"
echo "     $ ansible-playbook install_and_configure.yml --ask-vault-pass"
echo "     (Ansible will use ansible.cfg in this directory)"
echo "     ---> This runs Play 1 (reboot), then Play 2 (configures)."
echo ""
echo " 10. **Post-Installation Verification:**"
echo "     ---> After the playbook completes, run the verification script:"
echo "          $ ./verify_installation.sh"
echo "     ---> Review the output for [OK], [WARN], or [FAIL] status."
echo "     ---> SSH as your configured user ('{{ target_user }}')."
echo "     ---> Log out and log back in for group changes (e.g., Docker) to take effect."
echo "     ---> Manually test key applications and configurations (Sway, autorotation, theming, GCM with 'git clone', etc.) as listed in the playbook's final message and the verification script."
echo "--------------------------------------------------"
log_warn "Verification checks added throughout the setup script and generated Ansible playbook."
log_warn "Added post-install verification script: verify_installation.sh"
log_warn "Integrated Git Credential Manager installation (via source script) and configuration (cache store + GitHub credential pre-seeding)."
log_warn "Corrected service state checks in the generated playbook's pre_tasks and network role."
log_warn "Review 'group_vars/all/config.yml' partition mappings CAREFULLY. Formatting is DESTRUCTIVE."
log_warn "***CRITICAL*** Ensure your CONTROLLER machine can resolve '.local' hostnames for Stage 2 to work automatically."
log_warn "TEST IN A VIRTUAL MACHINE FIRST IF POSSIBLE!"
echo "--------------------------------------------------"
# [2025-02-28] Keep all the comments that were there in the original files.

exit 0
