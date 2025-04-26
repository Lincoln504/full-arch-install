# Ansible Arch Linux Two-Stage Installation

This repository contains an Ansible project designed to perform a two-stage installation and configuration of Arch Linux, primarily targeting a Sway desktop environment.

## Purpose

* Automates the installation of a base Arch Linux system onto pre-existing partitions.
* Configures the system with a range of software, including a desktop environment, development tools, and utilities.
* Handles the reboot required between the base installation and final configuration.

## Setup Script (`setup_controller.sh`)

* Prepares the **controller machine** (where you run Ansible from) by installing necessary dependencies (Ansible, Python, Git, SSH, Curl, etc.).
* Generates the complete Ansible project structure, including roles, playbook, inventory, and example configuration files.
* Copies user-provided configuration files (like Sway config, .bashrc) into the generated project roles.
* Creates a verification script (`verify_installation.sh`) to run post-installation.
* Provides detailed instructions on how to configure variables, secrets (using Ansible Vault), and run the playbook.

## Ansible Playbook (`install_and_configure.yml`)

* **Play 1 (Runs on Live ISO):**
    * Formats and mounts existing target partitions.
    * Installs the base Arch system and essential packages (`base`, `linux`, `networkmanager`, `openssh`, `sudo`, `python`, `git`, etc.) using `pacstrap`.
    * Configures basic system settings (locale, timezone, hostname, fstab, bootloader).
    * Sets up root and user accounts with specified passwords (hashed in vault) and SSH keys.
    * Configures passwordless `sudo` for the `wheel` group.
    * Installs and enables core services like `NetworkManager`, `sshd`, `avahi-daemon`.
    * Optionally creates a temporary service to connect to Wi-Fi on first boot.
    * Triggers a reboot.
* **Play 2 (Runs on Newly Installed System):**
    * Waits for the target machine to become available via SSH using its `.local` hostname (requires working Avahi/mDNS).
    * Updates the system and installs `yay` AUR helper.
    * Installs extra packages from official repositories (Sway, Waybar, Pipewire, Docker, TLP, Micro, Nautilus, Codecs, etc.).
    * Installs AUR packages using `yay` (libinput-gestures, autotiling, etc.).
    * Configures user settings (groups, Git user/email).
    * **Installs and configures Git Credential Manager (GCM)** using the official source script, sets the credential store to `cache`, and pre-seeds GitHub credentials from the vault.
    * Sets up swap files (on root and optionally MicroSD).
    * Mounts MicroSD card (if configured).
    * Configures the firewall (nftables or ufw).
    * Installs and configures Docker (if enabled).
    * Configures the Sway desktop environment (theming, gestures, autorotation script, wallpaper script, Alacritty, etc.) using user-provided files where available.
    * Enables specified system services (`seatd`, `tlp`, firewall, etc.).
    * Cleans up temporary first-boot files.

## Customization

* Core configuration is done by copying `group_vars/all/config.yml.example` to `config.yml` and editing values (partitions, user, hostname, packages, feature flags like GCM/Docker).
* Sensitive data (passwords, API keys, GCM credentials) is stored securely using `ansible-vault` in `group_vars/all/vault.yml`.
* Target machines (Live ISO IP, final hostname) are defined in `inventory.ini`.
* Specific desktop configuration files (`config` for Sway, `libinput-gestures.conf`, `.bashrc`, etc.) can be placed alongside `setup_controller.sh` before running it to have them copied into the project.

## Key Features Installed/Configured

* Arch Linux Base System
* Sway Compositor & Ecosystem (Waybar, Wofi, Foot, Alacritty, Mako, grim/slurp)
* Pipewire Audio
* NetworkManager & Avahi (for `.local` resolution)
* Yay AUR Helper
* Git & Git Credential Manager (GCM) with Cache Store & GitHub Pre-seeding
* Docker & Docker Compose (Optional)
* Swap Files
* Firewall (nftables/ufw)
* TLP Power Management
* XDG User Directories
* Common Utilities (htop, tmux, micro, vim, rsync, curl, etc.)
* Visual Studio Code
* Nautilus File Manager
* Fonts (Fira Code, Noto, Font Awesome)
* GTK/Qt Theming (Adwaita-dark default)
* Libinput Gestures
* Screen Autorotation Script (requires manual hardware path configuration)
* Unsplash/Pywal Wallpaper Script


* does not partition volumes yet just formats them. 
* ansible-playbook install_and_configure.yml -i inventory.ini --ask-vault-pass


## Broken

* *(Add any known issues here)*

TASK [users : GCM | Install GCM using source helper script] *********************************
fatal: [laptop]: FAILED! => {"changed": false, "changed_when_result": "The conditional check ''Installing Git Credential Manager' in gcm_install_result.stdout' failed. The error was: error while evaluating conditional ('Installing Git Credential Manager' in gcm_install_result.stdout): 'dict object' has no attribute 'stdout'. 'dict object' has no attribute 'stdout'", "msg": "Unsupported parameters for (ansible.legacy.command) module: warn. Supported parameters include: _raw_params, _uses_shell, argv, chdir, creates, executable, removes, stdin, stdin_add_newline, strip_empty_ends."}

PLAY RECAP **********************************************************************************
laptop                     : ok=37   changed=9    unreachable=0    failed=1    skipped=0    rescued=0    ignored=0   
target_live                : ok=53   changed=33   unreachable=0    failed=0    skipped=3    rescued=0    ignored=0   


## TODO

* *(Add future plans or improvements here)*
