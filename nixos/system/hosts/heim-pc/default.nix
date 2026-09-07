{ self, heimPcProfile ? { }, config, lib, pkgs, ... }:
let
  sourceRevision =
    if self ? rev then self.rev
    else if self ? dirtyRev then self.dirtyRev
    else "prototype-unbound";

  # The one-shot credential bootstrap exists only on storage-backed physical
  # profiles. The impossible-root prototype and VM proof never consume secret
  # material, and live media has its own user model.
  firstBootCredentialBootstrap =
    (heimPcProfile.physical or false)
    && builtins.hasAttr "/persist" config.fileSystems;

  firstBootCredentialScript = ''
    # BEGIN_FIRSTBOOT_CREDENTIAL_SCRIPT
    set -euo pipefail
    umask 077

    secret_dir="/persist/secrets/heim-pc/first-boot"
    secret_path="$secret_dir/alex-password-hash"
    marker_dir="/persist/heim-pc/bootstrap"
    marker_path="$marker_dir/alex-password-initialized"
    expected_owner="$(id -u):$(id -g)"

    fail() {
      printf 'heim-pc first-boot credential bootstrap failed: %s\n' "$1" >&2
      exit 1
    }

    owner_mode() {
      stat -c '%u:%g:%a' -- "$1"
    }

    exact_path() {
      [ "$(readlink -f -- "$1")" = "$1" ]
    }

    account_state() {
      status_line="$(passwd -S alex 2>/dev/null)" || fail "alex account status unavailable"
      set -- $status_line
      [ "$1" = "alex" ] || fail "unexpected account status identity"
      printf '%s\n' "$2"
    }

    validate_marker_dir() {
      [ -d "$marker_dir" ] && [ ! -L "$marker_dir" ] && exact_path "$marker_dir" \
        || fail "bootstrap marker directory is missing or unsafe"
      [ "$(owner_mode "$marker_dir")" = "$expected_owner:700" ] \
        || fail "bootstrap marker directory owner or mode mismatch"
    }

    validate_marker() {
      validate_marker_dir
      [ -f "$marker_path" ] && [ ! -L "$marker_path" ] && exact_path "$marker_path" \
        || fail "bootstrap marker is missing or unsafe"
      [ "$(owner_mode "$marker_path")" = "$expected_owner:600" ] \
        || fail "bootstrap marker owner or mode mismatch"
    }

    [ "$expected_owner" = "0:0" ] || fail "credential bootstrap is not running as root"
    state="$(account_state)"

    # Once initialized, the bootstrap lane is permanently non-overwriting.
    # A newly staged secret is treated as an operator error rather than as
    # implicit password rotation.
    if [ -e "$marker_path" ] || [ -L "$marker_path" ]; then
      validate_marker
      [ ! -e "$secret_path" ] && [ ! -L "$secret_path" ] \
        || fail "bootstrap secret remains after initialization"
      [ "$state" = "P" ] || fail "marker exists but alex has no usable password"
      exit 0
    fi

    # Missing marker plus an already-passworded account is ambiguous. Refuse
    # to overwrite it; recovery must reconcile the marker under separate
    # authority.
    [ "$state" != "P" ] || fail "marker missing for already-passworded alex account"
    case "$state" in
      L|NP) ;;
      *) fail "unexpected pre-bootstrap alex password state" ;;
    esac

    [ -d "$secret_dir" ] && [ ! -L "$secret_dir" ] && exact_path "$secret_dir" \
      || fail "bootstrap secret directory is missing or unsafe"
    [ "$(owner_mode "$secret_dir")" = "$expected_owner:700" ] \
      || fail "bootstrap secret directory owner or mode mismatch"
    [ -f "$secret_path" ] && [ ! -L "$secret_path" ] && exact_path "$secret_path" \
      || fail "bootstrap secret is missing or unsafe"
    [ "$(owner_mode "$secret_path")" = "$expected_owner:600" ] \
      || fail "bootstrap secret owner or mode mismatch"
    [ "$(wc -c < "$secret_path")" -le 512 ] \
      || fail "bootstrap secret is unexpectedly large"

    mapfile -t lines < "$secret_path"
    [ "''${#lines[@]}" -eq 1 ] || fail "bootstrap secret must contain exactly one line"
    hash="''${lines[0]}"
    printf '%s\n' "$hash" | grep -Eq '^\$(y|6)\$[^[:space:]:]{20,255}$' \
      || fail "bootstrap secret is not an accepted password hash"

    # chpasswd receives the hash on stdin, never argv. No command in this
    # service prints the hash or copies it into the Nix Store.
    printf 'alex:%s\n' "$hash" | chpasswd -e \
      || fail "setting alex password failed"
    unset hash
    unset 'lines[0]'

    [ "$(account_state)" = "P" ] || fail "alex password did not become usable"

    # The staged hash is single-use. If cleanup or marker publication fails,
    # the next boot observes an already-passworded account without a marker
    # and fails closed instead of retrying the password mutation.
    rm -- "$secret_path" || fail "consuming bootstrap secret failed"

    if [ -e "$marker_dir" ] || [ -L "$marker_dir" ]; then
      validate_marker_dir
    else
      install -d -m 0700 -- "$marker_dir"
      validate_marker_dir
    fi

    marker_tmp="$marker_dir/.alex-password-initialized.$$"
    trap 'rm -f -- "$marker_tmp"' EXIT
    printf 'schema_version=1\nuser=alex\nstate=initialized\n' > "$marker_tmp"
    chmod 0600 -- "$marker_tmp"
    mv -fT -- "$marker_tmp" "$marker_path"
    trap - EXIT
    validate_marker
    # END_FIRSTBOOT_CREDENTIAL_SCRIPT
  '';
in
{
  imports = [ ../../modules/desktop.nix ../../modules/nvidia.nix ../../modules/audio.nix ../../modules/development.nix ../../modules/containers.nix ../../modules/grabowski.nix ../../modules/bureau.nix ../../modules/networking.nix ../../modules/backup.nix ../../modules/observability.nix ../../modules/physical-gates.nix ];
  networking.hostName = "heim-pc";
  nixpkgs.config.allowUnfree = true;

  # Placeholder boot surface for heim-pc and the VM proof only. The physical
  # storage target and gate profiles replace it with storage-layout.nix, derived
  # from the same rehearsal contract. Neither profile authorizes installation.
  fileSystems."/" = {
    device = "/dev/disk/by-label/NIXOS_PROTOTYPE_DO_NOT_INSTALL";
    fsType = "ext4";
  };
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = false;
  system.stateVersion = "26.05";

  # Physical hardware policy must not leak into the hardware-neutral VM proof.
  hardware.cpu.amd.updateMicrocode = heimPcProfile.physical or false;

  # Runtime identity is always observable. The explicit provenance bundle in
  # flake.nix is the fail-closed gate that rejects dirty or path-only sources.
  system.configurationRevision = sourceRevision;
  environment.etc."heim-pc/source-revision".text = sourceRevision;

  heimPc.desktop.enable = heimPcProfile.desktop or false;
  heimPc.hardware.nvidia = {
    enable = heimPcProfile.nvidia or false;
    openKernelModule = heimPcProfile.nvidiaOpen or false;
  };
  heimPc.physicalGates.enable = heimPcProfile.physicalGates or false;

  # Password changes after the one-shot bootstrap are intentionally mutable;
  # later NixOS activations must not reset them from declarative source.
  users.mutableUsers = true;
  users.users.alex = {
    isNormalUser = true;
    extraGroups = [ "wheel" "audio" "video" "networkmanager" ];
  };

  # The console autologin exists only for the hardware-neutral VM proof. It is
  # never accepted as physical credential evidence.
  services.getty.autologinUser = lib.mkIf (!(heimPcProfile.desktop or false)) "alex";

  systemd.services.heim-pc-firstboot-credentials = lib.mkIf firstBootCredentialBootstrap {
    description = "Fail-closed one-shot Heim-PC credential bootstrap";
    after = [ "local-fs.target" "persist.mount" ];
    requires = [ "persist.mount" ];
    before = [ "multi-user.target" "display-manager.service" ];
    requiredBy = [ "multi-user.target" "display-manager.service" ];
    path = [ pkgs.coreutils pkgs.shadow pkgs.gnugrep ];
    script = firstBootCredentialScript;
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      User = "root";
      Group = "root";
      UMask = "0077";
    };
  };
}