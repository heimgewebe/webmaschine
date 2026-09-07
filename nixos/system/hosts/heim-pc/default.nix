{ self, heimPcProfile ? { }, config, lib, pkgs, ... }:
let
  sourceRevision =
    if self ? rev then self.rev
    else if self ? dirtyRev then self.dirtyRev
    else "prototype-unbound";

  # Credential bootstrap is deliberately narrower than "physical": it is
  # enabled only for the current desktop-shaped, storage-backed physical
  # profiles. A future headless physical profile therefore fails closed until
  # it gets an explicit reviewed credential design.
  firstBootCredentialBootstrap =
    (heimPcProfile.physical or false)
    && (heimPcProfile.desktop or false)
    && builtins.hasAttr "/persist" config.fileSystems;

  firstBootCredentialProgram = pkgs.writeText "heim-pc-firstboot-credentials.py" ''
    import os
    import re
    import stat
    import subprocess
    import sys

    PERSIST_PATH = "/persist"
    SHADOW_PATH = "/etc/shadow"
    EXPECTED_UID = 0
    EXPECTED_GID = 0
    MARKER_BYTES = b"schema_version=1\nuser=alex\nstate=initialized\n"
    YESCRYPT_RE = re.compile(r"^\$y\$[./0-9A-Za-z]{3}\$[./0-9A-Za-z]{22}\$[./0-9A-Za-z]{43}$")
    NOFOLLOW = os.O_NOFOLLOW
    DIRECTORY = os.O_DIRECTORY


    def fail(message):
        print("heim-pc first-boot credential bootstrap failed: " + message, file=sys.stderr)
        raise SystemExit(1)


    def checked_dir_fd(fd, label, exact_mode=None):
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode):
            fail(label + " is not a directory")
        if info.st_uid != EXPECTED_UID or info.st_gid != EXPECTED_GID:
            fail(label + " owner mismatch")
        mode = stat.S_IMODE(info.st_mode)
        if exact_mode is not None:
            if mode != exact_mode:
                fail(label + " mode mismatch")
        elif mode & 0o022:
            fail(label + " is group/other writable")
        return fd


    def open_absolute_dir(path, label):
        try:
            fd = os.open(path, os.O_RDONLY | DIRECTORY | NOFOLLOW)
        except OSError:
            fail(label + " is missing or unsafe")
        return checked_dir_fd(fd, label)


    def open_child_dir(parent_fd, name, label, exact_mode=0o700, create=False):
        if create:
            try:
                os.mkdir(name, exact_mode, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except FileExistsError:
                pass
            except OSError:
                fail(label + " could not be created")
        try:
            fd = os.open(name, os.O_RDONLY | DIRECTORY | NOFOLLOW, dir_fd=parent_fd)
        except OSError:
            fail(label + " is missing or unsafe")
        return checked_dir_fd(fd, label, exact_mode)


    def open_optional_child_dir(parent_fd, name, label, exact_mode=0o700):
        try:
            fd = os.open(name, os.O_RDONLY | DIRECTORY | NOFOLLOW, dir_fd=parent_fd)
        except FileNotFoundError:
            return None
        except OSError:
            fail(label + " is unsafe")
        return checked_dir_fd(fd, label, exact_mode)


    def entry_exists(parent_fd, name):
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False
        except OSError:
            fail("could not inspect " + name)


    def read_regular_at(parent_fd, name, label, exact_mode, max_bytes):
        try:
            fd = os.open(name, os.O_RDONLY | NOFOLLOW, dir_fd=parent_fd)
        except OSError:
            fail(label + " is missing or unsafe")
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                fail(label + " is not one regular file")
            if info.st_uid != EXPECTED_UID or info.st_gid != EXPECTED_GID:
                fail(label + " owner mismatch")
            if stat.S_IMODE(info.st_mode) != exact_mode:
                fail(label + " mode mismatch")
            data = b""
            while len(data) <= max_bytes:
                chunk = os.read(fd, max_bytes + 1 - len(data))
                if not chunk:
                    break
                data += chunk
            if len(data) > max_bytes:
                fail(label + " is unexpectedly large")
            return data
        finally:
            os.close(fd)


    def write_all(fd, data):
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                fail("short bootstrap marker write")
            view = view[written:]


    def shadow_hash():
        try:
            fd = os.open(SHADOW_PATH, os.O_RDONLY | NOFOLLOW)
        except OSError:
            fail("shadow database is unavailable")
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != EXPECTED_UID:
                fail("shadow database identity is unsafe")
            with os.fdopen(os.dup(fd), "r", encoding="utf-8", errors="strict") as handle:
                matches = []
                for line in handle:
                    fields = line.rstrip("\n").split(":")
                    if fields and fields[0] == "alex":
                        if len(fields) != 9:
                            fail("alex shadow entry is malformed")
                        matches.append(fields[1])
            if len(matches) != 1:
                fail("alex shadow entry is missing or duplicated")
            return matches[0]
        finally:
            os.close(fd)


    def fsync_shadow():
        try:
            fd = os.open(SHADOW_PATH, os.O_RDONLY | NOFOLLOW)
            parent = os.open(os.path.dirname(SHADOW_PATH), os.O_RDONLY | DIRECTORY | NOFOLLOW)
        except OSError:
            fail("shadow durability path is unavailable")
        try:
            os.fsync(fd)
            os.fsync(parent)
        except OSError:
            fail("shadow durability sync failed")
        finally:
            os.close(fd)
            os.close(parent)


    def open_secret_dir(persist_fd, optional=False):
        opener = open_optional_child_dir if optional else open_child_dir
        secrets_fd = opener(persist_fd, "secrets", "bootstrap secrets directory")
        if secrets_fd is None:
            return None
        try:
            heim_fd = opener(secrets_fd, "heim-pc", "bootstrap secret namespace")
            if heim_fd is None:
                return None
            try:
                return opener(heim_fd, "first-boot", "bootstrap secret directory")
            finally:
                os.close(heim_fd)
        finally:
            os.close(secrets_fd)


    def open_marker_dir(persist_fd, create=False, optional=False):
        if optional:
            heim_fd = open_optional_child_dir(persist_fd, "heim-pc", "bootstrap marker namespace")
        else:
            heim_fd = open_child_dir(
                persist_fd, "heim-pc", "bootstrap marker namespace", create=create
            )
        if heim_fd is None:
            return None
        try:
            if optional:
                return open_optional_child_dir(heim_fd, "bootstrap", "bootstrap marker directory")
            return open_child_dir(
                heim_fd, "bootstrap", "bootstrap marker directory", create=create
            )
        finally:
            os.close(heim_fd)


    def validate_marker(marker_dir_fd):
        marker = read_regular_at(
            marker_dir_fd,
            "alex-password-initialized",
            "bootstrap marker",
            0o600,
            128,
        )
        if marker != MARKER_BYTES:
            fail("bootstrap marker content mismatch")


    if os.geteuid() != EXPECTED_UID or os.getegid() != EXPECTED_GID:
        fail("credential bootstrap is not running as root")

    persist_fd = open_absolute_dir(PERSIST_PATH, "persist mount")
    try:
        marker_dir_fd = open_marker_dir(persist_fd, optional=True)
        if marker_dir_fd is not None:
            try:
                if entry_exists(marker_dir_fd, "alex-password-initialized"):
                    validate_marker(marker_dir_fd)
                    secret_dir_fd = open_secret_dir(persist_fd, optional=True)
                    if secret_dir_fd is not None:
                        try:
                            if entry_exists(secret_dir_fd, "alex-password-hash"):
                                fail("bootstrap secret remains after initialization")
                        finally:
                            os.close(secret_dir_fd)
                    raise SystemExit(0)
            finally:
                os.close(marker_dir_fd)

        current_hash = shadow_hash()
        if current_hash not in {"!", "!!", "*"}:
            fail("alex account is not in the virgin locked state")

        secret_dir_fd = open_secret_dir(persist_fd)
        try:
            secret = read_regular_at(
                secret_dir_fd,
                "alex-password-hash",
                "bootstrap secret",
                0o600,
                256,
            )
            if secret.count(b"\n") != 1 or not secret.endswith(b"\n"):
                fail("bootstrap secret must contain exactly one newline-terminated line")
            try:
                password_hash = secret[:-1].decode("ascii")
            except UnicodeDecodeError:
                fail("bootstrap secret is not ASCII")
            if YESCRYPT_RE.fullmatch(password_hash) is None:
                fail("bootstrap secret is not canonical yescrypt")

            # Preflight the durable marker destination before mutating /etc/shadow.
            marker_dir_fd = open_marker_dir(persist_fd, create=True)
            try:
                if entry_exists(marker_dir_fd, "alex-password-initialized"):
                    fail("bootstrap marker appeared during preflight")

                try:
                    result = subprocess.run(
                        ["chpasswd", "-e"],
                        input=("alex:" + password_hash + "\n").encode("ascii"),
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                        timeout=10,
                    )
                except subprocess.TimeoutExpired:
                    fail("setting alex password timed out")
                except OSError:
                    fail("setting alex password could not start")
                if result.returncode != 0:
                    fail("setting alex password failed")

                if shadow_hash() != password_hash:
                    fail("alex shadow hash does not match staged bootstrap material")
                fsync_shadow()

                # From here on, failure must never replay chpasswd. Secret removal
                # is descriptor-relative and durably synced before marker publish.
                try:
                    os.unlink("alex-password-hash", dir_fd=secret_dir_fd)
                    os.fsync(secret_dir_fd)
                except OSError:
                    fail("consuming bootstrap secret failed")

                tmp_name = ".alex-password-initialized.tmp-" + str(os.getpid())
                try:
                    marker_fd = os.open(
                        tmp_name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW,
                        0o600,
                        dir_fd=marker_dir_fd,
                    )
                except OSError:
                    fail("bootstrap marker staging failed")
                try:
                    write_all(marker_fd, MARKER_BYTES)
                    os.fsync(marker_fd)
                except OSError:
                    fail("bootstrap marker write failed")
                finally:
                    os.close(marker_fd)

                try:
                    os.replace(
                        tmp_name,
                        "alex-password-initialized",
                        src_dir_fd=marker_dir_fd,
                        dst_dir_fd=marker_dir_fd,
                    )
                    os.fsync(marker_dir_fd)
                except OSError:
                    try:
                        os.unlink(tmp_name, dir_fd=marker_dir_fd)
                    except OSError:
                        pass
                    fail("bootstrap marker publication failed")
                validate_marker(marker_dir_fd)
            finally:
                os.close(marker_dir_fd)
        finally:
            os.close(secret_dir_fd)
    finally:
        os.close(persist_fd)
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

  # Console autologin belongs solely to the non-physical VM proof. A future
  # physical headless profile must define credentials explicitly instead of
  # inheriting an autologin escape hatch.
  services.getty.autologinUser = lib.mkIf (
    !(heimPcProfile.physical or false)
    && !(heimPcProfile.desktop or false)
  ) "alex";

  systemd.services.heim-pc-firstboot-credentials = lib.mkIf firstBootCredentialBootstrap {
    description = "Fail-closed one-shot Heim-PC credential bootstrap";
    after = [ "local-fs.target" "persist.mount" ];
    requires = [ "persist.mount" ];

    # systemd-user-sessions.service removes the global PAM nologin gate. Keep it
    # required and ordered behind the complete transaction, not merely behind
    # the password write. The display manager is separately held behind it too.
    before = [ "systemd-user-sessions.service" "display-manager.service" ];
    requiredBy = [ "systemd-user-sessions.service" "display-manager.service" ];

    path = [ pkgs.shadow ];
    script = ''
      exec ${pkgs.python3}/bin/python3 ${firstBootCredentialProgram}
    '';
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      User = "root";
      Group = "root";
      UMask = "0077";
    };
  };
}
