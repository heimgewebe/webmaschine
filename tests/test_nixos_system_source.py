from pathlib import Path
import fcntl
import hashlib
import os
import re
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "nixos" / "system"
SOURCE_SNAPSHOT_SHA256 = "b50f670605eaae7417e48a5eab49b0bc2235c54f9e6d4795bf7f137109ba4dac"
ROOT_LOCK_SHA256 = "19d83aededafff8a80ca354e4fba18c1470d638b683079bd983639eb5719e26d"
TEST_SOURCE_REVISION = "a" * 40


class T(unittest.TestCase):
    def test_root_flake_is_thin_adapter(self):
        root_flake = (ROOT / "flake.nix").read_text()
        nested = (SOURCE / "flake.nix").read_text()
        self.assertTrue(root_flake.startswith("{\n"))
        # Static drift guard only; the Nix CI lane proves actual evaluation.
        metadata = r'description = "[^"\n]+";'
        inputs = r"  inputs = \{.*?\n  \};"
        self.assertEqual(re.search(metadata, root_flake).group(), re.search(metadata, nested).group())
        self.assertEqual(re.search(inputs, root_flake, re.S).group(), re.search(inputs, nested, re.S).group())
        self.assertIn("outputs = inputs@{ self, nixpkgs, microvm }:", root_flake)
        self.assertIn("(import ./nixos/system/flake.nix).outputs inputs", root_flake)
        self.assertNotIn("(import ./nixos/system/flake.nix).description", root_flake)
        self.assertNotIn("(import ./nixos/system/flake.nix).inputs", root_flake)

    def test_nix_workflow_binds_exact_source_without_lock_update(self):
        workflow = (ROOT / ".github/workflows/heim-pc-nix.yml").read_text()
        self.assertIn("ref: ${{ github.event.pull_request.head.sha || github.sha }}", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn('test "$(git rev-parse HEAD)" = "$EXPECTED_SOURCE_REVISION"', workflow)
        self.assertIn("nix flake check --no-build --no-update-lock-file", workflow)
        self.assertIn(".#checks.x86_64-linux.profile-contract", workflow)

    def test_root_lock_is_bound(self):
        self.assertEqual(hashlib.sha256((ROOT / "flake.lock").read_bytes()).hexdigest(), ROOT_LOCK_SHA256)

    def test_current_nixos_source_snapshot_is_bound(self):
        digest = hashlib.sha256()
        files = sorted(path for path in SOURCE.rglob("*") if path.is_file())
        for path in files:
            relative = str(path.relative_to(SOURCE)).encode()
            digest.update(relative + b"\0" + path.read_bytes() + b"\0")
        self.assertEqual(len(files), 21)
        self.assertEqual(digest.hexdigest(), SOURCE_SNAPSHOT_SHA256)

    def test_canonical_source_layout(self):
        for relative in (
            "flake.nix", "README.md", "hosts/heim-pc/default.nix",
            "modules/audio.nix", "modules/backup.nix", "modules/bureau.nix",
            "modules/containers.nix", "modules/desktop.nix", "modules/development.nix",
            "modules/grabowski.nix", "modules/live-media.nix", "modules/networking.nix",
            "modules/nvidia.nix", "modules/observability.nix", "modules/physical-gates.nix",
            "modules/storage-layout.nix",
            "tests/integration.nix", "tests/trust-zones.nix", "tests/vsock-broker.nix",
            "zones/agent.nix",
        ):
            self.assertTrue((SOURCE / relative).is_file(), relative)

    def test_managed_root_entrypoint_exists(self):
        flake = (SOURCE / "flake.nix").read_text()
        host = (SOURCE / "hosts/heim-pc/default.nix").read_text()
        self.assertIn("nixosConfigurations.heim-pc", flake)
        self.assertIn("system.configurationRevision = sourceRevision", host)
        self.assertIn("NIXOS_PROTOTYPE_DO_NOT_INSTALL", host)
        self.assertIn("boot.loader.efi.canTouchEfiVariables = false", host)

    def test_storage_target_build_is_contract_derived_and_separate_from_prototype(self):
        flake = (SOURCE / "flake.nix").read_text()
        host = (SOURCE / "hosts/heim-pc/default.nix").read_text()
        layout = (SOURCE / "modules/storage-layout.nix").read_text()
        deployment = (ROOT / "nixos" / "deployment" / "contract-v1.json").read_text()
        self.assertIn("nixosConfigurations.heim-pc-storage-target", flake)
        self.assertIn("./modules/storage-layout.nix", flake)
        self.assertIn("../../rehearsal/contract-v1.json", layout)
        self.assertIn("boot.initrd.luks.devices.${mapperName}", layout)
        self.assertIn("fileSystems = lib.mkForce", layout)
        self.assertIn(
            ".#nixosConfigurations.heim-pc-storage-target.config.system.build.toplevel",
            deployment,
        )
        self.assertIn("NIXOS_PROTOTYPE_DO_NOT_INSTALL", host)

    def test_live_media_excludes_boot_and_heavy_model_gates(self):
        live = (SOURCE / "modules/live-media.nix").read_text()
        gates = (SOURCE / "modules/physical-gates.nix").read_text()
        self.assertIn("bootReadiness = false", live)
        self.assertIn("modelRuntime = false", live)
        self.assertIn('"networkmanager"', live)
        self.assertIn('fail "persistent-disk-mount-inventory"', live)
        self.assertIn("findmnt --json --list -o TARGET,SOURCE,FSTYPE,OPTIONS,MAJ:MIN", live)
        self.assertIn("lsblk --json --list --paths", live)
        self.assertIn("${./live-block-inventory.jq}", live)
        self.assertNotIn("done < <(lsblk", live)
        self.assertIn('fail "raw-block-device-inventory"; exit 1;', live)
        self.assertIn("lib.optional cfg.bootReadiness gateDReport", gates)
        self.assertIn("lib.optional cfg.modelRuntime llamaCuda", gates)
        self.assertIn("services.ollama = lib.mkIf cfg.modelRuntime", gates)
        self.assertNotIn("mesa-demos", live)

    def test_declarative_nixos_system_source_remains_non_destructive(self):
        content = "\n".join(
            path.read_text() for path in SOURCE.rglob("*")
            if path.is_file() and path.suffix in {".nix", ".sh", ".py"}
        )
        for marker in ("/dev/nvme0", "parted ", "mkfs.", "nixos-install", "efibootmgr"):
            self.assertNotIn(marker, content)

    def test_gate_a_uses_pinned_nvidia_binary_and_exact_pinned_cdi_contract(self):
        gate = (SOURCE / "modules/physical-gates.nix").read_text()
        self.assertIn("lib.getExe' config.hardware.nvidia.package \"nvidia-smi\"", gate)
        self.assertIn("/run/cdi/nvidia-container-toolkit.json", gate)
        self.assertNotIn("/etc/cdi/nvidia-container-toolkit.json", gate)
        self.assertIn('any(.devices[]?; .name == "all")', gate)
        self.assertNotIn('.devices[]?.name == "all"', gate)
        self.assertNotIn('gpu_info="$(nvidia-smi ', gate)
        self.assertIn("c5c4a43b0e8056328ec4529f735cabdb8f1942bb", gate)
        self.assertIn("for _attempt in $(seq 1 90)", gate)
        self.assertIn("systemctl is-failed --quiet nvidia-container-toolkit-cdi-generator.service", gate)
        self.assertNotIn("mesa-demos", gate)

    def test_integration_test_is_scoped_to_grabowski_and_bureau(self):
        integration = (SOURCE / "tests/integration.nix").read_text()
        self.assertIn("../modules/grabowski.nix", integration)
        self.assertIn("../modules/bureau.nix", integration)
        for unrelated in (
            "../modules/audio.nix",
            "../modules/development.nix",
            "../modules/containers.nix",
            "../modules/networking.nix",
            "../modules/backup.nix",
            "../modules/observability.nix",
        ):
            self.assertNotIn(unrelated, integration)
        self.assertIn("virtualisation.memorySize = 1024", integration)
        self.assertIn("virtualisation.cores = 1", integration)

    def test_readme_separates_current_snapshot_from_historical_runtime_evidence(self):
        readme = (SOURCE / "README.md").read_text()
        self.assertIn("## Current snapshot evidence status", readme)
        self.assertIn("not re-established Nix/QEMU/KVM execution evidence", readme)
        self.assertIn("## Historical evidence from earlier revisions", readme)
        self.assertIn("../../tests/test_nixos_system_source.py", readme)
        self.assertNotIn("../../tests/test_nixos_heim_pc_prototype.py", readme)

    def test_grabowski_operator_readback_is_nonsecret_and_user_readable(self):
        module = (SOURCE / "modules/grabowski.nix").read_text()
        integration = (SOURCE / "tests/integration.nix").read_text()
        self.assertIn('RuntimeDirectoryMode = "0755"', module)
        self.assertIn('chmod 0644 "$RUNTIME_DIRECTORY/readback.json"', module)
        self.assertIn("jq -cn", module)
        self.assertIn("su -s /bin/sh -c 'grabowski-demo-operator status' alex", integration)

    def _firstboot_program(self):
        host = (SOURCE / "hosts/heim-pc/default.nix").read_text()
        match = re.search(
            r'  firstBootCredentialProgram = pkgs\.writeText "heim-pc-firstboot-credentials\.py" \'\'\n(?P<body>.*?)\n  \'\';\nin\n\{',
            host,
            re.S,
        )
        self.assertIsNotNone(match)
        return textwrap.dedent(match.group("body")).replace(
            "SOURCE_REVISION = ${builtins.toJSON sourceRevision}",
            f"SOURCE_REVISION = {TEST_SOURCE_REVISION!r}",
        )

    @staticmethod
    def _write_shadow(root, password_hash):
        shadow = root / "shadow"
        shadow.write_text(f"alex:{password_hash}:1:0:99999:7:::\n")
        shadow.chmod(0o600)
        return shadow

    def _firstboot_fixture(self, root, initial_hash="!"):
        persist = root / "persist"
        persist.mkdir(mode=0o755)
        shadow = self._write_shadow(root, initial_hash)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        chpasswd_log = root / "chpasswd.log"

        chpasswd = bin_dir / "chpasswd"
        chpasswd.write_text(textwrap.dedent("""\
            #!/usr/bin/python3
            import os
            import sys

            if sys.argv[1:] != ["-e"]:
                raise SystemExit(64)
            line = sys.stdin.buffer.readline().decode("ascii").rstrip("\\n")
            if sys.stdin.buffer.read():
                raise SystemExit(65)
            try:
                user, password_hash = line.split(":", 1)
            except ValueError:
                raise SystemExit(66)
            if user != "alex" or not password_hash.startswith("$"):
                raise SystemExit(67)
            path = os.environ["HEIM_PC_TEST_SHADOW"]
            rows = []
            found = 0
            with open(path, encoding="utf-8") as handle:
                for row in handle:
                    fields = row.rstrip("\\n").split(":")
                    if fields[0] == "alex":
                        fields[1] = password_hash
                        found += 1
                    rows.append(":".join(fields))
            if found != 1:
                raise SystemExit(68)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("\\n".join(rows) + "\\n")
                handle.flush()
                os.fsync(handle.fileno())
            with open(os.environ["HEIM_PC_TEST_CHPASSWD_LOG"], "a", encoding="utf-8") as handle:
                handle.write("called\\n")
            marker_path = os.environ.get("HEIM_PC_TEST_AFTER_CHPASSWD_MARKER_PATH")
            if marker_path:
                with open(marker_path, "x", encoding="utf-8") as handle:
                    handle.write("foreign-marker\\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(marker_path, 0o600)
        """))
        chpasswd.chmod(0o700)
        return bin_dir, shadow, chpasswd_log

    def _stage_firstboot_secret(
        self, root, content, mode=0o600, authority_revision=TEST_SOURCE_REVISION
    ):
        persist = root / "persist"
        secrets = persist / "secrets"
        namespace = secrets / "heim-pc"
        secret_dir = namespace / "first-boot"
        for directory in (secrets, namespace, secret_dir):
            directory.mkdir(exist_ok=True)
            directory.chmod(0o700)
        authority = secret_dir / "alex-password-bootstrap-authority"
        authority.write_text(
            "schema_version=1\n"
            "user=alex\n"
            "action=initialize-password\n"
            f"source_revision={authority_revision}\n"
        )
        authority.chmod(0o600)
        secret = secret_dir / "alex-password-hash"
        secret.write_text(content)
        secret.chmod(mode)
        return secret

    @staticmethod
    def _firstboot_authority_path(root):
        return root / "persist/secrets/heim-pc/first-boot/alex-password-bootstrap-authority"

    @staticmethod
    def _firstboot_marker_path(root):
        return root / "persist/heim-pc/bootstrap/alex-password-initialized"

    @staticmethod
    def _firstboot_pending_path(root):
        return root / "persist/heim-pc/bootstrap/.alex-password-initialized.pending"

    def _run_firstboot_program(
        self,
        root,
        bin_dir,
        shadow,
        chpasswd_log,
        extra_env=None,
        inject_secret_unlink_failure=False,
    ):
        program = self._firstboot_program()
        program = program.replace(
            'PERSIST_PATH = "/persist"', f'PERSIST_PATH = {str(root / "persist")!r}'
        ).replace(
            'SHADOW_PATH = "/etc/shadow"', f'SHADOW_PATH = {str(shadow)!r}'
        ).replace(
            "EXPECTED_UID = 0", f"EXPECTED_UID = {os.getuid()}"
        ).replace(
            "EXPECTED_GID = 0", f"EXPECTED_GID = {os.getgid()}"
        )
        if inject_secret_unlink_failure:
            original = 'os.unlink(SECRET_NAME, dir_fd=secret_dir_fd)'
            injected = 'raise OSError("injected bootstrap staging consumption failure")'
            self.assertIn(original, program)
            program = program.replace(original, injected, 1)
        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env['PATH']}"
        env["HEIM_PC_TEST_SHADOW"] = str(shadow)
        env["HEIM_PC_TEST_CHPASSWD_LOG"] = str(chpasswd_log)
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["/usr/bin/python3", "-c", program],
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )

    @staticmethod
    def _synthetic_password_hash():
        # Canonical-shape yescrypt fixture only; it is not a reusable credential.
        return "$y$j9T$" + ("s" * 21) + "0$" + ("x" * 42) + "A\n"

    @staticmethod
    def _shadow_hash(path):
        fields = path.read_text().splitlines()[0].split(":")
        return fields[1]

    @staticmethod
    def _chpasswd_call_count(path):
        return len(path.read_text().splitlines()) if path.exists() else 0

    def test_firstboot_credential_source_contract_is_fail_closed_and_out_of_store(self):
        host = (SOURCE / "hosts/heim-pc/default.nix").read_text()
        readme = (SOURCE / "README.md").read_text()
        self.assertIn("firstBootCredentialBootstrap =", host)
        self.assertIn("(heimPcProfile.physical or false)", host)
        self.assertIn("(heimPcProfile.desktop or false)", host)
        self.assertIn('builtins.hasAttr "/persist" config.fileSystems', host)
        self.assertIn("users.mutableUsers = true;", host)
        self.assertIn("heim-pc-firstboot-credentials", host)
        self.assertIn("services.getty.autologinUser = lib.mkIf (", host)
        self.assertIn("!(heimPcProfile.physical or false)", host)
        self.assertIn('requiredBy = [ "systemd-user-sessions.service" "display-manager.service" ];', host)
        self.assertIn('before = [ "systemd-user-sessions.service" "display-manager.service" ];', host)
        self.assertIn('User = "root";', host)
        self.assertIn('Group = "root";', host)
        self.assertIn("YESCRYPT_RE", host)
        self.assertIn(r'^\$y\$j9T\$', host)
        self.assertIn('CRYPT64_ALPHABET = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"', host)
        self.assertIn("YESCRYPT_SALT_LAST = frozenset(CRYPT64_ALPHABET[:4])", host)
        self.assertIn("YESCRYPT_CHECKSUM_LAST = frozenset(CRYPT64_ALPHABET[:16])", host)
        self.assertIn("is_canonical_default_yescrypt", host)
        self.assertIn("salt[-1] in YESCRYPT_SALT_LAST", host)
        self.assertIn("checksum[-1] in YESCRYPT_CHECKSUM_LAST", host)
        self.assertIn("SOURCE_REVISION_RE", host)
        self.assertIn("AUTHORITY_NAME", host)
        self.assertIn("AUTHORITY_BYTES", host)
        self.assertIn('PENDING_NAME = ".alex-password-initialized.pending"', host)
        self.assertIn("tmp_name = PENDING_NAME", host)
        self.assertIn("password_mutation_started = True", host)
        self.assertIn("bootstrap pending intent exists; recovery required", host)
        self.assertIn("fcntl.flock", host)
        self.assertIn("NOFOLLOW = os.O_NOFOLLOW", host)
        self.assertIn("dir_fd=", host)
        self.assertIn("assert_entry_identity", host)
        self.assertIn("os.fsync", host)
        self.assertIn("timeout=10", host)
        self.assertIn("write_all(marker_fd, MARKER_BYTES)", host)
        self.assertIn('current_hash not in {"!", "!!", "*"}', host)
        self.assertIn("require_shadow_hash(password_hash)", host)
        self.assertIn("os.link(", host)
        self.assertNotIn("os.replace(", host)
        self.assertIn('if marker != MARKER_BYTES:', host)
        self.assertNotIn("passwd -S", host)
        self.assertNotIn("hashedPasswordFile", host)
        self.assertNotRegex(
            host,
            r"\b(?:initialHashedPassword|initialPassword|hashedPassword|password)\s*=",
        )
        self.assertIn("exact default-cost yescrypt", readme)
        self.assertIn("systemd-user-sessions.service", readme)
        self.assertIn("descriptor-relative", readme)
        self.assertIn("separately authorized disposable installation", readme)
        self.assertIn("The repository task stages neither file", readme)

    def test_firstboot_credential_program_rejects_missing_malformed_unsafe_and_symlink_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir, shadow, log = self._firstboot_fixture(root)

            missing = self._run_firstboot_program(root, bin_dir, shadow, log)
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("bootstrap secrets directory is missing or unsafe", missing.stderr)
            self.assertEqual(self._shadow_hash(shadow), "!")
            self.assertEqual(self._chpasswd_call_count(log), 0)

            self._stage_firstboot_secret(root, "not-a-password-hash\n")
            invalid = self._run_firstboot_program(root, bin_dir, shadow, log)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("not canonical default-cost yescrypt", invalid.stderr)
            self.assertEqual(self._shadow_hash(shadow), "!")
            self.assertEqual(self._chpasswd_call_count(log), 0)

            self._stage_firstboot_secret(root, "$6$short$still-not-valid\n")
            crypt_like = self._run_firstboot_program(root, bin_dir, shadow, log)
            self.assertNotEqual(crypt_like.returncode, 0)
            self.assertIn("not canonical default-cost yescrypt", crypt_like.stderr)
            self.assertEqual(self._chpasswd_call_count(log), 0)

            secret = self._stage_firstboot_secret(
                root, self._synthetic_password_hash(), mode=0o644
            )
            unsafe = self._run_firstboot_program(root, bin_dir, shadow, log)
            self.assertNotEqual(unsafe.returncode, 0)
            self.assertIn("bootstrap secret mode mismatch", unsafe.stderr)
            self.assertTrue(secret.exists())
            self.assertEqual(self._chpasswd_call_count(log), 0)

            target = root / "secret-target"
            target.write_text(self._synthetic_password_hash())
            target.chmod(0o600)
            secret.unlink()
            secret.symlink_to(target)
            symlinked = self._run_firstboot_program(root, bin_dir, shadow, log)
            self.assertNotEqual(symlinked.returncode, 0)
            self.assertIn("bootstrap secret is missing or unsafe", symlinked.stderr)
            self.assertEqual(self._chpasswd_call_count(log), 0)

    def test_firstboot_credential_program_requires_exact_source_bound_authority_and_cost(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir, shadow, log = self._firstboot_fixture(root)
            self._stage_firstboot_secret(root, self._synthetic_password_hash())
            authority = self._firstboot_authority_path(root)
            authority.unlink()

            missing_authority = self._run_firstboot_program(root, bin_dir, shadow, log)
            self.assertNotEqual(missing_authority.returncode, 0)
            self.assertIn("bootstrap authority is missing or unsafe", missing_authority.stderr)
            self.assertEqual(self._chpasswd_call_count(log), 0)

            self._stage_firstboot_secret(
                root, self._synthetic_password_hash(), authority_revision="b" * 40
            )
            wrong_revision = self._run_firstboot_program(root, bin_dir, shadow, log)
            self.assertNotEqual(wrong_revision.returncode, 0)
            self.assertIn("not bound to this exact source", wrong_revision.stderr)
            self.assertEqual(self._chpasswd_call_count(log), 0)

            bad_cost = "$y$z9T$" + ("s" * 21) + "0$" + ("x" * 42) + "A\n"
            self._stage_firstboot_secret(root, bad_cost)
            wrong_cost = self._run_firstboot_program(root, bin_dir, shadow, log)
            self.assertNotEqual(wrong_cost.returncode, 0)
            self.assertIn("not canonical default-cost yescrypt", wrong_cost.stderr)
            self.assertEqual(self._chpasswd_call_count(log), 0)

    def test_firstboot_credential_program_rejects_noncanonical_crypt64_padding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir, shadow, log = self._firstboot_fixture(root)

            bad_salt_padding = (
                "$y$j9T$" + ("s" * 22) + "$" + ("x" * 42) + "A\n"
            )
            self._stage_firstboot_secret(root, bad_salt_padding)
            salt_result = self._run_firstboot_program(root, bin_dir, shadow, log)
            self.assertNotEqual(salt_result.returncode, 0)
            self.assertIn("not canonical default-cost yescrypt", salt_result.stderr)
            self.assertEqual(self._shadow_hash(shadow), "!")
            self.assertEqual(self._chpasswd_call_count(log), 0)

            bad_checksum_padding = (
                "$y$j9T$" + ("s" * 21) + "0$" + ("x" * 43) + "\n"
            )
            self._stage_firstboot_secret(root, bad_checksum_padding)
            checksum_result = self._run_firstboot_program(root, bin_dir, shadow, log)
            self.assertNotEqual(checksum_result.returncode, 0)
            self.assertIn("not canonical default-cost yescrypt", checksum_result.stderr)
            self.assertEqual(self._shadow_hash(shadow), "!")
            self.assertEqual(self._chpasswd_call_count(log), 0)

    def test_firstboot_stale_pending_intent_blocks_replay_from_bare_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir, shadow, log = self._firstboot_fixture(root)
            secret = self._stage_firstboot_secret(root, self._synthetic_password_hash())
            marker_namespace = root / "persist/heim-pc"
            marker_namespace.mkdir(parents=True, exist_ok=True)
            marker_namespace.chmod(0o700)
            marker_dir = marker_namespace / "bootstrap"
            marker_dir.mkdir(mode=0o700)
            pending = self._firstboot_pending_path(root)
            pending.write_bytes(b"schema_version=1\nuser=alex\nstate=initialized\n")
            pending.chmod(0o600)

            result = self._run_firstboot_program(root, bin_dir, shadow, log)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("bootstrap pending intent exists; recovery required", result.stderr)
            self.assertEqual(self._shadow_hash(shadow), "!")
            self.assertEqual(self._chpasswd_call_count(log), 0)
            self.assertTrue(pending.exists())
            self.assertTrue(secret.exists())
            self.assertTrue(self._firstboot_authority_path(root).exists())

    def test_firstboot_marker_publication_never_overwrites_concurrent_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir, shadow, log = self._firstboot_fixture(root)
            secret = self._stage_firstboot_secret(root, self._synthetic_password_hash())
            marker = self._firstboot_marker_path(root)

            result = self._run_firstboot_program(
                root,
                bin_dir,
                shadow,
                log,
                extra_env={"HEIM_PC_TEST_AFTER_CHPASSWD_MARKER_PATH": str(marker)},
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("bootstrap marker appeared before publication", result.stderr)
            self.assertEqual(marker.read_text(), "foreign-marker\n")
            self.assertEqual(self._chpasswd_call_count(log), 1)
            self.assertFalse(secret.exists())
            self.assertFalse(self._firstboot_authority_path(root).exists())
            self.assertTrue(self._firstboot_pending_path(root).exists())

            replay = self._run_firstboot_program(root, bin_dir, shadow, log)
            self.assertNotEqual(replay.returncode, 0)
            self.assertIn("bootstrap pending intent exists; recovery required", replay.stderr)
            self.assertEqual(self._chpasswd_call_count(log), 1)

    def test_firstboot_bootstrap_lock_blocks_parallel_instance_before_password_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir, shadow, log = self._firstboot_fixture(root)
            self._stage_firstboot_secret(root, self._synthetic_password_hash())
            marker_namespace = root / "persist/heim-pc"
            marker_namespace.mkdir(parents=True, exist_ok=True)
            marker_namespace.chmod(0o700)
            marker_dir = marker_namespace / "bootstrap"
            marker_dir.mkdir(mode=0o700)
            marker_dir.chmod(0o700)
            lock_path = marker_dir / ".alex-password-bootstrap.lock"
            lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                blocked = self._run_firstboot_program(root, bin_dir, shadow, log)
            finally:
                os.close(lock_fd)
            self.assertNotEqual(blocked.returncode, 0)
            self.assertIn("another bootstrap instance is active", blocked.stderr)
            self.assertEqual(self._shadow_hash(shadow), "!")
            self.assertEqual(self._chpasswd_call_count(log), 0)

    def test_firstboot_credential_program_is_single_use_and_marker_is_exact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir, shadow, log = self._firstboot_fixture(root)
            secret = self._stage_firstboot_secret(root, self._synthetic_password_hash())

            first = self._run_firstboot_program(root, bin_dir, shadow, log)
            self.assertEqual(first.returncode, 0, first.stderr)
            marker = self._firstboot_marker_path(root)
            self.assertEqual(self._shadow_hash(shadow), self._synthetic_password_hash().strip())
            self.assertFalse(secret.exists())
            self.assertFalse(self._firstboot_authority_path(root).exists())
            self.assertEqual(
                marker.read_bytes(), b"schema_version=1\nuser=alex\nstate=initialized\n"
            )
            self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
            self.assertFalse(self._firstboot_pending_path(root).exists())
            self.assertEqual(self._chpasswd_call_count(log), 1)

            # Marker means bootstrap is finished. A later password lock/rotation
            # must survive reboot and must not invoke chpasswd again.
            self._write_shadow(root, "!" + self._synthetic_password_hash().strip())
            repeat = self._run_firstboot_program(root, bin_dir, shadow, log)
            self.assertEqual(repeat.returncode, 0, repeat.stderr)
            self.assertEqual(self._chpasswd_call_count(log), 1)

            restaged = self._stage_firstboot_secret(
                root, self._synthetic_password_hash()
            )
            rejected = self._run_firstboot_program(root, bin_dir, shadow, log)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("bootstrap staging material remains after initialization", rejected.stderr)
            self.assertTrue(restaged.exists())
            self.assertEqual(self._chpasswd_call_count(log), 1)

            restaged.unlink()
            marker.write_text("corrupt\n")
            marker.chmod(0o600)
            corrupted = self._run_firstboot_program(root, bin_dir, shadow, log)
            self.assertNotEqual(corrupted.returncode, 0)
            self.assertIn("bootstrap marker content mismatch", corrupted.stderr)
            self.assertEqual(self._chpasswd_call_count(log), 1)

    def test_firstboot_credential_program_never_overwrites_nonvirgin_account_without_marker(self):
        for existing in (
            self._synthetic_password_hash().strip(),
            "!" + self._synthetic_password_hash().strip(),
        ):
            with self.subTest(existing=existing[:8]):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    bin_dir, shadow, log = self._firstboot_fixture(root, initial_hash=existing)
                    secret = self._stage_firstboot_secret(root, self._synthetic_password_hash())

                    result = self._run_firstboot_program(root, bin_dir, shadow, log)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("alex account is not in an initialization-compatible locked state", result.stderr)
                    self.assertEqual(self._shadow_hash(shadow), existing)
                    self.assertTrue(secret.exists())
                    self.assertEqual(self._chpasswd_call_count(log), 0)

    def test_firstboot_post_password_failure_is_recovery_required_and_non_replaying(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir, shadow, log = self._firstboot_fixture(root)
            secret = self._stage_firstboot_secret(root, self._synthetic_password_hash())
            first = self._run_firstboot_program(
                root,
                bin_dir,
                shadow,
                log,
                inject_secret_unlink_failure=True,
            )
            self.assertNotEqual(first.returncode, 0)
            self.assertIn("consuming bootstrap staging material failed", first.stderr)
            self.assertEqual(self._chpasswd_call_count(log), 1)
            self.assertEqual(self._shadow_hash(shadow), self._synthetic_password_hash().strip())
            self.assertTrue(secret.exists())
            self.assertTrue(self._firstboot_authority_path(root).exists())
            self.assertTrue(self._firstboot_pending_path(root).exists())
            self.assertFalse(
                (root / "persist/heim-pc/bootstrap/alex-password-initialized").exists()
            )

            second = self._run_firstboot_program(root, bin_dir, shadow, log)
            self.assertNotEqual(second.returncode, 0)
            self.assertIn("bootstrap pending intent exists; recovery required", second.stderr)
            self.assertEqual(self._chpasswd_call_count(log), 1)

    def test_nix_and_python_provenance_contracts_both_require_40_hex(self):
        flake = (SOURCE / "flake.nix").read_text()
        managed = (ROOT / "scripts/managed_nix.py").read_text()
        self.assertIn("^[0-9a-f]{40}$", flake)
        self.assertIn("len(value) != 40", managed)
        self.assertNotIn("len(value) not in {40, 64}", managed)


if __name__ == "__main__":
    unittest.main()