from pathlib import Path
import hashlib
import os
import re
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "nixos" / "system"
SOURCE_SNAPSHOT_SHA256 = "25e8ce238fd5969ec0b40ba226a2b7813aaaeb8632ecbf9d8cad7cb4762eafb8"
ROOT_LOCK_SHA256 = "19d83aededafff8a80ca354e4fba18c1470d638b683079bd983639eb5719e26d"


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

    def _firstboot_script(self):
        host = (SOURCE / "hosts/heim-pc/default.nix").read_text()
        match = re.search(
            r"  firstBootCredentialScript = ''\n(?P<body>.*?)\n  '';\nin\n\{",
            host,
            re.S,
        )
        self.assertIsNotNone(match)
        return textwrap.dedent(match.group("body")).replace("''${", "${")

    def _firstboot_fixture(self, root, initial_state="L"):
        bin_dir = root / "bin"
        bin_dir.mkdir()
        state_file = root / "account-state"
        state_file.write_text(initial_state + "\n")
        chpasswd_log = root / "chpasswd.log"

        passwd = bin_dir / "passwd"
        passwd.write_text(textwrap.dedent("""\
            #!/bin/sh
            set -eu
            [ "${1:-}" = "-S" ] && [ "${2:-}" = "alex" ] || exit 64
            state="$(cat "$HEIM_PC_TEST_ACCOUNT_STATE")"
            printf 'alex %s 2026-09-07 0 99999 7 -1\n' "$state"
        """))
        passwd.chmod(0o700)

        chpasswd = bin_dir / "chpasswd"
        chpasswd.write_text(textwrap.dedent("""\
            #!/bin/sh
            set -eu
            [ "${1:-}" = "-e" ] || exit 64
            IFS= read -r line || exit 65
            case "$line" in
              alex:\$*) ;;
              *) exit 66 ;;
            esac
            printf 'called\n' >> "$HEIM_PC_TEST_CHPASSWD_LOG"
            printf 'P\n' > "$HEIM_PC_TEST_ACCOUNT_STATE"
        """))
        chpasswd.chmod(0o700)
        return bin_dir, state_file, chpasswd_log

    def _stage_firstboot_secret(self, root, content, mode=0o600):
        secret_dir = root / "persist/secrets/heim-pc/first-boot"
        secret_dir.mkdir(parents=True, exist_ok=True)
        secret_dir.chmod(0o700)
        secret = secret_dir / "alex-password-hash"
        secret.write_text(content)
        secret.chmod(mode)
        return secret

    def _run_firstboot_script(self, root, bin_dir, state_file, chpasswd_log):
        secret_dir = root / "persist/secrets/heim-pc/first-boot"
        marker_dir = root / "persist/heim-pc/bootstrap"
        script = self._firstboot_script()
        script = script.replace(
            "/persist/secrets/heim-pc/first-boot", str(secret_dir)
        ).replace(
            "/persist/heim-pc/bootstrap", str(marker_dir)
        ).replace(
            '[ "$expected_owner" = "0:0" ] || fail "credential bootstrap is not running as root"',
            ': # test harness runs as the current unprivileged file owner',
        )
        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env['PATH']}"
        env["HEIM_PC_TEST_ACCOUNT_STATE"] = str(state_file)
        env["HEIM_PC_TEST_CHPASSWD_LOG"] = str(chpasswd_log)
        return subprocess.run(
            ["/usr/bin/bash", "-c", script],
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )

    @staticmethod
    def _synthetic_password_hash():
        # Structurally valid test material only; not a reusable login credential.
        return "$6$synthetic-test-fixture$" + ("x" * 64) + "\n"

    @staticmethod
    def _chpasswd_call_count(path):
        return len(path.read_text().splitlines()) if path.exists() else 0

    def test_firstboot_credential_source_contract_is_fail_closed_and_out_of_store(self):
        host = (SOURCE / "hosts/heim-pc/default.nix").read_text()
        readme = (SOURCE / "README.md").read_text()
        self.assertIn("firstBootCredentialBootstrap =", host)
        self.assertIn('builtins.hasAttr "/persist" config.fileSystems', host)
        self.assertIn("users.mutableUsers = true;", host)
        self.assertIn("heim-pc-firstboot-credentials", host)
        self.assertIn('[ "$expected_owner" = "0:0" ] || fail "credential bootstrap is not running as root"', host)
        self.assertIn('User = "root";', host)
        self.assertIn('Group = "root";', host)
        self.assertIn('requiredBy = [ "multi-user.target" "display-manager.service" ];', host)
        self.assertIn('exact_path "$secret_dir"', host)
        self.assertIn('validate_marker_dir', host)
        self.assertIn('secret_path="$secret_dir/alex-password-hash"', host)
        self.assertIn('marker_path="$marker_dir/alex-password-initialized"', host)
        self.assertIn("chpasswd -e", host)
        self.assertIn('rm -- "$secret_path"', host)
        self.assertIn('fail "marker missing for already-passworded alex account"', host)
        self.assertNotIn("hashedPasswordFile", host)
        self.assertNotRegex(
            host,
            r"\b(?:initialHashedPassword|initialPassword|hashedPassword|password)\s*=",
        )
        self.assertIn("separately authorized disposable installation", readme)
        self.assertIn("VM console autologin is explicitly not accepted", readme)
        self.assertIn("The repository task does not stage this file", readme)

    def test_firstboot_credential_script_rejects_missing_invalid_and_unsafe_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir, state_file, log = self._firstboot_fixture(root)

            missing = self._run_firstboot_script(root, bin_dir, state_file, log)
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("secret directory is missing or unsafe", missing.stderr)
            self.assertEqual(state_file.read_text().strip(), "L")
            self.assertEqual(self._chpasswd_call_count(log), 0)

            self._stage_firstboot_secret(root, "not-a-password-hash\n")
            invalid = self._run_firstboot_script(root, bin_dir, state_file, log)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("not an accepted password hash", invalid.stderr)
            self.assertEqual(state_file.read_text().strip(), "L")
            self.assertEqual(self._chpasswd_call_count(log), 0)

            secret = self._stage_firstboot_secret(
                root, self._synthetic_password_hash(), mode=0o644
            )
            unsafe = self._run_firstboot_script(root, bin_dir, state_file, log)
            self.assertNotEqual(unsafe.returncode, 0)
            self.assertIn("secret owner or mode mismatch", unsafe.stderr)
            self.assertTrue(secret.exists())
            self.assertEqual(state_file.read_text().strip(), "L")
            self.assertEqual(self._chpasswd_call_count(log), 0)

    def test_firstboot_credential_script_is_single_use_and_non_overwriting(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir, state_file, log = self._firstboot_fixture(root)
            secret = self._stage_firstboot_secret(root, self._synthetic_password_hash())

            first = self._run_firstboot_script(root, bin_dir, state_file, log)
            self.assertEqual(first.returncode, 0, first.stderr)
            marker = root / "persist/heim-pc/bootstrap/alex-password-initialized"
            self.assertEqual(state_file.read_text().strip(), "P")
            self.assertFalse(secret.exists())
            self.assertTrue(marker.is_file())
            self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self._chpasswd_call_count(log), 1)

            repeat = self._run_firstboot_script(root, bin_dir, state_file, log)
            self.assertEqual(repeat.returncode, 0, repeat.stderr)
            self.assertEqual(self._chpasswd_call_count(log), 1)

            restaged = self._stage_firstboot_secret(
                root, self._synthetic_password_hash()
            )
            rejected = self._run_firstboot_script(root, bin_dir, state_file, log)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("secret remains after initialization", rejected.stderr)
            self.assertTrue(restaged.exists())
            self.assertEqual(state_file.read_text().strip(), "P")
            self.assertEqual(self._chpasswd_call_count(log), 1)

    def test_firstboot_credential_script_never_overwrites_password_without_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir, state_file, log = self._firstboot_fixture(root, initial_state="P")
            secret = self._stage_firstboot_secret(root, self._synthetic_password_hash())

            result = self._run_firstboot_script(root, bin_dir, state_file, log)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("marker missing for already-passworded alex account", result.stderr)
            self.assertEqual(state_file.read_text().strip(), "P")
            self.assertTrue(secret.exists())
            self.assertFalse(
                (root / "persist/heim-pc/bootstrap/alex-password-initialized").exists()
            )
            self.assertEqual(self._chpasswd_call_count(log), 0)

    def test_nix_and_python_provenance_contracts_both_require_40_hex(self):
        flake = (SOURCE / "flake.nix").read_text()
        managed = (ROOT / "scripts/managed_nix.py").read_text()
        self.assertIn("^[0-9a-f]{40}$", flake)
        self.assertIn("len(value) != 40", managed)
        self.assertNotIn("len(value) not in {40, 64}", managed)


if __name__ == "__main__":
    unittest.main()