import fcntl
import grp
import hashlib
import os
import re
import stat
import subprocess
import sys

PERSIST_PATH = "/persist"
SHADOW_PATH = "/etc/shadow"
SOURCE_REVISION = @SOURCE_REVISION_JSON@
EXPECTED_UID = 0
EXPECTED_GID = 0
SHADOW_GID = grp.getgrnam("shadow").gr_gid
MARKER_NAME = "alex-password-initialized"
PENDING_NAME = ".alex-password-initialized.pending"
LOCK_NAME = ".alex-password-bootstrap.lock"
SECRET_NAME = "alex-password-hash"
AUTHORITY_NAME = "alex-password-bootstrap-authority"
MARKER_BYTES = b"schema_version=1\nuser=alex\nstate=initialized\n"
YESCRYPT_RE = re.compile(r"^\$y\$j9T\$[./0-9A-Za-z]{22}\$[./0-9A-Za-z]{43}$")
CRYPT64_ALPHABET = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
# The contract uses a 16-byte salt and a 256-bit yescrypt checksum. crypt's
# little-endian base64 therefore leaves only 2 payload bits in salt[-1]
# and 4 payload bits in checksum[-1]; all padding bits must be zero.
YESCRYPT_SALT_LAST = frozenset(CRYPT64_ALPHABET[:4])
YESCRYPT_CHECKSUM_LAST = frozenset(CRYPT64_ALPHABET[:16])
SOURCE_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
NOFOLLOW = os.O_NOFOLLOW
DIRECTORY = os.O_DIRECTORY


def fail(message):
    print("heim-pc first-boot credential bootstrap failed: " + message, file=sys.stderr)
    raise SystemExit(1)


def is_canonical_default_yescrypt(password_hash):
    if YESCRYPT_RE.fullmatch(password_hash) is None:
        return False
    _prefix, salt, checksum = password_hash.rsplit("$", 2)
    return salt[-1] in YESCRYPT_SALT_LAST and checksum[-1] in YESCRYPT_CHECKSUM_LAST


def expected_authority_bytes(secret):
    return (
        "schema_version=1\n"
        "user=alex\n"
        "action=initialize-password\n"
        "source_revision=" + SOURCE_REVISION + "\n"
        "password_hash_sha256=" + hashlib.sha256(secret).hexdigest() + "\n"
    ).encode("ascii")


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


def regular_identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        stat.S_IMODE(info.st_mode),
        info.st_size,
    )


def read_regular_at(parent_fd, name, label, exact_mode, max_bytes):
    try:
        fd = os.open(name, os.O_RDONLY | NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
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
        return data, regular_identity(info)
    finally:
        os.close(fd)


def assert_entry_identity(parent_fd, name, expected, label):
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        fail(label + " identity is no longer available")
    if not stat.S_ISREG(info.st_mode) or regular_identity(info) != expected:
        fail(label + " identity changed before consumption")


def write_all(fd, data):
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            fail("short bootstrap marker write")
        view = view[written:]


def validate_shadow_metadata(info, label):
    mode = stat.S_IMODE(info.st_mode)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != EXPECTED_UID
    ):
        fail(label + " identity is unsafe")
    if mode == 0o600:
        return
    if mode == 0o640 and info.st_gid == SHADOW_GID:
        return
    fail(label + " permissions are unsafe")


def open_shadow_hash():
    try:
        fd = os.open(SHADOW_PATH, os.O_RDONLY | NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        fail("shadow database is unavailable")
    try:
        info = os.fstat(fd)
        validate_shadow_metadata(info, "shadow database")
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
        return fd, matches[0], (info.st_dev, info.st_ino)
    except BaseException:
        os.close(fd)
        raise


def assert_shadow_path_identity(expected_identity):
    try:
        info = os.stat(SHADOW_PATH, follow_symlinks=False)
    except OSError:
        fail("verified shadow path is unavailable")
    validate_shadow_metadata(info, "verified shadow path")
    if (info.st_dev, info.st_ino) != expected_identity:
        fail("verified shadow path identity changed")


def fsync_verified_shadow(fd, expected_identity):
    # fstat(fd) cannot prove that SHADOW_PATH still names this inode: an open
    # descriptor survives a concurrent rename/replace. Bind the path before and
    # after the durability sync instead.
    assert_shadow_path_identity(expected_identity)
    try:
        parent = os.open(os.path.dirname(SHADOW_PATH), os.O_RDONLY | DIRECTORY | NOFOLLOW)
    except OSError:
        fail("shadow durability path is unavailable")
    try:
        parent_info = os.fstat(parent)
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != EXPECTED_UID
            or parent_info.st_gid != EXPECTED_GID
            or (stat.S_IMODE(parent_info.st_mode) & 0o022) != 0
        ):
            fail("shadow durability directory is unsafe")
        os.fsync(fd)
        os.fsync(parent)
        assert_shadow_path_identity(expected_identity)
    except OSError:
        fail("shadow durability sync failed")
    finally:
        os.close(parent)


def require_shadow_hash(expected_hash):
    fd, observed_hash, identity = open_shadow_hash()
    try:
        if observed_hash != expected_hash:
            fail("alex shadow hash does not match staged bootstrap material")
        fsync_verified_shadow(fd, identity)
    finally:
        os.close(fd)


def is_initialized_modular_crypt(password_field):
    if password_field.startswith("!"):
        password_field = password_field[1:]
    fields = password_field.split("$")
    return len(fields) >= 4 and fields[0] == "" and all(fields[1:])


def require_marker_shadow_initialized():
    fd, observed_hash, identity = open_shadow_hash()
    try:
        # The marker lives on /persist while /etc/shadow lives on the root
        # subvolume. A root rollback can therefore retain the marker while
        # restoring alex to a fresh bare lock. Do not pin later password
        # rotations to yescrypt, but require a structurally plausible modular
        # crypt field before releasing the login gate.
        if not is_initialized_modular_crypt(observed_hash):
            fail(
                "bootstrap marker exists but alex shadow state is uninitialized; "
                "recovery required"
            )
        assert_shadow_path_identity(identity)
    finally:
        os.close(fd)


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
    marker, _ = read_regular_at(
        marker_dir_fd,
        MARKER_NAME,
        "bootstrap marker",
        0o600,
        128,
    )
    if marker != MARKER_BYTES:
        fail("bootstrap marker content mismatch")


def acquire_bootstrap_lock(marker_dir_fd):
    try:
        fd = os.open(
            LOCK_NAME,
            os.O_RDWR | os.O_CREAT | NOFOLLOW,
            0o600,
            dir_fd=marker_dir_fd,
        )
    except OSError:
        fail("bootstrap lock is unavailable or unsafe")
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != EXPECTED_UID
            or info.st_gid != EXPECTED_GID
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            fail("bootstrap lock identity or mode mismatch")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fail("another bootstrap instance is active")
        return fd
    except BaseException:
        os.close(fd)
        raise


def remove_staging_file(marker_dir_fd, name):
    try:
        os.unlink(name, dir_fd=marker_dir_fd)
        os.fsync(marker_dir_fd)
    except FileNotFoundError:
        return
    except OSError:
        fail("bootstrap marker staging cleanup failed")


if SOURCE_REVISION_RE.fullmatch(SOURCE_REVISION) is None:
    fail("credential bootstrap requires an exact clean source revision")
if os.geteuid() != EXPECTED_UID or os.getegid() != EXPECTED_GID:
    fail("credential bootstrap is not running as root")

persist_fd = open_absolute_dir(PERSIST_PATH, "persist mount")
try:
    marker_dir_fd = open_marker_dir(persist_fd, create=True)
    try:
        lock_fd = acquire_bootstrap_lock(marker_dir_fd)
        try:
            # PENDING_NAME is the durable mutation intent. Once a previous
            # invocation reached chpasswd, normal boot must never infer from
            # a possibly rolled-back shadow file that replay is safe.
            if entry_exists(marker_dir_fd, PENDING_NAME):
                fail("bootstrap pending intent exists; recovery required")

            if entry_exists(marker_dir_fd, MARKER_NAME):
                validate_marker(marker_dir_fd)
                require_marker_shadow_initialized()
                secret_dir_fd = open_secret_dir(persist_fd, optional=True)
                if secret_dir_fd is not None:
                    try:
                        for staged_name in (SECRET_NAME, AUTHORITY_NAME):
                            if entry_exists(secret_dir_fd, staged_name):
                                fail("bootstrap staging material remains after initialization")
                    finally:
                        os.close(secret_dir_fd)
                raise SystemExit(0)

            shadow_fd, current_hash, _ = open_shadow_hash()
            os.close(shadow_fd)
            if current_hash not in {"!", "!!", "*"}:
                fail("alex account is not in an initialization-compatible locked state")

            secret_dir_fd = open_secret_dir(persist_fd)
            try:
                authority, authority_identity = read_regular_at(
                    secret_dir_fd,
                    AUTHORITY_NAME,
                    "bootstrap authority",
                    0o600,
                    384,
                )

                secret, secret_identity = read_regular_at(
                    secret_dir_fd,
                    SECRET_NAME,
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
                if not is_canonical_default_yescrypt(password_hash):
                    fail("bootstrap secret is not canonical default-cost yescrypt")
                if authority != expected_authority_bytes(secret):
                    fail("bootstrap authority is not bound to this exact source and hash")

                # Stage and fsync the actual marker inode before changing the
                # password. This proves the marker directory is writable and
                # keeps later publication to one create-if-absent link.
                tmp_name = PENDING_NAME
                probe_name = ".alex-password-publish-probe-" + str(os.getpid())
                publication_linked = False
                pending_created = False
                password_mutation_started = False
                try:
                    try:
                        marker_fd = os.open(
                            tmp_name,
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW,
                            0o600,
                            dir_fd=marker_dir_fd,
                        )
                    except FileExistsError:
                        fail("bootstrap pending intent appeared; recovery required")
                    except OSError:
                        fail("bootstrap pending intent could not be created")
                    pending_created = True
                    try:
                        write_all(marker_fd, MARKER_BYTES)
                        os.fsync(marker_fd)
                    finally:
                        os.close(marker_fd)

                    try:
                        os.link(
                            tmp_name,
                            probe_name,
                            src_dir_fd=marker_dir_fd,
                            dst_dir_fd=marker_dir_fd,
                            follow_symlinks=False,
                        )
                        os.fsync(marker_dir_fd)
                        os.unlink(probe_name, dir_fd=marker_dir_fd)
                        os.fsync(marker_dir_fd)
                    except OSError:
                        try:
                            os.unlink(probe_name, dir_fd=marker_dir_fd)
                        except OSError:
                            pass
                        fail("bootstrap marker destination is not durably publishable")

                    if entry_exists(marker_dir_fd, MARKER_NAME):
                        fail("bootstrap marker appeared during preflight")

                    # Crossing this boundary is intentionally sticky. An
                    # error, timeout or power loss from here until durable
                    # success must leave PENDING_NAME in place so a later
                    # boot cannot replay chpasswd from a bare-lock shadow.
                    password_mutation_started = True
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

                    require_shadow_hash(password_hash)

                    # From here on, failure must never replay chpasswd. Bind
                    # each staged directory entry to the inode that was read,
                    # then consume both the secret and its source-bound
                    # authorization before publishing success.
                    try:
                        assert_entry_identity(
                            secret_dir_fd, SECRET_NAME, secret_identity, "bootstrap secret"
                        )
                        os.unlink(SECRET_NAME, dir_fd=secret_dir_fd)
                        assert_entry_identity(
                            secret_dir_fd,
                            AUTHORITY_NAME,
                            authority_identity,
                            "bootstrap authority",
                        )
                        os.unlink(AUTHORITY_NAME, dir_fd=secret_dir_fd)
                        os.fsync(secret_dir_fd)
                    except OSError:
                        fail("consuming bootstrap staging material failed")

                    # Detect a password change after the first exact readback
                    # before the success marker is made visible.
                    require_shadow_hash(password_hash)

                    try:
                        os.link(
                            tmp_name,
                            MARKER_NAME,
                            src_dir_fd=marker_dir_fd,
                            dst_dir_fd=marker_dir_fd,
                            follow_symlinks=False,
                        )
                        publication_linked = True
                        os.fsync(marker_dir_fd)
                    except FileExistsError:
                        fail("bootstrap marker appeared before publication")
                    except OSError:
                        fail("bootstrap marker publication failed")

                    # A successful link is deliberately not cleaned up on a
                    # later error until its second name is durably removed.
                    # Thus an interrupted publication remains fail-closed as
                    # a two-link marker rather than silently looking complete.
                    try:
                        os.unlink(tmp_name, dir_fd=marker_dir_fd)
                        os.fsync(marker_dir_fd)
                    except OSError:
                        fail("bootstrap marker staging cleanup failed")
                    publication_linked = False
                    validate_marker(marker_dir_fd)
                finally:
                    # Cleanup is allowed only while we still know chpasswd
                    # was never attempted. Once mutation starts, the durable
                    # intent is recovery evidence and must survive every
                    # non-success path.
                    if (
                        pending_created
                        and not password_mutation_started
                        and not publication_linked
                        and entry_exists(marker_dir_fd, tmp_name)
                    ):
                        remove_staging_file(marker_dir_fd, tmp_name)
            finally:
                os.close(secret_dir_fd)
        finally:
            os.close(lock_fd)
    finally:
        os.close(marker_dir_fd)
finally:
    os.close(persist_fd)
