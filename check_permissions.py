#!/usr/bin/env python3
"""
check_permissions.py

A best-effort Linux filesystem mutation capability auditor.

The tool does not open files for writing, does not create files, and does not
remove anything.  It models the permissions that usually decide whether the
current process context could mutate filesystem state.

Default behaviour
-----------------
With no arguments, scans / in security-audit mode and reports any path with at
least one ordinary mutation capability.  The default / scan skips /proc and the
active writable temp directory, and suppresses home-directory output unless an
include option is supplied:

    d  delete existing path / recursively remove a directory tree
    a  append to an existing regular file
    o  overwrite or truncate an existing regular file
    c  create a child entry in an existing directory, or create an explicit
       missing path whose parent permits creation

Special files/devices are intentionally separated from the default audit to
avoid noisy /dev-style output.  Use --include-special-write or
--can-special-write-only when that signal is wanted.  --include-all/--all also
enables this signal in the default mutation audit.

Important model choices
-----------------------
- "write" is not a primitive capability.  Append, overwrite, create, delete,
  and special-file write are checked separately.
- Regular-file appendability is reported even when overwrite/truncate would be
  blocked by the Linux append-only inode flag.
- Symlink deletion is checked on the symlink itself, but content/create checks
  follow the symlink, because open("link", O_WRONLY) normally writes the target.
  Dangling symlinks are also checked for create-through-symlink risk.
- Directory "write" is reported as create capability: write + search on the
  directory, writable mount, and no immutable directory flag.
- This is a simulator.  MAC policy, idmapped mounts, filesystem-specific rules,
  races on live systems, leases, LSMs, and network/FUSE semantics can still make
  the real operation differ.
"""

from __future__ import annotations

import argparse
import ctypes
import csv
import errno
import json
import os
import pwd
import stat
import sys
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple, TypeVar

# ---------------------------------------------------------------------------
# Public vocabulary
# ---------------------------------------------------------------------------

CAP_DELETE = "delete"
CAP_APPEND = "append"
CAP_OVERWRITE = "overwrite"
CAP_CREATE = "create"
CAP_SPECIAL_WRITE = "special_write"

CAPABILITY_ORDER = (
    CAP_DELETE,
    CAP_APPEND,
    CAP_OVERWRITE,
    CAP_CREATE,
    CAP_SPECIAL_WRITE,
)

CAPABILITY_LABEL = {
    CAP_DELETE: "d",
    CAP_APPEND: "a",
    CAP_OVERWRITE: "o",
    CAP_CREATE: "c",
    CAP_SPECIAL_WRITE: "s",
}

DEFAULT_MUTATION_CAPS = (
    CAP_DELETE,
    CAP_APPEND,
    CAP_OVERWRITE,
    CAP_CREATE,
)

MODE_CAN_MUTATE = "can_mutate"
MODE_CAN_DELETE_ONLY = "can_delete_only"
MODE_CAN_APPEND_ONLY = "can_append_only"
MODE_CAN_OVERWRITE_ONLY = "can_overwrite_only"
MODE_CAN_CONTENT_WRITE_ONLY = "can_content_write_only"
MODE_CAN_CREATE_ONLY = "can_create_only"
MODE_CAN_SPECIAL_WRITE_ONLY = "can_special_write_only"
MODE_CAN_WRITE_ONLY = "can_write_only"

STATUS_WOULD_MUTATE = "WOULD_MUTATE"
STATUS_WOULD_DELETE = "WOULD_DELETE"
STATUS_WOULD_APPEND = "WOULD_APPEND"
STATUS_WOULD_OVERWRITE = "WOULD_OVERWRITE"
STATUS_WOULD_CONTENT_WRITE = "WOULD_CONTENT_WRITE"
STATUS_WOULD_CREATE = "WOULD_CREATE"
STATUS_WOULD_SPECIAL_WRITE = "WOULD_SPECIAL_WRITE"
STATUS_WOULD_WRITE = "WOULD_WRITE"
STATUS_WOULD_FAIL = "WOULD_FAIL"
STATUS_UNKNOWN = "UNKNOWN"
STATUS_SKIP = "SKIP"

VERDICT_PASS = "pass"
VERDICT_FAIL = "fail"
VERDICT_UNKNOWN = "unknown"
VERDICT_SKIP = "skip"

KIND_FILE = "file"
KIND_DIR = "dir"
KIND_SYMLINK = "symlink"
KIND_FIFO = "fifo"
KIND_SOCKET = "socket"
KIND_CHAR = "char"
KIND_BLOCK = "block"
KIND_OTHER = "other"
KIND_MISSING = "missing"

CAP_FOWNER = 3

T = TypeVar("T")

# ---------------------------------------------------------------------------
# Linux statx bindings for immutable / append-only inode attributes
# ---------------------------------------------------------------------------

AT_FDCWD = -100
AT_SYMLINK_NOFOLLOW = 0x100
STATX_ALL = 0x00000FFF
STATX_ATTR_IMMUTABLE = 0x00000010
STATX_ATTR_APPEND = 0x00000020


class StructStatx(ctypes.Structure):
    """
    ctypes view of Linux struct statx.

    The fields through stx_attributes_mask occupy the first 64 bytes of the
    UAPI structure.  The full structure is currently 256 bytes; the tail is
    kept opaque so the buffer is safely sized even though this program only
    needs the attributes fields.
    """

    _fields_ = [
        ("stx_mask", ctypes.c_uint),
        ("stx_blksize", ctypes.c_uint),
        ("stx_attributes", ctypes.c_ulonglong),
        ("stx_nlink", ctypes.c_uint),
        ("stx_uid", ctypes.c_uint),
        ("stx_gid", ctypes.c_uint),
        ("stx_mode", ctypes.c_ushort),
        ("__spare0", ctypes.c_ushort * 1),
        ("stx_ino", ctypes.c_ulonglong),
        ("stx_size", ctypes.c_ulonglong),
        ("stx_blocks", ctypes.c_ulonglong),
        ("stx_attributes_mask", ctypes.c_ulonglong),
        ("__opaque_tail", ctypes.c_ubyte * (256 - 64)),
    ]


libc = ctypes.CDLL(None, use_errno=True)
_HAS_STATX = hasattr(libc, "statx")

if _HAS_STATX:
    libc.statx.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.POINTER(StructStatx),
    ]
    libc.statx.restype = ctypes.c_int


@dataclass(frozen=True)
class FlagCheck:
    immutable: Optional[bool]
    append_only: Optional[bool]
    error_reason: Optional[str] = None

    @property
    def uncertain(self) -> bool:
        return self.error_reason is not None


def statx_flags(path: str, *, follow_symlinks: bool) -> FlagCheck:
    """Return immutable / append-only status when statx can provide it."""
    if not _HAS_STATX:
        return FlagCheck(None, None, "statx_unavailable")

    try:
        encoded = os.fsencode(path)
    except (TypeError, ValueError) as exc:
        return FlagCheck(None, None, f"statx_bad_path:{exc}")

    if b"\0" in encoded:
        return FlagCheck(None, None, "statx_bad_path:embedded_nul")

    buf = StructStatx()
    at_flags = 0 if follow_symlinks else AT_SYMLINK_NOFOLLOW
    rc = libc.statx(
        AT_FDCWD,
        ctypes.c_char_p(encoded),
        at_flags,
        STATX_ALL,
        ctypes.byref(buf),
    )
    if rc != 0:
        e = ctypes.get_errno()
        return FlagCheck(None, None, f"statx_errno_{e}:{os.strerror(e)}")

    immutable: Optional[bool] = None
    append_only: Optional[bool] = None
    if buf.stx_attributes_mask & STATX_ATTR_IMMUTABLE:
        immutable = bool(buf.stx_attributes & STATX_ATTR_IMMUTABLE)
    if buf.stx_attributes_mask & STATX_ATTR_APPEND:
        append_only = bool(buf.stx_attributes & STATX_ATTR_APPEND)

    return FlagCheck(immutable, append_only, None)


# ---------------------------------------------------------------------------
# Process credentials / access helpers
# ---------------------------------------------------------------------------


def parse_effective_capabilities() -> int:
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    return int(line.split()[1], 16)
    except Exception:
        pass
    return 0


def has_cap(caps: int, capno: int) -> bool:
    return bool(caps & (1 << capno))


def access_path(path: str, mode: int, *, effective_access: bool) -> bool:
    """
    Check path access using the intended credential model.

    By default the auditor asks the kernel using effective IDs, which is what
    actually matters for a normal non-setuid script.  --real-ids switches back
    to access(2)-style real-ID checks.
    """
    if not effective_access:
        return os.access(path, mode)

    try:
        return os.access(path, mode, effective_ids=True)
    except (TypeError, NotImplementedError):
        return os.access(path, mode)


# ---------------------------------------------------------------------------
# Paths, exclusions, home/temp discovery
# ---------------------------------------------------------------------------

TMP_ENV_VARS = ("TMPDIR", "TEMP", "TMP")
DEFAULT_PROC_EXCLUDE = "/proc"

DEFAULT_UNKNOWN_FSTYPES = {
    "proc",
    "sysfs",
    "cgroup",
    "cgroup2",
    "securityfs",
    "configfs",
    "debugfs",
    "tracefs",
    "pstore",
    "bpf",
    "fusectl",
    "autofs",
}


@dataclass(frozen=True)
class ExcludedPath:
    path: str
    recursive: bool


def normalize(path: str) -> str:
    p = os.path.abspath(path)
    return p if p == "/" else p.rstrip("/")


@lru_cache(maxsize=65536)
def _cached_real_normalize(normalized_path: str) -> str:
    try:
        return normalize(os.path.realpath(normalized_path))
    except OSError:
        return normalized_path


def real_normalize(path: str) -> str:
    return _cached_real_normalize(normalize(path))


def is_path_prefix(prefix: str, path: str) -> bool:
    prefix = normalize(prefix)
    path = normalize(path)
    if prefix == "/":
        return True
    return path == prefix or path.startswith(prefix + "/")


def dedupe_keep_order(items: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def discover_home_dirs() -> List[str]:
    homes: List[str] = []

    env_home = os.environ.get("HOME")
    if env_home:
        homes.append(normalize(env_home))

    for uid in (os.getuid(), os.geteuid()):
        try:
            homes.append(normalize(pwd.getpwuid(uid).pw_dir))
        except KeyError:
            pass

    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            homes.append(normalize(pwd.getpwnam(sudo_user).pw_dir))
        except KeyError:
            pass

    return [h for h in dedupe_keep_order(homes) if h and h != "/"]


def dir_is_writable_searchable(path: str, *, effective_access: bool) -> bool:
    try:
        return os.path.isdir(path) and access_path(
            path,
            os.W_OK | os.X_OK,
            effective_access=effective_access,
        )
    except OSError:
        return False


def discover_writable_tmp_dirs(*, effective_access: bool) -> List[str]:
    raw_candidates: List[str] = []
    for var in TMP_ENV_VARS:
        value = os.environ.get(var)
        if value:
            raw_candidates.append(value)
    raw_candidates.append("/tmp")

    for raw_path in dedupe_keep_order(raw_candidates):
        try:
            path = normalize(raw_path)
        except (OSError, TypeError, ValueError):
            continue
        if path == "/":
            continue
        if dir_is_writable_searchable(path, effective_access=effective_access):
            return [path]
    return []


def _exclude_is_recursive(raw_path: str, normalized: str) -> bool:
    if raw_path.endswith(os.sep):
        return True
    try:
        return stat.S_ISDIR(os.lstat(normalized).st_mode)
    except OSError:
        return False


def normalize_excluded_paths(raw_paths: Sequence[str]) -> List[ExcludedPath]:
    """
    Normalize exclusions lexically.

    Exclusions intentionally do not match by realpath: a system path that is a
    symlink into an excluded temp/home tree can itself be the security problem
    and must still be assessed.
    """
    seen: Set[Tuple[str, bool]] = set()
    out: List[ExcludedPath] = []
    for raw_path in raw_paths:
        normalized = normalize(raw_path)
        item = ExcludedPath(normalized, _exclude_is_recursive(raw_path, normalized))
        key = (item.path, item.recursive)
        if key not in seen and item.path:
            seen.add(key)
            out.append(item)
    return out


def path_is_within_any_excluded(path: str, excluded_paths: Sequence[ExcludedPath]) -> bool:
    normalized = normalize(path)
    for excluded in excluded_paths:
        if excluded.recursive:
            if is_path_prefix(excluded.path, normalized):
                return True
        elif normalized == excluded.path:
            return True
    return False


def path_is_within_any_home_lexically(path: str, home_dirs: Sequence[str]) -> bool:
    normalized = normalize(path)
    return any(is_path_prefix(home, normalized) for home in home_dirs)


# ---------------------------------------------------------------------------
# Mount table
# ---------------------------------------------------------------------------


def unescape_mount_field(s: str) -> str:
    out: List[str] = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 3 < len(s) and all(c in "01234567" for c in s[i + 1 : i + 4]):
            out.append(chr(int(s[i + 1 : i + 4], 8)))
            i += 4
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


@dataclass(frozen=True)
class Mount:
    mount_id: int
    parent_id: int
    mount_point: str
    real_mount_point: str
    fs_type: str
    mount_options: Tuple[str, ...]
    super_options: Tuple[str, ...]
    parse_index: int
    same_path_depth: int = 0

    @property
    def read_only(self) -> bool:
        return "ro" in self.mount_options or "ro" in self.super_options


@dataclass(frozen=True)
class MountParseResult:
    mounts: List[Mount]
    error_reason: Optional[str] = None


def parse_mountinfo() -> MountParseResult:
    try:
        mounts = _read_mountinfo_mounts()
    except OSError as e:
        fallback = Mount(
            mount_id=1,
            parent_id=0,
            mount_point="/",
            real_mount_point="/",
            fs_type="unknown",
            mount_options=(),
            super_options=(),
            parse_index=0,
        )
        return MountParseResult([fallback], f"mountinfo_unavailable_errno_{e.errno}:{e.strerror}")

    mounts = _mounts_with_same_path_depth(mounts)
    mounts = sorted(
        mounts,
        key=lambda m: (
            len(m.mount_point.rstrip("/")) if m.mount_point != "/" else 1,
            m.same_path_depth,
            m.parse_index,
        ),
        reverse=True,
    )
    return MountParseResult(mounts, None)


def _read_mountinfo_mounts() -> List[Mount]:
    mounts: List[Mount] = []
    with open("/proc/self/mountinfo", "r", encoding="utf-8") as f:
        for parse_index, line in enumerate(f):
            mounts.append(_parse_mountinfo_line(line, parse_index))
    return mounts


def _parse_mountinfo_line(line: str, parse_index: int) -> Mount:
    left, right = line.rstrip("\n").split(" - ", 1)
    lparts = left.split()
    rparts = right.split()

    mount_point = normalize(unescape_mount_field(lparts[4]))
    try:
        real_mount_point = normalize(os.path.realpath(mount_point))
    except OSError:
        real_mount_point = mount_point

    return Mount(
        mount_id=int(lparts[0]),
        parent_id=int(lparts[1]),
        mount_point=mount_point,
        real_mount_point=real_mount_point,
        fs_type=rparts[0],
        mount_options=tuple(lparts[5].split(",")),
        super_options=tuple(rparts[2].split(",")) if len(rparts) >= 3 else (),
        parse_index=parse_index,
    )


def _same_path_depth(mount_id: int, mounts_by_id: Dict[int, Mount], memo: Dict[int, int]) -> int:
    cached = memo.get(mount_id)
    if cached is not None:
        return cached

    mount = mounts_by_id[mount_id]
    parent = mounts_by_id.get(mount.parent_id)
    if parent is None or parent.mount_point != mount.mount_point:
        depth = 0
    else:
        depth = _same_path_depth(parent.mount_id, mounts_by_id, memo) + 1
    memo[mount_id] = depth
    return depth


def _mounts_with_same_path_depth(mounts: Sequence[Mount]) -> List[Mount]:
    mounts_by_id = {m.mount_id: m for m in mounts}
    memo: Dict[int, int] = {}
    out: List[Mount] = []
    for m in mounts:
        out.append(
            Mount(
                mount_id=m.mount_id,
                parent_id=m.parent_id,
                mount_point=m.mount_point,
                real_mount_point=m.real_mount_point,
                fs_type=m.fs_type,
                mount_options=m.mount_options,
                super_options=m.super_options,
                parse_index=m.parse_index,
                same_path_depth=_same_path_depth(m.mount_id, mounts_by_id, memo),
            )
        )
    return out


class MountTable:
    def __init__(self, parse_result: MountParseResult):
        self.mounts = list(parse_result.mounts)
        self.error_reason = parse_result.error_reason
        self.by_id = {m.mount_id: m for m in self.mounts}
        self.children_by_parent_id: Dict[int, List[Mount]] = {}
        for mount in self.mounts:
            self.children_by_parent_id.setdefault(mount.parent_id, []).append(mount)

        self._top_same_path_cache: Dict[int, Mount] = {}
        self.visible_mounts: List[Mount] = []
        self.visible_by_mountpoint: Dict[str, Mount] = {}
        self.visible_root = self._build_visible_mounts()

    @property
    def degraded(self) -> bool:
        return self.error_reason is not None

    def _root_fallback(self) -> Mount:
        if self.mounts:
            return self.mounts[0]
        raise RuntimeError("mount table is empty")

    def _same_path_children(self, mount: Mount) -> List[Mount]:
        return [
            child
            for child in self.children_by_parent_id.get(mount.mount_id, [])
            if child.mount_point == mount.mount_point
        ]

    @staticmethod
    def _choose_top_candidate(mounts: Sequence[Mount]) -> Mount:
        return max(mounts, key=lambda m: (m.same_path_depth, m.parse_index, m.mount_id))

    def _top_same_path_descendant(self, mount: Mount) -> Mount:
        cached = self._top_same_path_cache.get(mount.mount_id)
        if cached is not None:
            return cached

        current = mount
        seen: Set[int] = set()
        while current.mount_id not in seen:
            seen.add(current.mount_id)
            children = self._same_path_children(current)
            if not children:
                break
            current = self._choose_top_candidate(children)

        self._top_same_path_cache[mount.mount_id] = current
        return current

    def _build_visible_mounts(self) -> Mount:
        if not self.mounts:
            return self._root_fallback()

        root_candidates = [m for m in self.mounts if m.mount_point == "/"] or [self._root_fallback()]
        visible_root = self._top_same_path_descendant(self._choose_top_candidate(root_candidates))
        self._visit_visible_mount(visible_root, set())
        self.visible_mounts.sort(
            key=lambda m: len(m.mount_point.rstrip("/")) if m.mount_point != "/" else 1,
            reverse=True,
        )
        return visible_root

    def _visit_visible_mount(self, mount: Mount, seen: Set[int]) -> None:
        if mount.mount_id in seen:
            return
        seen.add(mount.mount_id)
        self.visible_mounts.append(mount)
        self.visible_by_mountpoint[normalize(mount.mount_point)] = mount

        grouped: Dict[str, List[Mount]] = {}
        for child in self.children_by_parent_id.get(mount.mount_id, []):
            if child.mount_point == mount.mount_point:
                continue
            grouped.setdefault(normalize(child.mount_point), []).append(child)

        for child_mounts in grouped.values():
            visible_child = self._top_same_path_descendant(self._choose_top_candidate(child_mounts))
            self._visit_visible_mount(visible_child, seen)

    def _visible_mount_for_lexical_path(self, path: str) -> Mount:
        probe = normalize(path)
        while True:
            match = self.visible_by_mountpoint.get(probe)
            if match is not None:
                return match
            if probe == "/":
                break
            probe = normalize(os.path.dirname(probe) or "/")
        return self.visible_root

    def mount_for(self, path: str) -> Mount:
        lexical_match = self._visible_mount_for_lexical_path(path)
        real = real_normalize(path)
        if real == normalize(path):
            return lexical_match
        return self._visible_mount_for_lexical_path(real)

    def is_mountpoint(self, path: str) -> bool:
        lexical = normalize(path)
        if self.degraded:
            return lexical == "/"
        return lexical in self.visible_by_mountpoint


# ---------------------------------------------------------------------------
# Assessment/result structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CapabilityResult:
    capability: str
    verdict: str
    reasons: Tuple[str, ...] = ()


@dataclass
class Assessment:
    kind: str
    path: str
    results: Dict[str, CapabilityResult] = field(default_factory=dict)
    target_path: Optional[str] = None
    target_kind: Optional[str] = None

    def result_for(self, capability: str) -> CapabilityResult:
        return self.results.get(
            capability,
            CapabilityResult(capability, VERDICT_FAIL, ("capability_not_applicable",)),
        )

    def render(self, mode: str, selected_capabilities: Sequence[str]) -> "Outcome":
        selected = [self.result_for(cap) for cap in selected_capabilities]
        passing = [r.capability for r in selected if r.verdict == VERDICT_PASS]
        unknown = {
            r.capability: list(r.reasons)
            for r in selected
            if r.verdict == VERDICT_UNKNOWN
        }
        blocked = {
            r.capability: list(r.reasons)
            for r in selected
            if r.verdict == VERDICT_FAIL
        }
        skipped = {
            r.capability: list(r.reasons)
            for r in selected
            if r.verdict == VERDICT_SKIP
        }
        reasons = dedupe_keep_order(
            reason
            for result in selected
            for reason in result.reasons
        )

        return Outcome(
            status=status_for_results(mode, passing, unknown, blocked, skipped),
            kind=self.kind,
            path=self.path,
            mode=mode,
            capabilities=passing,
            unknown_capabilities=unknown,
            blocked_capabilities=blocked,
            skipped_capabilities=skipped,
            reasons=reasons,
            target_path=self.target_path,
            target_kind=self.target_kind,
            label=label_for_capabilities(passing),
        )


@dataclass
class Outcome:
    status: str
    kind: str
    path: str
    mode: str
    capabilities: List[str]
    unknown_capabilities: Dict[str, List[str]]
    blocked_capabilities: Dict[str, List[str]]
    skipped_capabilities: Dict[str, List[str]]
    reasons: List[str]
    target_path: Optional[str] = None
    target_kind: Optional[str] = None
    label: Optional[str] = None

    def as_dict(self) -> Dict[str, object]:
        data: Dict[str, object] = {
            "status": self.status,
            "kind": self.kind,
            "path": self.path,
            "mode": self.mode,
            "capabilities": self.capabilities,
            "unknown_capabilities": self.unknown_capabilities,
            "blocked_capabilities": self.blocked_capabilities,
            "skipped_capabilities": self.skipped_capabilities,
            "reasons": self.reasons,
        }
        if self.target_path is not None:
            data["target_path"] = self.target_path
        if self.target_kind is not None:
            data["target_kind"] = self.target_kind
        return data


def status_for_results(
    mode: str,
    passing: Sequence[str],
    unknown: Dict[str, List[str]],
    blocked: Dict[str, List[str]],
    skipped: Dict[str, List[str]],
) -> str:
    del blocked
    if passing:
        return passing_status_for_mode(mode)
    if skipped and not unknown:
        return STATUS_SKIP
    if unknown:
        return STATUS_UNKNOWN
    return STATUS_WOULD_FAIL


def passing_status_for_mode(mode: str) -> str:
    return {
        MODE_CAN_MUTATE: STATUS_WOULD_MUTATE,
        MODE_CAN_DELETE_ONLY: STATUS_WOULD_DELETE,
        MODE_CAN_APPEND_ONLY: STATUS_WOULD_APPEND,
        MODE_CAN_OVERWRITE_ONLY: STATUS_WOULD_OVERWRITE,
        MODE_CAN_CONTENT_WRITE_ONLY: STATUS_WOULD_CONTENT_WRITE,
        MODE_CAN_CREATE_ONLY: STATUS_WOULD_CREATE,
        MODE_CAN_SPECIAL_WRITE_ONLY: STATUS_WOULD_SPECIAL_WRITE,
        MODE_CAN_WRITE_ONLY: STATUS_WOULD_WRITE,
    }[mode]


def label_for_capabilities(capabilities: Sequence[str]) -> Optional[str]:
    labels = [CAPABILITY_LABEL[cap] for cap in CAPABILITY_ORDER if cap in capabilities]
    return "".join(labels) if labels else None


def result(capability: str, verdict: str, reasons: Sequence[str] = ()) -> CapabilityResult:
    return CapabilityResult(capability, verdict, tuple(dedupe_keep_order(reasons)))


def verdict_from_flags(capability: str, hard_failure: bool, uncertain: bool, reasons: Sequence[str]) -> CapabilityResult:
    reason_list = dedupe_keep_order(reasons)
    if hard_failure:
        return result(capability, VERDICT_FAIL, reason_list)
    if uncertain:
        return result(capability, VERDICT_UNKNOWN, reason_list)
    return result(capability, VERDICT_PASS, reason_list)


# ---------------------------------------------------------------------------
# Simulator
# ---------------------------------------------------------------------------


def classify_kind(st: os.stat_result) -> str:
    mode = st.st_mode
    if stat.S_ISDIR(mode):
        return KIND_DIR
    if stat.S_ISLNK(mode):
        return KIND_SYMLINK
    if stat.S_ISREG(mode):
        return KIND_FILE
    if stat.S_ISFIFO(mode):
        return KIND_FIFO
    if stat.S_ISSOCK(mode):
        return KIND_SOCKET
    if stat.S_ISCHR(mode):
        return KIND_CHAR
    if stat.S_ISBLK(mode):
        return KIND_BLOCK
    return KIND_OTHER


def is_special_kind(kind: str) -> bool:
    return kind in {KIND_FIFO, KIND_SOCKET, KIND_CHAR, KIND_BLOCK, KIND_OTHER}


class Simulator:
    def __init__(
        self,
        mounts: MountTable,
        *,
        preserve_root: bool,
        one_file_system: bool,
        unknown_fstypes: Optional[Set[str]],
        effective_access: bool,
        excluded_paths: Optional[Sequence[str]] = None,
    ):
        self.mounts = mounts
        self.preserve_root = preserve_root
        self.one_file_system = one_file_system
        self.unknown_fstypes = unknown_fstypes
        self.effective_access = effective_access
        self.excluded_paths = tuple(normalize_excluded_paths(excluded_paths or ()))
        self.uid = os.geteuid() if effective_access else os.getuid()
        self.caps = parse_effective_capabilities() if effective_access else 0
        self.seen_dirs: Set[Tuple[int, int]] = set()

    def access(self, path: str, mode: int) -> bool:
        return access_path(path, mode, effective_access=self.effective_access)

    def simulate_path(
        self,
        path: str,
        *,
        selected_capabilities: Sequence[str],
        root_dev: Optional[int] = None,
        explicit: bool = True,
    ) -> Iterator[Assessment]:
        yield from self._simulate_path(
            path,
            selected_capabilities=tuple(selected_capabilities),
            root_dev=root_dev,
            explicit=explicit,
        )

    def _simulate_path(
        self,
        path: str,
        *,
        selected_capabilities: Tuple[str, ...],
        root_dev: Optional[int],
        explicit: bool,
    ) -> Iterator[Assessment]:
        path = normalize(path)

        terminal = self._terminal_if_excluded_or_preserved_root(path, selected_capabilities)
        if terminal is not None:
            yield terminal
            return

        try:
            st = os.lstat(path)
        except FileNotFoundError:
            if explicit:
                yield self.classify_missing_explicit_path(path, selected_capabilities)
            else:
                yield self._all_caps_assessment(
                    KIND_MISSING,
                    path,
                    selected_capabilities,
                    VERDICT_UNKNOWN,
                    ["not_found_during_scan"],
                )
            return
        except PermissionError as e:
            yield self._all_caps_assessment(
                KIND_OTHER,
                path,
                selected_capabilities,
                VERDICT_UNKNOWN,
                [f"lstat_denied:{e.strerror or 'Permission denied'}"],
            )
            return
        except OSError as e:
            yield self._all_caps_assessment(
                KIND_OTHER,
                path,
                selected_capabilities,
                VERDICT_UNKNOWN,
                [f"lstat_errno_{e.errno}:{e.strerror}"],
            )
            return

        kind = classify_kind(st)

        if self.one_file_system and root_dev is not None and st.st_dev != root_dev:
            yield self._all_caps_assessment(
                kind,
                path,
                selected_capabilities,
                VERDICT_SKIP,
                ["different_filesystem", "one_file_system"],
            )
            return

        if kind != KIND_DIR:
            yield self.classify_leaf(path, st, kind, selected_capabilities)
            return

        dir_key = (st.st_dev, st.st_ino)
        if dir_key in self.seen_dirs:
            yield self._all_caps_assessment(
                KIND_DIR,
                path,
                selected_capabilities,
                VERDICT_UNKNOWN,
                ["already_visited_directory"],
            )
            return

        self.seen_dirs.add(dir_key)
        unknown_children = False
        failed_children = False

        try:
            try:
                with os.scandir(path) as it:
                    for entry in it:
                        child_path = os.path.join(path, entry.name)
                        child_direct: Optional[Assessment] = None
                        for child_assessment in self._simulate_path(
                            child_path,
                            selected_capabilities=selected_capabilities,
                            root_dev=root_dev,
                            explicit=False,
                        ):
                            if child_direct is None and normalize(child_assessment.path) == normalize(child_path):
                                child_direct = child_assessment
                            yield child_assessment

                        if CAP_DELETE in selected_capabilities and child_direct is not None:
                            child_delete = child_direct.result_for(CAP_DELETE)
                            if child_delete.verdict == VERDICT_UNKNOWN:
                                unknown_children = True
                            elif child_delete.verdict in {VERDICT_FAIL, VERDICT_SKIP}:
                                failed_children = True
            except PermissionError as e:
                yield self.classify_directory_scan_failure(
                    path,
                    st,
                    selected_capabilities,
                    f"cannot_scan_dir:{e.strerror or 'Permission denied'}",
                )
                return
            except OSError as e:
                yield self.classify_directory_scan_failure(
                    path,
                    st,
                    selected_capabilities,
                    f"cannot_scan_dir_errno_{e.errno}:{e.strerror}",
                )
                return

            yield self.classify_directory(
                path,
                st,
                selected_capabilities,
                unknown_children=unknown_children,
                failed_children=failed_children,
            )
        finally:
            self.seen_dirs.discard(dir_key)

    def _terminal_if_excluded_or_preserved_root(
        self,
        path: str,
        selected_capabilities: Sequence[str],
    ) -> Optional[Assessment]:
        if self.excluded_paths and path_is_within_any_excluded(path, self.excluded_paths):
            try:
                kind = classify_kind(os.lstat(path))
            except OSError:
                kind = KIND_OTHER
            return self._all_caps_assessment(kind, path, selected_capabilities, VERDICT_SKIP, ["excluded_path"])

        if self.preserve_root and path == "/":
            return self._all_caps_assessment(KIND_DIR, path, selected_capabilities, VERDICT_SKIP, ["preserve_root"])

        return None

    @staticmethod
    def _all_caps_assessment(
        kind: str,
        path: str,
        selected_capabilities: Sequence[str],
        verdict: str,
        reasons: Sequence[str],
    ) -> Assessment:
        return Assessment(
            kind=kind,
            path=path,
            results={cap: result(cap, verdict, reasons) for cap in selected_capabilities},
        )

    def classify_missing_explicit_path(
        self,
        path: str,
        selected_capabilities: Sequence[str],
    ) -> Assessment:
        results: Dict[str, CapabilityResult] = {}
        for cap in selected_capabilities:
            if cap == CAP_CREATE:
                results[cap] = self.classify_missing_create(path)
            else:
                results[cap] = result(cap, VERDICT_FAIL, ["path_missing"])
        return Assessment(kind=KIND_MISSING, path=path, results=results)

    def classify_leaf(
        self,
        path: str,
        st: os.stat_result,
        kind: str,
        selected_capabilities: Sequence[str],
    ) -> Assessment:
        if kind == KIND_SYMLINK:
            return self.classify_symlink(path, st, selected_capabilities)

        results: Dict[str, CapabilityResult] = {}
        for cap in selected_capabilities:
            if cap == CAP_DELETE:
                results[cap] = self.classify_delete(path, st, kind, unknown_children=False, failed_children=False)
            elif cap == CAP_APPEND:
                results[cap] = self.classify_regular_file_content(path, kind, CAP_APPEND)
            elif cap == CAP_OVERWRITE:
                results[cap] = self.classify_regular_file_content(path, kind, CAP_OVERWRITE)
            elif cap == CAP_CREATE:
                results[cap] = result(CAP_CREATE, VERDICT_FAIL, ["not_directory"])
            elif cap == CAP_SPECIAL_WRITE:
                results[cap] = self.classify_special_write(path, kind)
        return Assessment(kind=kind, path=path, results=results)

    def classify_symlink(
        self,
        path: str,
        st: os.stat_result,
        selected_capabilities: Sequence[str],
    ) -> Assessment:
        results: Dict[str, CapabilityResult] = {}
        target_path = symlink_target_path(path)
        target_kind: Optional[str] = None
        target_st: Optional[os.stat_result] = None
        target_error: Optional[OSError] = None

        try:
            target_st = os.stat(path)
            target_kind = classify_kind(target_st)
        except OSError as e:
            target_error = e
            if e.errno == errno.ENOENT:
                target_kind = KIND_MISSING
            else:
                target_kind = KIND_OTHER

        for cap in selected_capabilities:
            if cap == CAP_DELETE:
                results[cap] = self.classify_delete(path, st, KIND_SYMLINK, unknown_children=False, failed_children=False)
                continue

            if target_error is not None and target_error.errno != errno.ENOENT:
                results[cap] = result(
                    cap,
                    VERDICT_UNKNOWN,
                    [f"symlink_target_stat_errno_{target_error.errno}:{target_error.strerror}"],
                )
                continue

            if cap == CAP_APPEND:
                if target_kind == KIND_FILE:
                    results[cap] = with_extra_reasons(
                        self.classify_regular_file_content(path, KIND_FILE, CAP_APPEND),
                        ["via_symlink_target"],
                    )
                else:
                    results[cap] = result(CAP_APPEND, VERDICT_FAIL, ["symlink_target_not_regular_file"])
            elif cap == CAP_OVERWRITE:
                if target_kind == KIND_FILE:
                    results[cap] = with_extra_reasons(
                        self.classify_regular_file_content(path, KIND_FILE, CAP_OVERWRITE),
                        ["via_symlink_target"],
                    )
                else:
                    results[cap] = result(CAP_OVERWRITE, VERDICT_FAIL, ["symlink_target_not_regular_file"])
            elif cap == CAP_CREATE:
                if target_kind == KIND_DIR and target_st is not None:
                    results[cap] = with_extra_reasons(
                        self.classify_create_in_directory(path, target_st, path_for_messages="symlink target directory"),
                        ["via_symlink_target_directory"],
                    )
                elif target_kind == KIND_MISSING and target_path is not None:
                    results[cap] = with_extra_reasons(
                        self.classify_missing_create(target_path),
                        ["via_dangling_symlink_target"],
                    )
                else:
                    results[cap] = result(CAP_CREATE, VERDICT_FAIL, ["symlink_target_not_directory_or_missing"])
            elif cap == CAP_SPECIAL_WRITE:
                if target_kind is not None and is_special_kind(target_kind):
                    results[cap] = with_extra_reasons(
                        self.classify_special_write(path, target_kind),
                        ["via_symlink_target"],
                    )
                else:
                    results[cap] = result(CAP_SPECIAL_WRITE, VERDICT_FAIL, ["symlink_target_not_special_file"])

        return Assessment(
            kind=KIND_SYMLINK,
            path=path,
            results=results,
            target_path=target_path,
            target_kind=target_kind,
        )

    def classify_directory_scan_failure(
        self,
        path: str,
        st: os.stat_result,
        selected_capabilities: Sequence[str],
        reason_text: str,
    ) -> Assessment:
        results: Dict[str, CapabilityResult] = {}
        for cap in selected_capabilities:
            if cap == CAP_DELETE:
                results[cap] = result(CAP_DELETE, VERDICT_UNKNOWN, [reason_text])
            elif cap == CAP_CREATE:
                results[cap] = self.classify_create_in_directory(path, st)
            elif cap == CAP_APPEND:
                results[cap] = result(CAP_APPEND, VERDICT_FAIL, ["not_regular_file"])
            elif cap == CAP_OVERWRITE:
                results[cap] = result(CAP_OVERWRITE, VERDICT_FAIL, ["not_regular_file"])
            elif cap == CAP_SPECIAL_WRITE:
                results[cap] = result(CAP_SPECIAL_WRITE, VERDICT_FAIL, ["not_special_file"])
        return Assessment(kind=KIND_DIR, path=path, results=results)

    def classify_directory(
        self,
        path: str,
        st: os.stat_result,
        selected_capabilities: Sequence[str],
        *,
        unknown_children: bool,
        failed_children: bool,
    ) -> Assessment:
        results: Dict[str, CapabilityResult] = {}
        for cap in selected_capabilities:
            if cap == CAP_DELETE:
                results[cap] = self.classify_delete(
                    path,
                    st,
                    KIND_DIR,
                    unknown_children=unknown_children,
                    failed_children=failed_children,
                )
            elif cap == CAP_CREATE:
                results[cap] = self.classify_create_in_directory(path, st)
            elif cap == CAP_APPEND:
                results[cap] = result(CAP_APPEND, VERDICT_FAIL, ["not_regular_file"])
            elif cap == CAP_OVERWRITE:
                results[cap] = result(CAP_OVERWRITE, VERDICT_FAIL, ["not_regular_file"])
            elif cap == CAP_SPECIAL_WRITE:
                results[cap] = result(CAP_SPECIAL_WRITE, VERDICT_FAIL, ["not_special_file"])
        return Assessment(kind=KIND_DIR, path=path, results=results)

    # ----- delete ----------------------------------------------------------

    def classify_delete(
        self,
        path: str,
        st: os.stat_result,
        kind: str,
        *,
        unknown_children: bool,
        failed_children: bool,
    ) -> CapabilityResult:
        del kind
        reasons: List[str] = []
        uncertain = False
        hard_failure = False

        flag_reasons, flag_uncertain, flag_hard_failure = self._target_delete_flag_reasons(path)
        reasons.extend(flag_reasons)
        uncertain |= flag_uncertain
        hard_failure |= flag_hard_failure

        if self.mounts.is_mountpoint(path):
            reasons.append("mountpoint_busy")
            hard_failure = True

        parent = normalize(os.path.dirname(path) or "/")
        fs_reasons, fs_uncertain = self.maybe_fs_uncertain(parent)
        reasons.extend(fs_reasons)
        uncertain |= fs_uncertain

        try:
            parent_st = os.lstat(parent)
        except OSError as e:
            reasons.append(f"parent_lstat_errno_{e.errno}:{e.strerror}")
            return result(CAP_DELETE, VERDICT_UNKNOWN, reasons)

        parent_reasons, parent_uncertain, parent_hard_failure = self.parent_delete_checks(parent, parent_st, st)
        reasons.extend(parent_reasons)
        uncertain |= parent_uncertain
        hard_failure |= parent_hard_failure

        if unknown_children:
            reasons.append("unknown_descendants")
            uncertain = True
        if failed_children:
            reasons.append("would_remain_nonempty_due_to_failed_children")
            hard_failure = True

        return verdict_from_flags(CAP_DELETE, hard_failure, uncertain, reasons)

    def _target_delete_flag_reasons(self, path: str) -> Tuple[List[str], bool, bool]:
        reasons: List[str] = []
        uncertain = False
        hard_failure = False

        flags = statx_flags(path, follow_symlinks=False)
        if flags.immutable is True:
            reasons.append("target_immutable_blocks_delete")
            hard_failure = True
        if flags.append_only is True:
            reasons.append("target_append_only_blocks_delete")
            hard_failure = True
        if flags.uncertain:
            reasons.append(f"target_flag_check:{flags.error_reason}")
            uncertain = True

        return reasons, uncertain, hard_failure

    def parent_delete_checks(
        self,
        parent: str,
        parent_st: os.stat_result,
        target_st: os.stat_result,
    ) -> Tuple[List[str], bool, bool]:
        reasons: List[str] = []
        uncertain = False
        hard_failure = False

        if not self.access(parent, os.W_OK | os.X_OK):
            reasons.append("parent_not_writable_searchable")
            hard_failure = True

        if self.sticky_blocks_delete(parent_st, target_st):
            reasons.append("sticky_bit_blocks_delete")
            hard_failure = True

        if self.mounts.degraded:
            reasons.append(str(self.mounts.error_reason))
            uncertain = True
        elif self.mounts.mount_for(parent).read_only:
            reasons.append("parent_mount_read_only")
            hard_failure = True

        flag_reasons, flag_uncertain, flag_hard_failure = self._parent_dir_delete_flag_reasons(parent)
        reasons.extend(flag_reasons)
        uncertain |= flag_uncertain
        hard_failure |= flag_hard_failure

        return reasons, uncertain, hard_failure

    def sticky_blocks_delete(self, parent_st: os.stat_result, target_st: os.stat_result) -> bool:
        if not (parent_st.st_mode & stat.S_ISVTX):
            return False
        if has_cap(self.caps, CAP_FOWNER):
            return False
        return self.uid not in {parent_st.st_uid, target_st.st_uid}

    def _parent_dir_delete_flag_reasons(self, parent: str) -> Tuple[List[str], bool, bool]:
        reasons: List[str] = []
        uncertain = False
        hard_failure = False

        flags = statx_flags(parent, follow_symlinks=True)
        if flags.immutable is True:
            reasons.append("parent_dir_immutable_blocks_delete")
            hard_failure = True
        if flags.append_only is True:
            reasons.append("parent_dir_append_only_blocks_delete")
            hard_failure = True
        if flags.uncertain:
            reasons.append(f"parent_flag_check:{flags.error_reason}")
            uncertain = True

        return reasons, uncertain, hard_failure

    # ----- regular-file content mutation ----------------------------------

    def classify_regular_file_content(self, path: str, target_kind: str, capability: str) -> CapabilityResult:
        if target_kind != KIND_FILE:
            return result(capability, VERDICT_FAIL, ["not_regular_file"])
        if capability not in {CAP_APPEND, CAP_OVERWRITE}:
            raise ValueError(f"not a regular-file content capability: {capability}")

        reasons: List[str] = []
        uncertain = False
        hard_failure = False

        flag_reasons, flag_uncertain, flag_hard_failure = self._content_flag_reasons(path, capability)
        reasons.extend(flag_reasons)
        uncertain |= flag_uncertain
        hard_failure |= flag_hard_failure

        fs_reasons, fs_uncertain = self.maybe_fs_uncertain(path)
        reasons.extend(fs_reasons)
        uncertain |= fs_uncertain

        mount_reasons, mount_uncertain, mount_hard_failure = self._write_mount_reasons(path)
        reasons.extend(mount_reasons)
        uncertain |= mount_uncertain
        hard_failure |= mount_hard_failure

        if not self.access(path, os.W_OK):
            reasons.append("target_not_writable")
            hard_failure = True

        return verdict_from_flags(capability, hard_failure, uncertain, reasons)

    def _content_flag_reasons(self, path: str, capability: str) -> Tuple[List[str], bool, bool]:
        reasons: List[str] = []
        uncertain = False
        hard_failure = False

        flags = statx_flags(path, follow_symlinks=True)
        if flags.immutable is True:
            reasons.append("target_immutable_blocks_content_change")
            hard_failure = True
        if flags.append_only is True:
            if capability == CAP_APPEND:
                reasons.append("target_append_only_allows_append")
            elif capability == CAP_OVERWRITE:
                reasons.append("target_append_only_blocks_overwrite")
                hard_failure = True
        if flags.uncertain:
            reasons.append(f"target_flag_check:{flags.error_reason}")
            uncertain = True

        return reasons, uncertain, hard_failure

    # ----- create ----------------------------------------------------------

    def classify_create_in_directory(
        self,
        directory_path: str,
        directory_st: os.stat_result,
        *,
        path_for_messages: str = "directory",
    ) -> CapabilityResult:
        if not stat.S_ISDIR(directory_st.st_mode):
            return result(CAP_CREATE, VERDICT_FAIL, [f"{path_for_messages}_not_directory"])

        reasons: List[str] = []
        uncertain = False
        hard_failure = False

        flags = statx_flags(directory_path, follow_symlinks=True)
        if flags.immutable is True:
            reasons.append("directory_immutable_blocks_create")
            hard_failure = True
        if flags.append_only is True:
            reasons.append("directory_append_only_allows_create_only")
        if flags.uncertain:
            reasons.append(f"directory_flag_check:{flags.error_reason}")
            uncertain = True

        fs_reasons, fs_uncertain = self.maybe_fs_uncertain(directory_path)
        reasons.extend(fs_reasons)
        uncertain |= fs_uncertain

        if self.mounts.degraded:
            uncertain = True
        elif self.mounts.mount_for(directory_path).read_only:
            reasons.append("directory_mount_read_only")
            hard_failure = True

        if not self.access(directory_path, os.W_OK | os.X_OK):
            if not self.access(directory_path, os.W_OK):
                reasons.append("directory_not_writable")
            if not self.access(directory_path, os.X_OK):
                reasons.append("directory_not_searchable")
            hard_failure = True

        return verdict_from_flags(CAP_CREATE, hard_failure, uncertain, reasons)

    def classify_missing_create(self, path: str) -> CapabilityResult:
        path = normalize(path)
        if path == "/":
            return result(CAP_CREATE, VERDICT_FAIL, ["cannot_create_root"])

        parent = normalize(os.path.dirname(path) or "/")
        basename = os.path.basename(path)
        if not basename:
            return result(CAP_CREATE, VERDICT_FAIL, ["missing_basename"])

        try:
            parent_st = os.stat(parent)
        except FileNotFoundError:
            return result(CAP_CREATE, VERDICT_FAIL, ["parent_missing"])
        except NotADirectoryError:
            return result(CAP_CREATE, VERDICT_FAIL, ["parent_not_directory"])
        except PermissionError as e:
            return result(CAP_CREATE, VERDICT_UNKNOWN, [f"parent_stat_denied:{e.strerror or 'Permission denied'}"])
        except OSError as e:
            return result(CAP_CREATE, VERDICT_UNKNOWN, [f"parent_stat_errno_{e.errno}:{e.strerror}"])

        create_result = self.classify_create_in_directory(parent, parent_st, path_for_messages="parent")
        if create_result.verdict == VERDICT_PASS:
            return with_extra_reasons(create_result, ["explicit_missing_path_parent_allows_create"])
        return create_result

    # ----- special files ---------------------------------------------------

    def classify_special_write(self, path: str, target_kind: str) -> CapabilityResult:
        if not is_special_kind(target_kind):
            return result(CAP_SPECIAL_WRITE, VERDICT_FAIL, ["not_special_file"])

        reasons: List[str] = [f"special_file_kind:{target_kind}"]
        uncertain = False
        hard_failure = False

        flags = statx_flags(path, follow_symlinks=True)
        if flags.immutable is True:
            reasons.append("target_immutable_blocks_special_write")
            hard_failure = True
        if flags.append_only is True:
            reasons.append("target_append_only_special_write_semantics_uncertain")
            uncertain = True
        if flags.uncertain:
            reasons.append(f"target_flag_check:{flags.error_reason}")
            uncertain = True

        fs_reasons, fs_uncertain = self.maybe_fs_uncertain(path)
        reasons.extend(fs_reasons)
        uncertain |= fs_uncertain

        mount_reasons, mount_uncertain, mount_hard_failure = self._write_mount_reasons(path)
        reasons.extend(mount_reasons)
        uncertain |= mount_uncertain
        hard_failure |= mount_hard_failure

        if not self.access(path, os.W_OK):
            reasons.append("target_not_writable")
            hard_failure = True

        return verdict_from_flags(CAP_SPECIAL_WRITE, hard_failure, uncertain, reasons)

    # ----- shared checks ---------------------------------------------------

    def maybe_fs_uncertain(self, path: str) -> Tuple[List[str], bool]:
        if self.mounts.degraded:
            return [str(self.mounts.error_reason)], True

        if self.unknown_fstypes:
            fs_type = self.mounts.mount_for(path).fs_type
            if fs_type in self.unknown_fstypes:
                return [f"special_fs:{fs_type}"], True

        return [], False

    def _write_mount_reasons(self, path: str) -> Tuple[List[str], bool, bool]:
        if self.mounts.degraded:
            return [str(self.mounts.error_reason)], True, False
        if self.mounts.mount_for(path).read_only:
            return ["target_mount_read_only"], False, True
        return [], False, False


# ---------------------------------------------------------------------------
# Small helpers for symlink targets and result composition
# ---------------------------------------------------------------------------


def with_extra_reasons(base: CapabilityResult, extra_reasons: Sequence[str]) -> CapabilityResult:
    return result(base.capability, base.verdict, list(base.reasons) + list(extra_reasons))


def symlink_target_path(path: str) -> Optional[str]:
    try:
        return normalize(os.path.realpath(path))
    except OSError:
        try:
            raw = os.readlink(path)
        except OSError:
            return None
        if os.path.isabs(raw):
            return normalize(raw)
        return normalize(os.path.join(os.path.dirname(path), raw))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class HelpFormatter(argparse.RawDescriptionHelpFormatter):
    pass


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = build_arg_parser()
    ns = parser.parse_args(argv)
    ns.default_paths = not bool(getattr(ns, "paths", []))
    if ns.default_paths:
        ns.paths = ["/"]
    apply_include_all_aliases(ns)
    return ns


def apply_include_all_aliases(ns: argparse.Namespace) -> None:
    """Expand --include-all / --all into the broad default-audit include switches."""
    if not getattr(ns, "include_all", False):
        return

    ns.include_home = True
    ns.include_tmp = True
    ns.include_proc = True
    ns.include_special_write = True


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=os.path.basename(sys.argv[0]) or "check_permissions.py",
        description="Best-effort Linux filesystem mutation capability auditor.",
        epilog=parser_epilog(),
        formatter_class=HelpFormatter,
    )

    p.add_argument(
        "paths",
        nargs="*",
        default=[],
        metavar="PATH",
        help="Root path(s) to inspect recursively. Defaults to / when omitted.",
    )

    add_mode_arguments(p)
    add_output_arguments(p)
    add_filter_arguments(p)
    add_execution_arguments(p)

    return p


def parser_epilog() -> str:
    return """
Capability labels in --format paths:
  [d]  delete existing path; directories mean recursive rm -rf-style removal
  [a]  append to an existing regular file
  [o]  overwrite/truncate an existing regular file
  [c]  create an entry in a directory, or create an explicit missing path
  [s]  write permission on a special file/device node; opt-in for default mode

Common examples:
  %(prog)s
      Default security audit of /. Reports delete, append, overwrite, create.

  setpriv --reuid nobody --regid nogroup --clear-groups -- %(prog)s
      Run the default audit as nobody.

  %(prog)s --can-delete-only /var/tmp/project
      Deletion-only rm -rf simulator.

  %(prog)s --can-append-only /etc /usr/bin
      Show only existing regular files appendable by this process context.

  %(prog)s --can-overwrite-only --format jsonl /etc
      Structured report of files whose existing contents can be overwritten.

  %(prog)s --can-create-only /usr/local /opt/new_file
      Show writable+searchable directories and explicit missing paths whose
      parent directories allow creation.

  %(prog)s --include-special-write --include-tmp /
      Broader audit including special-file/device write permission and temp.

  %(prog)s --include-all
      Default / audit with all default-suppressed areas/signals included: home
      output, the active temp directory, /proc, and special-write checks.

Default no-PATH / scan:
  With no PATH arguments, %(prog)s scans /. To keep the default security signal
  useful, it skips /proc and the active writable temp directory
  (TMPDIR/TEMP/TMP, then /tmp), and suppresses paths lexically under discovered
  home directories from output. Use --include-proc, --include-tmp, and
  --include-home to opt back in individually. Use --include-all or --all to
  include all default-suppressed areas/signals, including special-write checks.
  Explicit PATH arguments are never auto-excluded this way; explicit --exclude
  PATH rules still win.

Symlinks:
  Deletion checks the symlink itself. Append/overwrite/create/special-write
  checks follow the symlink because ordinary open/create operations normally do.
  A dangling symlink can still produce [c] if its target path could be created.

Root and capabilities:
  Running as root is blocked unless --run-as-root is supplied. In root or
  capability-restricted containers, checks use effective IDs/capabilities by
  default. Use --real-ids only when you specifically want real-ID access checks.

No-write guarantee:
  The auditor uses metadata, mountinfo, statx, and access checks. It does not
  open targets for writing, append, truncate, create, unlink, rename, chmod, or
  set inode flags.
"""

def add_mode_arguments(p: argparse.ArgumentParser) -> None:
    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--can-mutate",
        dest="mode",
        action="store_const",
        const=MODE_CAN_MUTATE,
        default=MODE_CAN_MUTATE,
        help="Default. Show paths with delete, append, overwrite, or create capability.",
    )
    mode.add_argument(
        "--can-delete-only",
        dest="mode",
        action="store_const",
        const=MODE_CAN_DELETE_ONLY,
        help="Show only paths that would likely be removable.",
    )
    mode.add_argument(
        "--can-append-only",
        dest="mode",
        action="store_const",
        const=MODE_CAN_APPEND_ONLY,
        help="Show only existing regular files appendable by this process context.",
    )
    mode.add_argument(
        "--can-overwrite-only",
        dest="mode",
        action="store_const",
        const=MODE_CAN_OVERWRITE_ONLY,
        help="Show only existing regular files overwritable/truncatable by this process context.",
    )
    mode.add_argument(
        "--can-content-write-only",
        dest="mode",
        action="store_const",
        const=MODE_CAN_CONTENT_WRITE_ONLY,
        help="Show existing regular files that are appendable or overwritable.",
    )
    mode.add_argument(
        "--can-create-only",
        dest="mode",
        action="store_const",
        const=MODE_CAN_CREATE_ONLY,
        help="Show directories, symlinked directories, and explicit missing paths where creation is likely possible.",
    )
    mode.add_argument(
        "--can-special-write-only",
        dest="mode",
        action="store_const",
        const=MODE_CAN_SPECIAL_WRITE_ONLY,
        help="Show writable special files/device nodes. Not included in the default audit unless --include-special-write is used.",
    )
    mode.add_argument(
        "--can-write-only",
        dest="mode",
        action="store_const",
        const=MODE_CAN_WRITE_ONLY,
        help="Broad write audit: append, overwrite, create, and optionally special-write with --include-special-write.",
    )
    mode.add_argument(
        "--can-write-or-delete",
        dest="mode",
        action="store_const",
        const=MODE_CAN_MUTATE,
        help=argparse.SUPPRESS,
    )


def add_output_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "-o",
        "--output",
        default="-",
        help="Write results to this file instead of stdout. Use - for stdout.",
    )
    p.add_argument(
        "--format",
        choices=("paths", "jsonl", "tsv"),
        default="paths",
        help="Output format. paths is compact and labels capabilities by default.",
    )
    labels = p.add_mutually_exclusive_group()
    labels.add_argument(
        "--labels",
        "--label",
        "--add-labels",
        dest="labels",
        action="store_true",
        default=True,
        help="Prefix --format paths records with compact capability labels.",
    )
    labels.add_argument(
        "--no-labels",
        "--bare-paths",
        dest="labels",
        action="store_false",
        help="For --format paths, print paths without capability labels.",
    )


def add_filter_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--all-results",
        action="store_true",
        help="Include WOULD_FAIL / UNKNOWN / SKIP records, not just passing capability matches.",
    )
    p.add_argument(
        "--include-home",
        action="store_true",
        help="In the default no-PATH / scan, include output paths lexically under discovered home directories.",
    )
    p.add_argument(
        "--exclude-home",
        action="store_true",
        help="Suppress home-directory paths from output even when PATH arguments are explicit.",
    )
    p.add_argument(
        "--include-tmp",
        action="store_true",
        help="For the default no-PATH / scan, do not auto-exclude the active writable temp directory.",
    )
    p.add_argument(
        "--include-proc",
        action="store_true",
        help="For the default no-PATH / scan, do not auto-exclude /proc. Explicit /proc PATH arguments are never auto-excluded.",
    )
    p.add_argument(
        "--include-all",
        "--all",
        dest="include_all",
        action="store_true",
        help=(
            "Include all default-suppressed audit areas/signals: home output, "
            "active temp, /proc, and special-write checks. Does not imply --all-results."
        ),
    )
    p.add_argument(
        "--directories-only",
        action="store_true",
        help="Only print directory entries after all other filtering is applied.",
    )
    p.add_argument(
        "--include-special-write",
        action="store_true",
        help="Add special-file/device write checks to --can-mutate and --can-write-only.",
    )


def add_execution_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--run-as-root",
        action="store_true",
        help="Allow execution as root. Useful for explicitly auditing a restricted root/capability context.",
    )
    p.add_argument(
        "--real-ids",
        action="store_true",
        help="Use real IDs for access checks and sticky-bit ownership tests; ignore effective capabilities.",
    )
    p.add_argument(
        "--preserve-root",
        action="store_true",
        help="Skip / itself, similar to GNU rm --preserve-root.",
    )
    p.add_argument(
        "--one-file-system",
        action="store_true",
        help="Do not descend into entries whose lstat st_dev differs from the starting path.",
    )
    p.add_argument(
        "--exclude",
        dest="exclude_paths",
        nargs="+",
        action="append",
        default=[],
        metavar="PATH",
        help="Exclude files or directory subtrees lexically. May be repeated.",
    )
    p.add_argument(
        "--no-special-fs-unknown",
        action="store_true",
        help="Do not downgrade kernel pseudo-filesystems such as proc/sysfs/cgroup to UNKNOWN.",
    )
    p.add_argument(
        "--unknown-fstype",
        dest="extra_unknown_fstypes",
        action="append",
        default=[],
        metavar="FSTYPE",
        help="Additionally treat this filesystem type as UNKNOWN. May be repeated.",
    )


def selected_capabilities_for(ns: argparse.Namespace) -> Tuple[str, ...]:
    if ns.mode == MODE_CAN_DELETE_ONLY:
        caps = [CAP_DELETE]
    elif ns.mode == MODE_CAN_APPEND_ONLY:
        caps = [CAP_APPEND]
    elif ns.mode == MODE_CAN_OVERWRITE_ONLY:
        caps = [CAP_OVERWRITE]
    elif ns.mode == MODE_CAN_CONTENT_WRITE_ONLY:
        caps = [CAP_APPEND, CAP_OVERWRITE]
    elif ns.mode == MODE_CAN_CREATE_ONLY:
        caps = [CAP_CREATE]
    elif ns.mode == MODE_CAN_SPECIAL_WRITE_ONLY:
        caps = [CAP_SPECIAL_WRITE]
    elif ns.mode == MODE_CAN_WRITE_ONLY:
        caps = [CAP_APPEND, CAP_OVERWRITE, CAP_CREATE]
    elif ns.mode == MODE_CAN_MUTATE:
        caps = list(DEFAULT_MUTATION_CAPS)
    else:
        raise ValueError(f"unknown mode: {ns.mode}")

    if (
        ns.include_special_write
        and ns.mode in {MODE_CAN_MUTATE, MODE_CAN_WRITE_ONLY}
        and CAP_SPECIAL_WRITE not in caps
    ):
        caps.append(CAP_SPECIAL_WRITE)

    return tuple(cap for cap in CAPABILITY_ORDER if cap in caps)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def should_keep_for_output(
    outcome: Outcome,
    *,
    all_results: bool,
    directories_only: bool,
    hide_home: bool,
    home_dirs: Sequence[str],
) -> bool:
    if not all_results and outcome.status != passing_status_for_mode(outcome.mode):
        return False
    if directories_only and outcome.kind != KIND_DIR:
        return False
    if hide_home and path_is_within_any_home_lexically(outcome.path, home_dirs):
        return False
    return True


def display_path(outcome: Outcome) -> str:
    path = outcome.path
    if outcome.kind == KIND_DIR and path != "/":
        path += "/"

    if outcome.kind == KIND_SYMLINK and outcome.target_path:
        target = outcome.target_path
        if outcome.target_kind == KIND_DIR and target != "/":
            target += "/"
        return f"{path} -> {target}"

    return path


def escape_text_field(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)[1:-1]


def write_header(fmt: str, fp) -> Optional[csv.writer]:
    if fmt != "tsv":
        return None
    writer = csv.writer(fp, dialect="excel-tab", lineterminator="\n")
    writer.writerow(
        [
            "status",
            "kind",
            "mode",
            "path",
            "target_path",
            "target_kind",
            "capabilities",
            "unknown_capabilities",
            "blocked_capabilities",
            "skipped_capabilities",
            "reasons",
        ]
    )
    return writer


def write_record(
    outcome: Outcome,
    fmt: str,
    fp,
    tsv_writer: Optional[csv.writer],
    *,
    labels: bool,
) -> None:
    if fmt == "paths":
        rendered = escape_text_field(display_path(outcome))
        if labels and outcome.label:
            fp.write(f"[{outcome.label}] {rendered}\n")
        else:
            fp.write(rendered + "\n")
        return

    if fmt == "jsonl":
        fp.write(json.dumps(outcome.as_dict(), sort_keys=False, ensure_ascii=False) + "\n")
        return

    if fmt == "tsv":
        assert tsv_writer is not None
        tsv_writer.writerow(
            [
                outcome.status,
                outcome.kind,
                outcome.mode,
                outcome.path,
                outcome.target_path or "",
                outcome.target_kind or "",
                json.dumps(outcome.capabilities, ensure_ascii=False, separators=(",", ":")),
                json.dumps(outcome.unknown_capabilities, ensure_ascii=False, separators=(",", ":")),
                json.dumps(outcome.blocked_capabilities, ensure_ascii=False, separators=(",", ":")),
                json.dumps(outcome.skipped_capabilities, ensure_ascii=False, separators=(",", ":")),
                json.dumps(outcome.reasons, ensure_ascii=False, separators=(",", ":")),
            ]
        )
        return

    raise ValueError(fmt)


def stream_outcomes(ns: argparse.Namespace, sim: Simulator) -> Iterator[Outcome]:
    selected = selected_capabilities_for(ns)
    home_dirs = discover_home_dirs()
    hide_home = ns.exclude_home or (ns.default_paths and not ns.include_home)

    for raw_path in ns.paths:
        path = normalize(raw_path)
        root_dev = root_dev_for_path(path)
        for assessment in sim.simulate_path(path, selected_capabilities=selected, root_dev=root_dev, explicit=True):
            outcome = assessment.render(ns.mode, selected)
            if should_keep_for_output(
                outcome,
                all_results=ns.all_results,
                directories_only=ns.directories_only,
                hide_home=hide_home,
                home_dirs=home_dirs,
            ):
                yield outcome


def root_dev_for_path(path: str) -> Optional[int]:
    try:
        return os.lstat(path).st_dev
    except OSError:
        return None


def flatten_exclude_args(groups: Sequence[Sequence[str]]) -> List[str]:
    return [path for group in groups for path in group]


def default_tmp_excludes(ns: argparse.Namespace) -> List[str]:
    if not ns.default_paths or ns.include_tmp:
        return []
    return discover_writable_tmp_dirs(effective_access=not ns.real_ids)


def default_proc_excludes(ns: argparse.Namespace) -> List[str]:
    if not ns.default_paths or ns.include_proc:
        return []
    return [DEFAULT_PROC_EXCLUDE]


def unknown_fstypes_for(ns: argparse.Namespace) -> Optional[Set[str]]:
    if ns.no_special_fs_unknown:
        return None
    unknown = set(DEFAULT_UNKNOWN_FSTYPES)
    unknown.update(ns.extra_unknown_fstypes)
    return unknown


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: Sequence[str]) -> int:
    ns = parse_args(argv)
    ns.exclude_paths = flatten_exclude_args(ns.exclude_paths)
    ns.exclude_paths.extend(default_tmp_excludes(ns))
    ns.exclude_paths.extend(default_proc_excludes(ns))

    if os.geteuid() == 0 and not ns.run_as_root:
        sys.stderr.write(
            "This tool audits the current process context. Running as unrestricted root usually reports\n"
            "root's power, not ordinary-user risk. Re-run as the user you want to audit, for example:\n"
            "\n"
            "    setpriv --reuid nobody --regid nogroup --clear-groups -- ./check_permissions.py\n"
            "\n"
            "If you intentionally want root-context results, including restricted-capability root\n"
            "inside a container, add --run-as-root.\n"
        )
        sys.stderr.flush()
        return 2

    sim = Simulator(
        MountTable(parse_mountinfo()),
        preserve_root=ns.preserve_root,
        one_file_system=ns.one_file_system,
        unknown_fstypes=unknown_fstypes_for(ns),
        effective_access=not ns.real_ids,
        excluded_paths=ns.exclude_paths,
    )

    if ns.output == "-":
        write_outcomes(ns, sim, sys.stdout)
    else:
        with open(ns.output, "w", encoding="utf-8", newline="") as f:
            write_outcomes(ns, sim, f)

    return 0


def write_outcomes(ns: argparse.Namespace, sim: Simulator, fp) -> None:
    writer = write_header(ns.format, fp)
    for outcome in stream_outcomes(ns, sim):
        write_record(outcome, ns.format, fp, writer, labels=ns.labels)


def safely_redirect_stdout_to_devnull() -> None:
    try:
        sys.stdout.flush()
    except Exception:
        pass

    try:
        devnull_fd = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull_fd, sys.stdout.fileno())
        finally:
            os.close(devnull_fd)
    except Exception:
        pass


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except BrokenPipeError:
        safely_redirect_stdout_to_devnull()
        raise SystemExit(0)
    except KeyboardInterrupt:
        try:
            sys.stderr.write("\n")
            sys.stderr.flush()
        except Exception:
            pass
        raise SystemExit(130)
