#!/usr/bin/env python3
"""
check_permissions.py

Best-effort Linux simulator for recursive deletion and writability checks.
Without actually opening the file for writing or actually deleting it either!
Importantly, for
  Regular files: no content change, no size change, no atime change, no mtime change, no ctime change.

Defaults
--------
- behaves like a best-effort `rm -rf` simulator (`--can-delete-only`)
- outputs only paths that match the selected capability check
- suppresses paths under the current user's home directory unless
  `--include-home` is given
- `--label` / `--add-label` / `--add-labels` optionally prefix path output
  with `[d]` for deletable entries or `[w]` for writable-only entries
- exits cleanly when stdout is closed early by tools like `head` or `tail`
  and when interrupted with Ctrl-C

Capability modes
----------------
--can-delete-only   default; show paths that would likely be removable
--can-write-only    show paths that are writable
--can-write-or-delete  show paths that are writable or removable

Notes
-----
- This is still not a formal guarantee on a live system.
- MAC policies (SELinux/AppArmor/Landlock), races, and odd FUSE/NFS behavior
  can still make reality differ.
- For directory writability, this tool checks write + search (execute) because
  that is usually what matters for modifying directory entries.
- Symlink writability is reported as UNKNOWN because Linux symlink mode bits are
  not a meaningful "can write this path" signal.
- Labels affect only `--format paths`. Structured formats keep their existing
  schema unchanged.
"""

from __future__ import annotations

import argparse
import ctypes
import csv
import json
import os
import pwd
import stat
import sys
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

STATUS_WOULD_REMOVE = "WOULD_REMOVE"
STATUS_WOULD_WRITE = "WOULD_WRITE"
STATUS_WOULD_WRITE_OR_DELETE = "WOULD_WRITE_OR_DELETE"
STATUS_WOULD_FAIL = "WOULD_FAIL"
STATUS_UNKNOWN = "UNKNOWN"
STATUS_SKIP = "SKIP"

VERDICT_PASS = "pass"
VERDICT_FAIL = "fail"
VERDICT_UNKNOWN = "unknown"
VERDICT_SKIP = "skip"

MODE_CAN_DELETE_ONLY = "can_delete_only"
MODE_CAN_WRITE_ONLY = "can_write_only"
MODE_CAN_WRITE_OR_DELETE = "can_write_or_delete"

# Backward-compatible internal aliases for older names.
MODE_CAN_DELETE = MODE_CAN_DELETE_ONLY
MODE_CAN_WRITE = MODE_CAN_WRITE_ONLY
MODE_CAN_WRITE_DELETE = MODE_CAN_WRITE_OR_DELETE

KIND_FILE = "file"
KIND_DIR = "dir"
KIND_SYMLINK = "symlink"
KIND_FIFO = "fifo"
KIND_SOCKET = "socket"
KIND_CHAR = "char"
KIND_BLOCK = "block"
KIND_OTHER = "other"

LABEL_DELETE = "d"
LABEL_WRITE = "w"

CAP_FOWNER = 3

AT_FDCWD = -100
AT_SYMLINK_NOFOLLOW = 0x100
STATX_ALL = 0x00000FFF
STATX_ATTR_IMMUTABLE = 0x00000010
STATX_ATTR_APPEND = 0x00000020

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


class StructStatx(ctypes.Structure):
    """
    Safe ctypes view of Linux struct statx.

    We only need the stable first 64 bytes through stx_attributes_mask.
    The full UAPI struct is 256 bytes, so we pad the rest as opaque bytes.
    This avoids crashes from an undersized struct definition.
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


def statx_flags(path: str) -> FlagCheck:
    """
    Return immutable / append-only status when available.

    Failure to inspect the flags is treated as uncertainty rather than proof
    that the operation would fail.
    """
    if not _HAS_STATX:
        return FlagCheck(None, None, "statx_unavailable")

    buf = StructStatx()
    rc = libc.statx(
        AT_FDCWD,
        os.fsencode(path),
        AT_SYMLINK_NOFOLLOW,
        STATX_ALL,
        ctypes.byref(buf),
    )
    if rc != 0:
        e = ctypes.get_errno()
        return FlagCheck(None, None, f"statx_errno_{e}:{os.strerror(e)}")

    immutable = None
    append_only = None

    if buf.stx_attributes_mask & STATX_ATTR_IMMUTABLE:
        immutable = bool(buf.stx_attributes & STATX_ATTR_IMMUTABLE)
    if buf.stx_attributes_mask & STATX_ATTR_APPEND:
        append_only = bool(buf.stx_attributes & STATX_ATTR_APPEND)

    return FlagCheck(immutable, append_only, None)


def parse_caps() -> int:
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


def unescape_mount_field(s: str) -> str:
    # /proc/self/mountinfo uses octal escapes like \040
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


def _same_path_depth(
    mount_id: int,
    mounts_by_id: Dict[int, Mount],
    _memo: Dict[int, int],
) -> int:
    cached = _memo.get(mount_id)
    if cached is not None:
        return cached

    mount = mounts_by_id[mount_id]
    parent = mounts_by_id.get(mount.parent_id)
    if parent is None or parent.mount_point != mount.mount_point:
        depth = 0
    else:
        depth = _same_path_depth(parent.mount_id, mounts_by_id, _memo) + 1

    _memo[mount_id] = depth
    return depth


def parse_mountinfo() -> MountParseResult:
    mounts: List[Mount] = []
    try:
        with open("/proc/self/mountinfo", "r", encoding="utf-8") as f:
            for parse_index, line in enumerate(f):
                line = line.rstrip("\n")
                left, right = line.split(" - ", 1)
                lparts = left.split()
                rparts = right.split()

                mount_id = int(lparts[0])
                parent_id = int(lparts[1])
                mount_point = normalize(unescape_mount_field(lparts[4]))
                try:
                    real_mount_point = normalize(os.path.realpath(mount_point))
                except OSError:
                    real_mount_point = mount_point

                mount_options = tuple(lparts[5].split(","))
                fs_type = rparts[0]
                super_options = tuple(rparts[2].split(",")) if len(rparts) >= 3 else ()

                mounts.append(
                    Mount(
                        mount_id=mount_id,
                        parent_id=parent_id,
                        mount_point=mount_point,
                        real_mount_point=real_mount_point,
                        fs_type=fs_type,
                        mount_options=mount_options,
                        super_options=super_options,
                        parse_index=parse_index,
                    )
                )
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

    mounts_by_id = {m.mount_id: m for m in mounts}
    depth_memo: Dict[int, int] = {}
    mounts = [
        Mount(
            mount_id=m.mount_id,
            parent_id=m.parent_id,
            mount_point=m.mount_point,
            real_mount_point=m.real_mount_point,
            fs_type=m.fs_type,
            mount_options=m.mount_options,
            super_options=m.super_options,
            parse_index=m.parse_index,
            same_path_depth=_same_path_depth(m.mount_id, mounts_by_id, depth_memo),
        )
        for m in mounts
    ]

    mounts.sort(
        key=lambda m: (
            len(m.mount_point.rstrip("/")) if m.mount_point != "/" else 1,
            m.same_path_depth,
            m.parse_index,
        ),
        reverse=True,
    )
    return MountParseResult(mounts, None)


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
    seen = set()
    out: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def discover_home_dirs() -> List[str]:
    """
    Return plausible home directories for the invoking context.

    This is more robust than relying only on os.path.expanduser("~"), which can
    point at the wrong home when the script runs under sudo, wrappers, cron, or
    a process with mismatched real/effective IDs.
    """
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

    homes = [h for h in dedupe_keep_order(homes) if h and h != "/"]
    return homes


def discover_home_dirs_with_realpaths() -> List[str]:
    """
    Return plausible home directories plus their realpaths, deduplicated.
    """
    homes = discover_home_dirs()
    expanded: List[str] = []
    for home in homes:
        expanded.append(home)
        try:
            expanded.append(normalize(os.path.realpath(home)))
        except OSError:
            pass
    return [h for h in dedupe_keep_order(expanded) if h and h != "/"]


def path_is_within_any_home(path: str, home_dirs: Sequence[str]) -> bool:
    """
    Check lexical absolute paths first, then fall back to a cached realpath.

    This keeps the common case fast while still suppressing symlinked-home paths
    by default.
    """
    normalized = normalize(path)

    for home_dir in home_dirs:
        if is_path_prefix(home_dir, normalized):
            return True

    real = real_normalize(normalized)
    if real == normalized:
        return False

    for home_dir in home_dirs:
        if is_path_prefix(home_dir, real):
            return True
    return False



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
        raise RuntimeError('mount table is empty')

    def _same_path_children(self, mount: Mount) -> List[Mount]:
        return [
            child
            for child in self.children_by_parent_id.get(mount.mount_id, [])
            if child.mount_point == mount.mount_point
        ]

    def _choose_top_candidate(self, mounts: Sequence[Mount]) -> Mount:
        return max(mounts, key=lambda m: (m.same_path_depth, m.parse_index, m.mount_id))

    def _top_same_path_descendant(self, mount: Mount) -> Mount:
        cached = self._top_same_path_cache.get(mount.mount_id)
        if cached is not None:
            return cached

        current = mount
        seen: Set[int] = set()
        while True:
            if current.mount_id in seen:
                break
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

        root_candidates = [m for m in self.mounts if m.mount_point == '/']
        if not root_candidates:
            root_candidates = [self._root_fallback()]

        visible_root = self._top_same_path_descendant(self._choose_top_candidate(root_candidates))
        visible_seen_ids: Set[int] = set()

        def visit(mount: Mount) -> None:
            if mount.mount_id in visible_seen_ids:
                return
            visible_seen_ids.add(mount.mount_id)
            self.visible_mounts.append(mount)
            self.visible_by_mountpoint[normalize(mount.mount_point)] = mount

            grouped_children: Dict[str, List[Mount]] = {}
            for child in self.children_by_parent_id.get(mount.mount_id, []):
                if child.mount_point == mount.mount_point:
                    continue
                grouped_children.setdefault(normalize(child.mount_point), []).append(child)

            for child_mounts in grouped_children.values():
                visible_child = self._top_same_path_descendant(self._choose_top_candidate(child_mounts))
                visit(visible_child)

        visit(visible_root)
        self.visible_mounts.sort(
            key=lambda m: len(m.mount_point.rstrip('/')) if m.mount_point != '/' else 1,
            reverse=True,
        )
        return visible_root

    def _visible_mount_for_lexical_path(self, path: str) -> Mount:
        lexical = normalize(path)
        probe = lexical
        while True:
            match = self.visible_by_mountpoint.get(probe)
            if match is not None:
                return match
            if probe == '/':
                break
            probe = normalize(os.path.dirname(probe) or '/')
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
            return lexical == '/'
        return lexical in self.visible_by_mountpoint




@dataclass
class Outcome:
    status: str
    kind: str
    path: str
    reasons: List[str] = field(default_factory=list)
    mode: str = MODE_CAN_DELETE_ONLY
    label: Optional[str] = None

    def as_dict(self) -> Dict[str, object]:
        return {
            "status": self.status,
            "kind": self.kind,
            "path": self.path,
            "reasons": self.reasons,
            "mode": self.mode,
        }


@dataclass
class Assessment:
    kind: str
    path: str
    delete_verdict: str
    delete_reasons: List[str] = field(default_factory=list)
    write_verdict: str = VERDICT_UNKNOWN
    write_reasons: List[str] = field(default_factory=list)

    def render(self, mode: str) -> Outcome:
        if mode == MODE_CAN_DELETE_ONLY:
            return Outcome(
                status=verdict_to_status(self.delete_verdict, mode),
                kind=self.kind,
                path=self.path,
                reasons=self.delete_reasons,
                mode=mode,
                label=choose_output_label(self.delete_verdict, self.write_verdict, mode),
            )

        if mode == MODE_CAN_WRITE_ONLY:
            return Outcome(
                status=verdict_to_status(self.write_verdict, mode),
                kind=self.kind,
                path=self.path,
                reasons=self.write_reasons,
                mode=mode,
                label=choose_output_label(self.delete_verdict, self.write_verdict, mode),
            )

        if mode == MODE_CAN_WRITE_OR_DELETE:
            combined_verdict = combine_verdicts(self.delete_verdict, self.write_verdict)
            return Outcome(
                status=verdict_to_status(combined_verdict, mode),
                kind=self.kind,
                path=self.path,
                reasons=dedupe_keep_order(self.delete_reasons + self.write_reasons),
                mode=mode,
                label=choose_output_label(self.delete_verdict, self.write_verdict, mode),
            )

        raise ValueError(f"unknown mode: {mode}")



def combine_verdicts(delete_verdict: str, write_verdict: str) -> str:
    verdicts = {delete_verdict, write_verdict}

    if VERDICT_PASS in verdicts:
        return VERDICT_PASS
    if VERDICT_UNKNOWN in verdicts:
        return VERDICT_UNKNOWN
    if verdicts == {VERDICT_SKIP}:
        return VERDICT_SKIP
    if VERDICT_FAIL in verdicts:
        return VERDICT_FAIL
    return VERDICT_UNKNOWN


def verdict_to_status(verdict: str, mode: str) -> str:
    if verdict == VERDICT_SKIP:
        return STATUS_SKIP
    if verdict == VERDICT_UNKNOWN:
        return STATUS_UNKNOWN
    if verdict == VERDICT_FAIL:
        return STATUS_WOULD_FAIL
    if mode == MODE_CAN_DELETE_ONLY:
        return STATUS_WOULD_REMOVE
    if mode == MODE_CAN_WRITE_ONLY:
        return STATUS_WOULD_WRITE
    if mode == MODE_CAN_WRITE_OR_DELETE:
        return STATUS_WOULD_WRITE_OR_DELETE
    raise ValueError(f"unknown mode: {mode}")


def choose_output_label(delete_verdict: str, write_verdict: str, mode: str) -> Optional[str]:
    if mode == MODE_CAN_DELETE_ONLY:
        if delete_verdict == VERDICT_PASS:
            return LABEL_DELETE
        return None

    if mode == MODE_CAN_WRITE_ONLY:
        if write_verdict == VERDICT_PASS:
            return LABEL_WRITE
        return None

    if mode == MODE_CAN_WRITE_OR_DELETE:
        if delete_verdict == VERDICT_PASS:
            return LABEL_DELETE
        if write_verdict == VERDICT_PASS:
            return LABEL_WRITE
        return None

    raise ValueError(f"unknown mode: {mode}")


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



class Simulator:
    def __init__(
        self,
        mounts: MountTable,
        preserve_root: bool,
        one_file_system: bool,
        unknown_fstypes: Optional[set[str]],
        effective_access: bool,
    ):
        self.mounts = mounts
        self.preserve_root = preserve_root
        self.one_file_system = one_file_system
        self.unknown_fstypes = unknown_fstypes
        self.effective_access = effective_access
        self.uid = os.geteuid() if effective_access else os.getuid()
        self.caps = parse_caps() if effective_access else 0
        self.seen_dirs: Set[Tuple[int, int]] = set()

    def access(self, path: str, mode: int) -> bool:
        if not self.effective_access:
            return os.access(path, mode)

        if os.access in getattr(os, "supports_effective_ids", set()):
            return os.access(path, mode, effective_ids=True)

        try:
            return os.access(path, mode, effective_ids=True)
        except (TypeError, NotImplementedError):
            return os.access(path, mode)

    def sticky_blocks_delete(self, parent_st: os.stat_result, target_st: os.stat_result) -> bool:
        if not (parent_st.st_mode & stat.S_ISVTX):
            return False
        if self.uid == 0:
            return False
        if has_cap(self.caps, CAP_FOWNER):
            return False
        return self.uid not in {parent_st.st_uid, target_st.st_uid}

    def parent_delete_checks(
        self,
        parent: str,
        target: str,
        parent_st: os.stat_result,
        target_st: os.stat_result,
    ) -> Tuple[List[str], bool, bool]:
        del target  # kept in signature because the call site is semantically clearer
        reasons: List[str] = []
        uncertain = False
        hard_failure = False

        if not self.access(parent, os.W_OK | os.X_OK):
            reasons.append("parent_not_writable_searchable")
            hard_failure = True

        if self.sticky_blocks_delete(parent_st, target_st):
            reasons.append("sticky_bit_blocks_delete")
            hard_failure = True

        mount = self.mounts.mount_for(parent)
        if self.mounts.degraded:
            reasons.append(f"{self.mounts.error_reason}")
            uncertain = True
        elif mount.read_only:
            reasons.append("parent_mount_read_only")
            hard_failure = True

        flags = statx_flags(parent)
        if flags.immutable is True:
            reasons.append("parent_dir_immutable")
            hard_failure = True
        if flags.append_only is True:
            reasons.append("parent_dir_append_only")
            hard_failure = True
        if flags.uncertain:
            reasons.append(f"parent_flag_check:{flags.error_reason}")
            uncertain = True

        return reasons, uncertain, hard_failure

    def target_inode_checks(self, path: str) -> Tuple[List[str], bool, bool]:
        reasons: List[str] = []
        uncertain = False
        hard_failure = False

        flags = statx_flags(path)
        if flags.immutable is True:
            reasons.append("target_immutable")
            hard_failure = True
        if flags.append_only is True:
            reasons.append("target_append_only")
            hard_failure = True
        if flags.uncertain:
            reasons.append(f"target_flag_check:{flags.error_reason}")
            uncertain = True

        return reasons, uncertain, hard_failure

    def maybe_fs_uncertain(self, path: str) -> Tuple[List[str], bool]:
        reasons: List[str] = []
        uncertain = False

        if self.mounts.degraded:
            return [f"{self.mounts.error_reason}"], True

        if self.unknown_fstypes:
            mount = self.mounts.mount_for(path)
            if mount.fs_type in self.unknown_fstypes:
                reasons.append(f"special_fs:{mount.fs_type}")
                uncertain = True

        return reasons, uncertain

    def iter_dir_entries(self, path: str) -> Iterator[os.DirEntry]:
        with os.scandir(path) as it:
            for entry in it:
                yield entry

    def scan_dir(self, path: str) -> Tuple[Optional[List[os.DirEntry]], Optional[str]]:
        try:
            with os.scandir(path) as it:
                return list(it), None
        except PermissionError as e:
            return None, f"cannot_scan_dir:{e.strerror or 'Permission denied'}"
        except OSError as e:
            return None, f"cannot_scan_dir_errno_{e.errno}:{e.strerror}"

    def simulate_path(self, path: str, root_dev: Optional[int] = None) -> Iterator[Assessment]:
        yield from self._simulate_path(path, root_dev=root_dev)

    def _basic_assessment(
        self,
        *,
        kind: str,
        path: str,
        verdict: str,
        reasons: Sequence[str],
    ) -> Assessment:
        reason_list = list(reasons)
        return Assessment(
            kind=kind,
            path=path,
            delete_verdict=verdict,
            delete_reasons=reason_list,
            write_verdict=verdict,
            write_reasons=reason_list,
        )

    def _prepare_path(
        self,
        path: str,
        root_dev: Optional[int] = None,
    ) -> Tuple[str, Optional[os.stat_result], Optional[Tuple[int, int]], Optional[List[Assessment]]]:
        path = normalize(path)

        if self.preserve_root and path == "/":
            return path, None, None, [
                self._basic_assessment(
                    kind=KIND_DIR,
                    path=path,
                    verdict=VERDICT_SKIP,
                    reasons=["preserve_root"],
                )
            ]

        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return path, None, None, [
                self._basic_assessment(
                    kind=KIND_OTHER,
                    path=path,
                    verdict=VERDICT_UNKNOWN,
                    reasons=["not_found_during_scan"],
                )
            ]
        except PermissionError as e:
            reason = f"lstat_denied:{e.strerror or 'Permission denied'}"
            return path, None, None, [
                self._basic_assessment(
                    kind=KIND_OTHER,
                    path=path,
                    verdict=VERDICT_UNKNOWN,
                    reasons=[reason],
                )
            ]
        except OSError as e:
            reason = f"lstat_errno_{e.errno}:{e.strerror}"
            return path, None, None, [
                self._basic_assessment(
                    kind=KIND_OTHER,
                    path=path,
                    verdict=VERDICT_UNKNOWN,
                    reasons=[reason],
                )
            ]

        kind = classify_kind(st)

        if self.one_file_system and root_dev is not None and st.st_dev != root_dev:
            reasons = ["different_filesystem", "one_file_system"]
            return path, None, None, [
                self._basic_assessment(
                    kind=kind,
                    path=path,
                    verdict=VERDICT_SKIP,
                    reasons=reasons,
                )
            ]

        if kind != KIND_DIR:
            return path, None, None, [self.classify_leaf(path, st, kind)]

        dir_key = (st.st_dev, st.st_ino)
        if dir_key in self.seen_dirs:
            reasons = ["already_visited_directory"]
            return path, None, None, [
                self._basic_assessment(
                    kind=KIND_DIR,
                    path=path,
                    verdict=VERDICT_UNKNOWN,
                    reasons=reasons,
                )
            ]

        self.seen_dirs.add(dir_key)
        return path, st, dir_key, None

    def _directory_scan_failure(self, path: str, st: os.stat_result, reason: str) -> Assessment:
        write_verdict, write_reasons = self.classify_dir_write_only(path, st)
        return Assessment(
            kind=KIND_DIR,
            path=path,
            delete_verdict=VERDICT_UNKNOWN,
            delete_reasons=[reason],
            write_verdict=write_verdict,
            write_reasons=dedupe_keep_order([reason] + write_reasons),
        )

    def _final_directory_assessment(
        self,
        path: str,
        st: os.stat_result,
        *,
        unknown_children: bool,
        failed_children: bool,
    ) -> Assessment:
        delete_verdict, delete_reasons = self.classify_dir_delete(path, st, unknown_children, failed_children)
        write_verdict, write_reasons = self.classify_dir_write_only(path, st)
        return Assessment(
            kind=KIND_DIR,
            path=path,
            delete_verdict=delete_verdict,
            delete_reasons=delete_reasons,
            write_verdict=write_verdict,
            write_reasons=write_reasons,
        )

    def _merge_child_delete_flags(
        self,
        direct: Optional[Assessment],
        *,
        unknown_children: bool,
        failed_children: bool,
    ) -> Tuple[bool, bool]:
        if direct is not None:
            if direct.delete_verdict == VERDICT_UNKNOWN:
                unknown_children = True
            if direct.delete_verdict == VERDICT_FAIL:
                failed_children = True
        return unknown_children, failed_children

    def _simulate_path(self, path: str, root_dev: Optional[int] = None) -> Iterator[Assessment]:
        path, st, dir_key, terminal = self._prepare_path(path, root_dev=root_dev)
        if terminal is not None:
            yield from terminal
            return

        assert st is not None
        assert dir_key is not None

        unknown_children = False
        failed_children = False

        try:
            try:
                for entry in self.iter_dir_entries(path):
                    child_path = os.path.join(path, entry.name)
                    child_direct: Optional[Assessment] = None
                    for child_assessment in self._simulate_path(child_path, root_dev=root_dev):
                        if child_direct is None and normalize(child_assessment.path) == normalize(child_path):
                            child_direct = child_assessment
                        yield child_assessment
                    unknown_children, failed_children = self._merge_child_delete_flags(
                        child_direct,
                        unknown_children=unknown_children,
                        failed_children=failed_children,
                    )
            except PermissionError as e:
                yield self._directory_scan_failure(
                    path,
                    st,
                    f"cannot_scan_dir:{e.strerror or 'Permission denied'}",
                )
                return
            except OSError as e:
                yield self._directory_scan_failure(
                    path,
                    st,
                    f"cannot_scan_dir_errno_{e.errno}:{e.strerror}",
                )
                return

            yield self._final_directory_assessment(
                path,
                st,
                unknown_children=unknown_children,
                failed_children=failed_children,
            )
        finally:
            self.seen_dirs.discard(dir_key)

    def classify_leaf(self, path: str, st: os.stat_result, kind: str) -> Assessment:
        delete_verdict, delete_reasons = self.classify_leaf_delete(path, st, kind)
        write_verdict, write_reasons = self.classify_leaf_write_only(path, st, kind)
        return Assessment(
            kind=kind,
            path=path,
            delete_verdict=delete_verdict,
            delete_reasons=delete_reasons,
            write_verdict=write_verdict,
            write_reasons=write_reasons,
        )

    def classify_leaf_delete(self, path: str, st: os.stat_result, kind: str) -> Tuple[str, List[str]]:
        del kind
        reasons: List[str] = []
        uncertain = False
        hard_failure = False

        flag_reasons, flag_uncertain, flag_hard_failure = self.target_inode_checks(path)
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
            return VERDICT_UNKNOWN, reasons

        parent_reasons, parent_uncertain, parent_hard_failure = self.parent_delete_checks(parent, path, parent_st, st)
        reasons.extend(parent_reasons)
        uncertain |= parent_uncertain
        hard_failure |= parent_hard_failure

        reasons = dedupe_keep_order(reasons)
        if hard_failure:
            return VERDICT_FAIL, reasons
        if uncertain:
            return VERDICT_UNKNOWN, reasons
        return VERDICT_PASS, []

    def classify_dir_delete(
        self,
        path: str,
        st: os.stat_result,
        unknown_children: bool,
        failed_children: bool,
    ) -> Tuple[str, List[str]]:
        reasons: List[str] = []
        uncertain = False
        hard_failure = False

        flag_reasons, flag_uncertain, flag_hard_failure = self.target_inode_checks(path)
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
            return VERDICT_UNKNOWN, reasons

        parent_reasons, parent_uncertain, parent_hard_failure = self.parent_delete_checks(parent, path, parent_st, st)
        reasons.extend(parent_reasons)
        uncertain |= parent_uncertain
        hard_failure |= parent_hard_failure

        if unknown_children:
            reasons.append("unknown_descendants")
            uncertain = True
        if failed_children:
            reasons.append("would_remain_nonempty_due_to_failed_children")
            hard_failure = True

        reasons = dedupe_keep_order(reasons)
        if hard_failure:
            return VERDICT_FAIL, reasons
        if uncertain:
            return VERDICT_UNKNOWN, reasons
        return VERDICT_PASS, []

    def classify_leaf_write_only(
        self,
        path: str,
        st: os.stat_result,
        kind: str,
    ) -> Tuple[str, List[str]]:
        del st  # symmetry with delete helpers; metadata is still available to callers if needed
        reasons: List[str] = []
        uncertain = False
        hard_failure = False

        if kind == KIND_SYMLINK:
            return VERDICT_UNKNOWN, ["symlink_writability_ambiguous"]

        flag_reasons, flag_uncertain, flag_hard_failure = self.target_inode_checks(path)
        reasons.extend(flag_reasons)
        uncertain |= flag_uncertain
        hard_failure |= flag_hard_failure

        fs_reasons, fs_uncertain = self.maybe_fs_uncertain(path)
        reasons.extend(fs_reasons)
        uncertain |= fs_uncertain

        if self.mounts.degraded:
            uncertain = True
        elif self.mounts.mount_for(path).read_only:
            reasons.append("target_mount_read_only")
            hard_failure = True

        if kind == KIND_DIR:
            if not self.access(path, os.W_OK | os.X_OK):
                if not self.access(path, os.W_OK):
                    reasons.append("dir_not_writable")
                    hard_failure = True
                if not self.access(path, os.X_OK):
                    reasons.append("dir_not_searchable")
                    hard_failure = True
        else:
            if not self.access(path, os.W_OK):
                reasons.append("target_not_writable")
                hard_failure = True

        reasons = dedupe_keep_order(reasons)
        if hard_failure:
            return VERDICT_FAIL, reasons
        if uncertain:
            return VERDICT_UNKNOWN, reasons
        return VERDICT_PASS, []

    def classify_dir_write_only(
        self,
        path: str,
        st: os.stat_result,
    ) -> Tuple[str, List[str]]:
        return self.classify_leaf_write_only(path, st, KIND_DIR)


class HelpFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    pass



def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    home = os.path.expanduser("~")
    example_home = normalize(home) if home else "$HOME"
    prog = os.path.basename(sys.argv[0]) or "check_permissions_v8.py"

    p = argparse.ArgumentParser(
        prog=prog,
        description=(
            "Best-effort Linux simulator for rm -rf style deletion, writability "
            "checks, and optional labeled path output."
        ),
        epilog=f"""
Examples:
  %(prog)s /var/tmp/project
  %(prog)s --label /tmp
  %(prog)s --add-labels --can-write-or-delete /dev
  %(prog)s --all-results --format tsv /etc /var
  %(prog)s --can-write-only --directories-only /srv/data
  %(prog)s --include-home {example_home}

Output filtering:
  By default, paths under your home directory are suppressed from output. This
  only affects what is printed, not what gets scanned. Use --include-home to
  show them.

Path labels:
  --label, --add-label, and --add-labels are the same feature. They affect only
  --format paths and prefix passing entries with one compact capability label:
    [d]  deletable
    [w]  writable but not deletable

  In --can-write-or-delete mode, [d] wins whenever both checks would pass.
  Only one label is shown.

Capability modes:
  --can-delete-only      default; path must be deletable
  --can-write-only       path must be writable
  --can-write-or-delete  path must be writable or deletable
""",
        formatter_class=HelpFormatter,
    )
    p.add_argument(
        "paths",
        nargs="*",
        default=["/"],
        help="Root path(s) to inspect recursively.",
    )
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
        help="Output format. 'paths' prints escaped path strings.",
    )
    p.add_argument(
        "--preserve-root",
        action="store_true",
        help="Skip / entirely, similar to GNU rm --preserve-root.",
    )
    p.add_argument(
        "--one-file-system",
        action="store_true",
        help="Do not descend into entries that live on a different st_dev.",
    )
    p.add_argument(
        "--no-special-fs-unknown",
        action="store_true",
        help="Do not automatically downgrade kernel pseudo-filesystems to UNKNOWN.",
    )
    p.add_argument(
        "--real-ids",
        action="store_true",
        help=(
            "Use real IDs for os.access checks and sticky-bit ownership tests; "
            "effective capabilities are ignored in this mode."
        ),
    )
    p.add_argument(
        "--all-results",
        action="store_true",
        help="Include WOULD_FAIL / UNKNOWN / SKIP entries too.",
    )
    p.add_argument(
        "--include-home",
        "--include_home",
        dest="include_home",
        action="store_true",
        help="Include paths from under the current user's home directory.",
    )
    p.add_argument(
        "--directories-only",
        "--directories_only",
        dest="directories_only",
        action="store_true",
        help="Only print directory entries after all other filtering is applied.",
    )
    p.add_argument(
        "--label",
        "--add-label",
        "--add-labels",
        dest="add_labels",
        action="store_true",
        help=(
            "For --format paths, prefix passing entries with [d] when deletable "
            "or [w] when writable-only. In --can-write-or-delete mode, [d] wins "
            "when both checks pass."
        ),
    )
    p.add_argument(
        "--add_label",
        "--add_labels",
        "-add-label",
        "-add-labels",
        dest="add_labels",
        action="store_true",
        help=argparse.SUPPRESS,
    )

    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--can-delete-only",
        "--can_delete_only",
        dest="mode",
        action="store_const",
        const=MODE_CAN_DELETE_ONLY,
        help="Require deletability only. This is the default mode.",
    )
    mode.add_argument(
        "--can-write-only",
        "--can_write_only",
        dest="mode",
        action="store_const",
        const=MODE_CAN_WRITE_ONLY,
        help="Require writability only. For directories this means write + search (execute).",
    )
    mode.add_argument(
        "--can-write-or-delete",
        "--can_write_or_delete",
        dest="mode",
        action="store_const",
        const=MODE_CAN_WRITE_OR_DELETE,
        help=(
            "Require writability or deletability. A path passes if either "
            "check succeeds."
        ),
    )

    mode.add_argument(
        "--can-write-delete",
        "--can_write_delete",
        dest="mode",
        action="store_const",
        const=MODE_CAN_WRITE_OR_DELETE,
        help=argparse.SUPPRESS,
    )

    mode.add_argument(
        "--can-delete",
        "--can_delete",
        dest="mode",
        action="store_const",
        const=MODE_CAN_DELETE_ONLY,
        help=argparse.SUPPRESS,
    )
    mode.add_argument(
        "--can-write",
        "--can_write",
        dest="mode",
        action="store_const",
        const=MODE_CAN_WRITE_ONLY,
        help=argparse.SUPPRESS,
    )

    p.set_defaults(mode=MODE_CAN_DELETE_ONLY)
    return p.parse_args(argv)


def should_keep_for_output(
    outcome: Outcome,
    *,
    include_home: bool,
    home_dirs: Sequence[str],
    directories_only: bool,
    all_results: bool,
) -> bool:
    if not all_results and outcome.status not in passing_statuses_for_mode(outcome.mode):
        return False

    if directories_only and outcome.kind != KIND_DIR:
        return False

    if not include_home and path_is_within_any_home(outcome.path, home_dirs):
        return False

    return True


def passing_statuses_for_mode(mode: str) -> set[str]:
    if mode == MODE_CAN_DELETE_ONLY:
        return {STATUS_WOULD_REMOVE}
    if mode == MODE_CAN_WRITE_ONLY:
        return {STATUS_WOULD_WRITE}
    if mode == MODE_CAN_WRITE_OR_DELETE:
        return {STATUS_WOULD_WRITE_OR_DELETE}
    raise ValueError(f"unknown mode: {mode}")


def display_path(outcome: Outcome) -> str:
    if outcome.kind == KIND_DIR and outcome.path != "/":
        return outcome.path + "/"
    return outcome.path


def escape_text_field(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)[1:-1]


def write_header(fmt: str, fp) -> Optional[csv.writer]:
    if fmt == "tsv":
        writer = csv.writer(fp, dialect="excel-tab", lineterminator="\n")
        writer.writerow(["status", "kind", "mode", "path", "reasons"])
        return writer
    return None


def write_record(
    record: Outcome,
    fmt: str,
    fp,
    tsv_writer: Optional[csv.writer] = None,
    add_labels: bool = False,
) -> None:
    if fmt == "paths":
        rendered_path = escape_text_field(display_path(record))
        if add_labels and record.label is not None:
            fp.write(f"[{record.label}] {rendered_path}\n")
        else:
            fp.write(rendered_path + "\n")
        return

    if fmt == "jsonl":
        fp.write(json.dumps(record.as_dict(), sort_keys=False, ensure_ascii=False) + "\n")
        return

    if fmt == "tsv":
        assert tsv_writer is not None
        tsv_writer.writerow(
            [
                record.status,
                record.kind,
                record.mode,
                display_path(record),
                json.dumps(record.reasons, ensure_ascii=False, separators=(",", ":")),
            ]
        )
        return

    raise ValueError(fmt)


def safely_redirect_stdout_to_devnull() -> None:
    """
    Prevent a second BrokenPipeError during interpreter shutdown.
    """
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


def stream_outcomes(ns: argparse.Namespace, sim: Simulator) -> Iterator[Outcome]:
    home_dirs = discover_home_dirs_with_realpaths()
    for raw in ns.paths:
        path = normalize(raw)
        try:
            root_dev = os.lstat(path).st_dev
        except OSError:
            root_dev = None
        for assessment in sim.simulate_path(path, root_dev=root_dev):
            outcome = assessment.render(ns.mode)
            if should_keep_for_output(
                outcome,
                include_home=ns.include_home,
                home_dirs=home_dirs,
                directories_only=ns.directories_only,
                all_results=ns.all_results,
            ):
                yield outcome


def main(argv: Sequence[str]) -> int:
    ns = parse_args(argv)

    sim = Simulator(
        mounts=MountTable(parse_mountinfo()),
        preserve_root=ns.preserve_root,
        one_file_system=ns.one_file_system,
        unknown_fstypes=None if ns.no_special_fs_unknown else set(DEFAULT_UNKNOWN_FSTYPES),
        effective_access=not ns.real_ids,
    )

    if ns.output == "-":
        writer = write_header(ns.format, sys.stdout)
        for outcome in stream_outcomes(ns, sim):
            write_record(outcome, ns.format, sys.stdout, writer, add_labels=ns.add_labels)
    else:
        with open(ns.output, "w", encoding="utf-8", newline="") as f:
            writer = write_header(ns.format, f)
            for outcome in stream_outcomes(ns, sim):
                write_record(outcome, ns.format, f, writer, add_labels=ns.add_labels)

    return 0



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
