#!/usr/bin/env python3
"""
Audit Linux filesystem mutation permissions for the current process identity.

The standalone tool requires Linux and Python 3.9 or newer.

This program observes Linux metadata and asks the kernel permission questions;
it does not prove that a future mutation syscall will succeed.  Every structured
record names the model version, observation time, process-credential evidence,
mount-table evidence, source-code digest, and modeled conclusions.  Routine
limitations are retained but omitted from normal output; ``--full-audit``
includes routine and material uncertainty.  Live filesystem races, MAC/LSM
policy, leases, idmapped mounts, remote filesystems, and device-specific
behavior can still disagree with the model.

Traversal captures each object and its parent with Linux O_PATH descriptors.
Directory entries are consumed lazily, and every metadata, access, statx, and
mount-ID query uses the captured identity.  This prevents a renamed parent from
redirecting the walk, without claiming an atomic filesystem snapshot.

Standard output uses compact, human-readable paths when it is attached to a
terminal and self-contained JSON Lines when it is redirected or piped.
``--tty``/``--human`` and ``--json``/``--machine`` override that automatic
selection.
Completed JSONL output ends with an audit_run_completion record; absent that
marker, the stream is incomplete.

Audited paths are never intentionally opened for writing, created, removed,
renamed, chmodded, chowned, or assigned inode flags.  Directory listing requests
Linux O_NOATIME; a clearly reported fallback read may update access time.  Reads
can also trigger automount, network, FUSE, or device effects.  Use a snapshot or
read-only mount when forensic non-interference is required.

Publishing ``--output FILE`` is the deliberate mutation exception.  A new
report is written to a mode-0600 O_EXCL temporary sibling and published with
RENAME_NOREPLACE only after synchronization.  ``--replace-output`` permits an
existing regular destination to be exchanged without immediate destruction;
the displaced identity/change snapshot and published report identity are then
validated, and a mismatch is exchanged back.  Non-sticky destination
directories writable by group or other users are refused because hostile
writers could race validation and cleanup entry names.  Same-identity writers
are not isolated by this process-identity trust boundary, so report publication
is not described as a general filesystem transaction.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import errno
import hashlib
import json
import os
import stat
import sys
import uuid
from collections.abc import Hashable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import TracebackType
from typing import TextIO, TypeVar, Union

try:
    import pwd
except ImportError:  # pragma: no cover - exercised only on non-POSIX hosts
    pwd = None  # type: ignore[assignment]

AUDIT_TOOL_NAME = "check_permissions.py"
AUDIT_TOOL_VERSION = "4.0.0"
CAPABILITY_MODEL_ID = "linux-filesystem-mutation-permission-model/v3"
STRUCTURED_RECORD_SCHEMA_ID = "linux-filesystem-permission-audit-record/v3"
AUDIT_RUN_PROVENANCE_SCHEMA_ID = "linux-filesystem-permission-audit-run-provenance/v3"

_OS_PATH_REALPATH_SUPPORTS_STRICT = sys.version_info >= (3, 10)
STRICT_PATH_RESOLUTION_EVIDENCE_SOURCE = (
    "os.path.realpath(strict=True)"
    if _OS_PATH_REALPATH_SUPPORTS_STRICT
    else "pathlib.Path.resolve(strict=True)"
)

EXIT_AUDIT_COMPLETED = 0
EXIT_COMMAND_LINE_REFUSED = 2
EXIT_REPORT_OUTPUT_FAILED = 3
EXIT_AUDIT_RUNTIME_FAILED = 4
EXIT_AUDIT_EVIDENCE_UNCERTAIN = 5
EXIT_INTERRUPTED = 130

CAPABILITY_DELETE_ENTRY_OR_TREE = "delete_entry_or_tree"
CAPABILITY_APPEND_REGULAR_FILE_CONTENT = "append_regular_file_content"
CAPABILITY_OVERWRITE_REGULAR_FILE_CONTENT = "overwrite_regular_file_content"
CAPABILITY_CREATE_DIRECTORY_ENTRY = "create_directory_entry"
CAPABILITY_SPECIAL_FILE_WRITE_PERMISSION = "special_file_write_permission"

CAPABILITY_EVALUATION_ORDER: tuple[str, ...] = (
    CAPABILITY_DELETE_ENTRY_OR_TREE,
    CAPABILITY_APPEND_REGULAR_FILE_CONTENT,
    CAPABILITY_OVERWRITE_REGULAR_FILE_CONTENT,
    CAPABILITY_CREATE_DIRECTORY_ENTRY,
    CAPABILITY_SPECIAL_FILE_WRITE_PERMISSION,
)

TERMINAL_CAPABILITY_LABEL_BY_NAME: Mapping[str, str] = {
    CAPABILITY_DELETE_ENTRY_OR_TREE: "d",
    CAPABILITY_APPEND_REGULAR_FILE_CONTENT: "a",
    CAPABILITY_OVERWRITE_REGULAR_FILE_CONTENT: "o",
    CAPABILITY_CREATE_DIRECTORY_ENTRY: "c",
    CAPABILITY_SPECIAL_FILE_WRITE_PERMISSION: "s",
}

DEFAULT_MUTATION_CAPABILITIES: tuple[str, ...] = (
    CAPABILITY_DELETE_ENTRY_OR_TREE,
    CAPABILITY_APPEND_REGULAR_FILE_CONTENT,
    CAPABILITY_OVERWRITE_REGULAR_FILE_CONTENT,
    CAPABILITY_CREATE_DIRECTORY_ENTRY,
)

CAPABILITY_OPERATION_DEFINITION_BY_NAME: Mapping[str, str] = {
    CAPABILITY_DELETE_ENTRY_OR_TREE: (
        "Remove a non-directory entry without following its final symbolic "
        "link, or recursively remove every assessed descendant before its "
        "directory."
    ),
    CAPABILITY_APPEND_REGULAR_FILE_CONTENT: (
        "Add content at the end of an existing regular file, including when "
        "the audited path is a symbolic link to that file."
    ),
    CAPABILITY_OVERWRITE_REGULAR_FILE_CONTENT: (
        "Modify or truncate existing regular-file content outside the "
        "append-only constraint, including through a symbolic link."
    ),
    CAPABILITY_CREATE_DIRECTORY_ENTRY: (
        "Create a child entry in an existing directory, or create an "
        "explicitly requested missing final path in its existing parent."
    ),
    CAPABILITY_SPECIAL_FILE_WRITE_PERMISSION: (
        "Satisfy permission-layer write checks for a FIFO, socket, character "
        "device, or block device without exercising endpoint behavior."
    ),
}

PATH_MODEL_STATUS_AT_LEAST_ONE_CAPABILITY_ALLOWED = (
    "at_least_one_selected_capability_is_model_allowed"
)
PATH_MODEL_STATUS_NO_CAPABILITY_ALLOWED = "no_selected_capability_is_model_allowed"
PATH_MODEL_STATUS_INSUFFICIENT_EVIDENCE = (
    "no_selected_capability_is_allowed_and_some_evidence_is_uncertain"
)
PATH_MODEL_STATUS_SKIPPED = "all_selected_capabilities_were_skipped"

OUTPUT_PRESENTATION_AUTOMATIC = "automatic_from_output_destination_and_tty"
OUTPUT_PRESENTATION_TERMINAL_PATHS = "human_readable_terminal_paths"
OUTPUT_PRESENTATION_JSON_LINES = "self_contained_json_lines"

MODEL_VERDICT_INDICATES_ALLOWED = "model_indicates_allowed"
MODEL_VERDICT_INDICATES_BLOCKED = "model_indicates_blocked"
MODEL_VERDICT_INSUFFICIENT_EVIDENCE = "insufficient_evidence"
MODEL_VERDICT_SKIPPED = "skipped"

UNCERTAINTY_GRADE_ROUTINE = "routine"
UNCERTAINTY_GRADE_MATERIAL = "material"

FILESYSTEM_OBJECT_KIND_REGULAR_FILE = "regular_file"
FILESYSTEM_OBJECT_KIND_DIRECTORY = "directory"
FILESYSTEM_OBJECT_KIND_SYMBOLIC_LINK = "symbolic_link"
FILESYSTEM_OBJECT_KIND_NAMED_PIPE = "named_pipe"
FILESYSTEM_OBJECT_KIND_SOCKET = "socket"
FILESYSTEM_OBJECT_KIND_CHARACTER_DEVICE = "character_device"
FILESYSTEM_OBJECT_KIND_BLOCK_DEVICE = "block_device"
FILESYSTEM_OBJECT_KIND_UNRECOGNIZED_STAT_MODE = "unrecognized_stat_mode_file_type"
FILESYSTEM_OBJECT_KIND_UNOBSERVED = "unobserved"
FILESYSTEM_OBJECT_KIND_MISSING = "missing"

LINUX_CAPABILITY_FOWNER_NUMBER = 3
LINUX_CAPABILITY_LINUX_IMMUTABLE_NUMBER = 9
LINUX_CAPABILITY_SYS_ADMIN_NUMBER = 21
ACCESS_IDENTITY_MODEL_FILESYSTEM_AUTHORITY_WHEN_IDS_MATCH = (
    "effective_id_kernel_access_query_when_effective_and_filesystem_ids_match"
)
LINUX_MOUNTINFO_SOURCE_PATH = "/proc/self/mountinfo"
LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH = "/proc/thread-self/status"
TEMPORARY_DIRECTORY_ENVIRONMENT_VARIABLE_NAMES = ("TMPDIR", "TEMP", "TMP")
DEFAULT_PROC_FILESYSTEM_EXCLUSION_PATH = "/proc"
HOME_DIRECTORY_CANDIDATE_ACCEPTED_FOR_DEFAULT_EXCLUSION = (
    "accepted_for_default_scan_exclusion"
)
HOME_DIRECTORY_CANDIDATE_REJECTED_AS_FILESYSTEM_ROOT = (
    "rejected_because_candidate_is_filesystem_root"
)

FILESYSTEM_TYPES_WITH_UNMODELED_MUTATION_SEMANTICS: frozenset[str] = frozenset(
    {
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
        "fuse",
        "fuseblk",
        "autofs",
        "overlay",
        "nfs",
        "nfs4",
        "cifs",
        "smb3",
        "9p",
        "ceph",
        "afs",
        "virtiofs",
        "devpts",
        "mqueue",
        "efivarfs",
        "binfmt_misc",
        "rpc_pipefs",
        "selinuxfs",
        "smackfs",
        "resctrl",
        "nsfs",
    }
)
FILESYSTEM_TYPE_PREFIXES_WITH_UNMODELED_MUTATION_SEMANTICS = ("fuse.",)

OrderedValue = TypeVar("OrderedValue", bound=Hashable)


def current_utc_timestamp() -> str:
    """Return an RFC 3339 UTC timestamp naming when an observation became true."""
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


@dataclass(frozen=True)
class EvidenceReason:
    """One structured reason supporting or limiting a model inference."""

    reason_code: str
    evidence_source: str | None = None
    detail: str | None = None
    operating_system_errno: int | None = None
    operating_system_message: str | None = None

    def as_serializable_dictionary(self) -> dict[str, object]:
        serialized_reason: dict[str, object] = {"reason_code": self.reason_code}
        if self.evidence_source is not None:
            serialized_reason["evidence_source"] = self.evidence_source
        if self.detail is not None:
            serialized_reason["detail"] = self.detail
        if self.operating_system_errno is not None:
            serialized_reason["operating_system_errno"] = self.operating_system_errno
        if self.operating_system_message is not None:
            serialized_reason["operating_system_message"] = (
                self.operating_system_message
            )
        return serialized_reason


ROUTINE_UNCERTAINTY_REASON_CODES = frozenset(
    {
        # A whole-filesystem scan normally reaches directories that this
        # credential cannot enumerate.  That is expected evidence about the
        # credential, not an abnormal failure of the audit machinery.
        "at_least_one_descendant_has_uncertain_delete_inference",
        # These branches deliberately avoid executing a preparatory chmod or
        # FS_IOC_SETFLAGS operation.  They are useful in a full diagnostic
        # report but are too conservative to pollute the permission-finding
        # view used by default.
        "parent_directory_access_may_be_changeable_by_chmod",
        "target_write_access_may_be_changeable_by_chmod",
        "directory_access_may_be_changeable_by_chmod",
        "special_file_write_access_may_be_changeable_by_chmod",
        "target_immutable_attribute_may_be_clearable_before_deletion",
        "target_append_only_attribute_may_be_clearable_before_deletion",
        "parent_directory_immutable_attribute_may_be_clearable_before_deletion",
        "parent_directory_append_only_attribute_may_be_clearable_before_deletion",
        "target_immutable_attribute_may_be_clearable_before_content_mutation",
        "target_append_only_attribute_may_be_clearable_before_overwrite",
        "directory_immutable_attribute_may_be_clearable_before_creation",
        "target_immutable_attribute_may_be_clearable_before_special_file_write",
    }
)


def evidence_reason_uncertainty_grade(reason: EvidenceReason) -> str | None:
    """Grade a reason only when it represents uncertainty rather than fact."""
    if reason.reason_code in ROUTINE_UNCERTAINTY_REASON_CODES:
        return UNCERTAINTY_GRADE_ROUTINE
    if reason.reason_code in {
        "cannot_list_directory",
        "cannot_continue_directory_listing",
    } and reason.operating_system_errno in {errno.EACCES, errno.EPERM}:
        return UNCERTAINTY_GRADE_ROUTINE
    if (
        reason.reason_code
        in {
            "path_disappeared_during_directory_scan",
            "cannot_capture_directory_entry",
        }
        and reason.operating_system_errno == errno.ENOENT
    ):
        return UNCERTAINTY_GRADE_ROUTINE

    material_uncertainty_fragments = (
        "cannot_",
        "_changed_",
        "_changed",
        "_failed",
        "_failure",
        "_unavailable",
        "_unobserved",
        "_unknown",
        "_uncertain",
        "_unrecognized",
        "unmodeled",
        "not_modeled",
        "may_reflect",
    )
    if any(
        fragment in reason.reason_code for fragment in material_uncertainty_fragments
    ):
        return UNCERTAINTY_GRADE_MATERIAL
    return None


def uncertainty_grade_for_reason_sequence(
    reasons: Iterable[EvidenceReason],
) -> str:
    """Return the highest grade; unclassified uncertain evidence is material."""
    observed_grades = {
        grade
        for reason in reasons
        if (grade := evidence_reason_uncertainty_grade(reason)) is not None
    }
    if UNCERTAINTY_GRADE_MATERIAL in observed_grades:
        return UNCERTAINTY_GRADE_MATERIAL
    if UNCERTAINTY_GRADE_ROUTINE in observed_grades:
        return UNCERTAINTY_GRADE_ROUTINE
    return UNCERTAINTY_GRADE_MATERIAL


CAPABILITY_MODEL_BOUNDARY_REASONS: tuple[EvidenceReason, ...] = (
    EvidenceReason(
        "mutation_syscalls_are_not_executed",
        evidence_source=CAPABILITY_MODEL_ID,
        detail=(
            "verdicts describe observed permission evidence rather than "
            "proof that a future mutation will succeed"
        ),
    ),
    EvidenceReason(
        "filesystem_state_can_change_after_each_observation",
        evidence_source=CAPABILITY_MODEL_ID,
        detail="path, credential, mount, and policy observations are not atomic",
    ),
    EvidenceReason(
        "operation_specific_mac_lsm_and_seccomp_decisions_are_not_fully_modeled",
        evidence_source=CAPABILITY_MODEL_ID,
    ),
    EvidenceReason(
        "idmapped_mount_ownership_translation_is_not_modeled",
        evidence_source=CAPABILITY_MODEL_ID,
        detail=(
            "kernel access queries and stat metadata use the mount-translated "
            "view, but mountinfo does not expose the attached ID mapping and "
            "effective capability namespace scope is not proven"
        ),
    ),
    EvidenceReason(
        "resource_limits_quotas_leases_and_capacity_are_not_modeled",
        evidence_source=CAPABILITY_MODEL_ID,
    ),
    EvidenceReason(
        "preparatory_discretionary_metadata_mutations_are_not_fully_modeled",
        evidence_source=CAPABILITY_MODEL_ID,
        detail=(
            "owner or CAP_FOWNER authority that might permit a preceding chmod "
            "turns a current access denial into uncertainty, not permission"
        ),
    ),
    EvidenceReason(
        "remote_filesystem_server_and_special_endpoint_behavior_is_not_modeled",
        evidence_source=CAPABILITY_MODEL_ID,
    ),
)


def operating_system_error_reason(
    reason_code: str,
    error: OSError,
    *,
    evidence_source: str,
) -> EvidenceReason:
    return EvidenceReason(
        reason_code=reason_code,
        evidence_source=evidence_source,
        operating_system_errno=error.errno,
        operating_system_message=error.strerror or str(error),
    )


def deduplicate_preserving_first_occurrence(
    values: Iterable[OrderedValue],
) -> list[OrderedValue]:
    observed_values: set[OrderedValue] = set()
    ordered_unique_values: list[OrderedValue] = []
    for value in values:
        if value in observed_values:
            continue
        observed_values.add(value)
        ordered_unique_values.append(value)
    return ordered_unique_values


@dataclass(frozen=True)
class FilesystemObjectIdentity:
    """Linux st_dev/st_ino identity observed at one instant."""

    device_number: int
    inode_number: int

    @classmethod
    def from_stat_result(
        cls,
        filesystem_metadata: os.stat_result,
    ) -> FilesystemObjectIdentity:
        return cls(
            device_number=filesystem_metadata.st_dev,
            inode_number=filesystem_metadata.st_ino,
        )


@dataclass(frozen=True)
class ObservedLinuxFilesystemObjectMetadata:
    """Permission-relevant values copied from one Linux stat result."""

    device_number: int
    inode_number: int
    file_type_and_permission_mode_octal: str
    permission_bits_octal: str
    owner_user_id: int
    owner_group_id: int
    hard_link_count: int
    size_bytes: int
    access_time_nanoseconds: int
    content_modification_time_nanoseconds: int
    inode_change_time_nanoseconds: int

    @classmethod
    def from_stat_result(
        cls,
        filesystem_metadata: os.stat_result,
    ) -> ObservedLinuxFilesystemObjectMetadata:
        return cls(
            device_number=filesystem_metadata.st_dev,
            inode_number=filesystem_metadata.st_ino,
            file_type_and_permission_mode_octal=f"0o{filesystem_metadata.st_mode:o}",
            permission_bits_octal=f"0o{stat.S_IMODE(filesystem_metadata.st_mode):04o}",
            owner_user_id=filesystem_metadata.st_uid,
            owner_group_id=filesystem_metadata.st_gid,
            hard_link_count=filesystem_metadata.st_nlink,
            size_bytes=filesystem_metadata.st_size,
            access_time_nanoseconds=filesystem_metadata.st_atime_ns,
            content_modification_time_nanoseconds=filesystem_metadata.st_mtime_ns,
            inode_change_time_nanoseconds=filesystem_metadata.st_ctime_ns,
        )

    def as_serializable_dictionary(self) -> dict[str, int | str]:
        return {
            "device_number": self.device_number,
            "inode_number": self.inode_number,
            "file_type_and_permission_mode_octal": (
                self.file_type_and_permission_mode_octal
            ),
            "permission_bits_octal": self.permission_bits_octal,
            "owner_user_id": self.owner_user_id,
            "owner_group_id": self.owner_group_id,
            "hard_link_count": self.hard_link_count,
            "size_bytes": self.size_bytes,
            "access_time_nanoseconds": self.access_time_nanoseconds,
            "content_modification_time_nanoseconds": (
                self.content_modification_time_nanoseconds
            ),
            "inode_change_time_nanoseconds": self.inode_change_time_nanoseconds,
        }


# Linux UAPI names are retained here because their kernel provenance is more
# informative than locally invented synonyms.
AT_FDCWD = -100
AT_SYMLINK_NOFOLLOW = 0x100
AT_EMPTY_PATH = 0x1000
AT_EACCESS = 0x200
STATX_ALL = 0x00000FFF
STATX_ATTR_IMMUTABLE = 0x00000010
STATX_ATTR_APPEND = 0x00000020
STATX_ATTR_VERITY = 0x00100000
LINUX_VERSION_WITH_DOCUMENTED_STATX_VERITY_REPORTING = (5, 5)
LINUX_STATX_STRUCTURE_SIZE_BYTES = 256
LINUX_STATX_ATTRIBUTES_OFFSET_BYTES = 8
LINUX_STATX_ATTRIBUTES_MASK_OFFSET_BYTES = 56
RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2
RUNNING_LINUX_KERNEL_RELEASE = (
    os.uname().release if sys.platform.startswith("linux") else "unavailable"
)
RUNNING_MACHINE_ARCHITECTURE = (
    os.uname().machine.lower() if sys.platform.startswith("linux") else "unavailable"
)

# Linux syscall numbers are ABI values, not universal API constants.  Keep the
# supported map deliberately explicit so an unfamiliar ABI degrades to named
# uncertainty instead of invoking the wrong syscall.  Most newer architectures
# use asm-generic numbers; legacy architectures retain their own tables.
_LINUX_SYSCALL_NUMBERS_BY_ARCHITECTURE: Mapping[str, Mapping[str, int]] = {
    "x86_64": {"renameat2": 316, "statx": 332, "faccessat2": 439},
    "i386": {"renameat2": 353, "statx": 383, "faccessat2": 439},
    "i486": {"renameat2": 353, "statx": 383, "faccessat2": 439},
    "i586": {"renameat2": 353, "statx": 383, "faccessat2": 439},
    "i686": {"renameat2": 353, "statx": 383, "faccessat2": 439},
    "aarch64": {"renameat2": 276, "statx": 291, "faccessat2": 439},
    "arm64": {"renameat2": 276, "statx": 291, "faccessat2": 439},
    "armv7l": {"renameat2": 382, "statx": 397, "faccessat2": 439},
    "armv8l": {"renameat2": 382, "statx": 397, "faccessat2": 439},
    "riscv64": {"renameat2": 276, "statx": 291, "faccessat2": 439},
    "loongarch64": {"renameat2": 276, "statx": 291, "faccessat2": 439},
    "s390x": {"renameat2": 347, "statx": 379, "faccessat2": 439},
    "ppc64": {"renameat2": 357, "statx": 383, "faccessat2": 439},
    "ppc64le": {"renameat2": 357, "statx": 383, "faccessat2": 439},
    "sparc64": {"renameat2": 345, "statx": 360, "faccessat2": 439},
    "alpha": {"renameat2": 510, "statx": 522, "faccessat2": 549},
}
_LINUX_64_BIT_SYSCALL_ARCHITECTURES = frozenset(
    {
        "x86_64",
        "aarch64",
        "arm64",
        "riscv64",
        "loongarch64",
        "s390x",
        "ppc64",
        "ppc64le",
        "sparc64",
        "alpha",
    }
)
_LINUX_32_BIT_SYSCALL_ARCHITECTURES = frozenset(
    {"i386", "i486", "i586", "i686", "armv7l", "armv8l"}
)


class LinuxStatxStructure(ctypes.Structure):
    """
    ctypes representation of the 256-byte Linux ``struct statx`` UAPI record.

    The named prefix ends at byte 64.  This auditor reads only
    ``stx_attributes`` and ``stx_attributes_mask``; the remaining kernel record
    stays explicitly opaque.
    """

    _fields_ = [
        ("stx_mask", ctypes.c_uint),
        ("stx_blksize", ctypes.c_uint),
        ("stx_attributes", ctypes.c_ulonglong),
        ("stx_nlink", ctypes.c_uint),
        ("stx_uid", ctypes.c_uint),
        ("stx_gid", ctypes.c_uint),
        ("stx_mode", ctypes.c_ushort),
        ("stx_spare_alignment", ctypes.c_ushort),
        ("stx_ino", ctypes.c_ulonglong),
        ("stx_size", ctypes.c_ulonglong),
        ("stx_blocks", ctypes.c_ulonglong),
        ("stx_attributes_mask", ctypes.c_ulonglong),
        (
            "opaque_kernel_extension_bytes",
            ctypes.c_ubyte * (LINUX_STATX_STRUCTURE_SIZE_BYTES - 64),
        ),
    ]


_LINUX_C_LIBRARY = (
    ctypes.CDLL(None, use_errno=True) if sys.platform.startswith("linux") else None
)
_LINUX_STATX_FUNCTION = (
    None if _LINUX_C_LIBRARY is None else getattr(_LINUX_C_LIBRARY, "statx", None)
)
_LINUX_RENAMEAT2_FUNCTION = (
    None if _LINUX_C_LIBRARY is None else getattr(_LINUX_C_LIBRARY, "renameat2", None)
)
_LINUX_FACCESSAT_FUNCTION = (
    None if _LINUX_C_LIBRARY is None else getattr(_LINUX_C_LIBRARY, "faccessat", None)
)
_LINUX_SYSCALL_FUNCTION = (
    None if _LINUX_C_LIBRARY is None else getattr(_LINUX_C_LIBRARY, "syscall", None)
)
if _LINUX_STATX_FUNCTION is not None:
    _LINUX_STATX_FUNCTION.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.POINTER(LinuxStatxStructure),
    ]
    _LINUX_STATX_FUNCTION.restype = ctypes.c_int
if _LINUX_RENAMEAT2_FUNCTION is not None:
    _LINUX_RENAMEAT2_FUNCTION.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    _LINUX_RENAMEAT2_FUNCTION.restype = ctypes.c_int
if _LINUX_FACCESSAT_FUNCTION is not None:
    _LINUX_FACCESSAT_FUNCTION.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_int,
    ]
    _LINUX_FACCESSAT_FUNCTION.restype = ctypes.c_int
if _LINUX_SYSCALL_FUNCTION is not None:
    # syscall(2) is variadic.  Setting argtypes would incorrectly impose one
    # signature on statx, renameat2, and faccessat2; every call below instead
    # supplies explicitly sized ctypes arguments.
    _LINUX_SYSCALL_FUNCTION.restype = ctypes.c_long


def linux_syscall_number(syscall_name: str) -> int | None:
    """Return a verified number for this process ABI, never a guessed value."""
    process_pointer_size = ctypes.sizeof(ctypes.c_void_p)
    if (
        RUNNING_MACHINE_ARCHITECTURE in _LINUX_64_BIT_SYSCALL_ARCHITECTURES
        and process_pointer_size != 8
    ):
        # uname reports the kernel architecture.  A compat or x32 process can
        # use a different syscall table on that same kernel.
        return None
    if (
        RUNNING_MACHINE_ARCHITECTURE in _LINUX_32_BIT_SYSCALL_ARCHITECTURES
        and process_pointer_size != 4
    ):
        return None
    architecture_numbers = _LINUX_SYSCALL_NUMBERS_BY_ARCHITECTURE.get(
        RUNNING_MACHINE_ARCHITECTURE
    )
    if architecture_numbers is None:
        return None
    return architecture_numbers.get(syscall_name)


def call_linux_statx(
    directory_file_descriptor: int,
    encoded_path: bytes,
    lookup_flags: int,
    requested_mask: int,
    statx_record: LinuxStatxStructure,
) -> int:
    """Call libc statx when present, otherwise its verified raw syscall."""
    if _LINUX_STATX_FUNCTION is not None:
        return int(
            _LINUX_STATX_FUNCTION(
                directory_file_descriptor,
                ctypes.c_char_p(encoded_path),
                lookup_flags,
                requested_mask,
                ctypes.byref(statx_record),
            )
        )

    syscall_number = linux_syscall_number("statx")
    if _LINUX_SYSCALL_FUNCTION is None or syscall_number is None:
        ctypes.set_errno(errno.ENOSYS)
        return -1
    return int(
        _LINUX_SYSCALL_FUNCTION(
            ctypes.c_long(syscall_number),
            ctypes.c_int(directory_file_descriptor),
            ctypes.c_char_p(encoded_path),
            ctypes.c_int(lookup_flags),
            ctypes.c_uint(requested_mask),
            ctypes.byref(statx_record),
        )
    )


def call_linux_faccessat2(
    directory_file_descriptor: int,
    encoded_path: bytes,
    requested_access_mode: int,
    lookup_flags: int,
) -> int:
    """Invoke faccessat2 through a verified raw-syscall ABI mapping."""
    syscall_number = linux_syscall_number("faccessat2")
    if _LINUX_SYSCALL_FUNCTION is None or syscall_number is None:
        ctypes.set_errno(errno.ENOSYS)
        return -1
    return int(
        _LINUX_SYSCALL_FUNCTION(
            ctypes.c_long(syscall_number),
            ctypes.c_int(directory_file_descriptor),
            ctypes.c_char_p(encoded_path),
            ctypes.c_int(requested_access_mode),
            ctypes.c_int(lookup_flags),
        )
    )


def rename_linux_directory_entry_with_flags(
    source_directory_file_descriptor: int,
    source_entry_name: str,
    destination_directory_file_descriptor: int,
    destination_entry_name: str,
    rename_flags: int,
) -> None:
    """Conditionally rename entries relative to already-open directories."""
    encoded_source_entry_name = os.fsencode(source_entry_name)
    encoded_destination_entry_name = os.fsencode(destination_entry_name)
    if b"\0" in encoded_source_entry_name or b"\0" in encoded_destination_entry_name:
        raise ValueError("rename entry names must not contain embedded NUL bytes")

    ctypes.set_errno(0)
    if _LINUX_RENAMEAT2_FUNCTION is not None:
        rename_return_code = _LINUX_RENAMEAT2_FUNCTION(
            source_directory_file_descriptor,
            ctypes.c_char_p(encoded_source_entry_name),
            destination_directory_file_descriptor,
            ctypes.c_char_p(encoded_destination_entry_name),
            rename_flags,
        )
    else:
        syscall_number = linux_syscall_number("renameat2")
        if _LINUX_SYSCALL_FUNCTION is None or syscall_number is None:
            raise OSError(
                errno.ENOSYS,
                "Linux renameat2 is unavailable for this process ABI",
            )
        rename_return_code = _LINUX_SYSCALL_FUNCTION(
            ctypes.c_long(syscall_number),
            ctypes.c_int(source_directory_file_descriptor),
            ctypes.c_char_p(encoded_source_entry_name),
            ctypes.c_int(destination_directory_file_descriptor),
            ctypes.c_char_p(encoded_destination_entry_name),
            ctypes.c_uint(rename_flags),
        )
    if rename_return_code != 0:
        rename_errno = ctypes.get_errno()
        raise OSError(
            rename_errno,
            os.strerror(rename_errno),
            destination_entry_name,
        )


@dataclass(frozen=True)
class LinuxInodeAttributeEvidence:
    """Mutation-constraining inode attributes returned by Linux statx."""

    immutable_attribute_is_set: bool | None
    append_only_attribute_is_set: bool | None
    verity_attribute_is_set: bool | None
    verity_uncertainty_reason: EvidenceReason | None = None
    uncertainty_reasons: tuple[EvidenceReason, ...] = ()
    observed_at_utc: str = field(default_factory=current_utc_timestamp)

    @property
    def evidence_is_uncertain(self) -> bool:
        return bool(self.uncertainty_reasons)


def running_kernel_version_has_documented_statx_verity_reporting() -> bool | None:
    """Interpret the running kernel's major/minor release for statx verity."""
    release_components = RUNNING_LINUX_KERNEL_RELEASE.split(".")
    if len(release_components) < 2:
        return None
    try:
        running_kernel_major_minor_version = (
            int(release_components[0], 10),
            int(release_components[1], 10),
        )
    except ValueError:
        return None
    return (
        running_kernel_major_minor_version
        >= LINUX_VERSION_WITH_DOCUMENTED_STATX_VERITY_REPORTING
    )


def observe_linux_inode_attributes(
    path: str,
    *,
    follow_final_symbolic_link: bool,
    file_descriptor: int | None = None,
) -> LinuxInodeAttributeEvidence:
    """Observe mutation attributes by stable descriptor when one is available."""
    observed_statx_structure_size = ctypes.sizeof(LinuxStatxStructure)
    observed_attributes_offset = LinuxStatxStructure.stx_attributes.offset
    observed_attributes_mask_offset = LinuxStatxStructure.stx_attributes_mask.offset
    if (
        observed_statx_structure_size != LINUX_STATX_STRUCTURE_SIZE_BYTES
        or observed_attributes_offset != LINUX_STATX_ATTRIBUTES_OFFSET_BYTES
        or observed_attributes_mask_offset != LINUX_STATX_ATTRIBUTES_MASK_OFFSET_BYTES
    ):
        return LinuxInodeAttributeEvidence(
            immutable_attribute_is_set=None,
            append_only_attribute_is_set=None,
            verity_attribute_is_set=None,
            uncertainty_reasons=(
                EvidenceReason(
                    "ctypes_linux_statx_structure_has_unexpected_layout",
                    evidence_source="ctypes.sizeof and ctypes field offsets",
                    detail=(
                        f"expected_size_bytes={LINUX_STATX_STRUCTURE_SIZE_BYTES}; "
                        f"observed_size_bytes={observed_statx_structure_size}; "
                        "expected_stx_attributes_offset_bytes="
                        f"{LINUX_STATX_ATTRIBUTES_OFFSET_BYTES}; "
                        "observed_stx_attributes_offset_bytes="
                        f"{observed_attributes_offset}; "
                        "expected_stx_attributes_mask_offset_bytes="
                        f"{LINUX_STATX_ATTRIBUTES_MASK_OFFSET_BYTES}; "
                        "observed_stx_attributes_mask_offset_bytes="
                        f"{observed_attributes_mask_offset}"
                    ),
                ),
            ),
        )
    try:
        filesystem_encoded_path = (
            b"" if file_descriptor is not None else os.fsencode(path)
        )
    except (TypeError, ValueError) as error:
        return LinuxInodeAttributeEvidence(
            immutable_attribute_is_set=None,
            append_only_attribute_is_set=None,
            verity_attribute_is_set=None,
            uncertainty_reasons=(
                EvidenceReason(
                    "path_cannot_be_encoded_for_linux_statx",
                    evidence_source="os.fsencode",
                    detail=str(error),
                ),
            ),
        )

    if b"\0" in filesystem_encoded_path:
        return LinuxInodeAttributeEvidence(
            immutable_attribute_is_set=None,
            append_only_attribute_is_set=None,
            verity_attribute_is_set=None,
            uncertainty_reasons=(
                EvidenceReason(
                    "path_contains_embedded_nul",
                    evidence_source="os.fsencode",
                ),
            ),
        )

    statx_record = LinuxStatxStructure()
    statx_lookup_flags = (
        AT_EMPTY_PATH
        if file_descriptor is not None
        else (0 if follow_final_symbolic_link else AT_SYMLINK_NOFOLLOW)
    )
    statx_directory_file_descriptor = (
        file_descriptor if file_descriptor is not None else AT_FDCWD
    )
    ctypes.set_errno(0)
    statx_return_code = call_linux_statx(
        statx_directory_file_descriptor,
        filesystem_encoded_path,
        statx_lookup_flags,
        STATX_ALL,
        statx_record,
    )
    if statx_return_code != 0:
        statx_errno = ctypes.get_errno()
        return LinuxInodeAttributeEvidence(
            immutable_attribute_is_set=None,
            append_only_attribute_is_set=None,
            verity_attribute_is_set=None,
            uncertainty_reasons=(
                EvidenceReason(
                    (
                        "linux_statx_unavailable_for_process_abi"
                        if statx_errno == errno.ENOSYS
                        else "linux_statx_failed"
                    ),
                    evidence_source="statx(2)",
                    operating_system_errno=statx_errno,
                    operating_system_message=os.strerror(statx_errno),
                ),
            ),
        )

    uncertainty_reasons: list[EvidenceReason] = []
    if statx_record.stx_attributes_mask & STATX_ATTR_IMMUTABLE:
        immutable_attribute_is_set: bool | None = bool(
            statx_record.stx_attributes & STATX_ATTR_IMMUTABLE
        )
    else:
        # stx_attributes_mask names attributes supported by both the VFS and
        # filesystem.  An unsupported immutable bit cannot be set and is not an
        # unknown state.
        immutable_attribute_is_set = False

    if statx_record.stx_attributes_mask & STATX_ATTR_APPEND:
        append_only_attribute_is_set: bool | None = bool(
            statx_record.stx_attributes & STATX_ATTR_APPEND
        )
    else:
        append_only_attribute_is_set = False

    if statx_record.stx_attributes_mask & STATX_ATTR_VERITY:
        verity_attribute_is_set = bool(statx_record.stx_attributes & STATX_ATTR_VERITY)
        verity_uncertainty_reason = None
    else:
        kernel_has_documented_verity_reporting = (
            running_kernel_version_has_documented_statx_verity_reporting()
        )
        if kernel_has_documented_verity_reporting is True:
            verity_attribute_is_set = False
            verity_uncertainty_reason = None
        else:
            verity_attribute_is_set = None
            verity_uncertainty_reason = EvidenceReason(
                (
                    "running_kernel_predates_documented_statx_verity_reporting"
                    if kernel_has_documented_verity_reporting is False
                    else "running_kernel_release_cannot_be_interpreted_for_statx_verity"
                ),
                evidence_source="os.uname().release",
                detail=RUNNING_LINUX_KERNEL_RELEASE,
            )

    return LinuxInodeAttributeEvidence(
        immutable_attribute_is_set=immutable_attribute_is_set,
        append_only_attribute_is_set=append_only_attribute_is_set,
        verity_attribute_is_set=verity_attribute_is_set,
        verity_uncertainty_reason=verity_uncertainty_reason,
        uncertainty_reasons=tuple(uncertainty_reasons),
    )


@dataclass(frozen=True)
class EffectiveLinuxCapabilityMaskEvidence:
    """Effective capability bitmask read from the calling thread's status."""

    capability_mask: int | None
    uncertainty_reason: EvidenceReason | None
    source_path: str = LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH
    observed_at_utc: str = field(default_factory=current_utc_timestamp)

    def capability_presence(self, capability_number: int) -> bool | None:
        if self.capability_mask is None:
            return None
        return bool(self.capability_mask & (1 << capability_number))

    @property
    def capability_mask_hexadecimal(self) -> str | None:
        if self.capability_mask is None:
            return None
        return f"0x{self.capability_mask:x}"


def observe_effective_linux_capability_mask() -> EffectiveLinuxCapabilityMaskEvidence:
    try:
        with open(
            LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH,
            encoding="ascii",
            errors="strict",
        ) as process_status_stream:
            for process_status_line in process_status_stream:
                if not process_status_line.startswith("CapEff:"):
                    continue
                capability_fields = process_status_line.split()
                if len(capability_fields) != 2:
                    return EffectiveLinuxCapabilityMaskEvidence(
                        capability_mask=None,
                        uncertainty_reason=EvidenceReason(
                            "effective_capability_line_has_unexpected_shape",
                            evidence_source=LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH,
                            detail=process_status_line.rstrip("\n"),
                        ),
                    )
                try:
                    capability_mask = int(capability_fields[1], 16)
                except ValueError as error:
                    return EffectiveLinuxCapabilityMaskEvidence(
                        capability_mask=None,
                        uncertainty_reason=EvidenceReason(
                            "effective_capability_mask_is_not_hexadecimal",
                            evidence_source=LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH,
                            detail=str(error),
                        ),
                    )
                return EffectiveLinuxCapabilityMaskEvidence(
                    capability_mask=capability_mask,
                    uncertainty_reason=None,
                )
    except (OSError, UnicodeError) as error:
        if isinstance(error, OSError):
            uncertainty_reason = operating_system_error_reason(
                "cannot_read_effective_linux_capabilities",
                error,
                evidence_source=LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH,
            )
        else:
            uncertainty_reason = EvidenceReason(
                "effective_capability_source_is_not_ascii",
                evidence_source=LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH,
                detail=str(error),
            )
        return EffectiveLinuxCapabilityMaskEvidence(
            capability_mask=None,
            uncertainty_reason=uncertainty_reason,
        )

    return EffectiveLinuxCapabilityMaskEvidence(
        capability_mask=None,
        uncertainty_reason=EvidenceReason(
            "effective_capability_line_is_missing",
            evidence_source=LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH,
        ),
    )


@dataclass(frozen=True)
class LinuxFilesystemIdentifierEvidence:
    """Filesystem UID/GID read from the calling thread's proc status."""

    filesystem_user_id: int | None
    filesystem_group_id: int | None
    uncertainty_reason: EvidenceReason | None
    source_path: str = LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH
    observed_at_utc: str = field(default_factory=current_utc_timestamp)


def observe_linux_filesystem_identifiers(
    *,
    expected_real_effective_saved_user_ids: tuple[int, int, int],
    expected_real_effective_saved_group_ids: tuple[int, int, int],
) -> LinuxFilesystemIdentifierEvidence:
    observation_timestamp = current_utc_timestamp()
    status_identifier_fields: dict[str, tuple[int, int, int, int]] = {}
    try:
        with open(
            LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH,
            encoding="ascii",
            errors="strict",
        ) as process_status_stream:
            for process_status_line in process_status_stream:
                field_name, separator, field_value = process_status_line.partition(":")
                if not separator or field_name not in {"Uid", "Gid"}:
                    continue
                identifier_text_fields = field_value.split()
                if len(identifier_text_fields) != 4:
                    raise ValueError(
                        f"{field_name} status field expected 4 identifiers; "
                        f"observed {len(identifier_text_fields)}"
                    )
                status_identifier_fields[field_name] = tuple(
                    int(identifier_text, 10)
                    for identifier_text in identifier_text_fields
                )
    except (OSError, UnicodeError, ValueError) as error:
        if isinstance(error, OSError):
            uncertainty_reason = operating_system_error_reason(
                "cannot_read_linux_filesystem_identifiers",
                error,
                evidence_source=LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH,
            )
        else:
            uncertainty_reason = EvidenceReason(
                "cannot_parse_linux_filesystem_identifiers",
                evidence_source=LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH,
                detail=str(error),
            )
        return LinuxFilesystemIdentifierEvidence(
            filesystem_user_id=None,
            filesystem_group_id=None,
            uncertainty_reason=uncertainty_reason,
            observed_at_utc=observation_timestamp,
        )

    reported_user_ids = status_identifier_fields.get("Uid")
    reported_group_ids = status_identifier_fields.get("Gid")
    if reported_user_ids is None or reported_group_ids is None:
        return LinuxFilesystemIdentifierEvidence(
            filesystem_user_id=None,
            filesystem_group_id=None,
            uncertainty_reason=EvidenceReason(
                "linux_filesystem_identifier_fields_are_missing",
                evidence_source=LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH,
            ),
            observed_at_utc=observation_timestamp,
        )

    proc_status_matches_direct_system_calls = (
        reported_user_ids[:3] == expected_real_effective_saved_user_ids
        and reported_group_ids[:3] == expected_real_effective_saved_group_ids
    )
    return LinuxFilesystemIdentifierEvidence(
        filesystem_user_id=reported_user_ids[3],
        filesystem_group_id=reported_group_ids[3],
        uncertainty_reason=(
            None
            if proc_status_matches_direct_system_calls
            else EvidenceReason(
                "proc_status_identifiers_disagree_with_direct_system_calls",
                evidence_source=(
                    f"{LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH} and "
                    "os.getresuid/os.getresgid"
                ),
                detail=(
                    f"proc_user_ids={reported_user_ids}; "
                    f"system_call_user_ids="
                    f"{expected_real_effective_saved_user_ids}; "
                    f"proc_group_ids={reported_group_ids}; "
                    f"system_call_group_ids="
                    f"{expected_real_effective_saved_group_ids}"
                ),
            )
        ),
        observed_at_utc=observation_timestamp,
    )


@dataclass(frozen=True)
class LinuxProcessCredentialEvidence:
    """Process identities used by access and sticky-directory inference."""

    access_identity_model: str
    real_user_id: int
    effective_user_id: int
    saved_user_id: int
    real_group_id: int
    effective_group_id: int
    saved_group_id: int
    supplementary_group_ids: tuple[int, ...]
    effective_capabilities: EffectiveLinuxCapabilityMaskEvidence
    filesystem_identifiers: LinuxFilesystemIdentifierEvidence
    observed_at_utc: str = field(default_factory=current_utc_timestamp)


def observe_linux_process_credentials() -> LinuxProcessCredentialEvidence:
    real_user_id, effective_user_id, saved_user_id = os.getresuid()
    real_group_id, effective_group_id, saved_group_id = os.getresgid()
    filesystem_identifiers = observe_linux_filesystem_identifiers(
        expected_real_effective_saved_user_ids=(
            real_user_id,
            effective_user_id,
            saved_user_id,
        ),
        expected_real_effective_saved_group_ids=(
            real_group_id,
            effective_group_id,
            saved_group_id,
        ),
    )
    return LinuxProcessCredentialEvidence(
        access_identity_model=(
            ACCESS_IDENTITY_MODEL_FILESYSTEM_AUTHORITY_WHEN_IDS_MATCH
        ),
        real_user_id=real_user_id,
        effective_user_id=effective_user_id,
        saved_user_id=saved_user_id,
        real_group_id=real_group_id,
        effective_group_id=effective_group_id,
        saved_group_id=saved_group_id,
        supplementary_group_ids=tuple(sorted(os.getgroups())),
        effective_capabilities=observe_effective_linux_capability_mask(),
        filesystem_identifiers=filesystem_identifiers,
    )


@dataclass(frozen=True)
class KernelPathAccessEvidence:
    """Kernel response to one access-mode question."""

    access_is_allowed: bool | None
    uncertainty_reason: EvidenceReason | None
    operating_system_errno: int | None = None
    evidence_source: str = "faccessat2(2)"


def ask_kernel_about_path_access(
    path: str,
    requested_access_mode: int,
    *,
    process_credentials: LinuxProcessCredentialEvidence,
    file_descriptor: int | None = None,
) -> KernelPathAccessEvidence:
    filesystem_identifiers = process_credentials.filesystem_identifiers
    if filesystem_identifiers.uncertainty_reason is not None:
        return KernelPathAccessEvidence(
            access_is_allowed=None,
            uncertainty_reason=filesystem_identifiers.uncertainty_reason,
        )
    if (
        filesystem_identifiers.filesystem_user_id
        != process_credentials.effective_user_id
        or filesystem_identifiers.filesystem_group_id
        != process_credentials.effective_group_id
    ):
        return KernelPathAccessEvidence(
            access_is_allowed=None,
            uncertainty_reason=EvidenceReason(
                "effective_id_access_query_cannot_model_distinct_filesystem_ids",
                evidence_source=(
                    f"{LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH} and "
                    "faccessat2(AT_EACCESS)"
                ),
                detail=(
                    f"effective_user_id={process_credentials.effective_user_id}; "
                    f"filesystem_user_id="
                    f"{filesystem_identifiers.filesystem_user_id}; "
                    f"effective_group_id={process_credentials.effective_group_id}; "
                    f"filesystem_group_id="
                    f"{filesystem_identifiers.filesystem_group_id}"
                ),
            ),
        )

    try:
        encoded_path = b"" if file_descriptor is not None else os.fsencode(path)
    except (TypeError, ValueError) as error:
        return KernelPathAccessEvidence(
            access_is_allowed=None,
            uncertainty_reason=EvidenceReason(
                "path_cannot_be_encoded_for_faccessat2",
                evidence_source="os.fsencode",
                detail=str(error),
            ),
        )
    if b"\0" in encoded_path:
        return KernelPathAccessEvidence(
            access_is_allowed=None,
            uncertainty_reason=EvidenceReason(
                "path_contains_embedded_nul",
                evidence_source="os.fsencode",
            ),
        )

    lookup_flags = AT_EACCESS
    directory_file_descriptor = AT_FDCWD
    if file_descriptor is not None:
        lookup_flags |= AT_EMPTY_PATH
        directory_file_descriptor = file_descriptor
    ctypes.set_errno(0)
    access_return_code = call_linux_faccessat2(
        directory_file_descriptor,
        encoded_path,
        requested_access_mode,
        lookup_flags,
    )
    access_evidence_source = "faccessat2(2)"
    access_errno = 0 if access_return_code == 0 else ctypes.get_errno()
    matching_real_and_effective_ids = (
        process_credentials.real_user_id == process_credentials.effective_user_id
        and process_credentials.real_group_id == process_credentials.effective_group_id
    )
    fallback_access_and_at_eaccess_semantics_are_equivalent = (
        matching_real_and_effective_ids
        and process_credentials.effective_user_id != 0
        and process_credentials.effective_capabilities.capability_mask == 0
        and process_credentials.effective_capabilities.uncertainty_reason is None
    )
    if (
        access_return_code != 0
        and access_errno == errno.ENOSYS
        and fallback_access_and_at_eaccess_semantics_are_equivalent
        and _LINUX_FACCESSAT_FUNCTION is not None
    ):
        fallback_encoded_path = (
            os.fsencode(proc_path_for_file_descriptor(file_descriptor))
            if file_descriptor is not None
            else encoded_path
        )
        ctypes.set_errno(0)
        access_return_code = _LINUX_FACCESSAT_FUNCTION(
            AT_FDCWD,
            ctypes.c_char_p(fallback_encoded_path),
            requested_access_mode,
            0,
        )
        access_errno = 0 if access_return_code == 0 else ctypes.get_errno()
        access_evidence_source = (
            "faccessat(2) with matching real/effective/filesystem IDs, "
            "non-root identity, and empty effective capability mask"
        )
    if access_return_code == 0:
        return KernelPathAccessEvidence(
            access_is_allowed=True,
            uncertainty_reason=None,
            evidence_source=access_evidence_source,
        )

    if access_errno in {errno.EACCES, errno.EPERM}:
        return KernelPathAccessEvidence(
            access_is_allowed=False,
            uncertainty_reason=None,
            operating_system_errno=access_errno,
            evidence_source=access_evidence_source,
        )

    if access_errno == errno.ENOSYS:
        reason_code = (
            "linux_faccessat2_unavailable_and_faccessat_semantics_are_not_equivalent"
            if _LINUX_FACCESSAT_FUNCTION is not None
            and not fallback_access_and_at_eaccess_semantics_are_equivalent
            else "linux_faccessat2_unavailable_for_process_abi_or_kernel"
        )
    else:
        reason_code = (
            "access_check_observed_read_only_filesystem"
            if access_errno == errno.EROFS
            else "effective_id_access_check_failed"
        )
    return KernelPathAccessEvidence(
        access_is_allowed=None,
        uncertainty_reason=EvidenceReason(
            reason_code,
            evidence_source=access_evidence_source,
            operating_system_errno=access_errno,
            operating_system_message=os.strerror(access_errno),
        ),
        operating_system_errno=access_errno,
        evidence_source=access_evidence_source,
    )


def lexically_normalize_absolute_path(path: str) -> str:
    """
    Return an absolute normalized path without resolving symbolic links.

    Empty strings are rejected rather than silently reinterpreted as the current
    working directory. Multiple leading separators collapse to Linux's single
    filesystem root so ``//`` cannot become an empty path.
    """
    if not isinstance(path, str):
        raise TypeError(f"path must be str, received {type(path).__name__}")
    if path == "":
        raise ValueError("path must not be empty")
    if "\0" in path:
        raise ValueError("path must not contain an embedded NUL byte")
    absolute_path = os.path.abspath(path)
    linux_single_rooted_path = "/" + absolute_path.lstrip("/")
    return (
        linux_single_rooted_path
        if linux_single_rooted_path == "/"
        else linux_single_rooted_path.rstrip("/")
    )


def absolute_path_without_lexical_normalization(path: str) -> str:
    """Make a path absolute while retaining kernel-significant dot components."""
    if not isinstance(path, str):
        raise TypeError(f"path must be str, received {type(path).__name__}")
    if path == "":
        raise ValueError("path must not be empty")
    if "\0" in path:
        raise ValueError("path must not contain an embedded NUL byte")
    if path.startswith("/"):
        return "/" + path.lstrip("/")
    current_directory = os.getcwd()
    if current_directory == "/":
        return "/" + path
    return current_directory.rstrip("/") + "/" + path


@dataclass(frozen=True)
class RequestedPathComponents:
    """Final-component split that preserves the kernel's parent walk."""

    absolute_path_with_dot_components: str
    parent_path_with_dot_components: str
    final_component: str
    trailing_separator_requires_directory: bool

    @property
    def final_component_is_dot_or_dot_dot(self) -> bool:
        return self.final_component in {".", ".."}


def split_requested_path_without_normalizing(path: str) -> RequestedPathComponents:
    absolute_path = absolute_path_without_lexical_normalization(path)
    trailing_separator_requires_directory = (
        absolute_path != "/" and absolute_path.endswith("/")
    )
    path_without_trailing_separators = absolute_path.rstrip("/") or "/"
    if path_without_trailing_separators == "/":
        return RequestedPathComponents(
            absolute_path_with_dot_components=absolute_path,
            parent_path_with_dot_components="/",
            final_component=".",
            trailing_separator_requires_directory=True,
        )
    parent_path, separator, final_component = (
        path_without_trailing_separators.rpartition("/")
    )
    if not separator or not final_component:
        raise ValueError("absolute path has no final component")
    return RequestedPathComponents(
        absolute_path_with_dot_components=absolute_path,
        parent_path_with_dot_components=parent_path or "/",
        final_component=final_component,
        trailing_separator_requires_directory=trailing_separator_requires_directory,
    )


def proc_path_for_file_descriptor(file_descriptor: int) -> str:
    return f"/proc/self/fd/{file_descriptor}"


def observe_canonical_path_for_file_descriptor(
    file_descriptor: int,
    *,
    fallback_path: str,
) -> tuple[str, EvidenceReason | None]:
    """Read the kernel's resolved pathname for a captured object descriptor."""
    descriptor_link_path = proc_path_for_file_descriptor(file_descriptor)
    try:
        observed_path = os.readlink(descriptor_link_path)
        if not observed_path.startswith("/"):
            raise ValueError("descriptor link target is not absolute")
        if observed_path.endswith(" (deleted)"):
            return (
                fallback_path,
                EvidenceReason(
                    "captured_path_was_unlinked_before_display_path_observation",
                    evidence_source=descriptor_link_path,
                    detail=observed_path,
                ),
            )
        return lexically_normalize_absolute_path(observed_path), None
    except (OSError, ValueError) as error:
        if isinstance(error, OSError):
            reason = operating_system_error_reason(
                "cannot_observe_canonical_path_from_file_descriptor",
                error,
                evidence_source=descriptor_link_path,
            )
        else:
            reason = EvidenceReason(
                "cannot_observe_canonical_path_from_file_descriptor",
                evidence_source=descriptor_link_path,
                detail=str(error),
            )
        return fallback_path, reason


def observe_canonical_existing_directory(
    path: str,
    *,
    failure_reason_code: str,
    evidence_source: str,
) -> tuple[str | None, EvidenceReason | None]:
    """Resolve a directory with kernel component semantics and a stable FD."""
    requested_absolute_path = absolute_path_without_lexical_normalization(path)
    directory_file_descriptor: int | None = None
    try:
        directory_file_descriptor = os.open(
            requested_absolute_path,
            getattr(os, "O_PATH", 0o10000000)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0),
        )
        canonical_path, canonical_path_note = (
            observe_canonical_path_for_file_descriptor(
                directory_file_descriptor,
                fallback_path=requested_absolute_path,
            )
        )
        if canonical_path_note is not None:
            return None, canonical_path_note
        return canonical_path, None
    except OSError as error:
        return (
            None,
            operating_system_error_reason(
                failure_reason_code,
                error,
                evidence_source=evidence_source,
            ),
        )
    finally:
        if directory_file_descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(directory_file_descriptor)


@dataclass(frozen=True)
class StrictPathResolutionObservation:
    """Context-neutral result of one strict pathname resolution attempt."""

    resolved_path: str | None
    failure_kind: str | None = None
    operating_system_errno: int | None = None
    operating_system_message: str | None = None
    runtime_error_detail: str | None = None


def observe_strict_path_resolution(
    path: str,
    *,
    resolution_cache: dict[str, StrictPathResolutionObservation] | None = None,
) -> StrictPathResolutionObservation:
    """Observe strict resolution, optionally reusing it within one assessment."""
    if resolution_cache is not None:
        cached_observation = resolution_cache.get(path)
        if cached_observation is not None:
            return cached_observation

    try:
        observation = StrictPathResolutionObservation(
            resolved_path=strictly_resolve_path(path)
        )
    except OSError as error:
        observation = StrictPathResolutionObservation(
            resolved_path=None,
            failure_kind="operating_system_error",
            operating_system_errno=error.errno,
            operating_system_message=error.strerror or str(error),
        )
    except RuntimeError as error:
        observation = StrictPathResolutionObservation(
            resolved_path=None,
            failure_kind="runtime_error",
            runtime_error_detail=str(error),
        )

    if resolution_cache is not None:
        resolution_cache[path] = observation
    return observation


def strict_path_resolution_failure_reason(
    reason_code: str,
    observation: StrictPathResolutionObservation,
) -> EvidenceReason | None:
    """Give a shared raw resolution failure its caller-specific meaning."""
    if observation.failure_kind == "operating_system_error":
        return EvidenceReason(
            reason_code,
            evidence_source=STRICT_PATH_RESOLUTION_EVIDENCE_SOURCE,
            operating_system_errno=observation.operating_system_errno,
            operating_system_message=observation.operating_system_message,
        )
    if observation.failure_kind == "runtime_error":
        return EvidenceReason(
            reason_code,
            evidence_source=STRICT_PATH_RESOLUTION_EVIDENCE_SOURCE,
            detail=observation.runtime_error_detail,
        )
    return None


def best_effort_resolve_existing_path(
    lexically_normalized_path: str,
    *,
    resolution_cache: dict[str, StrictPathResolutionObservation] | None = None,
) -> tuple[str, EvidenceReason | None]:
    observation = observe_strict_path_resolution(
        lexically_normalized_path,
        resolution_cache=resolution_cache,
    )
    uncertainty_reason = strict_path_resolution_failure_reason(
        "cannot_resolve_path_for_mount_lookup",
        observation,
    )
    if uncertainty_reason is not None:
        return lexically_normalized_path, uncertainty_reason
    if observation.resolved_path is None:
        raise RuntimeError("strict path resolution returned no result or failure")
    return lexically_normalize_absolute_path(observation.resolved_path), None


def strictly_resolve_path(path: str) -> str:
    """Resolve one existing path without constructing an intermediate Path."""
    if not _OS_PATH_REALPATH_SUPPORTS_STRICT:
        return str(Path(path).resolve(strict=True))

    try:
        return os.path.realpath(path, strict=True)
    except OSError as error:
        # pathlib.Path.resolve translates ELOOP into RuntimeError.  Preserve
        # that established evidence shape while avoiding Path construction on
        # runtimes whose realpath already supports strict resolution.
        if error.errno == errno.ELOOP:
            raise RuntimeError(f"Symlink loop from {error.filename!r}") from error
        raise


def best_effort_resolve_parent_components_only(
    lexically_normalized_path: str,
    *,
    resolution_cache: dict[str, StrictPathResolutionObservation] | None = None,
) -> tuple[str, EvidenceReason | None]:
    """Resolve deletion-path parents while retaining the final entry itself."""
    parent_path = lexically_normalize_absolute_path(
        os.path.dirname(lexically_normalized_path) or "/"
    )
    final_component = os.path.basename(lexically_normalized_path)
    observation = observe_strict_path_resolution(
        parent_path,
        resolution_cache=resolution_cache,
    )
    uncertainty_reason = strict_path_resolution_failure_reason(
        "cannot_resolve_parent_for_mountpoint_lookup",
        observation,
    )
    if uncertainty_reason is not None:
        return lexically_normalized_path, uncertainty_reason
    if observation.resolved_path is None:
        raise RuntimeError("strict parent resolution returned no result or failure")
    if lexically_normalized_path == "/":
        return "/", None
    return (
        lexically_normalize_absolute_path(
            os.path.join(observation.resolved_path, final_component)
        ),
        None,
    )


def path_is_same_as_or_descendant_of(
    possible_ancestor_path: str,
    possible_descendant_path: str,
) -> bool:
    normalized_ancestor_path = lexically_normalize_absolute_path(possible_ancestor_path)
    normalized_descendant_path = lexically_normalize_absolute_path(
        possible_descendant_path
    )
    if normalized_ancestor_path == "/":
        return True
    return (
        normalized_descendant_path == normalized_ancestor_path
        or normalized_descendant_path.startswith(normalized_ancestor_path + "/")
    )


@dataclass(frozen=True)
class PathExclusionRule:
    """Lexical path exclusion and whether it covers descendants."""

    excluded_path: str
    includes_descendants: bool
    rule_origin: str
    classification_uncertainty_reason: EvidenceReason | None = None


def path_exclusion_rule_from_user_argument(
    unnormalized_path: str,
) -> PathExclusionRule:
    requested_path = split_requested_path_without_normalizing(unnormalized_path)
    normalized_path = requested_path.absolute_path_with_dot_components
    includes_descendants = requested_path.trailing_separator_requires_directory
    classification_uncertainty_reason: EvidenceReason | None = None
    parent_file_descriptor: int | None = None
    object_file_descriptor: int | None = None
    try:
        parent_file_descriptor = os.open(
            requested_path.parent_path_with_dot_components,
            getattr(os, "O_PATH", 0o10000000)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0),
        )
        canonical_parent_path, parent_path_note = (
            observe_canonical_path_for_file_descriptor(
                parent_file_descriptor,
                fallback_path=requested_path.parent_path_with_dot_components,
            )
        )
        object_lookup_name = requested_path.final_component
        if requested_path.trailing_separator_requires_directory:
            object_lookup_name += "/"
        object_file_descriptor = os.open(
            object_lookup_name,
            getattr(os, "O_PATH", 0o10000000)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_file_descriptor,
        )
        object_metadata = os.fstat(object_file_descriptor)
        normalized_path, object_path_note = observe_canonical_path_for_file_descriptor(
            object_file_descriptor,
            fallback_path=os.path.join(
                canonical_parent_path,
                requested_path.final_component,
            ),
        )
        includes_descendants |= stat.S_ISDIR(object_metadata.st_mode)
        classification_uncertainty_reason = object_path_note or parent_path_note
    except OSError as error:
        if parent_file_descriptor is not None:
            canonical_parent_path, _ = observe_canonical_path_for_file_descriptor(
                parent_file_descriptor,
                fallback_path=requested_path.parent_path_with_dot_components,
            )
            normalized_path = os.path.join(
                canonical_parent_path,
                requested_path.final_component,
            )
        classification_uncertainty_reason = operating_system_error_reason(
            "cannot_determine_whether_exclusion_is_directory",
            error,
            evidence_source="openat/fstat",
        )
    finally:
        if object_file_descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(object_file_descriptor)
        if parent_file_descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(parent_file_descriptor)
    return PathExclusionRule(
        excluded_path=lexically_normalize_absolute_path(normalized_path),
        includes_descendants=includes_descendants,
        rule_origin="user --exclude argument",
        classification_uncertainty_reason=(classification_uncertainty_reason),
    )


def path_matches_any_exclusion_rule(
    path: str,
    exclusion_rules: Sequence[PathExclusionRule],
) -> bool:
    normalized_path = lexically_normalize_absolute_path(path)
    for exclusion_rule in exclusion_rules:
        if exclusion_rule.includes_descendants:
            if path_is_same_as_or_descendant_of(
                exclusion_rule.excluded_path,
                normalized_path,
            ):
                return True
        elif normalized_path == exclusion_rule.excluded_path:
            return True
    return False


@dataclass(frozen=True)
class HomeDirectoryCandidateObservation:
    """Source, transformation, and disposition of one reported home path."""

    candidate_source: str
    reported_home_directory_path: str
    normalized_home_directory_path: str
    candidate_disposition: str

    def as_serializable_dictionary(self) -> dict[str, str]:
        return {
            "candidate_source": self.candidate_source,
            "reported_home_directory_path": self.reported_home_directory_path,
            "normalized_home_directory_path": self.normalized_home_directory_path,
            "candidate_disposition": self.candidate_disposition,
        }


@dataclass(frozen=True)
class HomeDirectoryDiscoveryEvidence:
    accepted_home_directory_exclusion_paths: tuple[str, ...]
    candidate_observations: tuple[HomeDirectoryCandidateObservation, ...]
    uncertainty_reasons: tuple[EvidenceReason, ...]
    observed_at_utc: str


def discover_process_related_home_directories(
    process_credentials: LinuxProcessCredentialEvidence,
) -> HomeDirectoryDiscoveryEvidence:
    candidate_sources_by_reported_path: dict[str, list[str]] = {}
    candidate_observations: list[HomeDirectoryCandidateObservation] = []
    accepted_home_directory_exclusion_paths: list[str] = []
    uncertainty_reasons: list[EvidenceReason] = []
    observation_timestamp = current_utc_timestamp()

    environment_home_directory = os.environ.get("HOME")
    if environment_home_directory:
        candidate_sources_by_reported_path.setdefault(
            environment_home_directory,
            [],
        ).append("HOME environment variable")

    process_credential_roles_by_user_id: dict[int, list[str]] = {}
    for process_credential_role, process_user_id in (
        ("real_user_id", process_credentials.real_user_id),
        ("effective_user_id", process_credentials.effective_user_id),
    ):
        process_credential_roles_by_user_id.setdefault(process_user_id, []).append(
            process_credential_role
        )

    for (
        process_user_id,
        process_credential_roles,
    ) in process_credential_roles_by_user_id.items():
        candidate_source = (
            f"pwd.getpwuid(user_id={process_user_id}; "
            f"process_credential_roles={','.join(process_credential_roles)})"
        )
        try:
            passwd_home_directory = pwd.getpwuid(process_user_id).pw_dir
        except (KeyError, OSError) as error:
            uncertainty_reasons.append(
                EvidenceReason(
                    "passwd_home_directory_lookup_failed",
                    evidence_source=candidate_source,
                    detail=str(error),
                )
            )
            continue
        candidate_sources_by_reported_path.setdefault(
            passwd_home_directory,
            [],
        ).append(candidate_source)

    invoking_sudo_user_name = os.environ.get("SUDO_USER")
    if invoking_sudo_user_name:
        candidate_source = (
            f"pwd.getpwnam(user_name_from_SUDO_USER={invoking_sudo_user_name!r})"
        )
        try:
            sudo_user_home_directory = pwd.getpwnam(invoking_sudo_user_name).pw_dir
        except (KeyError, OSError) as error:
            uncertainty_reasons.append(
                EvidenceReason(
                    "sudo_user_home_directory_lookup_failed",
                    evidence_source=candidate_source,
                    detail=str(error),
                )
            )
        else:
            candidate_sources_by_reported_path.setdefault(
                sudo_user_home_directory,
                [],
            ).append(candidate_source)

    for (
        reported_home_directory_path,
        candidate_sources,
    ) in candidate_sources_by_reported_path.items():
        joined_candidate_sources = ", ".join(candidate_sources)
        try:
            (
                normalized_home_directory_path,
                directory_resolution_uncertainty,
            ) = observe_canonical_existing_directory(
                reported_home_directory_path,
                failure_reason_code="home_directory_candidate_cannot_be_resolved",
                evidence_source=joined_candidate_sources,
            )
        except (OSError, TypeError, ValueError) as error:
            uncertainty_reasons.append(
                EvidenceReason(
                    "home_directory_candidate_cannot_be_normalized",
                    evidence_source=joined_candidate_sources,
                    detail=(
                        f"reported_home_directory_path="
                        f"{reported_home_directory_path!r}; error={error}"
                    ),
                )
            )
            continue
        if directory_resolution_uncertainty is not None:
            uncertainty_reasons.append(directory_resolution_uncertainty)
            continue
        if normalized_home_directory_path is None:
            uncertainty_reasons.append(
                EvidenceReason(
                    "home_directory_candidate_resolution_returned_no_path",
                    evidence_source=joined_candidate_sources,
                )
            )
            continue

        if normalized_home_directory_path == "/":
            candidate_disposition = HOME_DIRECTORY_CANDIDATE_REJECTED_AS_FILESYSTEM_ROOT
        else:
            candidate_disposition = (
                HOME_DIRECTORY_CANDIDATE_ACCEPTED_FOR_DEFAULT_EXCLUSION
            )
            accepted_home_directory_exclusion_paths.append(
                normalized_home_directory_path
            )

        candidate_observations.append(
            HomeDirectoryCandidateObservation(
                candidate_source=joined_candidate_sources,
                reported_home_directory_path=reported_home_directory_path,
                normalized_home_directory_path=normalized_home_directory_path,
                candidate_disposition=candidate_disposition,
            )
        )

    return HomeDirectoryDiscoveryEvidence(
        accepted_home_directory_exclusion_paths=tuple(
            deduplicate_preserving_first_occurrence(
                accepted_home_directory_exclusion_paths
            )
        ),
        candidate_observations=tuple(candidate_observations),
        uncertainty_reasons=tuple(
            deduplicate_preserving_first_occurrence(uncertainty_reasons)
        ),
        observed_at_utc=observation_timestamp,
    )


@dataclass(frozen=True)
class TemporaryDirectoryDiscoveryEvidence:
    selected_writable_temporary_directory: str | None
    normalized_candidate_paths: tuple[str, ...]
    candidate_observations: tuple[EvidenceReason, ...]
    uncertainty_reasons: tuple[EvidenceReason, ...]
    observed_at_utc: str


def discover_active_writable_temporary_directory(
    process_credentials: LinuxProcessCredentialEvidence,
) -> TemporaryDirectoryDiscoveryEvidence:
    candidate_sources_by_path: dict[str, list[str]] = {}
    normalized_candidate_paths: list[str] = []
    candidate_observations: list[EvidenceReason] = []
    uncertainty_reasons: list[EvidenceReason] = []
    observation_timestamp = current_utc_timestamp()
    for environment_variable_name in TEMPORARY_DIRECTORY_ENVIRONMENT_VARIABLE_NAMES:
        environment_value = os.environ.get(environment_variable_name)
        if environment_value:
            candidate_sources_by_path.setdefault(
                environment_value,
                [],
            ).append(f"{environment_variable_name} environment variable")
    candidate_sources_by_path.setdefault("/tmp", []).append(  # nosec B108
        "conventional Linux /tmp path"
    )

    for (
        unnormalized_candidate,
        candidate_sources,
    ) in candidate_sources_by_path.items():
        joined_candidate_sources = ", ".join(candidate_sources)
        try:
            requested_candidate_path = absolute_path_without_lexical_normalization(
                unnormalized_candidate
            )
            candidate_path = lexically_normalize_absolute_path(requested_candidate_path)
            normalized_candidate_paths.append(candidate_path)
            candidate_metadata = os.stat(requested_candidate_path)
        except OSError as error:
            uncertainty_reasons.append(
                operating_system_error_reason(
                    "temporary_directory_candidate_cannot_be_observed",
                    error,
                    evidence_source=joined_candidate_sources,
                )
            )
            continue
        except (TypeError, ValueError) as error:
            uncertainty_reasons.append(
                EvidenceReason(
                    "temporary_directory_candidate_cannot_be_normalized",
                    evidence_source=joined_candidate_sources,
                    detail=(f"candidate={unnormalized_candidate!r}; error={error}"),
                )
            )
            continue
        if candidate_path == "/":
            candidate_observations.append(
                EvidenceReason(
                    "temporary_directory_candidate_is_filesystem_root",
                    evidence_source=joined_candidate_sources,
                    detail=candidate_path,
                )
            )
            continue
        if not stat.S_ISDIR(candidate_metadata.st_mode):
            candidate_observations.append(
                EvidenceReason(
                    "temporary_directory_candidate_is_not_a_directory",
                    evidence_source=joined_candidate_sources,
                    detail=candidate_path,
                )
            )
            continue

        candidate_path, directory_resolution_uncertainty = (
            observe_canonical_existing_directory(
                requested_candidate_path,
                failure_reason_code=(
                    "temporary_directory_candidate_cannot_be_resolved"
                ),
                evidence_source=joined_candidate_sources,
            )
        )
        if directory_resolution_uncertainty is not None:
            uncertainty_reasons.append(directory_resolution_uncertainty)
            continue
        if candidate_path is None:
            uncertainty_reasons.append(
                EvidenceReason(
                    "temporary_directory_candidate_resolution_returned_no_path",
                    evidence_source=joined_candidate_sources,
                )
            )
            continue
        normalized_candidate_paths[-1] = candidate_path
        if candidate_path == "/":
            candidate_observations.append(
                EvidenceReason(
                    "temporary_directory_candidate_is_filesystem_root",
                    evidence_source=joined_candidate_sources,
                    detail=candidate_path,
                )
            )
            continue

        access_evidence = ask_kernel_about_path_access(
            candidate_path,
            os.W_OK | os.X_OK,
            process_credentials=process_credentials,
        )
        if access_evidence.access_is_allowed is True:
            candidate_observations.append(
                EvidenceReason(
                    "temporary_directory_candidate_was_selected",
                    evidence_source=joined_candidate_sources,
                    detail=candidate_path,
                )
            )
            return TemporaryDirectoryDiscoveryEvidence(
                selected_writable_temporary_directory=candidate_path,
                normalized_candidate_paths=tuple(
                    deduplicate_preserving_first_occurrence(normalized_candidate_paths)
                ),
                candidate_observations=tuple(candidate_observations),
                uncertainty_reasons=tuple(
                    deduplicate_preserving_first_occurrence(uncertainty_reasons)
                ),
                observed_at_utc=observation_timestamp,
            )
        if access_evidence.access_is_allowed is False:
            candidate_observations.append(
                EvidenceReason(
                    "temporary_directory_candidate_is_not_writable_and_searchable",
                    evidence_source=joined_candidate_sources,
                    detail=candidate_path,
                )
            )
        if access_evidence.access_is_allowed is None:
            uncertainty_reasons.append(
                access_evidence.uncertainty_reason
                or EvidenceReason(
                    "temporary_directory_access_evidence_is_missing",
                    evidence_source="faccessat2(2)",
                )
            )
    return TemporaryDirectoryDiscoveryEvidence(
        selected_writable_temporary_directory=None,
        normalized_candidate_paths=tuple(
            deduplicate_preserving_first_occurrence(normalized_candidate_paths)
        ),
        candidate_observations=tuple(candidate_observations),
        uncertainty_reasons=tuple(
            deduplicate_preserving_first_occurrence(uncertainty_reasons)
        ),
        observed_at_utc=observation_timestamp,
    )


def unescape_linux_mountinfo_field(escaped_mountinfo_field: str) -> str:
    """Decode Linux mountinfo octal escapes without changing other backslashes."""
    decoded_characters: list[str] = []
    character_index = 0
    while character_index < len(escaped_mountinfo_field):
        possible_octal_escape = escaped_mountinfo_field[
            character_index + 1 : character_index + 4
        ]
        escape_is_complete = (
            escaped_mountinfo_field[character_index] == "\\"
            and len(possible_octal_escape) == 3
            and all(octal_digit in "01234567" for octal_digit in possible_octal_escape)
        )
        if escape_is_complete:
            decoded_characters.append(chr(int(possible_octal_escape, 8)))
            character_index += 4
            continue
        decoded_characters.append(escaped_mountinfo_field[character_index])
        character_index += 1
    return "".join(decoded_characters)


@dataclass(frozen=True)
class LinuxMountRecord:
    mount_id: int
    parent_mount_id: int
    mount_point: str
    filesystem_type: str
    mount_options: tuple[str, ...]
    superblock_options: tuple[str, ...]
    mountinfo_line_number: int
    same_mountpoint_stack_depth: int = 0

    @property
    def filesystem_is_mounted_read_only(self) -> bool:
        return "ro" in self.mount_options or "ro" in self.superblock_options


def linux_mount_record_evidence_summary(mount_record: LinuxMountRecord) -> str:
    """Name the parsed mount fields that support one path inference."""
    return (
        f"mount_id={mount_record.mount_id}; "
        f"mount_point={json.dumps(mount_record.mount_point, ensure_ascii=True)}; "
        f"filesystem_type={mount_record.filesystem_type}; "
        f"mount_options={','.join(mount_record.mount_options)}; "
        f"superblock_options={','.join(mount_record.superblock_options)}"
    )


@dataclass(frozen=True)
class LinuxMountTableReadEvidence:
    mount_records: tuple[LinuxMountRecord, ...]
    uncertainty_reasons: tuple[EvidenceReason, ...]
    source_path: str
    source_sha256: str | None
    observed_at_utc: str

    @property
    def evidence_is_degraded(self) -> bool:
        return bool(self.uncertainty_reasons)


def parse_linux_mountinfo_line(
    mountinfo_line: str,
    *,
    line_number: int,
) -> LinuxMountRecord:
    fields_before_separator, separator, fields_after_separator = mountinfo_line.rstrip(
        "\n"
    ).partition(" - ")
    if not separator:
        raise ValueError("missing ' - ' separator")

    pre_separator_fields = fields_before_separator.split(" ")
    post_separator_fields = fields_after_separator.split(" ")
    if "" in pre_separator_fields or "" in post_separator_fields:
        raise ValueError("mountinfo contains an empty space-delimited field")
    if len(pre_separator_fields) < 6:
        raise ValueError(
            "expected at least 6 fields before the separator, "
            f"observed {len(pre_separator_fields)}"
        )
    if len(post_separator_fields) < 3:
        raise ValueError(
            "expected at least 3 fields after the separator, "
            f"observed {len(post_separator_fields)}"
        )

    try:
        mount_id = int(pre_separator_fields[0])
        parent_mount_id = int(pre_separator_fields[1])
    except ValueError as error:
        raise ValueError(f"mount IDs are not decimal integers: {error}") from error

    unescaped_mount_point = unescape_linux_mountinfo_field(pre_separator_fields[4])
    if not unescaped_mount_point.startswith("/"):
        raise ValueError("mount point is not an absolute path")
    if "\0" in unescaped_mount_point:
        raise ValueError("mount point contains a NUL byte")
    filesystem_type = post_separator_fields[0]
    if not filesystem_type:
        raise ValueError("filesystem type is empty")
    if mount_id <= 0 or parent_mount_id < 0:
        raise ValueError(
            "mount ID must be positive and parent mount ID must be nonnegative"
        )

    return LinuxMountRecord(
        mount_id=mount_id,
        parent_mount_id=parent_mount_id,
        mount_point=lexically_normalize_absolute_path(unescaped_mount_point),
        filesystem_type=filesystem_type,
        mount_options=tuple(pre_separator_fields[5].split(",")),
        superblock_options=tuple(post_separator_fields[2].split(",")),
        mountinfo_line_number=line_number,
    )


def validate_linux_mount_record_graph(
    mount_records: Sequence[LinuxMountRecord],
) -> None:
    """Reject duplicate IDs and parent cycles before topology inference."""
    mount_record_by_id: dict[int, LinuxMountRecord] = {}
    for mount_record in mount_records:
        if mount_record.mount_id in mount_record_by_id:
            raise ValueError(f"duplicate mount ID {mount_record.mount_id} in mountinfo")
        mount_record_by_id[mount_record.mount_id] = mount_record

    mount_ids_with_validated_parent_chains: set[int] = set()
    for starting_mount_record in mount_records:
        unresolved_mount_ids: list[int] = []
        unresolved_mount_id_set: set[int] = set()
        current_mount_record = starting_mount_record
        while (
            current_mount_record.mount_id not in mount_ids_with_validated_parent_chains
        ):
            if current_mount_record.mount_id in unresolved_mount_id_set:
                raise ValueError(
                    "mount parent cycle detected at mount ID "
                    f"{current_mount_record.mount_id}"
                )
            unresolved_mount_ids.append(current_mount_record.mount_id)
            unresolved_mount_id_set.add(current_mount_record.mount_id)
            parent_mount_record = mount_record_by_id.get(
                current_mount_record.parent_mount_id
            )
            if parent_mount_record is None:
                break
            current_mount_record = parent_mount_record
        mount_ids_with_validated_parent_chains.update(unresolved_mount_ids)


def add_same_mountpoint_stack_depths(
    mount_records: Sequence[LinuxMountRecord],
) -> tuple[LinuxMountRecord, ...]:
    validate_linux_mount_record_graph(mount_records)
    mount_record_by_id = {
        mount_record.mount_id: mount_record for mount_record in mount_records
    }
    depth_by_mount_id: dict[int, int] = {}

    def calculate_depth_without_recursion(starting_mount_id: int) -> int:
        if starting_mount_id in depth_by_mount_id:
            return depth_by_mount_id[starting_mount_id]

        unresolved_chain: list[LinuxMountRecord] = []
        unresolved_mount_ids: set[int] = set()
        current_mount_record = mount_record_by_id[starting_mount_id]

        while True:
            if current_mount_record.mount_id in depth_by_mount_id:
                current_depth = depth_by_mount_id[current_mount_record.mount_id]
                break
            if current_mount_record.mount_id in unresolved_mount_ids:
                raise ValueError(
                    "mount parent cycle detected at mount ID "
                    f"{current_mount_record.mount_id}"
                )
            unresolved_mount_ids.add(current_mount_record.mount_id)

            parent_mount_record = mount_record_by_id.get(
                current_mount_record.parent_mount_id
            )
            if (
                parent_mount_record is None
                or parent_mount_record.mount_point != current_mount_record.mount_point
            ):
                depth_by_mount_id[current_mount_record.mount_id] = 0
                current_depth = 0
                break

            unresolved_chain.append(current_mount_record)
            current_mount_record = parent_mount_record

        for descendant_mount_record in reversed(unresolved_chain):
            current_depth += 1
            depth_by_mount_id[descendant_mount_record.mount_id] = current_depth

        return depth_by_mount_id[starting_mount_id]

    records_with_depth: list[LinuxMountRecord] = []
    for mount_record in mount_records:
        records_with_depth.append(
            LinuxMountRecord(
                mount_id=mount_record.mount_id,
                parent_mount_id=mount_record.parent_mount_id,
                mount_point=mount_record.mount_point,
                filesystem_type=mount_record.filesystem_type,
                mount_options=mount_record.mount_options,
                superblock_options=mount_record.superblock_options,
                mountinfo_line_number=mount_record.mountinfo_line_number,
                same_mountpoint_stack_depth=(
                    calculate_depth_without_recursion(mount_record.mount_id)
                ),
            )
        )
    return tuple(records_with_depth)


def read_current_process_linux_mount_table() -> LinuxMountTableReadEvidence:
    observation_timestamp = current_utc_timestamp()
    mountinfo_bytes: bytes | None = None
    try:
        with open(LINUX_MOUNTINFO_SOURCE_PATH, "rb") as mountinfo_stream:
            mountinfo_bytes = mountinfo_stream.read()
        mountinfo_text = os.fsdecode(mountinfo_bytes)
        parsed_mount_record_list: list[LinuxMountRecord] = []
        for line_number, mountinfo_line in enumerate(
            mountinfo_text.split("\n"),
            start=1,
        ):
            if mountinfo_line == "":
                continue
            try:
                parsed_mount_record_list.append(
                    parse_linux_mountinfo_line(
                        mountinfo_line,
                        line_number=line_number,
                    )
                )
            except ValueError as error:
                raise ValueError(f"mountinfo line {line_number}: {error}") from error
        parsed_mount_records = tuple(parsed_mount_record_list)
        if not parsed_mount_records:
            raise ValueError("mountinfo contained no mount records")
        if not any(
            mount_record.mount_point == "/" for mount_record in parsed_mount_records
        ):
            raise ValueError("mountinfo contained no root mount record")
        mount_records_with_depth = add_same_mountpoint_stack_depths(
            parsed_mount_records
        )
    except (OSError, UnicodeError, ValueError) as error:
        if isinstance(error, OSError):
            uncertainty_reason = operating_system_error_reason(
                "cannot_read_linux_mount_table",
                error,
                evidence_source=LINUX_MOUNTINFO_SOURCE_PATH,
            )
        else:
            uncertainty_reason = EvidenceReason(
                "cannot_parse_linux_mount_table",
                evidence_source=LINUX_MOUNTINFO_SOURCE_PATH,
                detail=str(error),
            )
        fallback_mount_record = LinuxMountRecord(
            mount_id=1,
            parent_mount_id=0,
            mount_point="/",
            filesystem_type="unknown",
            mount_options=(),
            superblock_options=(),
            mountinfo_line_number=0,
        )
        return LinuxMountTableReadEvidence(
            mount_records=(fallback_mount_record,),
            uncertainty_reasons=(uncertainty_reason,),
            source_path=LINUX_MOUNTINFO_SOURCE_PATH,
            source_sha256=(
                None
                if mountinfo_bytes is None
                else hashlib.sha256(mountinfo_bytes).hexdigest()
            ),
            observed_at_utc=observation_timestamp,
        )

    return LinuxMountTableReadEvidence(
        mount_records=mount_records_with_depth,
        uncertainty_reasons=(),
        source_path=LINUX_MOUNTINFO_SOURCE_PATH,
        source_sha256=hashlib.sha256(mountinfo_bytes).hexdigest(),
        observed_at_utc=observation_timestamp,
    )


@dataclass(frozen=True)
class MountLookupEvidence:
    mount_record: LinuxMountRecord
    uncertainty_reasons: tuple[EvidenceReason, ...]
    resolved_path_used_for_lookup: str


class VisibleLinuxMountTable:
    """Visible mount topology derived from one /proc/self/mountinfo observation."""

    def __init__(self, read_evidence: LinuxMountTableReadEvidence):
        self.read_evidence = read_evidence
        self.mount_records = tuple(read_evidence.mount_records)
        if not self.mount_records:
            raise ValueError(
                "visible mount topology requires at least one mount record"
            )
        validate_linux_mount_record_graph(self.mount_records)
        self.mount_record_by_id = {
            mount_record.mount_id: mount_record for mount_record in self.mount_records
        }
        self.mount_records_by_parent_id: dict[int, list[LinuxMountRecord]] = {}
        for mount_record in self.mount_records:
            self.mount_records_by_parent_id.setdefault(
                mount_record.parent_mount_id,
                [],
            ).append(mount_record)

        self._top_same_mountpoint_cache: dict[int, LinuxMountRecord] = {}
        self.visible_mount_by_mountpoint: dict[str, LinuxMountRecord] = {}
        self.visible_root_mount = self._derive_visible_mount_topology()

    @property
    def evidence_is_degraded(self) -> bool:
        return self.read_evidence.evidence_is_degraded

    @property
    def uncertainty_reasons(self) -> tuple[EvidenceReason, ...]:
        return self.read_evidence.uncertainty_reasons

    @staticmethod
    def _choose_topmost_mount_record(
        candidates: Sequence[LinuxMountRecord],
    ) -> LinuxMountRecord:
        return max(
            candidates,
            key=lambda candidate: (
                candidate.same_mountpoint_stack_depth,
                candidate.mountinfo_line_number,
                candidate.mount_id,
            ),
        )

    def _same_mountpoint_children(
        self,
        mount_record: LinuxMountRecord,
    ) -> list[LinuxMountRecord]:
        return [
            child_mount_record
            for child_mount_record in self.mount_records_by_parent_id.get(
                mount_record.mount_id,
                [],
            )
            if child_mount_record.mount_point == mount_record.mount_point
        ]

    def _top_same_mountpoint_descendant(
        self,
        mount_record: LinuxMountRecord,
    ) -> LinuxMountRecord:
        cached_mount_record = self._top_same_mountpoint_cache.get(mount_record.mount_id)
        if cached_mount_record is not None:
            return cached_mount_record

        current_mount_record = mount_record
        visited_mount_ids: set[int] = set()
        while current_mount_record.mount_id not in visited_mount_ids:
            visited_mount_ids.add(current_mount_record.mount_id)
            same_path_children = self._same_mountpoint_children(current_mount_record)
            if not same_path_children:
                break
            current_mount_record = self._choose_topmost_mount_record(same_path_children)

        self._top_same_mountpoint_cache[mount_record.mount_id] = current_mount_record
        return current_mount_record

    def _derive_visible_mount_topology(self) -> LinuxMountRecord:
        root_mount_candidates = [
            mount_record
            for mount_record in self.mount_records
            if mount_record.mount_point == "/"
        ]
        if not root_mount_candidates:
            root_mount_candidates = [self.mount_records[0]]

        visible_root_mount = self._top_same_mountpoint_descendant(
            self._choose_topmost_mount_record(root_mount_candidates)
        )
        self._visit_visible_mounts_iteratively(visible_root_mount)
        return visible_root_mount

    def _visit_visible_mounts_iteratively(
        self,
        visible_root_mount: LinuxMountRecord,
    ) -> None:
        pending_mount_records = [visible_root_mount]
        visited_mount_ids: set[int] = set()

        while pending_mount_records:
            current_mount_record = pending_mount_records.pop()
            if current_mount_record.mount_id in visited_mount_ids:
                continue
            visited_mount_ids.add(current_mount_record.mount_id)
            normalized_mountpoint = lexically_normalize_absolute_path(
                current_mount_record.mount_point
            )
            self.visible_mount_by_mountpoint[normalized_mountpoint] = (
                current_mount_record
            )

            child_mounts_grouped_by_mountpoint: dict[
                str,
                list[LinuxMountRecord],
            ] = {}
            for child_mount_record in self.mount_records_by_parent_id.get(
                current_mount_record.mount_id,
                [],
            ):
                if child_mount_record.mount_point == current_mount_record.mount_point:
                    continue
                normalized_child_mountpoint = lexically_normalize_absolute_path(
                    child_mount_record.mount_point
                )
                child_mounts_grouped_by_mountpoint.setdefault(
                    normalized_child_mountpoint,
                    [],
                ).append(child_mount_record)

            for same_mountpoint_children in child_mounts_grouped_by_mountpoint.values():
                visible_child_mount = self._top_same_mountpoint_descendant(
                    self._choose_topmost_mount_record(same_mountpoint_children)
                )
                pending_mount_records.append(visible_child_mount)

    def _visible_mount_for_lexical_path(
        self,
        lexically_normalized_path: str,
    ) -> LinuxMountRecord:
        current_ancestor_path = lexically_normalized_path
        while True:
            matching_mount_record = self.visible_mount_by_mountpoint.get(
                current_ancestor_path
            )
            if matching_mount_record is not None:
                return matching_mount_record
            if current_ancestor_path == "/":
                return self.visible_root_mount
            # The input and every derived ancestor are already normalized
            # absolute Linux paths.  Re-running abspath/normpath for every
            # component is pure duplicate work on this hot path.
            current_ancestor_path = current_ancestor_path.rsplit("/", 1)[0] or "/"

    def lookup_mount_for_path(
        self,
        path: str,
        *,
        follow_final_symbolic_link: bool = True,
        strict_path_resolution_cache: (
            dict[str, StrictPathResolutionObservation] | None
        ) = None,
    ) -> MountLookupEvidence:
        lexically_normalized_path = lexically_normalize_absolute_path(path)
        if follow_final_symbolic_link:
            resolved_path, resolution_uncertainty = best_effort_resolve_existing_path(
                lexically_normalized_path,
                resolution_cache=strict_path_resolution_cache,
            )
        else:
            resolved_path, resolution_uncertainty = (
                best_effort_resolve_parent_components_only(
                    lexically_normalized_path,
                    resolution_cache=strict_path_resolution_cache,
                )
            )
        lookup_uncertainties = list(self.uncertainty_reasons)
        if resolution_uncertainty is not None:
            lookup_uncertainties.append(resolution_uncertainty)

        return MountLookupEvidence(
            mount_record=self._visible_mount_for_lexical_path(resolved_path),
            uncertainty_reasons=tuple(
                deduplicate_preserving_first_occurrence(lookup_uncertainties)
            ),
            resolved_path_used_for_lookup=resolved_path,
        )

    def lookup_mount_for_file_descriptor(
        self,
        file_descriptor: int,
        *,
        fallback_path: str,
    ) -> MountLookupEvidence:
        """Identify the descriptor's mount directly from proc fdinfo."""
        fdinfo_path = f"/proc/self/fdinfo/{file_descriptor}"
        try:
            descriptor_mount_id: int | None = None
            with open(fdinfo_path, encoding="ascii", errors="strict") as fdinfo_stream:
                for fdinfo_line in fdinfo_stream:
                    if not fdinfo_line.startswith("mnt_id:"):
                        continue
                    mount_id_fields = fdinfo_line.split()
                    if len(mount_id_fields) != 2:
                        raise ValueError("mnt_id field has an unexpected shape")
                    descriptor_mount_id = int(mount_id_fields[1], 10)
                    break
            if descriptor_mount_id is None:
                raise ValueError("mnt_id field is missing")
            descriptor_mount_record = self.mount_record_by_id.get(descriptor_mount_id)
            if descriptor_mount_record is None:
                raise ValueError(
                    f"mount ID {descriptor_mount_id} is absent from the captured mount table"
                )
        except (OSError, UnicodeError, ValueError) as error:
            fallback_lookup = self.lookup_mount_for_path(fallback_path)
            if isinstance(error, OSError):
                descriptor_reason = operating_system_error_reason(
                    "cannot_observe_descriptor_mount_id",
                    error,
                    evidence_source=fdinfo_path,
                )
            else:
                descriptor_reason = EvidenceReason(
                    "cannot_parse_descriptor_mount_id",
                    evidence_source=fdinfo_path,
                    detail=str(error),
                )
            return MountLookupEvidence(
                mount_record=fallback_lookup.mount_record,
                uncertainty_reasons=tuple(
                    deduplicate_preserving_first_occurrence(
                        (*fallback_lookup.uncertainty_reasons, descriptor_reason)
                    )
                ),
                resolved_path_used_for_lookup=(
                    fallback_lookup.resolved_path_used_for_lookup
                ),
            )

        return MountLookupEvidence(
            mount_record=descriptor_mount_record,
            uncertainty_reasons=self.uncertainty_reasons,
            resolved_path_used_for_lookup=fallback_path,
        )

    def observe_path_is_visible_mountpoint(
        self,
        path: str,
    ) -> tuple[bool | None, tuple[EvidenceReason, ...]]:
        lookup_evidence = self.lookup_mount_for_path(
            path,
            follow_final_symbolic_link=False,
        )
        if lookup_evidence.uncertainty_reasons:
            return None, lookup_evidence.uncertainty_reasons
        path_is_mountpoint = (
            lookup_evidence.resolved_path_used_for_lookup
            in self.visible_mount_by_mountpoint
        )
        return path_is_mountpoint, ()


@dataclass(frozen=True)
class CapabilityModelInference:
    """The model's conclusion for one capability on one observed path."""

    capability_name: str
    model_verdict: str
    evidence_reasons: tuple[EvidenceReason, ...] = ()


def capability_inference(
    capability_name: str,
    model_verdict: str,
    evidence_reasons: Iterable[EvidenceReason] = (),
) -> CapabilityModelInference:
    return CapabilityModelInference(
        capability_name=capability_name,
        model_verdict=model_verdict,
        evidence_reasons=tuple(
            deduplicate_preserving_first_occurrence(evidence_reasons)
        ),
    )


def infer_verdict_from_constraints(
    capability_name: str,
    *,
    model_has_blocking_evidence: bool,
    model_has_uncertain_evidence: bool,
    evidence_reasons: Iterable[EvidenceReason],
) -> CapabilityModelInference:
    ordered_reasons = tuple(deduplicate_preserving_first_occurrence(evidence_reasons))
    if model_has_blocking_evidence:
        model_verdict = MODEL_VERDICT_INDICATES_BLOCKED
    elif model_has_uncertain_evidence:
        model_verdict = MODEL_VERDICT_INSUFFICIENT_EVIDENCE
    else:
        model_verdict = MODEL_VERDICT_INDICATES_ALLOWED
    return CapabilityModelInference(
        capability_name=capability_name,
        model_verdict=model_verdict,
        evidence_reasons=ordered_reasons,
    )


def add_observation_reasons_to_inference(
    base_inference: CapabilityModelInference,
    additional_reasons: Iterable[EvidenceReason],
) -> CapabilityModelInference:
    return capability_inference(
        base_inference.capability_name,
        base_inference.model_verdict,
        (
            *base_inference.evidence_reasons,
            *tuple(additional_reasons),
        ),
    )


def classify_filesystem_object_kind(
    filesystem_metadata: os.stat_result,
) -> str:
    filesystem_mode = filesystem_metadata.st_mode
    if stat.S_ISDIR(filesystem_mode):
        return FILESYSTEM_OBJECT_KIND_DIRECTORY
    if stat.S_ISLNK(filesystem_mode):
        return FILESYSTEM_OBJECT_KIND_SYMBOLIC_LINK
    if stat.S_ISREG(filesystem_mode):
        return FILESYSTEM_OBJECT_KIND_REGULAR_FILE
    if stat.S_ISFIFO(filesystem_mode):
        return FILESYSTEM_OBJECT_KIND_NAMED_PIPE
    if stat.S_ISSOCK(filesystem_mode):
        return FILESYSTEM_OBJECT_KIND_SOCKET
    if stat.S_ISCHR(filesystem_mode):
        return FILESYSTEM_OBJECT_KIND_CHARACTER_DEVICE
    if stat.S_ISBLK(filesystem_mode):
        return FILESYSTEM_OBJECT_KIND_BLOCK_DEVICE
    return FILESYSTEM_OBJECT_KIND_UNRECOGNIZED_STAT_MODE


def filesystem_object_kind_is_special_file(
    filesystem_object_kind: str,
) -> bool:
    return filesystem_object_kind in {
        FILESYSTEM_OBJECT_KIND_NAMED_PIPE,
        FILESYSTEM_OBJECT_KIND_SOCKET,
        FILESYSTEM_OBJECT_KIND_CHARACTER_DEVICE,
        FILESYSTEM_OBJECT_KIND_BLOCK_DEVICE,
    }


@dataclass(frozen=True)
class PathCapabilityAssessment:
    """Per-capability model evidence observed for one lexical path."""

    filesystem_object_kind: str
    audited_path: str
    inference_by_capability_name: Mapping[str, CapabilityModelInference]
    assessment_completed_at_utc: str = field(default_factory=current_utc_timestamp)
    observation_notes: tuple[EvidenceReason, ...] = ()
    audited_path_lstat_metadata: ObservedLinuxFilesystemObjectMetadata | None = None
    resolved_symbolic_link_target_path: str | None = None
    resolved_symbolic_link_target_kind: str | None = None
    resolved_symbolic_link_target_stat_metadata: (
        ObservedLinuxFilesystemObjectMetadata | None
    ) = None

    def inference_for_capability(
        self,
        capability_name: str,
    ) -> CapabilityModelInference:
        try:
            return self.inference_by_capability_name[capability_name]
        except KeyError as error:
            raise RuntimeError(
                "path assessment has no inference for selected capability "
                f"{capability_name!r}"
            ) from error

    def create_structured_record(
        self,
        *,
        selected_capabilities: Sequence[str],
        originating_scan_root_path: str,
    ) -> StructuredPathAuditRecord:
        selected_inferences = [
            self.inference_for_capability(capability_name)
            for capability_name in selected_capabilities
        ]
        model_indicated_capabilities = tuple(
            inference.capability_name
            for inference in selected_inferences
            if inference.model_verdict == MODEL_VERDICT_INDICATES_ALLOWED
        )
        capabilities_with_insufficient_evidence = {
            inference.capability_name: tuple(inference.evidence_reasons)
            for inference in selected_inferences
            if inference.model_verdict == MODEL_VERDICT_INSUFFICIENT_EVIDENCE
        }
        model_blocked_capabilities = {
            inference.capability_name: tuple(inference.evidence_reasons)
            for inference in selected_inferences
            if inference.model_verdict == MODEL_VERDICT_INDICATES_BLOCKED
        }
        skipped_capabilities = {
            inference.capability_name: tuple(inference.evidence_reasons)
            for inference in selected_inferences
            if inference.model_verdict == MODEL_VERDICT_SKIPPED
        }
        all_capability_evidence_reasons = tuple(
            deduplicate_preserving_first_occurrence(
                reason
                for inference in selected_inferences
                for reason in inference.evidence_reasons
            )
        )

        return StructuredPathAuditRecord(
            model_status=determine_path_model_status(
                selected_capability_count=len(selected_capabilities),
                model_indicated_capabilities=model_indicated_capabilities,
                capabilities_with_insufficient_evidence=(
                    capabilities_with_insufficient_evidence
                ),
                skipped_capabilities=skipped_capabilities,
            ),
            filesystem_object_kind=self.filesystem_object_kind,
            audited_path=self.audited_path,
            originating_scan_root_path=originating_scan_root_path,
            model_indicated_capabilities=model_indicated_capabilities,
            capabilities_with_insufficient_evidence=(
                capabilities_with_insufficient_evidence
            ),
            model_blocked_capabilities=model_blocked_capabilities,
            skipped_capabilities=skipped_capabilities,
            capability_evidence_reasons=all_capability_evidence_reasons,
            observation_notes=self.observation_notes,
            assessment_completed_at_utc=self.assessment_completed_at_utc,
            audited_path_lstat_metadata=self.audited_path_lstat_metadata,
            resolved_symbolic_link_target_path=(
                self.resolved_symbolic_link_target_path
            ),
            resolved_symbolic_link_target_kind=(
                self.resolved_symbolic_link_target_kind
            ),
            resolved_symbolic_link_target_stat_metadata=(
                self.resolved_symbolic_link_target_stat_metadata
            ),
        )


@dataclass(frozen=True)
class StructuredPathAuditRecord:
    """One versioned, serialization-ready path assessment."""

    model_status: str
    filesystem_object_kind: str
    audited_path: str
    originating_scan_root_path: str
    model_indicated_capabilities: tuple[str, ...]
    capabilities_with_insufficient_evidence: Mapping[
        str,
        tuple[EvidenceReason, ...],
    ]
    model_blocked_capabilities: Mapping[str, tuple[EvidenceReason, ...]]
    skipped_capabilities: Mapping[str, tuple[EvidenceReason, ...]]
    capability_evidence_reasons: tuple[EvidenceReason, ...]
    observation_notes: tuple[EvidenceReason, ...]
    assessment_completed_at_utc: str
    audited_path_lstat_metadata: ObservedLinuxFilesystemObjectMetadata | None
    resolved_symbolic_link_target_path: str | None = None
    resolved_symbolic_link_target_kind: str | None = None
    resolved_symbolic_link_target_stat_metadata: (
        ObservedLinuxFilesystemObjectMetadata | None
    ) = None

    def as_serializable_dictionary(
        self,
        *,
        serialized_audit_run_provenance: Mapping[str, object],
        include_routine_uncertainty: bool,
    ) -> dict[str, object]:
        uncertainty_grade_by_capability = {
            capability_name: uncertainty_grade_for_reason_sequence(reasons)
            for capability_name, reasons in (
                self.capabilities_with_insufficient_evidence.items()
            )
        }
        visible_uncertain_capabilities = {
            capability_name: reasons
            for capability_name, reasons in (
                self.capabilities_with_insufficient_evidence.items()
            )
            if include_routine_uncertainty
            or uncertainty_grade_by_capability[capability_name]
            == UNCERTAINTY_GRADE_MATERIAL
        }
        omitted_routine_reasons = {
            reason
            for capability_name, reasons in (
                self.capabilities_with_insufficient_evidence.items()
            )
            if capability_name not in visible_uncertain_capabilities
            for reason in reasons
        }
        visible_blocked_capabilities = {
            capability_name: tuple(
                reason
                for reason in reasons
                if include_routine_uncertainty
                or evidence_reason_uncertainty_grade(reason)
                != UNCERTAINTY_GRADE_ROUTINE
            )
            for capability_name, reasons in self.model_blocked_capabilities.items()
        }
        visible_skipped_capabilities = {
            capability_name: tuple(
                reason
                for reason in reasons
                if include_routine_uncertainty
                or evidence_reason_uncertainty_grade(reason)
                != UNCERTAINTY_GRADE_ROUTINE
            )
            for capability_name, reasons in self.skipped_capabilities.items()
        }
        serialized_record: dict[str, object] = {
            "record_schema_id": STRUCTURED_RECORD_SCHEMA_ID,
            "record_type": "filesystem_path_capability_assessment",
            "path_assessment_completed_at_utc": self.assessment_completed_at_utc,
            "model_status": self.model_status,
            "filesystem_object_kind": self.filesystem_object_kind,
            "audited_path": self.audited_path,
            "originating_scan_root_path": self.originating_scan_root_path,
            "audited_path_lstat_metadata": (
                None
                if self.audited_path_lstat_metadata is None
                else self.audited_path_lstat_metadata.as_serializable_dictionary()
            ),
            "model_indicated_capabilities": list(self.model_indicated_capabilities),
            "model_blocked_capabilities": (
                serialize_capability_reason_mapping(visible_blocked_capabilities)
            ),
            "skipped_capabilities": serialize_capability_reason_mapping(
                visible_skipped_capabilities
            ),
            "capability_evidence_reasons": [
                reason.as_serializable_dictionary()
                for reason in self.capability_evidence_reasons
                if reason not in omitted_routine_reasons
                and (
                    include_routine_uncertainty
                    or evidence_reason_uncertainty_grade(reason)
                    != UNCERTAINTY_GRADE_ROUTINE
                )
            ],
            "observation_notes": [
                reason.as_serializable_dictionary()
                for reason in self.observation_notes
                if include_routine_uncertainty
                or evidence_reason_uncertainty_grade(reason)
                != UNCERTAINTY_GRADE_ROUTINE
            ],
        }
        if include_routine_uncertainty or visible_uncertain_capabilities:
            serialized_record["capabilities_with_insufficient_evidence"] = (
                serialize_capability_reason_mapping(visible_uncertain_capabilities)
            )
            serialized_record["uncertainty_grade_by_capability"] = {
                capability_name: uncertainty_grade_by_capability[capability_name]
                for capability_name in visible_uncertain_capabilities
            }
        if self.resolved_symbolic_link_target_path is not None:
            serialized_record["resolved_symbolic_link_target_path"] = (
                self.resolved_symbolic_link_target_path
            )
        if self.resolved_symbolic_link_target_kind is not None:
            serialized_record["resolved_symbolic_link_target_kind"] = (
                self.resolved_symbolic_link_target_kind
            )
            serialized_record["resolved_symbolic_link_target_stat_metadata"] = (
                None
                if self.resolved_symbolic_link_target_stat_metadata is None
                else (
                    self.resolved_symbolic_link_target_stat_metadata.as_serializable_dictionary()
                )
            )
        serialized_record["audit_run_provenance"] = serialized_audit_run_provenance
        return serialized_record


def serialize_capability_reason_mapping(
    reason_mapping: Mapping[str, tuple[EvidenceReason, ...]],
) -> dict[str, list[dict[str, object]]]:
    return {
        capability_name: [
            reason.as_serializable_dictionary() for reason in capability_reasons
        ]
        for capability_name, capability_reasons in reason_mapping.items()
    }


def determine_path_model_status(
    *,
    selected_capability_count: int,
    model_indicated_capabilities: Sequence[str],
    capabilities_with_insufficient_evidence: Mapping[
        str,
        Sequence[EvidenceReason],
    ],
    skipped_capabilities: Mapping[str, Sequence[EvidenceReason]],
) -> str:
    if selected_capability_count <= 0:
        raise ValueError(
            "selected_capability_count must identify at least one capability"
        )
    if model_indicated_capabilities:
        return PATH_MODEL_STATUS_AT_LEAST_ONE_CAPABILITY_ALLOWED
    if len(skipped_capabilities) == selected_capability_count:
        return PATH_MODEL_STATUS_SKIPPED
    if capabilities_with_insufficient_evidence:
        return PATH_MODEL_STATUS_INSUFFICIENT_EVIDENCE
    return PATH_MODEL_STATUS_NO_CAPABILITY_ALLOWED


@dataclass
class DirectoryPostorderAssessmentState:
    """Constant-size state retained while one directory is streamed."""

    directory_path: str
    directory_evidence_path: str
    directory_metadata: os.stat_result
    directory_identity: FilesystemObjectIdentity
    directory_file_descriptor: int
    parent_directory_file_descriptor: int
    parent_directory_evidence_path: str
    directory_entry_name: str
    entry_lookup_followed_symbolic_link: bool
    path_was_explicitly_requested: bool
    directory_iterator: os.ScandirIterator | None
    parent_directory_state: DirectoryPostorderAssessmentState | None
    directory_listing_failure: EvidenceReason | None = None
    directory_observation_notes: list[EvidenceReason] = field(default_factory=list)
    opened_directory_identity_matched_lstat: bool | None = None
    has_child_with_uncertain_delete_inference: bool = False
    has_child_with_blocked_or_skipped_delete_inference: bool = False


@dataclass(frozen=True)
class InspectPathTraversalInstruction:
    audited_path: str
    evidence_path: str
    filesystem_metadata: os.stat_result
    object_file_descriptor: int
    parent_directory_file_descriptor: int
    parent_directory_evidence_path: str
    directory_entry_name: str
    entry_lookup_followed_symbolic_link: bool
    path_was_explicitly_requested: bool
    parent_directory_state: DirectoryPostorderAssessmentState | None
    observation_notes: tuple[EvidenceReason, ...] = ()


@dataclass(frozen=True)
class ContinueDirectoryTraversalInstruction:
    directory_state: DirectoryPostorderAssessmentState


@dataclass(frozen=True)
class EmitDirectoryTraversalInstruction:
    directory_state: DirectoryPostorderAssessmentState


# ``type_a | type_b`` would be evaluated here despite postponed annotations;
# typing.Union keeps this importable on the supported Python 3.9 floor.
TraversalInstruction = Union[
    InspectPathTraversalInstruction,
    ContinueDirectoryTraversalInstruction,
    EmitDirectoryTraversalInstruction,
]


@dataclass(frozen=True)
class OpenDirectoryForListingEvidence:
    directory_iterator: os.ScandirIterator
    opened_directory_identity: FilesystemObjectIdentity
    noatime_was_used: bool
    observation_notes: tuple[EvidenceReason, ...]


@dataclass
class PathAssessmentEvidenceCache:
    """Reuse identical observations only within one path assessment.

    The cache deliberately does not outlive an assessment.  This removes
    duplicate capability checks while avoiding a run-wide view that could
    silently retain stale pathname or permission evidence on a live system.
    """

    mount_lookup_by_path_and_follow_mode: dict[
        tuple[str, bool],
        MountLookupEvidence,
    ] = field(default_factory=dict)
    strict_path_resolution_by_path: dict[
        str,
        StrictPathResolutionObservation,
    ] = field(default_factory=dict)
    inode_attributes_by_path_and_follow_mode: dict[
        tuple[str, bool],
        LinuxInodeAttributeEvidence,
    ] = field(default_factory=dict)
    kernel_access_by_path_and_mode: dict[
        tuple[str, int],
        KernelPathAccessEvidence,
    ] = field(default_factory=dict)
    file_descriptor_by_path_and_follow_mode: dict[
        tuple[str, bool],
        int,
    ] = field(default_factory=dict)
    access_file_descriptor_by_path: dict[str, int] = field(default_factory=dict)


class LinuxFilesystemMutationPermissionAuditor:
    """Best-effort Linux permission model with explicit evidence boundaries."""

    def __init__(
        self,
        mount_table: VisibleLinuxMountTable,
        process_credentials: LinuxProcessCredentialEvidence,
        *,
        remain_on_starting_filesystem: bool,
        filesystem_types_with_unmodeled_semantics: set[str],
        exclusion_rules: Sequence[PathExclusionRule] = (),
        internally_ignored_paths: Sequence[str] = (),
    ):
        self.mount_table = mount_table
        self.process_credentials = process_credentials
        self.remain_on_starting_filesystem = remain_on_starting_filesystem
        self.filesystem_types_with_unmodeled_semantics = frozenset(
            filesystem_types_with_unmodeled_semantics
        )
        self.exclusion_rules = tuple(exclusion_rules)
        self.internally_ignored_paths = frozenset(
            lexically_normalize_absolute_path(path) for path in internally_ignored_paths
        )

    def ask_kernel_about_access(
        self,
        path: str,
        requested_access_mode: int,
        *,
        file_descriptor: int | None = None,
    ) -> KernelPathAccessEvidence:
        return ask_kernel_about_path_access(
            path,
            requested_access_mode,
            process_credentials=self.process_credentials,
            file_descriptor=file_descriptor,
        )

    def _lookup_mount_within_path_assessment(
        self,
        path: str,
        *,
        follow_final_symbolic_link: bool,
        evidence_cache: PathAssessmentEvidenceCache | None,
    ) -> MountLookupEvidence:
        if evidence_cache is None:
            return self.mount_table.lookup_mount_for_path(
                path,
                follow_final_symbolic_link=follow_final_symbolic_link,
            )
        cache_key = (path, follow_final_symbolic_link)
        cached_evidence = evidence_cache.mount_lookup_by_path_and_follow_mode.get(
            cache_key
        )
        if cached_evidence is None:
            stable_file_descriptor = (
                evidence_cache.file_descriptor_by_path_and_follow_mode.get(cache_key)
            )
            if stable_file_descriptor is not None:
                cached_evidence = self.mount_table.lookup_mount_for_file_descriptor(
                    stable_file_descriptor,
                    fallback_path=path,
                )
            else:
                cached_evidence = self.mount_table.lookup_mount_for_path(
                    path,
                    follow_final_symbolic_link=follow_final_symbolic_link,
                    strict_path_resolution_cache=(
                        evidence_cache.strict_path_resolution_by_path
                    ),
                )
            evidence_cache.mount_lookup_by_path_and_follow_mode[cache_key] = (
                cached_evidence
            )
        return cached_evidence

    @staticmethod
    def _observe_inode_attributes_within_path_assessment(
        path: str,
        *,
        follow_final_symbolic_link: bool,
        evidence_cache: PathAssessmentEvidenceCache | None,
    ) -> LinuxInodeAttributeEvidence:
        if evidence_cache is None:
            return observe_linux_inode_attributes(
                path,
                follow_final_symbolic_link=follow_final_symbolic_link,
            )
        cache_key = (path, follow_final_symbolic_link)
        cached_evidence = evidence_cache.inode_attributes_by_path_and_follow_mode.get(
            cache_key
        )
        if cached_evidence is None:
            stable_file_descriptor = (
                evidence_cache.file_descriptor_by_path_and_follow_mode.get(cache_key)
            )
            cached_evidence = observe_linux_inode_attributes(
                path,
                follow_final_symbolic_link=follow_final_symbolic_link,
                file_descriptor=stable_file_descriptor,
            )
            evidence_cache.inode_attributes_by_path_and_follow_mode[cache_key] = (
                cached_evidence
            )
        return cached_evidence

    def _ask_kernel_about_access_within_path_assessment(
        self,
        path: str,
        requested_access_mode: int,
        *,
        evidence_cache: PathAssessmentEvidenceCache | None,
    ) -> KernelPathAccessEvidence:
        if evidence_cache is None:
            return self.ask_kernel_about_access(path, requested_access_mode)
        cache_key = (path, requested_access_mode)
        cached_evidence = evidence_cache.kernel_access_by_path_and_mode.get(cache_key)
        if cached_evidence is None:
            stable_file_descriptor = evidence_cache.access_file_descriptor_by_path.get(
                path
            )
            if stable_file_descriptor is None:
                cached_evidence = self.ask_kernel_about_access(
                    path,
                    requested_access_mode,
                )
            else:
                cached_evidence = self.ask_kernel_about_access(
                    path,
                    requested_access_mode,
                    file_descriptor=stable_file_descriptor,
                )
            evidence_cache.kernel_access_by_path_and_mode[cache_key] = cached_evidence
        return cached_evidence

    def _ask_kernel_about_write_and_search_within_path_assessment(
        self,
        path: str,
        *,
        evidence_cache: PathAssessmentEvidenceCache | None,
    ) -> tuple[KernelPathAccessEvidence, KernelPathAccessEvidence]:
        """Prove both permissions together, splitting only when necessary."""
        combined_access = self._ask_kernel_about_access_within_path_assessment(
            path,
            os.W_OK | os.X_OK,
            evidence_cache=evidence_cache,
        )
        if combined_access.access_is_allowed is True:
            individually_allowed = KernelPathAccessEvidence(
                access_is_allowed=True,
                uncertainty_reason=None,
            )
            if evidence_cache is not None:
                evidence_cache.kernel_access_by_path_and_mode.setdefault(
                    (path, os.W_OK),
                    individually_allowed,
                )
                evidence_cache.kernel_access_by_path_and_mode.setdefault(
                    (path, os.X_OK),
                    individually_allowed,
                )
            return individually_allowed, individually_allowed

        # A combined denial does not identify which bit failed.  Separate
        # questions preserve the existing precise reason codes.  Retrying
        # separately after an uncertain combined query likewise avoids
        # broadening one transient failure into two unsupported conclusions.
        return (
            self._ask_kernel_about_access_within_path_assessment(
                path,
                os.W_OK,
                evidence_cache=evidence_cache,
            ),
            self._ask_kernel_about_access_within_path_assessment(
                path,
                os.X_OK,
                evidence_cache=evidence_cache,
            ),
        )

    def assess_path_tree(
        self,
        path: str,
        *,
        selected_capabilities: Sequence[str],
    ) -> Iterator[PathCapabilityAssessment]:
        requested_path = split_requested_path_without_normalizing(path)
        normalized_selected_capabilities = tuple(selected_capabilities)
        starting_filesystem_device_number: int | None = None
        pending_instructions: list[TraversalInstruction] = []
        active_directory_identities: set[FilesystemObjectIdentity] = set()
        owned_file_descriptors: set[int] = set()
        open_directory_iterators: list[os.ScandirIterator] = []

        parent_open_flags = getattr(os, "O_PATH", 0o10000000)
        parent_open_flags |= getattr(os, "O_CLOEXEC", 0)
        parent_open_flags |= getattr(os, "O_DIRECTORY", 0)
        object_open_flags = getattr(os, "O_PATH", 0o10000000)
        object_open_flags |= getattr(os, "O_CLOEXEC", 0)
        object_open_flags |= getattr(os, "O_NOFOLLOW", 0)

        try:
            try:
                root_parent_file_descriptor = os.open(
                    requested_path.parent_path_with_dot_components,
                    parent_open_flags,
                )
                owned_file_descriptors.add(root_parent_file_descriptor)
            except OSError as error:
                unavailable_assessment = self._same_verdict_for_all_capabilities(
                    filesystem_object_kind=(
                        FILESYSTEM_OBJECT_KIND_MISSING
                        if error.errno == errno.ENOENT
                        else FILESYSTEM_OBJECT_KIND_UNOBSERVED
                    ),
                    audited_path=requested_path.absolute_path_with_dot_components,
                    selected_capabilities=normalized_selected_capabilities,
                    model_verdict=(
                        MODEL_VERDICT_INDICATES_BLOCKED
                        if error.errno in {errno.ENOENT, errno.ENOTDIR}
                        else MODEL_VERDICT_INSUFFICIENT_EVIDENCE
                    ),
                    evidence_reasons=(
                        operating_system_error_reason(
                            "cannot_open_requested_path_parent_directory",
                            error,
                            evidence_source="openat(O_PATH|O_DIRECTORY)",
                        ),
                    ),
                )
                yield unavailable_assessment
                return

            parent_display_path, parent_display_note = (
                observe_canonical_path_for_file_descriptor(
                    root_parent_file_descriptor,
                    fallback_path=requested_path.parent_path_with_dot_components,
                )
            )
            root_lookup_name = requested_path.final_component
            if requested_path.trailing_separator_requires_directory:
                root_lookup_name += "/"
            try:
                root_object_file_descriptor = os.open(
                    root_lookup_name,
                    object_open_flags,
                    dir_fd=root_parent_file_descriptor,
                )
                owned_file_descriptors.add(root_object_file_descriptor)
                root_metadata = os.fstat(root_object_file_descriptor)
            except FileNotFoundError:
                existing_final_entry_metadata: os.stat_result | None = None
                if requested_path.trailing_separator_requires_directory:
                    with contextlib.suppress(OSError):
                        existing_final_entry_metadata = os.stat(
                            requested_path.final_component,
                            dir_fd=root_parent_file_descriptor,
                            follow_symlinks=False,
                        )
                if existing_final_entry_metadata is not None:
                    unresolved_target_assessment = self._same_verdict_for_all_capabilities(
                        filesystem_object_kind=classify_filesystem_object_kind(
                            existing_final_entry_metadata
                        ),
                        audited_path=(requested_path.absolute_path_with_dot_components),
                        selected_capabilities=normalized_selected_capabilities,
                        model_verdict=MODEL_VERDICT_INDICATES_BLOCKED,
                        evidence_reasons=(
                            EvidenceReason(
                                "trailing_separator_target_cannot_be_resolved_as_directory",
                                evidence_source="openat(O_PATH|O_NOFOLLOW)",
                                operating_system_errno=errno.ENOENT,
                                operating_system_message=os.strerror(errno.ENOENT),
                            ),
                        ),
                        audited_path_lstat_metadata=(
                            ObservedLinuxFilesystemObjectMetadata.from_stat_result(
                                existing_final_entry_metadata
                            )
                        ),
                    )
                    yield unresolved_target_assessment
                    return
                missing_display_path = (
                    parent_display_path
                    if requested_path.final_component == "."
                    else os.path.join(
                        parent_display_path,
                        requested_path.final_component,
                    )
                )
                missing_assessment = self.assess_explicitly_requested_missing_path(
                    missing_display_path,
                    normalized_selected_capabilities,
                    parent_directory_path=proc_path_for_file_descriptor(
                        root_parent_file_descriptor
                    ),
                    parent_directory_metadata=os.fstat(root_parent_file_descriptor),
                    parent_directory_file_descriptor=root_parent_file_descriptor,
                )
                try:
                    os.stat(
                        requested_path.final_component,
                        dir_fd=root_parent_file_descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    pass
                except OSError as error:
                    missing_assessment = self._assessment_with_identity_instability(
                        missing_assessment,
                        normalized_selected_capabilities,
                        operating_system_error_reason(
                            "cannot_revalidate_requested_missing_path",
                            error,
                            evidence_source="fstatat(2)",
                        ),
                    )
                else:
                    missing_assessment = self._assessment_with_identity_instability(
                        missing_assessment,
                        normalized_selected_capabilities,
                        EvidenceReason(
                            "requested_missing_path_appeared_during_assessment",
                            evidence_source="fstatat(2)",
                        ),
                    )
                yield missing_assessment
                return
            except NotADirectoryError as error:
                invalid_assessment = self._same_verdict_for_all_capabilities(
                    filesystem_object_kind=FILESYSTEM_OBJECT_KIND_UNOBSERVED,
                    audited_path=requested_path.absolute_path_with_dot_components,
                    selected_capabilities=normalized_selected_capabilities,
                    model_verdict=MODEL_VERDICT_INDICATES_BLOCKED,
                    evidence_reasons=(
                        operating_system_error_reason(
                            "requested_path_component_is_not_a_directory",
                            error,
                            evidence_source="openat(O_PATH)",
                        ),
                    ),
                )
                yield invalid_assessment
                return
            except OSError as error:
                unavailable_assessment = self._same_verdict_for_all_capabilities(
                    filesystem_object_kind=FILESYSTEM_OBJECT_KIND_UNOBSERVED,
                    audited_path=requested_path.absolute_path_with_dot_components,
                    selected_capabilities=normalized_selected_capabilities,
                    model_verdict=MODEL_VERDICT_INSUFFICIENT_EVIDENCE,
                    evidence_reasons=(
                        operating_system_error_reason(
                            "cannot_capture_requested_path",
                            error,
                            evidence_source="openat(O_PATH|O_NOFOLLOW)",
                        ),
                    ),
                )
                yield unavailable_assessment
                return

            root_display_path, root_display_note = (
                observe_canonical_path_for_file_descriptor(
                    root_object_file_descriptor,
                    fallback_path=requested_path.absolute_path_with_dot_components,
                )
            )
            root_observation_notes = tuple(
                reason
                for reason in (parent_display_note, root_display_note)
                if reason is not None
            )
            pending_instructions.append(
                InspectPathTraversalInstruction(
                    audited_path=root_display_path,
                    evidence_path=proc_path_for_file_descriptor(
                        root_object_file_descriptor
                    ),
                    filesystem_metadata=root_metadata,
                    object_file_descriptor=root_object_file_descriptor,
                    parent_directory_file_descriptor=root_parent_file_descriptor,
                    parent_directory_evidence_path=proc_path_for_file_descriptor(
                        root_parent_file_descriptor
                    ),
                    directory_entry_name=requested_path.final_component,
                    entry_lookup_followed_symbolic_link=(
                        requested_path.trailing_separator_requires_directory
                    ),
                    path_was_explicitly_requested=True,
                    parent_directory_state=None,
                    observation_notes=root_observation_notes,
                )
            )

            while pending_instructions:
                current_instruction = pending_instructions.pop()
                if isinstance(
                    current_instruction,
                    EmitDirectoryTraversalInstruction,
                ):
                    directory_state = current_instruction.directory_state
                    evidence_cache = self._captured_object_evidence_cache(
                        evidence_path=directory_state.directory_evidence_path,
                        object_file_descriptor=(
                            directory_state.directory_file_descriptor
                        ),
                        parent_directory_evidence_path=(
                            directory_state.parent_directory_evidence_path
                        ),
                        parent_directory_file_descriptor=(
                            directory_state.parent_directory_file_descriptor
                        ),
                    )
                    directory_assessment = self.assess_directory(
                        directory_state.directory_evidence_path,
                        directory_state.directory_metadata,
                        normalized_selected_capabilities,
                        audited_path=directory_state.directory_path,
                        parent_directory_path=(
                            directory_state.parent_directory_evidence_path
                        ),
                        evidence_cache=evidence_cache,
                        has_uncertain_descendant_delete=(
                            directory_state.has_child_with_uncertain_delete_inference
                        ),
                        has_blocked_descendant_delete=(
                            directory_state.has_child_with_blocked_or_skipped_delete_inference
                        ),
                        directory_listing_failure=(
                            directory_state.directory_listing_failure
                        ),
                        observation_notes=tuple(
                            deduplicate_preserving_first_occurrence(
                                directory_state.directory_observation_notes
                            )
                        ),
                        directory_identity_matched_lstat=(
                            directory_state.opened_directory_identity_matched_lstat
                        ),
                    )
                    if (
                        directory_state.path_was_explicitly_requested
                        and directory_state.directory_entry_name in {".", ".."}
                    ):
                        directory_assessment = (
                            self._assessment_with_unremovable_dot_component(
                                directory_assessment
                            )
                        )
                    identity_instability = self._entry_identity_instability_reason(
                        parent_directory_file_descriptor=(
                            directory_state.parent_directory_file_descriptor
                        ),
                        directory_entry_name=directory_state.directory_entry_name,
                        expected_identity=directory_state.directory_identity,
                        follow_symbolic_link=(
                            directory_state.entry_lookup_followed_symbolic_link
                        ),
                    )
                    if identity_instability is not None:
                        directory_assessment = (
                            self._assessment_with_identity_instability(
                                directory_assessment,
                                normalized_selected_capabilities,
                                identity_instability,
                            )
                        )
                    active_directory_identities.discard(
                        directory_state.directory_identity
                    )
                    self._record_direct_child_delete_inference(
                        directory_state.parent_directory_state,
                        directory_assessment,
                    )
                    self._close_owned_file_descriptor(
                        directory_state.directory_file_descriptor,
                        owned_file_descriptors,
                    )
                    yield directory_assessment
                    continue

                if isinstance(
                    current_instruction,
                    ContinueDirectoryTraversalInstruction,
                ):
                    directory_state = current_instruction.directory_state
                    directory_iterator = directory_state.directory_iterator
                    if directory_iterator is None:
                        pending_instructions.append(
                            EmitDirectoryTraversalInstruction(directory_state)
                        )
                        continue
                    try:
                        directory_entry = next(directory_iterator)
                    except StopIteration:
                        self._close_directory_iterator(
                            directory_state,
                            open_directory_iterators,
                        )
                        pending_instructions.append(
                            EmitDirectoryTraversalInstruction(directory_state)
                        )
                        continue
                    except OSError as error:
                        directory_state.directory_listing_failure = (
                            operating_system_error_reason(
                                "cannot_continue_directory_listing",
                                error,
                                evidence_source="os.scandir",
                            )
                        )
                        self._close_directory_iterator(
                            directory_state,
                            open_directory_iterators,
                        )
                        pending_instructions.append(
                            EmitDirectoryTraversalInstruction(directory_state)
                        )
                        continue

                    child_file_descriptor: int | None = None
                    try:
                        child_file_descriptor = os.open(
                            directory_entry.name,
                            object_open_flags,
                            dir_fd=directory_state.directory_file_descriptor,
                        )
                        owned_file_descriptors.add(child_file_descriptor)
                        child_metadata = os.fstat(child_file_descriptor)
                    except OSError as error:
                        if child_file_descriptor is not None:
                            self._close_owned_file_descriptor(
                                child_file_descriptor,
                                owned_file_descriptors,
                            )
                        if error.errno in {errno.EMFILE, errno.ENFILE}:
                            directory_state.directory_listing_failure = operating_system_error_reason(
                                "directory_traversal_file_descriptor_budget_exhausted",
                                error,
                                evidence_source="openat(O_PATH|O_NOFOLLOW)",
                            )
                            self._close_directory_iterator(
                                directory_state,
                                open_directory_iterators,
                            )
                            pending_instructions.append(
                                EmitDirectoryTraversalInstruction(directory_state)
                            )
                            continue

                        pending_instructions.append(
                            ContinueDirectoryTraversalInstruction(directory_state)
                        )
                        child_path = os.path.join(
                            directory_state.directory_path,
                            directory_entry.name,
                        )
                        child_failure_assessment = (
                            self._same_verdict_for_all_capabilities(
                                filesystem_object_kind=(
                                    FILESYSTEM_OBJECT_KIND_MISSING
                                    if error.errno == errno.ENOENT
                                    else FILESYSTEM_OBJECT_KIND_UNOBSERVED
                                ),
                                audited_path=child_path,
                                selected_capabilities=(
                                    normalized_selected_capabilities
                                ),
                                model_verdict=MODEL_VERDICT_INSUFFICIENT_EVIDENCE,
                                evidence_reasons=(
                                    operating_system_error_reason(
                                        (
                                            "path_disappeared_during_directory_scan"
                                            if error.errno == errno.ENOENT
                                            else "cannot_capture_directory_entry"
                                        ),
                                        error,
                                        evidence_source=("openat(O_PATH|O_NOFOLLOW)"),
                                    ),
                                ),
                            )
                        )
                        self._record_direct_child_delete_inference(
                            directory_state,
                            child_failure_assessment,
                        )
                        yield child_failure_assessment
                        continue

                    pending_instructions.append(
                        ContinueDirectoryTraversalInstruction(directory_state)
                    )
                    child_fallback_path = os.path.join(
                        directory_state.directory_path,
                        directory_entry.name,
                    )
                    child_display_path, child_display_note = (
                        observe_canonical_path_for_file_descriptor(
                            child_file_descriptor,
                            fallback_path=child_fallback_path,
                        )
                    )
                    pending_instructions.append(
                        InspectPathTraversalInstruction(
                            audited_path=child_display_path,
                            evidence_path=proc_path_for_file_descriptor(
                                child_file_descriptor
                            ),
                            filesystem_metadata=child_metadata,
                            object_file_descriptor=child_file_descriptor,
                            parent_directory_file_descriptor=(
                                directory_state.directory_file_descriptor
                            ),
                            parent_directory_evidence_path=(
                                directory_state.directory_evidence_path
                            ),
                            directory_entry_name=directory_entry.name,
                            entry_lookup_followed_symbolic_link=False,
                            path_was_explicitly_requested=False,
                            parent_directory_state=directory_state,
                            observation_notes=(
                                ()
                                if child_display_note is None
                                else (child_display_note,)
                            ),
                        )
                    )
                    continue

                current_path = current_instruction.audited_path
                current_metadata = current_instruction.filesystem_metadata
                current_identity = FilesystemObjectIdentity.from_stat_result(
                    current_metadata
                )
                if current_path in self.internally_ignored_paths:
                    ignored_report_artifact_assessment = (
                        self._same_verdict_for_all_capabilities(
                            filesystem_object_kind=FILESYSTEM_OBJECT_KIND_UNOBSERVED,
                            audited_path=current_path,
                            selected_capabilities=(normalized_selected_capabilities),
                            model_verdict=MODEL_VERDICT_SKIPPED,
                            evidence_reasons=(
                                EvidenceReason(
                                    "path_is_an_active_audit_report_artifact",
                                    evidence_source="report publication scope",
                                ),
                            ),
                        )
                    )
                    self._record_direct_child_delete_inference(
                        current_instruction.parent_directory_state,
                        ignored_report_artifact_assessment,
                    )
                    self._close_owned_file_descriptor(
                        current_instruction.object_file_descriptor,
                        owned_file_descriptors,
                    )
                    continue

                terminal_assessment = self._assessment_if_excluded(
                    current_path,
                    normalized_selected_capabilities,
                    filesystem_metadata=current_metadata,
                )
                if terminal_assessment is not None:
                    self._record_direct_child_delete_inference(
                        current_instruction.parent_directory_state,
                        terminal_assessment,
                    )
                    self._close_owned_file_descriptor(
                        current_instruction.object_file_descriptor,
                        owned_file_descriptors,
                    )
                    yield terminal_assessment
                    continue

                filesystem_object_kind = classify_filesystem_object_kind(
                    current_metadata
                )
                if current_instruction.path_was_explicitly_requested:
                    starting_filesystem_device_number = current_metadata.st_dev
                if (
                    self.remain_on_starting_filesystem
                    and starting_filesystem_device_number is not None
                    and current_metadata.st_dev != starting_filesystem_device_number
                ):
                    different_filesystem_assessment = (
                        self._same_verdict_for_all_capabilities(
                            filesystem_object_kind=filesystem_object_kind,
                            audited_path=current_path,
                            selected_capabilities=(normalized_selected_capabilities),
                            model_verdict=MODEL_VERDICT_SKIPPED,
                            evidence_reasons=(
                                EvidenceReason(
                                    "path_is_on_different_filesystem",
                                    evidence_source="lstat.st_dev",
                                    detail=(
                                        "starting_device="
                                        f"{starting_filesystem_device_number};"
                                        " observed_device="
                                        f"{current_metadata.st_dev}"
                                    ),
                                ),
                            ),
                        )
                    )
                    self._record_direct_child_delete_inference(
                        current_instruction.parent_directory_state,
                        different_filesystem_assessment,
                    )
                    self._close_owned_file_descriptor(
                        current_instruction.object_file_descriptor,
                        owned_file_descriptors,
                    )
                    yield different_filesystem_assessment
                    continue

                if filesystem_object_kind != FILESYSTEM_OBJECT_KIND_DIRECTORY:
                    evidence_cache = self._captured_object_evidence_cache(
                        evidence_path=current_instruction.evidence_path,
                        object_file_descriptor=(
                            current_instruction.object_file_descriptor
                        ),
                        parent_directory_evidence_path=(
                            current_instruction.parent_directory_evidence_path
                        ),
                        parent_directory_file_descriptor=(
                            current_instruction.parent_directory_file_descriptor
                        ),
                    )
                    leaf_assessment = self.assess_non_directory_path(
                        current_instruction.evidence_path,
                        current_metadata,
                        filesystem_object_kind,
                        normalized_selected_capabilities,
                        audited_path=current_path,
                        parent_directory_path=(
                            current_instruction.parent_directory_evidence_path
                        ),
                        parent_directory_file_descriptor=(
                            current_instruction.parent_directory_file_descriptor
                        ),
                        directory_entry_name=(current_instruction.directory_entry_name),
                        evidence_cache=evidence_cache,
                    )
                    if current_instruction.observation_notes:
                        leaf_assessment = self._assessment_with_observation_notes(
                            leaf_assessment,
                            current_instruction.observation_notes,
                        )
                    if (
                        current_instruction.path_was_explicitly_requested
                        and current_instruction.directory_entry_name in {".", ".."}
                    ):
                        leaf_assessment = (
                            self._assessment_with_unremovable_dot_component(
                                leaf_assessment
                            )
                        )
                    identity_instability = self._entry_identity_instability_reason(
                        parent_directory_file_descriptor=(
                            current_instruction.parent_directory_file_descriptor
                        ),
                        directory_entry_name=(current_instruction.directory_entry_name),
                        expected_identity=current_identity,
                        follow_symbolic_link=(
                            current_instruction.entry_lookup_followed_symbolic_link
                        ),
                    )
                    if identity_instability is not None:
                        leaf_assessment = self._assessment_with_identity_instability(
                            leaf_assessment,
                            normalized_selected_capabilities,
                            identity_instability,
                        )
                    self._record_direct_child_delete_inference(
                        current_instruction.parent_directory_state,
                        leaf_assessment,
                    )
                    self._close_owned_file_descriptor(
                        current_instruction.object_file_descriptor,
                        owned_file_descriptors,
                    )
                    yield leaf_assessment
                    continue

                directory_identity = current_identity
                if directory_identity in active_directory_identities:
                    repeated_directory_assessment = (
                        self._same_verdict_for_all_capabilities(
                            filesystem_object_kind=(FILESYSTEM_OBJECT_KIND_DIRECTORY),
                            audited_path=current_path,
                            selected_capabilities=(normalized_selected_capabilities),
                            model_verdict=(MODEL_VERDICT_INSUFFICIENT_EVIDENCE),
                            evidence_reasons=(
                                EvidenceReason(
                                    "directory_identity_is_already_active",
                                    evidence_source="lstat.st_dev/st_ino",
                                    detail=(
                                        f"device={directory_identity.device_number};"
                                        f" inode={directory_identity.inode_number}"
                                    ),
                                ),
                            ),
                        )
                    )
                    self._record_direct_child_delete_inference(
                        current_instruction.parent_directory_state,
                        repeated_directory_assessment,
                    )
                    self._close_owned_file_descriptor(
                        current_instruction.object_file_descriptor,
                        owned_file_descriptors,
                    )
                    yield repeated_directory_assessment
                    continue

                try:
                    opened_directory = self._open_directory_for_listing(
                        current_instruction.object_file_descriptor,
                    )
                    directory_iterator = opened_directory.directory_iterator
                    open_directory_iterators.append(directory_iterator)
                    directory_observation_notes = [
                        *current_instruction.observation_notes,
                        *opened_directory.observation_notes,
                    ]
                    if opened_directory.noatime_was_used:
                        directory_observation_notes.append(
                            EvidenceReason(
                                "directory_was_opened_with_o_noatime",
                                evidence_source="openat(O_NOATIME)",
                            )
                        )
                    directory_identity_matched = (
                        opened_directory.opened_directory_identity == directory_identity
                    )
                    directory_listing_failure = (
                        None
                        if directory_identity_matched
                        else EvidenceReason(
                            "directory_identity_changed_between_capture_and_listing",
                            evidence_source="fstat st_dev/st_ino",
                        )
                    )
                    if not directory_identity_matched:
                        with contextlib.suppress(OSError):
                            directory_iterator.close()
                        open_directory_iterators.remove(directory_iterator)
                        directory_iterator = None
                except OSError as error:
                    directory_iterator = None
                    directory_identity_matched = None
                    directory_observation_notes = list(
                        current_instruction.observation_notes
                    )
                    directory_listing_failure = operating_system_error_reason(
                        "cannot_list_directory",
                        error,
                        evidence_source="openat/os.scandir",
                    )

                directory_state = DirectoryPostorderAssessmentState(
                    directory_path=current_path,
                    directory_evidence_path=current_instruction.evidence_path,
                    directory_metadata=current_metadata,
                    directory_identity=directory_identity,
                    directory_file_descriptor=(
                        current_instruction.object_file_descriptor
                    ),
                    parent_directory_file_descriptor=(
                        current_instruction.parent_directory_file_descriptor
                    ),
                    parent_directory_evidence_path=(
                        current_instruction.parent_directory_evidence_path
                    ),
                    directory_entry_name=current_instruction.directory_entry_name,
                    entry_lookup_followed_symbolic_link=(
                        current_instruction.entry_lookup_followed_symbolic_link
                    ),
                    path_was_explicitly_requested=(
                        current_instruction.path_was_explicitly_requested
                    ),
                    directory_iterator=directory_iterator,
                    parent_directory_state=(current_instruction.parent_directory_state),
                    directory_listing_failure=directory_listing_failure,
                    directory_observation_notes=directory_observation_notes,
                    opened_directory_identity_matched_lstat=(
                        directory_identity_matched
                    ),
                )
                active_directory_identities.add(directory_identity)
                if directory_iterator is None:
                    pending_instructions.append(
                        EmitDirectoryTraversalInstruction(directory_state)
                    )
                else:
                    pending_instructions.append(
                        ContinueDirectoryTraversalInstruction(directory_state)
                    )
        finally:
            for directory_iterator in reversed(open_directory_iterators):
                with contextlib.suppress(OSError):
                    directory_iterator.close()
            for file_descriptor in tuple(owned_file_descriptors):
                with contextlib.suppress(OSError):
                    os.close(file_descriptor)
            active_directory_identities.clear()

    @staticmethod
    def _captured_object_evidence_cache(
        *,
        evidence_path: str,
        object_file_descriptor: int,
        parent_directory_evidence_path: str,
        parent_directory_file_descriptor: int,
    ) -> PathAssessmentEvidenceCache:
        return PathAssessmentEvidenceCache(
            file_descriptor_by_path_and_follow_mode={
                (evidence_path, False): object_file_descriptor,
                (evidence_path, True): object_file_descriptor,
                (parent_directory_evidence_path, False): (
                    parent_directory_file_descriptor
                ),
                (parent_directory_evidence_path, True): (
                    parent_directory_file_descriptor
                ),
            },
            access_file_descriptor_by_path={
                evidence_path: object_file_descriptor,
                parent_directory_evidence_path: parent_directory_file_descriptor,
            },
        )

    @staticmethod
    def _close_owned_file_descriptor(
        file_descriptor: int,
        owned_file_descriptors: set[int],
    ) -> None:
        if file_descriptor not in owned_file_descriptors:
            return
        os.close(file_descriptor)
        owned_file_descriptors.remove(file_descriptor)

    @staticmethod
    def _close_directory_iterator(
        directory_state: DirectoryPostorderAssessmentState,
        open_directory_iterators: list[os.ScandirIterator],
    ) -> None:
        directory_iterator = directory_state.directory_iterator
        if directory_iterator is None:
            return
        try:
            directory_iterator.close()
        except OSError as error:
            close_reason = operating_system_error_reason(
                "cannot_close_directory_iterator",
                error,
                evidence_source="os.ScandirIterator.close",
            )
            if directory_state.directory_listing_failure is None:
                directory_state.directory_listing_failure = close_reason
            else:
                directory_state.directory_observation_notes.append(close_reason)
        finally:
            directory_state.directory_iterator = None
            with contextlib.suppress(ValueError):
                open_directory_iterators.remove(directory_iterator)

    @staticmethod
    def _entry_identity_instability_reason(
        *,
        parent_directory_file_descriptor: int,
        directory_entry_name: str,
        expected_identity: FilesystemObjectIdentity,
        follow_symbolic_link: bool,
    ) -> EvidenceReason | None:
        try:
            current_metadata = os.stat(
                directory_entry_name,
                dir_fd=parent_directory_file_descriptor,
                follow_symlinks=follow_symbolic_link,
            )
        except OSError as error:
            return operating_system_error_reason(
                "directory_entry_changed_after_descriptor_capture",
                error,
                evidence_source="fstatat(2)",
            )
        current_identity = FilesystemObjectIdentity.from_stat_result(current_metadata)
        if current_identity == expected_identity:
            return None
        return EvidenceReason(
            "directory_entry_identity_changed_after_descriptor_capture",
            evidence_source="fstat/fstatat st_dev/st_ino",
            detail=f"captured={expected_identity}; current={current_identity}",
        )

    @staticmethod
    def _assessment_with_observation_notes(
        assessment: PathCapabilityAssessment,
        additional_notes: Iterable[EvidenceReason],
    ) -> PathCapabilityAssessment:
        return PathCapabilityAssessment(
            filesystem_object_kind=assessment.filesystem_object_kind,
            audited_path=assessment.audited_path,
            inference_by_capability_name=assessment.inference_by_capability_name,
            assessment_completed_at_utc=assessment.assessment_completed_at_utc,
            observation_notes=tuple(
                deduplicate_preserving_first_occurrence(
                    (*assessment.observation_notes, *tuple(additional_notes))
                )
            ),
            audited_path_lstat_metadata=assessment.audited_path_lstat_metadata,
            resolved_symbolic_link_target_path=(
                assessment.resolved_symbolic_link_target_path
            ),
            resolved_symbolic_link_target_kind=(
                assessment.resolved_symbolic_link_target_kind
            ),
            resolved_symbolic_link_target_stat_metadata=(
                assessment.resolved_symbolic_link_target_stat_metadata
            ),
        )

    @classmethod
    def _assessment_with_identity_instability(
        cls,
        assessment: PathCapabilityAssessment,
        selected_capabilities: Sequence[str],
        instability_reason: EvidenceReason,
    ) -> PathCapabilityAssessment:
        uncertain_inferences = {
            capability_name: capability_inference(
                capability_name,
                MODEL_VERDICT_INSUFFICIENT_EVIDENCE,
                (
                    *assessment.inference_for_capability(
                        capability_name
                    ).evidence_reasons,
                    instability_reason,
                ),
            )
            for capability_name in selected_capabilities
        }
        return PathCapabilityAssessment(
            filesystem_object_kind=assessment.filesystem_object_kind,
            audited_path=assessment.audited_path,
            inference_by_capability_name=uncertain_inferences,
            assessment_completed_at_utc=assessment.assessment_completed_at_utc,
            observation_notes=assessment.observation_notes,
            audited_path_lstat_metadata=assessment.audited_path_lstat_metadata,
            resolved_symbolic_link_target_path=(
                assessment.resolved_symbolic_link_target_path
            ),
            resolved_symbolic_link_target_kind=(
                assessment.resolved_symbolic_link_target_kind
            ),
            resolved_symbolic_link_target_stat_metadata=(
                assessment.resolved_symbolic_link_target_stat_metadata
            ),
        )

    @staticmethod
    def _assessment_with_unremovable_dot_component(
        assessment: PathCapabilityAssessment,
    ) -> PathCapabilityAssessment:
        delete_inference = assessment.inference_by_capability_name.get(
            CAPABILITY_DELETE_ENTRY_OR_TREE
        )
        if delete_inference is None:
            return assessment
        updated_inferences = dict(assessment.inference_by_capability_name)
        updated_inferences[CAPABILITY_DELETE_ENTRY_OR_TREE] = capability_inference(
            CAPABILITY_DELETE_ENTRY_OR_TREE,
            MODEL_VERDICT_INDICATES_BLOCKED,
            (
                *delete_inference.evidence_reasons,
                EvidenceReason(
                    "requested_final_dot_component_cannot_be_removed",
                    evidence_source="unlinkat(2)/rmdir(2) pathname semantics",
                ),
            ),
        )
        return PathCapabilityAssessment(
            filesystem_object_kind=assessment.filesystem_object_kind,
            audited_path=assessment.audited_path,
            inference_by_capability_name=updated_inferences,
            assessment_completed_at_utc=assessment.assessment_completed_at_utc,
            observation_notes=assessment.observation_notes,
            audited_path_lstat_metadata=assessment.audited_path_lstat_metadata,
            resolved_symbolic_link_target_path=(
                assessment.resolved_symbolic_link_target_path
            ),
            resolved_symbolic_link_target_kind=(
                assessment.resolved_symbolic_link_target_kind
            ),
            resolved_symbolic_link_target_stat_metadata=(
                assessment.resolved_symbolic_link_target_stat_metadata
            ),
        )

    @staticmethod
    def _record_direct_child_delete_inference(
        parent_directory_state: DirectoryPostorderAssessmentState | None,
        child_assessment: PathCapabilityAssessment,
    ) -> None:
        if parent_directory_state is None:
            return
        child_delete_inference = child_assessment.inference_by_capability_name.get(
            CAPABILITY_DELETE_ENTRY_OR_TREE
        )
        if child_delete_inference is None:
            return
        if child_delete_inference.model_verdict == MODEL_VERDICT_INSUFFICIENT_EVIDENCE:
            parent_directory_state.has_child_with_uncertain_delete_inference = True
        elif child_delete_inference.model_verdict in {
            MODEL_VERDICT_INDICATES_BLOCKED,
            MODEL_VERDICT_SKIPPED,
        }:
            (
                parent_directory_state.has_child_with_blocked_or_skipped_delete_inference
            ) = True

    @staticmethod
    def _open_directory_for_listing(
        directory_file_descriptor: int,
    ) -> OpenDirectoryForListingEvidence:
        directory_open_flags = os.O_RDONLY
        directory_open_flags |= getattr(os, "O_CLOEXEC", 0)
        directory_open_flags |= getattr(os, "O_DIRECTORY", 0)
        directory_open_flags |= getattr(os, "O_NOFOLLOW", 0)
        noatime_open_flag = getattr(os, "O_NOATIME", 0)

        if noatime_open_flag:
            try:
                readable_directory_file_descriptor = os.open(
                    ".",
                    directory_open_flags | noatime_open_flag,
                    dir_fd=directory_file_descriptor,
                )
                try:
                    opened_directory_identity = (
                        FilesystemObjectIdentity.from_stat_result(
                            os.fstat(readable_directory_file_descriptor)
                        )
                    )
                    directory_iterator = os.scandir(readable_directory_file_descriptor)
                except BaseException:
                    os.close(readable_directory_file_descriptor)
                    raise
                os.close(readable_directory_file_descriptor)
                return OpenDirectoryForListingEvidence(
                    directory_iterator=directory_iterator,
                    opened_directory_identity=opened_directory_identity,
                    noatime_was_used=True,
                    observation_notes=(),
                )
            except OSError as error:
                noatime_retry_errno_numbers = {
                    errno.EACCES,
                    errno.EINVAL,
                    errno.EPERM,
                    getattr(errno, "ENOTSUP", errno.EOPNOTSUPP),
                    errno.EOPNOTSUPP,
                }
                if error.errno not in noatime_retry_errno_numbers:
                    raise
                noatime_fallback_reason = operating_system_error_reason(
                    "directory_read_retried_without_o_noatime",
                    error,
                    evidence_source="os.open(O_NOATIME)",
                )
        else:
            noatime_fallback_reason = EvidenceReason(
                "python_runtime_does_not_expose_o_noatime",
                evidence_source="os.O_NOATIME",
            )

        readable_directory_file_descriptor = os.open(
            ".",
            directory_open_flags,
            dir_fd=directory_file_descriptor,
        )
        try:
            opened_directory_identity = FilesystemObjectIdentity.from_stat_result(
                os.fstat(readable_directory_file_descriptor)
            )
            directory_iterator = os.scandir(readable_directory_file_descriptor)
        except BaseException:
            os.close(readable_directory_file_descriptor)
            raise
        os.close(readable_directory_file_descriptor)
        return OpenDirectoryForListingEvidence(
            directory_iterator=directory_iterator,
            opened_directory_identity=opened_directory_identity,
            noatime_was_used=False,
            observation_notes=(noatime_fallback_reason,),
        )

    def _assessment_if_excluded(
        self,
        path: str,
        selected_capabilities: Sequence[str],
        *,
        filesystem_metadata: os.stat_result | None = None,
    ) -> PathCapabilityAssessment | None:
        if path_matches_any_exclusion_rule(path, self.exclusion_rules):
            try:
                excluded_path_metadata = (
                    filesystem_metadata
                    if filesystem_metadata is not None
                    else os.lstat(path)
                )
                excluded_object_kind = classify_filesystem_object_kind(
                    excluded_path_metadata
                )
            except OSError:
                excluded_path_metadata = None
                excluded_object_kind = FILESYSTEM_OBJECT_KIND_UNOBSERVED
            return self._same_verdict_for_all_capabilities(
                filesystem_object_kind=excluded_object_kind,
                audited_path=path,
                selected_capabilities=selected_capabilities,
                model_verdict=MODEL_VERDICT_SKIPPED,
                evidence_reasons=(
                    EvidenceReason(
                        "path_matches_exclusion_rule",
                        evidence_source="audit configuration",
                    ),
                ),
                audited_path_lstat_metadata=(
                    None
                    if excluded_path_metadata is None
                    else ObservedLinuxFilesystemObjectMetadata.from_stat_result(
                        excluded_path_metadata
                    )
                ),
            )

        return None

    @staticmethod
    def _same_verdict_for_all_capabilities(
        *,
        filesystem_object_kind: str,
        audited_path: str,
        selected_capabilities: Sequence[str],
        model_verdict: str,
        evidence_reasons: Iterable[EvidenceReason],
        observation_notes: Iterable[EvidenceReason] = (),
        audited_path_lstat_metadata: (
            ObservedLinuxFilesystemObjectMetadata | None
        ) = None,
    ) -> PathCapabilityAssessment:
        ordered_reasons = tuple(
            deduplicate_preserving_first_occurrence(evidence_reasons)
        )
        return PathCapabilityAssessment(
            filesystem_object_kind=filesystem_object_kind,
            audited_path=audited_path,
            inference_by_capability_name={
                capability_name: capability_inference(
                    capability_name,
                    model_verdict,
                    ordered_reasons,
                )
                for capability_name in selected_capabilities
            },
            observation_notes=tuple(observation_notes),
            audited_path_lstat_metadata=audited_path_lstat_metadata,
        )

    def assess_explicitly_requested_missing_path(
        self,
        missing_path: str,
        selected_capabilities: Sequence[str],
        *,
        parent_directory_path: str | None = None,
        parent_directory_metadata: os.stat_result | None = None,
        parent_directory_file_descriptor: int | None = None,
    ) -> PathCapabilityAssessment:
        evidence_cache = PathAssessmentEvidenceCache()
        if (
            parent_directory_path is not None
            and parent_directory_file_descriptor is not None
        ):
            evidence_cache.file_descriptor_by_path_and_follow_mode.update(
                {
                    (parent_directory_path, False): parent_directory_file_descriptor,
                    (parent_directory_path, True): parent_directory_file_descriptor,
                }
            )
            evidence_cache.access_file_descriptor_by_path[parent_directory_path] = (
                parent_directory_file_descriptor
            )
        inference_by_capability_name: dict[str, CapabilityModelInference] = {}
        for capability_name in selected_capabilities:
            if capability_name == CAPABILITY_CREATE_DIRECTORY_ENTRY:
                inference_by_capability_name[capability_name] = (
                    self.infer_create_explicit_missing_path(
                        missing_path,
                        parent_directory_path=parent_directory_path,
                        parent_directory_metadata=parent_directory_metadata,
                        evidence_cache=evidence_cache,
                    )
                )
            else:
                inference_by_capability_name[capability_name] = capability_inference(
                    capability_name,
                    MODEL_VERDICT_INDICATES_BLOCKED,
                    (
                        EvidenceReason(
                            "audited_path_is_missing",
                            evidence_source="os.lstat",
                        ),
                    ),
                )
        return PathCapabilityAssessment(
            filesystem_object_kind=FILESYSTEM_OBJECT_KIND_MISSING,
            audited_path=missing_path,
            inference_by_capability_name=inference_by_capability_name,
        )

    def assess_non_directory_path(
        self,
        path: str,
        path_metadata: os.stat_result,
        filesystem_object_kind: str,
        selected_capabilities: Sequence[str],
        *,
        audited_path: str | None = None,
        parent_directory_path: str | None = None,
        parent_directory_file_descriptor: int | None = None,
        directory_entry_name: str | None = None,
        evidence_cache: PathAssessmentEvidenceCache | None = None,
    ) -> PathCapabilityAssessment:
        displayed_path = path if audited_path is None else audited_path
        if filesystem_object_kind == FILESYSTEM_OBJECT_KIND_SYMBOLIC_LINK:
            return self.assess_symbolic_link(
                path,
                path_metadata,
                selected_capabilities,
                audited_path=displayed_path,
                parent_directory_path=parent_directory_path,
                parent_directory_file_descriptor=parent_directory_file_descriptor,
                directory_entry_name=directory_entry_name,
                evidence_cache=evidence_cache,
            )

        if evidence_cache is None:
            evidence_cache = PathAssessmentEvidenceCache()
        inference_by_capability_name: dict[str, CapabilityModelInference] = {}
        for capability_name in selected_capabilities:
            if capability_name == CAPABILITY_DELETE_ENTRY_OR_TREE:
                inference_by_capability_name[capability_name] = (
                    self.infer_delete_entry_or_tree(
                        path,
                        path_metadata,
                        has_uncertain_descendant_delete=False,
                        has_blocked_descendant_delete=False,
                        directory_listing_failure=None,
                        evidence_cache=evidence_cache,
                        parent_directory_path=parent_directory_path,
                    )
                )
            elif capability_name == CAPABILITY_APPEND_REGULAR_FILE_CONTENT:
                inference_by_capability_name[capability_name] = (
                    self.infer_regular_file_content_mutation(
                        path,
                        filesystem_object_kind,
                        CAPABILITY_APPEND_REGULAR_FILE_CONTENT,
                        evidence_cache=evidence_cache,
                        target_metadata=path_metadata,
                    )
                )
            elif capability_name == CAPABILITY_OVERWRITE_REGULAR_FILE_CONTENT:
                inference_by_capability_name[capability_name] = (
                    self.infer_regular_file_content_mutation(
                        path,
                        filesystem_object_kind,
                        CAPABILITY_OVERWRITE_REGULAR_FILE_CONTENT,
                        evidence_cache=evidence_cache,
                        target_metadata=path_metadata,
                    )
                )
            elif capability_name == CAPABILITY_CREATE_DIRECTORY_ENTRY:
                inference_by_capability_name[capability_name] = capability_inference(
                    capability_name,
                    MODEL_VERDICT_INDICATES_BLOCKED,
                    (
                        EvidenceReason(
                            "audited_object_is_not_a_directory",
                            evidence_source="lstat.st_mode",
                            detail=filesystem_object_kind,
                        ),
                    ),
                )
            elif capability_name == CAPABILITY_SPECIAL_FILE_WRITE_PERMISSION:
                inference_by_capability_name[capability_name] = (
                    self.infer_special_file_write_permission(
                        path,
                        filesystem_object_kind,
                        evidence_cache=evidence_cache,
                        target_metadata=path_metadata,
                    )
                )

        return PathCapabilityAssessment(
            filesystem_object_kind=filesystem_object_kind,
            audited_path=displayed_path,
            inference_by_capability_name=inference_by_capability_name,
            audited_path_lstat_metadata=(
                ObservedLinuxFilesystemObjectMetadata.from_stat_result(path_metadata)
            ),
        )

    def assess_symbolic_link(
        self,
        symbolic_link_path: str,
        symbolic_link_metadata: os.stat_result,
        selected_capabilities: Sequence[str],
        *,
        audited_path: str | None = None,
        parent_directory_path: str | None = None,
        parent_directory_file_descriptor: int | None = None,
        directory_entry_name: str | None = None,
        evidence_cache: PathAssessmentEvidenceCache | None = None,
    ) -> PathCapabilityAssessment:
        displayed_symbolic_link_path = (
            symbolic_link_path if audited_path is None else audited_path
        )
        if evidence_cache is None:
            evidence_cache = PathAssessmentEvidenceCache()
        inference_by_capability_name: dict[str, CapabilityModelInference] = {}
        resolved_target_path: str | None = None
        target_path_resolution_note: EvidenceReason | None = None
        target_metadata: os.stat_result | None = None
        target_kind: str | None = None
        target_stat_error: OSError | None = None

        target_following_capability_is_selected = any(
            capability_name != CAPABILITY_DELETE_ENTRY_OR_TREE
            for capability_name in selected_capabilities
        )
        if target_following_capability_is_selected:
            link_file_descriptor = (
                evidence_cache.file_descriptor_by_path_and_follow_mode.get(
                    (symbolic_link_path, False)
                )
            )
            (
                resolved_target_path,
                target_path_resolution_note,
            ) = self._observe_symbolic_link_target_path(
                displayed_symbolic_link_path,
                symbolic_link_file_descriptor=link_file_descriptor,
            )
            target_file_descriptor: int | None = None
            try:
                if (
                    parent_directory_file_descriptor is not None
                    and directory_entry_name is not None
                ):
                    target_file_descriptor = os.open(
                        directory_entry_name,
                        getattr(os, "O_PATH", 0o10000000) | getattr(os, "O_CLOEXEC", 0),
                        dir_fd=parent_directory_file_descriptor,
                    )
                    target_metadata = os.fstat(target_file_descriptor)
                    (
                        resolved_target_path,
                        target_display_note,
                    ) = observe_canonical_path_for_file_descriptor(
                        target_file_descriptor,
                        fallback_path=resolved_target_path
                        or displayed_symbolic_link_path,
                    )
                    if target_display_note is not None:
                        target_path_resolution_note = target_display_note
                    evidence_cache.file_descriptor_by_path_and_follow_mode[
                        (symbolic_link_path, True)
                    ] = target_file_descriptor
                    evidence_cache.access_file_descriptor_by_path[
                        symbolic_link_path
                    ] = target_file_descriptor
                    # Capture every target query used by the selected
                    # capabilities before closing this short-lived descriptor.
                    self._observe_inode_attributes_within_path_assessment(
                        symbolic_link_path,
                        follow_final_symbolic_link=True,
                        evidence_cache=evidence_cache,
                    )
                    self._lookup_mount_within_path_assessment(
                        symbolic_link_path,
                        follow_final_symbolic_link=True,
                        evidence_cache=evidence_cache,
                    )
                    for access_mode in (os.W_OK, os.X_OK, os.W_OK | os.X_OK):
                        self._ask_kernel_about_access_within_path_assessment(
                            symbolic_link_path,
                            access_mode,
                            evidence_cache=evidence_cache,
                        )
                else:
                    target_metadata = os.stat(symbolic_link_path)
                target_kind = classify_filesystem_object_kind(target_metadata)
            except OSError as error:
                target_stat_error = error
                if error.errno == errno.ENOENT:
                    target_kind = FILESYSTEM_OBJECT_KIND_MISSING
                else:
                    target_kind = FILESYSTEM_OBJECT_KIND_UNOBSERVED
            finally:
                if target_file_descriptor is not None:
                    os.close(target_file_descriptor)
                    evidence_cache.file_descriptor_by_path_and_follow_mode.pop(
                        (symbolic_link_path, True),
                        None,
                    )
                    evidence_cache.access_file_descriptor_by_path.pop(
                        symbolic_link_path,
                        None,
                    )

        for capability_name in selected_capabilities:
            if capability_name == CAPABILITY_DELETE_ENTRY_OR_TREE:
                inference_by_capability_name[capability_name] = (
                    self.infer_delete_entry_or_tree(
                        symbolic_link_path,
                        symbolic_link_metadata,
                        has_uncertain_descendant_delete=False,
                        has_blocked_descendant_delete=False,
                        directory_listing_failure=None,
                        evidence_cache=evidence_cache,
                        parent_directory_path=parent_directory_path,
                    )
                )
                continue

            if (
                target_stat_error is not None
                and target_stat_error.errno != errno.ENOENT
            ):
                inference_by_capability_name[capability_name] = capability_inference(
                    capability_name,
                    MODEL_VERDICT_INSUFFICIENT_EVIDENCE,
                    (
                        operating_system_error_reason(
                            "cannot_observe_symbolic_link_target",
                            target_stat_error,
                            evidence_source="os.stat",
                        ),
                    ),
                )
                continue

            if capability_name == CAPABILITY_APPEND_REGULAR_FILE_CONTENT:
                if target_kind == FILESYSTEM_OBJECT_KIND_REGULAR_FILE:
                    inference_by_capability_name[capability_name] = (
                        add_observation_reasons_to_inference(
                            self.infer_regular_file_content_mutation(
                                symbolic_link_path,
                                FILESYSTEM_OBJECT_KIND_REGULAR_FILE,
                                CAPABILITY_APPEND_REGULAR_FILE_CONTENT,
                                evidence_cache=evidence_cache,
                                target_metadata=target_metadata,
                            ),
                            (
                                EvidenceReason(
                                    "capability_is_evaluated_through_symbolic_link",
                                    evidence_source=CAPABILITY_MODEL_ID,
                                ),
                            ),
                        )
                    )
                else:
                    inference_by_capability_name[capability_name] = (
                        capability_inference(
                            capability_name,
                            MODEL_VERDICT_INDICATES_BLOCKED,
                            (
                                EvidenceReason(
                                    "symbolic_link_target_is_not_a_regular_file",
                                    evidence_source="os.stat",
                                    detail=target_kind,
                                ),
                            ),
                        )
                    )
            elif capability_name == CAPABILITY_OVERWRITE_REGULAR_FILE_CONTENT:
                if target_kind == FILESYSTEM_OBJECT_KIND_REGULAR_FILE:
                    inference_by_capability_name[capability_name] = (
                        add_observation_reasons_to_inference(
                            self.infer_regular_file_content_mutation(
                                symbolic_link_path,
                                FILESYSTEM_OBJECT_KIND_REGULAR_FILE,
                                CAPABILITY_OVERWRITE_REGULAR_FILE_CONTENT,
                                evidence_cache=evidence_cache,
                                target_metadata=target_metadata,
                            ),
                            (
                                EvidenceReason(
                                    "capability_is_evaluated_through_symbolic_link",
                                    evidence_source=CAPABILITY_MODEL_ID,
                                ),
                            ),
                        )
                    )
                else:
                    inference_by_capability_name[capability_name] = (
                        capability_inference(
                            capability_name,
                            MODEL_VERDICT_INDICATES_BLOCKED,
                            (
                                EvidenceReason(
                                    "symbolic_link_target_is_not_a_regular_file",
                                    evidence_source="os.stat",
                                    detail=target_kind,
                                ),
                            ),
                        )
                    )
            elif capability_name == CAPABILITY_CREATE_DIRECTORY_ENTRY:
                if (
                    target_kind == FILESYSTEM_OBJECT_KIND_DIRECTORY
                    and target_metadata is not None
                ):
                    inference_by_capability_name[capability_name] = (
                        add_observation_reasons_to_inference(
                            self.infer_create_child_in_directory(
                                symbolic_link_path,
                                target_metadata,
                                evidence_cache=evidence_cache,
                            ),
                            (
                                EvidenceReason(
                                    "directory_creation_is_evaluated_through_symbolic_link",
                                    evidence_source=CAPABILITY_MODEL_ID,
                                ),
                            ),
                        )
                    )
                elif target_kind == FILESYSTEM_OBJECT_KIND_MISSING:
                    inference_by_capability_name[capability_name] = (
                        capability_inference(
                            capability_name,
                            MODEL_VERDICT_INDICATES_BLOCKED,
                            (
                                EvidenceReason(
                                    "symbolic_link_with_missing_target_cannot_create_a_child_entry",
                                    evidence_source="os.stat",
                                    detail=resolved_target_path,
                                ),
                            ),
                        )
                    )
                else:
                    inference_by_capability_name[capability_name] = (
                        capability_inference(
                            capability_name,
                            MODEL_VERDICT_INDICATES_BLOCKED,
                            (
                                EvidenceReason(
                                    "symbolic_link_target_is_not_a_directory",
                                    evidence_source="os.stat",
                                    detail=target_kind,
                                ),
                            ),
                        )
                    )
            elif capability_name == CAPABILITY_SPECIAL_FILE_WRITE_PERMISSION:
                if target_kind is not None and filesystem_object_kind_is_special_file(
                    target_kind
                ):
                    inference_by_capability_name[capability_name] = (
                        add_observation_reasons_to_inference(
                            self.infer_special_file_write_permission(
                                symbolic_link_path,
                                target_kind,
                                evidence_cache=evidence_cache,
                                target_metadata=target_metadata,
                            ),
                            (
                                EvidenceReason(
                                    "special_file_permission_is_evaluated_through_symbolic_link",
                                    evidence_source=CAPABILITY_MODEL_ID,
                                ),
                            ),
                        )
                    )
                else:
                    inference_by_capability_name[capability_name] = (
                        capability_inference(
                            capability_name,
                            MODEL_VERDICT_INDICATES_BLOCKED,
                            (
                                EvidenceReason(
                                    "symbolic_link_target_is_not_a_special_file",
                                    evidence_source="os.stat",
                                    detail=target_kind,
                                ),
                            ),
                        )
                    )

        return PathCapabilityAssessment(
            filesystem_object_kind=FILESYSTEM_OBJECT_KIND_SYMBOLIC_LINK,
            audited_path=displayed_symbolic_link_path,
            inference_by_capability_name=inference_by_capability_name,
            observation_notes=(
                ()
                if target_path_resolution_note is None
                else (target_path_resolution_note,)
            ),
            audited_path_lstat_metadata=(
                ObservedLinuxFilesystemObjectMetadata.from_stat_result(
                    symbolic_link_metadata
                )
            ),
            resolved_symbolic_link_target_path=resolved_target_path,
            resolved_symbolic_link_target_kind=target_kind,
            resolved_symbolic_link_target_stat_metadata=(
                None
                if target_metadata is None
                else ObservedLinuxFilesystemObjectMetadata.from_stat_result(
                    target_metadata
                )
            ),
        )

    @staticmethod
    def _observe_symbolic_link_target_path(
        symbolic_link_path: str,
        *,
        symbolic_link_file_descriptor: int | None = None,
    ) -> tuple[str | None, EvidenceReason | None]:
        try:
            raw_link_target = (
                os.readlink("", dir_fd=symbolic_link_file_descriptor)
                if symbolic_link_file_descriptor is not None
                else os.readlink(symbolic_link_path)
            )
        except OSError as error:
            return (
                None,
                operating_system_error_reason(
                    "cannot_read_symbolic_link_target_path",
                    error,
                    evidence_source="os.readlink",
                ),
            )

        if os.path.isabs(raw_link_target):
            immediate_target_path = raw_link_target
        else:
            immediate_target_path = os.path.join(
                os.path.dirname(symbolic_link_path),
                raw_link_target,
            )
        try:
            best_effort_resolved_target = os.path.realpath(immediate_target_path)
            return (
                lexically_normalize_absolute_path(best_effort_resolved_target),
                None,
            )
        except (OSError, TypeError, ValueError) as resolution_error:
            try:
                return (
                    lexically_normalize_absolute_path(immediate_target_path),
                    EvidenceReason(
                        "symbolic_link_target_path_was_only_lexically_normalized",
                        evidence_source="os.path.realpath",
                        detail=str(resolution_error),
                    ),
                )
            except (
                OSError,
                TypeError,
                ValueError,
            ) as normalization_error:
                return (
                    None,
                    EvidenceReason(
                        "cannot_resolve_symbolic_link_target_path",
                        evidence_source="os.readlink/os.path.realpath",
                        detail=(
                            f"resolution_error={resolution_error}; "
                            f"normalization_error={normalization_error}"
                        ),
                    ),
                )

    def assess_directory(
        self,
        directory_path: str,
        directory_metadata: os.stat_result,
        selected_capabilities: Sequence[str],
        *,
        audited_path: str | None = None,
        parent_directory_path: str | None = None,
        evidence_cache: PathAssessmentEvidenceCache | None = None,
        has_uncertain_descendant_delete: bool,
        has_blocked_descendant_delete: bool,
        directory_listing_failure: EvidenceReason | None,
        observation_notes: Sequence[EvidenceReason],
        directory_identity_matched_lstat: bool | None,
    ) -> PathCapabilityAssessment:
        displayed_directory_path = (
            directory_path if audited_path is None else audited_path
        )
        complete_observation_notes = tuple(
            deduplicate_preserving_first_occurrence(
                (
                    *observation_notes,
                    *(
                        ()
                        if directory_listing_failure is None
                        else (directory_listing_failure,)
                    ),
                )
            )
        )
        if directory_identity_matched_lstat is False:
            identity_change_reason = directory_listing_failure or EvidenceReason(
                "directory_identity_changed_between_lstat_and_open",
                evidence_source="lstat/fstat st_dev/st_ino",
            )
            return self._same_verdict_for_all_capabilities(
                filesystem_object_kind=FILESYSTEM_OBJECT_KIND_DIRECTORY,
                audited_path=displayed_directory_path,
                selected_capabilities=selected_capabilities,
                model_verdict=MODEL_VERDICT_INSUFFICIENT_EVIDENCE,
                evidence_reasons=(identity_change_reason,),
                observation_notes=complete_observation_notes,
                audited_path_lstat_metadata=(
                    ObservedLinuxFilesystemObjectMetadata.from_stat_result(
                        directory_metadata
                    )
                ),
            )

        if evidence_cache is None:
            evidence_cache = PathAssessmentEvidenceCache()
        inference_by_capability_name: dict[str, CapabilityModelInference] = {}
        for capability_name in selected_capabilities:
            if capability_name == CAPABILITY_DELETE_ENTRY_OR_TREE:
                inference_by_capability_name[capability_name] = (
                    self.infer_delete_entry_or_tree(
                        directory_path,
                        directory_metadata,
                        has_uncertain_descendant_delete=(
                            has_uncertain_descendant_delete
                        ),
                        has_blocked_descendant_delete=(has_blocked_descendant_delete),
                        directory_listing_failure=directory_listing_failure,
                        evidence_cache=evidence_cache,
                        parent_directory_path=parent_directory_path,
                    )
                )
            elif capability_name == CAPABILITY_CREATE_DIRECTORY_ENTRY:
                inference_by_capability_name[capability_name] = (
                    self.infer_create_child_in_directory(
                        directory_path,
                        directory_metadata,
                        evidence_cache=evidence_cache,
                    )
                )
            elif capability_name in {
                CAPABILITY_APPEND_REGULAR_FILE_CONTENT,
                CAPABILITY_OVERWRITE_REGULAR_FILE_CONTENT,
            }:
                inference_by_capability_name[capability_name] = capability_inference(
                    capability_name,
                    MODEL_VERDICT_INDICATES_BLOCKED,
                    (
                        EvidenceReason(
                            "audited_object_is_not_a_regular_file",
                            evidence_source="lstat.st_mode",
                            detail=(FILESYSTEM_OBJECT_KIND_DIRECTORY),
                        ),
                    ),
                )
            elif capability_name == CAPABILITY_SPECIAL_FILE_WRITE_PERMISSION:
                inference_by_capability_name[capability_name] = capability_inference(
                    capability_name,
                    MODEL_VERDICT_INDICATES_BLOCKED,
                    (
                        EvidenceReason(
                            "audited_object_is_not_a_special_file",
                            evidence_source="lstat.st_mode",
                            detail=(FILESYSTEM_OBJECT_KIND_DIRECTORY),
                        ),
                    ),
                )

        return PathCapabilityAssessment(
            filesystem_object_kind=FILESYSTEM_OBJECT_KIND_DIRECTORY,
            audited_path=displayed_directory_path,
            inference_by_capability_name=inference_by_capability_name,
            observation_notes=complete_observation_notes,
            audited_path_lstat_metadata=(
                ObservedLinuxFilesystemObjectMetadata.from_stat_result(
                    directory_metadata
                )
            ),
        )

    def infer_delete_entry_or_tree(
        self,
        path: str,
        target_metadata: os.stat_result,
        *,
        has_uncertain_descendant_delete: bool,
        has_blocked_descendant_delete: bool,
        directory_listing_failure: EvidenceReason | None,
        evidence_cache: PathAssessmentEvidenceCache | None = None,
        parent_directory_path: str | None = None,
    ) -> CapabilityModelInference:
        evidence_reasons: list[EvidenceReason] = []
        model_has_uncertain_evidence = False
        model_has_blocking_evidence = False
        if (
            classify_filesystem_object_kind(target_metadata)
            == FILESYSTEM_OBJECT_KIND_UNRECOGNIZED_STAT_MODE
        ):
            evidence_reasons.append(
                EvidenceReason(
                    "target_stat_mode_file_type_is_unrecognized",
                    evidence_source="lstat.st_mode",
                )
            )
            model_has_uncertain_evidence = True

        target_attribute_evidence = (
            self._observe_inode_attributes_within_path_assessment(
                path,
                follow_final_symbolic_link=False,
                evidence_cache=evidence_cache,
            )
        )
        for (
            attribute_is_set,
            blocking_reason_code,
            clearable_reason_code,
        ) in (
            (
                target_attribute_evidence.immutable_attribute_is_set,
                "target_immutable_attribute_blocks_deletion",
                "target_immutable_attribute_may_be_clearable_before_deletion",
            ),
            (
                target_attribute_evidence.append_only_attribute_is_set,
                "target_append_only_attribute_blocks_deletion",
                "target_append_only_attribute_may_be_clearable_before_deletion",
            ),
        ):
            attribute_reasons, attribute_uncertain, attribute_blocks = (
                self._infer_set_inode_flag_constraint(
                    attribute_is_set=attribute_is_set,
                    inode_owner_user_id=target_metadata.st_uid,
                    blocking_reason_code=blocking_reason_code,
                    potentially_clearable_reason_code=clearable_reason_code,
                )
            )
            evidence_reasons.extend(attribute_reasons)
            model_has_uncertain_evidence |= attribute_uncertain
            model_has_blocking_evidence |= attribute_blocks
        if target_attribute_evidence.evidence_is_uncertain:
            evidence_reasons.extend(target_attribute_evidence.uncertainty_reasons)
            model_has_uncertain_evidence = True

        mountpoint_lookup = self._lookup_mount_within_path_assessment(
            path,
            follow_final_symbolic_link=False,
            evidence_cache=evidence_cache,
        )
        mountpoint_uncertainties = list(mountpoint_lookup.uncertainty_reasons)
        if parent_directory_path is not None:
            parent_mountpoint_lookup = self._lookup_mount_within_path_assessment(
                parent_directory_path,
                follow_final_symbolic_link=True,
                evidence_cache=evidence_cache,
            )
            mountpoint_uncertainties.extend(
                parent_mountpoint_lookup.uncertainty_reasons
            )
            path_is_mountpoint = (
                None
                if mountpoint_uncertainties
                else (
                    mountpoint_lookup.mount_record.mount_id
                    != parent_mountpoint_lookup.mount_record.mount_id
                )
            )
        else:
            path_is_mountpoint = (
                None
                if mountpoint_uncertainties
                else (
                    mountpoint_lookup.resolved_path_used_for_lookup
                    in self.mount_table.visible_mount_by_mountpoint
                )
            )
        if path_is_mountpoint is True:
            evidence_reasons.append(
                EvidenceReason(
                    "visible_mountpoint_is_busy_for_unlink_or_rmdir",
                    evidence_source=LINUX_MOUNTINFO_SOURCE_PATH,
                )
            )
            model_has_blocking_evidence = True
        elif path_is_mountpoint is None:
            evidence_reasons.extend(mountpoint_uncertainties)
            model_has_uncertain_evidence = True

        if parent_directory_path is None:
            parent_directory_path = lexically_normalize_absolute_path(
                os.path.dirname(path) or "/"
            )
        (
            filesystem_uncertainty_reasons,
            filesystem_semantics_are_uncertain,
        ) = self._filesystem_semantics_uncertainty(
            parent_directory_path,
            evidence_cache=evidence_cache,
        )
        evidence_reasons.extend(filesystem_uncertainty_reasons)
        model_has_uncertain_evidence |= filesystem_semantics_are_uncertain

        try:
            # Deletion resolves symbolic links in every parent component.
            # os.stat is therefore intentional; os.lstat would inspect the
            # wrong inode when the lexical parent is itself a symbolic link.
            stable_parent_file_descriptor = (
                None
                if evidence_cache is None
                else evidence_cache.file_descriptor_by_path_and_follow_mode.get(
                    (parent_directory_path, True)
                )
            )
            parent_directory_metadata = (
                os.fstat(stable_parent_file_descriptor)
                if stable_parent_file_descriptor is not None
                else os.stat(parent_directory_path)
            )
        except OSError as error:
            evidence_reasons.append(
                operating_system_error_reason(
                    "cannot_observe_resolved_parent_directory",
                    error,
                    evidence_source="os.stat",
                )
            )
            return capability_inference(
                CAPABILITY_DELETE_ENTRY_OR_TREE,
                MODEL_VERDICT_INSUFFICIENT_EVIDENCE,
                evidence_reasons,
            )

        (
            parent_reasons,
            parent_has_uncertain_evidence,
            parent_has_blocking_evidence,
        ) = self._infer_parent_directory_allows_deletion(
            parent_directory_path,
            parent_directory_metadata,
            target_metadata,
            evidence_cache=evidence_cache,
        )
        evidence_reasons.extend(parent_reasons)
        model_has_uncertain_evidence |= parent_has_uncertain_evidence
        model_has_blocking_evidence |= parent_has_blocking_evidence

        if directory_listing_failure is not None:
            evidence_reasons.append(directory_listing_failure)
            model_has_uncertain_evidence = True
        if has_uncertain_descendant_delete:
            evidence_reasons.append(
                EvidenceReason(
                    "at_least_one_descendant_has_uncertain_delete_inference",
                    evidence_source="postorder traversal aggregation",
                )
            )
            model_has_uncertain_evidence = True
        if has_blocked_descendant_delete:
            evidence_reasons.append(
                EvidenceReason(
                    "at_least_one_descendant_would_remain",
                    evidence_source="postorder traversal aggregation",
                )
            )
            model_has_blocking_evidence = True

        return infer_verdict_from_constraints(
            CAPABILITY_DELETE_ENTRY_OR_TREE,
            model_has_blocking_evidence=model_has_blocking_evidence,
            model_has_uncertain_evidence=model_has_uncertain_evidence,
            evidence_reasons=evidence_reasons,
        )

    def _infer_parent_directory_allows_deletion(
        self,
        parent_directory_path: str,
        parent_directory_metadata: os.stat_result,
        target_metadata: os.stat_result,
        *,
        evidence_cache: PathAssessmentEvidenceCache | None = None,
    ) -> tuple[list[EvidenceReason], bool, bool]:
        evidence_reasons: list[EvidenceReason] = []
        model_has_uncertain_evidence = False
        model_has_blocking_evidence = False

        write_access, search_access = (
            self._ask_kernel_about_write_and_search_within_path_assessment(
                parent_directory_path,
                evidence_cache=evidence_cache,
            )
        )
        for access_evidence, blocked_reason_code in (
            (write_access, "parent_directory_is_not_writable"),
            (search_access, "parent_directory_is_not_searchable"),
        ):
            if access_evidence.access_is_allowed is False:
                access_reasons, access_uncertain, access_blocks = (
                    self._infer_denied_access_constraint(
                        access_evidence=access_evidence,
                        target_metadata=parent_directory_metadata,
                        blocked_reason_code=blocked_reason_code,
                        potentially_changeable_reason_code=(
                            "parent_directory_access_may_be_changeable_by_chmod"
                        ),
                    )
                )
                evidence_reasons.extend(access_reasons)
                model_has_uncertain_evidence |= access_uncertain
                model_has_blocking_evidence |= access_blocks
            elif access_evidence.access_is_allowed is None:
                if access_evidence.uncertainty_reason is not None:
                    evidence_reasons.append(access_evidence.uncertainty_reason)
                model_has_uncertain_evidence = True

        (
            sticky_reasons,
            sticky_is_uncertain,
            sticky_blocks_deletion,
        ) = self._infer_sticky_directory_deletion_constraint(
            parent_directory_metadata,
            target_metadata,
        )
        evidence_reasons.extend(sticky_reasons)
        model_has_uncertain_evidence |= sticky_is_uncertain
        model_has_blocking_evidence |= sticky_blocks_deletion

        (
            mount_reasons,
            mount_is_uncertain,
            mount_blocks_mutation,
        ) = self._infer_mount_write_constraint(
            parent_directory_path,
            read_only_reason_code="parent_directory_mount_is_read_only",
            evidence_cache=evidence_cache,
        )
        evidence_reasons.extend(mount_reasons)
        model_has_uncertain_evidence |= mount_is_uncertain
        model_has_blocking_evidence |= mount_blocks_mutation

        parent_attribute_evidence = (
            self._observe_inode_attributes_within_path_assessment(
                parent_directory_path,
                follow_final_symbolic_link=True,
                evidence_cache=evidence_cache,
            )
        )
        for (
            attribute_is_set,
            blocking_reason_code,
            clearable_reason_code,
        ) in (
            (
                parent_attribute_evidence.immutable_attribute_is_set,
                "parent_directory_immutable_attribute_blocks_deletion",
                "parent_directory_immutable_attribute_may_be_clearable_before_deletion",
            ),
            (
                parent_attribute_evidence.append_only_attribute_is_set,
                "parent_directory_append_only_attribute_blocks_deletion",
                "parent_directory_append_only_attribute_may_be_clearable_before_deletion",
            ),
        ):
            attribute_reasons, attribute_uncertain, attribute_blocks = (
                self._infer_set_inode_flag_constraint(
                    attribute_is_set=attribute_is_set,
                    inode_owner_user_id=parent_directory_metadata.st_uid,
                    blocking_reason_code=blocking_reason_code,
                    potentially_clearable_reason_code=clearable_reason_code,
                )
            )
            evidence_reasons.extend(attribute_reasons)
            model_has_uncertain_evidence |= attribute_uncertain
            model_has_blocking_evidence |= attribute_blocks
        if parent_attribute_evidence.evidence_is_uncertain:
            evidence_reasons.extend(parent_attribute_evidence.uncertainty_reasons)
            model_has_uncertain_evidence = True

        return (
            evidence_reasons,
            model_has_uncertain_evidence,
            model_has_blocking_evidence,
        )

    def _infer_sticky_directory_deletion_constraint(
        self,
        parent_directory_metadata: os.stat_result,
        target_metadata: os.stat_result,
    ) -> tuple[list[EvidenceReason], bool, bool]:
        if not (parent_directory_metadata.st_mode & stat.S_ISVTX):
            return [], False, False

        filesystem_identifier_evidence = self.process_credentials.filesystem_identifiers
        if filesystem_identifier_evidence.uncertainty_reason is not None:
            return (
                [filesystem_identifier_evidence.uncertainty_reason],
                True,
                False,
            )
        filesystem_user_id = filesystem_identifier_evidence.filesystem_user_id
        if filesystem_user_id is None:
            return (
                [
                    EvidenceReason(
                        "filesystem_user_id_is_unobserved_for_sticky_directory",
                        evidence_source=LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH,
                    )
                ],
                True,
                False,
            )
        if filesystem_user_id in {
            parent_directory_metadata.st_uid,
            target_metadata.st_uid,
        }:
            return [], False, False

        fowner_capability_presence = (
            self.process_credentials.effective_capabilities.capability_presence(
                LINUX_CAPABILITY_FOWNER_NUMBER
            )
        )
        if fowner_capability_presence is True:
            return (
                [
                    EvidenceReason(
                        "cap_fowner_is_present_but_its_user_namespace_scope_is_unmodeled",
                        evidence_source=LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH,
                    )
                ],
                True,
                False,
            )
        if fowner_capability_presence is False:
            return (
                [
                    EvidenceReason(
                        "sticky_directory_ownership_rule_blocks_deletion",
                        evidence_source=(
                            "parent/target st_uid, filesystem user ID, and CapEff"
                        ),
                    )
                ],
                False,
                True,
            )

        capability_uncertainty = (
            self.process_credentials.effective_capabilities.uncertainty_reason
        )
        return (
            [
                capability_uncertainty
                or EvidenceReason(
                    "cap_fowner_presence_is_unknown",
                    evidence_source=LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH,
                )
            ],
            True,
            False,
        )

    def _infer_set_inode_flag_constraint(
        self,
        *,
        attribute_is_set: bool | None,
        inode_owner_user_id: int,
        blocking_reason_code: str,
        potentially_clearable_reason_code: str,
    ) -> tuple[list[EvidenceReason], bool, bool]:
        """Model FS_IOC_SETFLAGS authority without claiming namespace scope."""
        if attribute_is_set is not True:
            return [], False, False

        filesystem_identifiers = self.process_credentials.filesystem_identifiers
        if filesystem_identifiers.uncertainty_reason is not None:
            return [filesystem_identifiers.uncertainty_reason], True, False
        filesystem_user_id = filesystem_identifiers.filesystem_user_id
        if filesystem_user_id is None:
            return (
                [
                    EvidenceReason(
                        "filesystem_user_id_is_unobserved_for_inode_flag_change",
                        evidence_source=LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH,
                    )
                ],
                True,
                False,
            )

        effective_capabilities = self.process_credentials.effective_capabilities
        immutable_capability_presence = effective_capabilities.capability_presence(
            LINUX_CAPABILITY_LINUX_IMMUTABLE_NUMBER
        )
        if filesystem_user_id == inode_owner_user_id:
            owner_or_fowner_authority: bool | None = True
        else:
            owner_or_fowner_authority = effective_capabilities.capability_presence(
                LINUX_CAPABILITY_FOWNER_NUMBER
            )

        if immutable_capability_presence is False or owner_or_fowner_authority is False:
            return (
                [
                    EvidenceReason(
                        blocking_reason_code,
                        evidence_source=(
                            "statx attributes, inode st_uid, filesystem UID, and CapEff"
                        ),
                    )
                ],
                False,
                True,
            )
        if immutable_capability_presence is None or owner_or_fowner_authority is None:
            return (
                [
                    effective_capabilities.uncertainty_reason
                    or EvidenceReason(
                        "inode_flag_change_capability_presence_is_unknown",
                        evidence_source=LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH,
                    )
                ],
                True,
                False,
            )

        return (
            [
                EvidenceReason(
                    potentially_clearable_reason_code,
                    evidence_source=(
                        "FS_IOC_SETFLAGS ownership and effective-capability model"
                    ),
                    detail=(
                        "the required capability's governing user-namespace scope "
                        "and the intervening ioctl outcome are not proven"
                    ),
                )
            ],
            True,
            False,
        )

    def _infer_denied_access_constraint(
        self,
        *,
        access_evidence: KernelPathAccessEvidence,
        target_metadata: os.stat_result | None,
        blocked_reason_code: str,
        potentially_changeable_reason_code: str,
    ) -> tuple[list[EvidenceReason], bool, bool]:
        """Avoid treating owner-changeable mode/ACL denial as permanent."""
        if access_evidence.operating_system_errno == errno.EPERM:
            return (
                [
                    EvidenceReason(
                        "access_denial_may_reflect_a_separately_modeled_inode_constraint",
                        evidence_source=access_evidence.evidence_source,
                        operating_system_errno=errno.EPERM,
                        operating_system_message=os.strerror(errno.EPERM),
                    )
                ],
                True,
                False,
            )
        if target_metadata is None:
            return (
                [
                    EvidenceReason(
                        blocked_reason_code,
                        evidence_source=access_evidence.evidence_source,
                    )
                ],
                False,
                True,
            )

        filesystem_identifiers = self.process_credentials.filesystem_identifiers
        if filesystem_identifiers.uncertainty_reason is not None:
            return [filesystem_identifiers.uncertainty_reason], True, False
        filesystem_user_id = filesystem_identifiers.filesystem_user_id
        if filesystem_user_id is None:
            return (
                [
                    EvidenceReason(
                        "filesystem_user_id_is_unobserved_for_chmod_authority",
                        evidence_source=LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH,
                    )
                ],
                True,
                False,
            )

        if filesystem_user_id == target_metadata.st_uid:
            return (
                [
                    EvidenceReason(
                        potentially_changeable_reason_code,
                        evidence_source="inode st_uid and filesystem UID",
                        detail=(
                            "the inode owner may be able to grant the needed "
                            "mode bits with a preceding chmod; that syscall was "
                            "not executed"
                        ),
                    )
                ],
                True,
                False,
            )

        effective_capabilities = self.process_credentials.effective_capabilities
        fowner_capability_presence = effective_capabilities.capability_presence(
            LINUX_CAPABILITY_FOWNER_NUMBER
        )
        if fowner_capability_presence is True:
            return (
                [
                    EvidenceReason(
                        potentially_changeable_reason_code,
                        evidence_source=(
                            f"{LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH} CapEff"
                        ),
                        detail=(
                            "CAP_FOWNER is present, but its governing user-namespace "
                            "scope and a preceding chmod outcome are not proven"
                        ),
                    )
                ],
                True,
                False,
            )
        if fowner_capability_presence is None:
            return (
                [
                    effective_capabilities.uncertainty_reason
                    or EvidenceReason(
                        "cap_fowner_presence_is_unknown_for_chmod_authority",
                        evidence_source=LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH,
                    )
                ],
                True,
                False,
            )
        return (
            [
                EvidenceReason(
                    blocked_reason_code,
                    evidence_source=access_evidence.evidence_source,
                )
            ],
            False,
            True,
        )

    def infer_regular_file_content_mutation(
        self,
        path: str,
        filesystem_object_kind: str,
        requested_content_capability: str,
        *,
        evidence_cache: PathAssessmentEvidenceCache | None = None,
        target_metadata: os.stat_result | None = None,
    ) -> CapabilityModelInference:
        if requested_content_capability not in {
            CAPABILITY_APPEND_REGULAR_FILE_CONTENT,
            CAPABILITY_OVERWRITE_REGULAR_FILE_CONTENT,
        }:
            raise ValueError(
                "regular-file content inference received non-content "
                f"capability {requested_content_capability!r}"
            )
        if filesystem_object_kind != FILESYSTEM_OBJECT_KIND_REGULAR_FILE:
            return capability_inference(
                requested_content_capability,
                MODEL_VERDICT_INDICATES_BLOCKED,
                (
                    EvidenceReason(
                        "audited_object_is_not_a_regular_file",
                        evidence_source="stat.st_mode",
                        detail=filesystem_object_kind,
                    ),
                ),
            )

        evidence_reasons: list[EvidenceReason] = []
        model_has_uncertain_evidence = False
        model_has_blocking_evidence = False

        inode_attribute_evidence = (
            self._observe_inode_attributes_within_path_assessment(
                path,
                follow_final_symbolic_link=True,
                evidence_cache=evidence_cache,
            )
        )
        if inode_attribute_evidence.immutable_attribute_is_set is True:
            if target_metadata is None:
                evidence_reasons.append(
                    EvidenceReason(
                        "target_immutable_attribute_blocks_content_mutation",
                        evidence_source="statx.stx_attributes",
                    )
                )
                model_has_blocking_evidence = True
            else:
                attribute_reasons, attribute_uncertain, attribute_blocks = (
                    self._infer_set_inode_flag_constraint(
                        attribute_is_set=True,
                        inode_owner_user_id=target_metadata.st_uid,
                        blocking_reason_code=(
                            "target_immutable_attribute_blocks_content_mutation"
                        ),
                        potentially_clearable_reason_code=(
                            "target_immutable_attribute_may_be_clearable_before_content_mutation"
                        ),
                    )
                )
                evidence_reasons.extend(attribute_reasons)
                model_has_uncertain_evidence |= attribute_uncertain
                model_has_blocking_evidence |= attribute_blocks
        if inode_attribute_evidence.append_only_attribute_is_set is True:
            if requested_content_capability == CAPABILITY_APPEND_REGULAR_FILE_CONTENT:
                evidence_reasons.append(
                    EvidenceReason(
                        "target_append_only_attribute_allows_append",
                        evidence_source="statx.stx_attributes",
                    )
                )
            else:
                if target_metadata is None:
                    evidence_reasons.append(
                        EvidenceReason(
                            "target_append_only_attribute_blocks_overwrite",
                            evidence_source="statx.stx_attributes",
                        )
                    )
                    model_has_blocking_evidence = True
                else:
                    attribute_reasons, attribute_uncertain, attribute_blocks = (
                        self._infer_set_inode_flag_constraint(
                            attribute_is_set=True,
                            inode_owner_user_id=target_metadata.st_uid,
                            blocking_reason_code=(
                                "target_append_only_attribute_blocks_overwrite"
                            ),
                            potentially_clearable_reason_code=(
                                "target_append_only_attribute_may_be_clearable_before_overwrite"
                            ),
                        )
                    )
                    evidence_reasons.extend(attribute_reasons)
                    model_has_uncertain_evidence |= attribute_uncertain
                    model_has_blocking_evidence |= attribute_blocks
        if inode_attribute_evidence.verity_attribute_is_set is True:
            evidence_reasons.append(
                EvidenceReason(
                    "target_verity_attribute_blocks_content_mutation",
                    evidence_source="statx.stx_attributes",
                )
            )
            model_has_blocking_evidence = True
        elif inode_attribute_evidence.verity_attribute_is_set is None:
            if inode_attribute_evidence.verity_uncertainty_reason is not None:
                evidence_reasons.append(
                    inode_attribute_evidence.verity_uncertainty_reason
                )
            elif not inode_attribute_evidence.evidence_is_uncertain:
                evidence_reasons.append(
                    EvidenceReason(
                        "statx_verity_state_is_unobserved",
                        evidence_source="statx.stx_attributes",
                    )
                )
            model_has_uncertain_evidence = True
        if inode_attribute_evidence.evidence_is_uncertain:
            evidence_reasons.extend(inode_attribute_evidence.uncertainty_reasons)
            model_has_uncertain_evidence = True

        (
            filesystem_uncertainty_reasons,
            filesystem_semantics_are_uncertain,
        ) = self._filesystem_semantics_uncertainty(
            path,
            evidence_cache=evidence_cache,
        )
        evidence_reasons.extend(filesystem_uncertainty_reasons)
        model_has_uncertain_evidence |= filesystem_semantics_are_uncertain

        (
            mount_reasons,
            mount_is_uncertain,
            mount_blocks_mutation,
        ) = self._infer_mount_write_constraint(
            path,
            read_only_reason_code="target_mount_is_read_only",
            evidence_cache=evidence_cache,
        )
        evidence_reasons.extend(mount_reasons)
        model_has_uncertain_evidence |= mount_is_uncertain
        model_has_blocking_evidence |= mount_blocks_mutation

        write_access_evidence = self._ask_kernel_about_access_within_path_assessment(
            path,
            os.W_OK,
            evidence_cache=evidence_cache,
        )
        if write_access_evidence.access_is_allowed is False:
            access_reasons, access_uncertain, access_blocks = (
                self._infer_denied_access_constraint(
                    access_evidence=write_access_evidence,
                    target_metadata=target_metadata,
                    blocked_reason_code=(
                        "target_is_not_writable_by_requested_credential_model"
                    ),
                    potentially_changeable_reason_code=(
                        "target_write_access_may_be_changeable_by_chmod"
                    ),
                )
            )
            evidence_reasons.extend(access_reasons)
            model_has_uncertain_evidence |= access_uncertain
            model_has_blocking_evidence |= access_blocks
        elif write_access_evidence.access_is_allowed is None:
            if write_access_evidence.uncertainty_reason is not None:
                evidence_reasons.append(write_access_evidence.uncertainty_reason)
            model_has_uncertain_evidence = True

        return infer_verdict_from_constraints(
            requested_content_capability,
            model_has_blocking_evidence=model_has_blocking_evidence,
            model_has_uncertain_evidence=model_has_uncertain_evidence,
            evidence_reasons=evidence_reasons,
        )

    def infer_create_child_in_directory(
        self,
        directory_path: str,
        directory_metadata: os.stat_result,
        *,
        evidence_cache: PathAssessmentEvidenceCache | None = None,
    ) -> CapabilityModelInference:
        if not stat.S_ISDIR(directory_metadata.st_mode):
            return capability_inference(
                CAPABILITY_CREATE_DIRECTORY_ENTRY,
                MODEL_VERDICT_INDICATES_BLOCKED,
                (
                    EvidenceReason(
                        "creation_parent_is_not_a_directory",
                        evidence_source="stat.st_mode",
                    ),
                ),
            )

        evidence_reasons: list[EvidenceReason] = []
        model_has_uncertain_evidence = False
        model_has_blocking_evidence = False

        inode_attribute_evidence = (
            self._observe_inode_attributes_within_path_assessment(
                directory_path,
                follow_final_symbolic_link=True,
                evidence_cache=evidence_cache,
            )
        )
        if inode_attribute_evidence.immutable_attribute_is_set is True:
            attribute_reasons, attribute_uncertain, attribute_blocks = (
                self._infer_set_inode_flag_constraint(
                    attribute_is_set=True,
                    inode_owner_user_id=directory_metadata.st_uid,
                    blocking_reason_code=(
                        "directory_immutable_attribute_blocks_creation"
                    ),
                    potentially_clearable_reason_code=(
                        "directory_immutable_attribute_may_be_clearable_before_creation"
                    ),
                )
            )
            evidence_reasons.extend(attribute_reasons)
            model_has_uncertain_evidence |= attribute_uncertain
            model_has_blocking_evidence |= attribute_blocks
        if inode_attribute_evidence.append_only_attribute_is_set is True:
            evidence_reasons.append(
                EvidenceReason(
                    "directory_append_only_attribute_allows_creation_but_not_removal",
                    evidence_source="statx.stx_attributes",
                )
            )
        if inode_attribute_evidence.evidence_is_uncertain:
            evidence_reasons.extend(inode_attribute_evidence.uncertainty_reasons)
            model_has_uncertain_evidence = True

        (
            filesystem_uncertainty_reasons,
            filesystem_semantics_are_uncertain,
        ) = self._filesystem_semantics_uncertainty(
            directory_path,
            evidence_cache=evidence_cache,
        )
        evidence_reasons.extend(filesystem_uncertainty_reasons)
        model_has_uncertain_evidence |= filesystem_semantics_are_uncertain

        (
            mount_reasons,
            mount_is_uncertain,
            mount_blocks_mutation,
        ) = self._infer_mount_write_constraint(
            directory_path,
            read_only_reason_code="directory_mount_is_read_only",
            evidence_cache=evidence_cache,
        )
        evidence_reasons.extend(mount_reasons)
        model_has_uncertain_evidence |= mount_is_uncertain
        model_has_blocking_evidence |= mount_blocks_mutation

        write_access, search_access = (
            self._ask_kernel_about_write_and_search_within_path_assessment(
                directory_path,
                evidence_cache=evidence_cache,
            )
        )
        for access_evidence, blocked_reason_code in (
            (write_access, "directory_is_not_writable"),
            (search_access, "directory_is_not_searchable"),
        ):
            if access_evidence.access_is_allowed is False:
                access_reasons, access_uncertain, access_blocks = (
                    self._infer_denied_access_constraint(
                        access_evidence=access_evidence,
                        target_metadata=directory_metadata,
                        blocked_reason_code=blocked_reason_code,
                        potentially_changeable_reason_code=(
                            "directory_access_may_be_changeable_by_chmod"
                        ),
                    )
                )
                evidence_reasons.extend(access_reasons)
                model_has_uncertain_evidence |= access_uncertain
                model_has_blocking_evidence |= access_blocks
            elif access_evidence.access_is_allowed is None:
                if access_evidence.uncertainty_reason is not None:
                    evidence_reasons.append(access_evidence.uncertainty_reason)
                model_has_uncertain_evidence = True

        return infer_verdict_from_constraints(
            CAPABILITY_CREATE_DIRECTORY_ENTRY,
            model_has_blocking_evidence=model_has_blocking_evidence,
            model_has_uncertain_evidence=model_has_uncertain_evidence,
            evidence_reasons=evidence_reasons,
        )

    def infer_create_explicit_missing_path(
        self,
        missing_path: str,
        *,
        parent_directory_path: str | None = None,
        parent_directory_metadata: os.stat_result | None = None,
        evidence_cache: PathAssessmentEvidenceCache | None = None,
    ) -> CapabilityModelInference:
        normalized_missing_path = lexically_normalize_absolute_path(missing_path)
        if normalized_missing_path == "/":
            return capability_inference(
                CAPABILITY_CREATE_DIRECTORY_ENTRY,
                MODEL_VERDICT_INDICATES_BLOCKED,
                (
                    EvidenceReason(
                        "root_directory_cannot_be_created",
                        evidence_source=CAPABILITY_MODEL_ID,
                    ),
                ),
            )

        missing_basename = os.path.basename(normalized_missing_path)
        if not missing_basename:
            return capability_inference(
                CAPABILITY_CREATE_DIRECTORY_ENTRY,
                MODEL_VERDICT_INDICATES_BLOCKED,
                (
                    EvidenceReason(
                        "missing_path_has_no_final_component",
                        evidence_source="os.path.basename",
                    ),
                ),
            )

        if parent_directory_path is None:
            parent_directory_path = lexically_normalize_absolute_path(
                os.path.dirname(normalized_missing_path) or "/"
            )
        if parent_directory_metadata is None:
            try:
                parent_directory_metadata = os.stat(parent_directory_path)
            except FileNotFoundError:
                return capability_inference(
                    CAPABILITY_CREATE_DIRECTORY_ENTRY,
                    MODEL_VERDICT_INDICATES_BLOCKED,
                    (
                        EvidenceReason(
                            "creation_parent_directory_is_missing",
                            evidence_source="os.stat",
                        ),
                    ),
                )
            except NotADirectoryError:
                return capability_inference(
                    CAPABILITY_CREATE_DIRECTORY_ENTRY,
                    MODEL_VERDICT_INDICATES_BLOCKED,
                    (
                        EvidenceReason(
                            "creation_parent_component_is_not_a_directory",
                            evidence_source="os.stat",
                        ),
                    ),
                )
            except OSError as error:
                return capability_inference(
                    CAPABILITY_CREATE_DIRECTORY_ENTRY,
                    MODEL_VERDICT_INSUFFICIENT_EVIDENCE,
                    (
                        operating_system_error_reason(
                            "cannot_observe_creation_parent_directory",
                            error,
                            evidence_source="os.stat",
                        ),
                    ),
                )

        parent_inference = self.infer_create_child_in_directory(
            parent_directory_path,
            parent_directory_metadata,
            evidence_cache=evidence_cache,
        )
        if parent_inference.model_verdict == MODEL_VERDICT_INDICATES_ALLOWED:
            return add_observation_reasons_to_inference(
                parent_inference,
                (
                    EvidenceReason(
                        "explicit_missing_path_parent_allows_creation",
                        evidence_source=CAPABILITY_MODEL_ID,
                    ),
                ),
            )
        return parent_inference

    def infer_special_file_write_permission(
        self,
        path: str,
        filesystem_object_kind: str,
        *,
        evidence_cache: PathAssessmentEvidenceCache | None = None,
        target_metadata: os.stat_result | None = None,
    ) -> CapabilityModelInference:
        if filesystem_object_kind in {
            FILESYSTEM_OBJECT_KIND_UNOBSERVED,
            FILESYSTEM_OBJECT_KIND_UNRECOGNIZED_STAT_MODE,
        }:
            return capability_inference(
                CAPABILITY_SPECIAL_FILE_WRITE_PERMISSION,
                MODEL_VERDICT_INSUFFICIENT_EVIDENCE,
                (
                    EvidenceReason(
                        "special_file_kind_cannot_be_classified",
                        evidence_source="lstat.st_mode",
                        detail=filesystem_object_kind,
                    ),
                ),
            )
        if not filesystem_object_kind_is_special_file(filesystem_object_kind):
            return capability_inference(
                CAPABILITY_SPECIAL_FILE_WRITE_PERMISSION,
                MODEL_VERDICT_INDICATES_BLOCKED,
                (
                    EvidenceReason(
                        "audited_object_is_not_a_special_file",
                        evidence_source="stat.st_mode",
                        detail=filesystem_object_kind,
                    ),
                ),
            )

        evidence_reasons: list[EvidenceReason] = [
            EvidenceReason(
                "special_file_runtime_behavior_is_not_exercised",
                evidence_source=CAPABILITY_MODEL_ID,
                detail=(
                    "the verdict models permission-layer write access, "
                    "not endpoint availability or device effects"
                ),
            )
        ]
        model_has_uncertain_evidence = False
        model_has_blocking_evidence = False

        inode_attribute_evidence = (
            self._observe_inode_attributes_within_path_assessment(
                path,
                follow_final_symbolic_link=True,
                evidence_cache=evidence_cache,
            )
        )
        if inode_attribute_evidence.immutable_attribute_is_set is True:
            if target_metadata is None:
                evidence_reasons.append(
                    EvidenceReason(
                        "target_immutable_attribute_blocks_special_file_write",
                        evidence_source="statx.stx_attributes",
                    )
                )
                model_has_blocking_evidence = True
            else:
                attribute_reasons, attribute_uncertain, attribute_blocks = (
                    self._infer_set_inode_flag_constraint(
                        attribute_is_set=True,
                        inode_owner_user_id=target_metadata.st_uid,
                        blocking_reason_code=(
                            "target_immutable_attribute_blocks_special_file_write"
                        ),
                        potentially_clearable_reason_code=(
                            "target_immutable_attribute_may_be_clearable_before_special_file_write"
                        ),
                    )
                )
                evidence_reasons.extend(attribute_reasons)
                model_has_uncertain_evidence |= attribute_uncertain
                model_has_blocking_evidence |= attribute_blocks
        if inode_attribute_evidence.append_only_attribute_is_set is True:
            evidence_reasons.append(
                EvidenceReason(
                    "append_only_special_file_semantics_are_unmodeled",
                    evidence_source=CAPABILITY_MODEL_ID,
                )
            )
            model_has_uncertain_evidence = True
        if inode_attribute_evidence.evidence_is_uncertain:
            evidence_reasons.extend(inode_attribute_evidence.uncertainty_reasons)
            model_has_uncertain_evidence = True

        (
            filesystem_uncertainty_reasons,
            filesystem_semantics_are_uncertain,
        ) = self._filesystem_semantics_uncertainty(
            path,
            evidence_cache=evidence_cache,
        )
        evidence_reasons.extend(filesystem_uncertainty_reasons)
        model_has_uncertain_evidence |= filesystem_semantics_are_uncertain

        # A read-only mount controls filesystem mutation.  Whether it blocks
        # I/O through a FIFO/socket/device node varies by object and kernel
        # path, so faccessat2 plus an explicit runtime-semantics boundary is more
        # accurate than treating mount "ro" as a universal hard failure here.
        mount_lookup = self._lookup_mount_within_path_assessment(
            path,
            follow_final_symbolic_link=True,
            evidence_cache=evidence_cache,
        )
        if mount_lookup.uncertainty_reasons:
            evidence_reasons.extend(mount_lookup.uncertainty_reasons)
            model_has_uncertain_evidence = True

        write_access_evidence = self._ask_kernel_about_access_within_path_assessment(
            path,
            os.W_OK,
            evidence_cache=evidence_cache,
        )
        if write_access_evidence.access_is_allowed is False:
            access_reasons, access_uncertain, access_blocks = (
                self._infer_denied_access_constraint(
                    access_evidence=write_access_evidence,
                    target_metadata=target_metadata,
                    blocked_reason_code=(
                        "special_file_is_not_writable_by_requested_credential_model"
                    ),
                    potentially_changeable_reason_code=(
                        "special_file_write_access_may_be_changeable_by_chmod"
                    ),
                )
            )
            evidence_reasons.extend(access_reasons)
            model_has_uncertain_evidence |= access_uncertain
            model_has_blocking_evidence |= access_blocks
        elif write_access_evidence.access_is_allowed is None:
            if write_access_evidence.uncertainty_reason is not None:
                evidence_reasons.append(write_access_evidence.uncertainty_reason)
            model_has_uncertain_evidence = True

        return infer_verdict_from_constraints(
            CAPABILITY_SPECIAL_FILE_WRITE_PERMISSION,
            model_has_blocking_evidence=model_has_blocking_evidence,
            model_has_uncertain_evidence=model_has_uncertain_evidence,
            evidence_reasons=evidence_reasons,
        )

    def _filesystem_semantics_uncertainty(
        self,
        path: str,
        *,
        evidence_cache: PathAssessmentEvidenceCache | None = None,
    ) -> tuple[list[EvidenceReason], bool]:
        mount_lookup = self._lookup_mount_within_path_assessment(
            path,
            follow_final_symbolic_link=True,
            evidence_cache=evidence_cache,
        )
        evidence_reasons = list(mount_lookup.uncertainty_reasons)
        filesystem_semantics_are_uncertain = bool(evidence_reasons)

        filesystem_type = mount_lookup.mount_record.filesystem_type
        filesystem_type_is_unmodeled = (
            filesystem_type in self.filesystem_types_with_unmodeled_semantics
            or filesystem_type.startswith(
                FILESYSTEM_TYPE_PREFIXES_WITH_UNMODELED_MUTATION_SEMANTICS
            )
        )
        if filesystem_type_is_unmodeled:
            evidence_reasons.append(
                EvidenceReason(
                    "filesystem_type_has_unmodeled_mutation_semantics",
                    evidence_source=LINUX_MOUNTINFO_SOURCE_PATH,
                    detail=linux_mount_record_evidence_summary(
                        mount_lookup.mount_record
                    ),
                )
            )
            filesystem_semantics_are_uncertain = True

        return (
            deduplicate_preserving_first_occurrence(evidence_reasons),
            filesystem_semantics_are_uncertain,
        )

    def _infer_mount_write_constraint(
        self,
        path: str,
        *,
        read_only_reason_code: str,
        evidence_cache: PathAssessmentEvidenceCache | None = None,
    ) -> tuple[list[EvidenceReason], bool, bool]:
        mount_lookup = self._lookup_mount_within_path_assessment(
            path,
            follow_final_symbolic_link=True,
            evidence_cache=evidence_cache,
        )
        if mount_lookup.uncertainty_reasons:
            return (
                list(mount_lookup.uncertainty_reasons),
                True,
                False,
            )
        if mount_lookup.mount_record.filesystem_is_mounted_read_only:
            sys_admin_presence = (
                self.process_credentials.effective_capabilities.capability_presence(
                    LINUX_CAPABILITY_SYS_ADMIN_NUMBER
                )
            )
            if sys_admin_presence is True:
                return (
                    [
                        EvidenceReason(
                            "read_only_mount_may_be_remountable_with_cap_sys_admin",
                            evidence_source=(
                                f"{LINUX_MOUNTINFO_SOURCE_PATH} and "
                                f"{LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH}"
                            ),
                            detail=linux_mount_record_evidence_summary(
                                mount_lookup.mount_record
                            ),
                        )
                    ],
                    True,
                    False,
                )
            if sys_admin_presence is None:
                return (
                    [
                        self.process_credentials.effective_capabilities.uncertainty_reason
                        or EvidenceReason(
                            "cap_sys_admin_presence_is_unknown_for_read_only_mount",
                            evidence_source=LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH,
                        )
                    ],
                    True,
                    False,
                )
            return (
                [
                    EvidenceReason(
                        read_only_reason_code,
                        evidence_source=LINUX_MOUNTINFO_SOURCE_PATH,
                        detail=linux_mount_record_evidence_summary(
                            mount_lookup.mount_record
                        ),
                    )
                ],
                False,
                True,
            )
        return [], False, False


@dataclass(frozen=True)
class AuditCommandLineConfiguration:
    """Validated command-line intent with no dynamically named attributes."""

    scan_root_paths: tuple[str, ...]
    scan_roots_were_defaulted: bool
    selected_capabilities: tuple[str, ...]
    output_destination: str
    requested_output_presentation: str
    replace_existing_output: bool
    include_nonmatching_records: bool
    full_audit: bool
    fail_on_uncertainty: bool
    include_home_paths_in_default_scan: bool
    include_temporary_directory_in_default_scan: bool
    include_proc_filesystem_in_default_scan: bool
    allow_effective_root_execution: bool
    remain_on_starting_filesystem: bool
    user_excluded_paths: tuple[str, ...]
    additional_uncertain_filesystem_types: tuple[str, ...]


def build_audit_argument_parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser(
        prog=os.path.basename(sys.argv[0]) or AUDIT_TOOL_NAME,
        description=(
            "Best-effort Linux filesystem mutation-permission auditor. "
            "Terminal stdout is human-readable; redirected stdout is JSONL."
        ),
        epilog=audit_argument_parser_epilog(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    argument_parser.add_argument(
        "paths",
        nargs="*",
        metavar="PATH",
        help="Root path(s) to inspect recursively; defaults to /.",
    )
    argument_parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {AUDIT_TOOL_VERSION}",
    )
    add_capability_selection_arguments(argument_parser)
    add_output_presentation_arguments(argument_parser)
    add_report_publication_arguments(argument_parser)
    add_audit_scope_arguments(argument_parser)
    add_process_identity_arguments(argument_parser)
    return argument_parser


def parse_audit_command_line_arguments(
    command_line_arguments: Sequence[str],
) -> AuditCommandLineConfiguration:
    argument_parser = build_audit_argument_parser()
    parsed_arguments = argument_parser.parse_args(command_line_arguments)

    if (
        parsed_arguments.replace_existing_output
        and parsed_arguments.output_destination == "-"
    ):
        argument_parser.error(
            "--replace-output requires a file-valued --output destination"
        )

    for path_argument in (
        *parsed_arguments.paths,
        *parsed_arguments.user_excluded_paths,
    ):
        if path_argument == "":
            argument_parser.error("PATH arguments must not be empty strings")
        if "\0" in path_argument:
            argument_parser.error("PATH arguments must not contain NUL bytes")
    if parsed_arguments.output_destination == "":
        argument_parser.error("--output FILE must not be an empty string")
    if "\0" in parsed_arguments.output_destination:
        argument_parser.error("--output FILE must not contain NUL bytes")
    for filesystem_type in parsed_arguments.additional_uncertain_filesystem_types:
        if not filesystem_type or any(
            character.isspace() for character in filesystem_type
        ):
            argument_parser.error(
                "--uncertain-filesystem-type requires a nonempty "
                "whitespace-free filesystem type"
            )

    scan_roots_were_defaulted = not bool(parsed_arguments.paths)
    unnormalized_scan_root_paths = (
        tuple(parsed_arguments.paths) if parsed_arguments.paths else ("/",)
    )
    try:
        scan_root_paths = tuple(
            deduplicate_preserving_first_occurrence(
                absolute_path_without_lexical_normalization(scan_root_path)
                for scan_root_path in unnormalized_scan_root_paths
            )
        )
        output_destination = (
            "-"
            if parsed_arguments.output_destination == "-"
            else absolute_path_without_lexical_normalization(
                parsed_arguments.output_destination
            )
        )
    except (OSError, ValueError) as error:
        argument_parser.error(f"cannot prepare configured path: {error}")
    requested_capabilities = (
        tuple(parsed_arguments.selected_capabilities)
        if parsed_arguments.selected_capabilities
        else DEFAULT_MUTATION_CAPABILITIES
    )
    selected_capability_set = set(requested_capabilities)
    selected_capabilities = tuple(
        capability_name
        for capability_name in CAPABILITY_EVALUATION_ORDER
        if capability_name in selected_capability_set
    )

    return AuditCommandLineConfiguration(
        scan_root_paths=scan_root_paths,
        scan_roots_were_defaulted=scan_roots_were_defaulted,
        selected_capabilities=selected_capabilities,
        output_destination=output_destination,
        requested_output_presentation=(parsed_arguments.requested_output_presentation),
        replace_existing_output=(parsed_arguments.replace_existing_output),
        include_nonmatching_records=(
            parsed_arguments.include_nonmatching_records or parsed_arguments.full_audit
        ),
        full_audit=parsed_arguments.full_audit,
        fail_on_uncertainty=parsed_arguments.fail_on_uncertainty,
        include_home_paths_in_default_scan=(
            parsed_arguments.include_home_paths_in_default_scan
        ),
        include_temporary_directory_in_default_scan=(
            parsed_arguments.include_temporary_directory_in_default_scan
        ),
        include_proc_filesystem_in_default_scan=(
            parsed_arguments.include_proc_filesystem_in_default_scan
        ),
        allow_effective_root_execution=(
            parsed_arguments.allow_effective_root_execution
        ),
        remain_on_starting_filesystem=(parsed_arguments.remain_on_starting_filesystem),
        user_excluded_paths=tuple(parsed_arguments.user_excluded_paths),
        additional_uncertain_filesystem_types=tuple(
            parsed_arguments.additional_uncertain_filesystem_types
        ),
    )


def add_capability_selection_arguments(
    argument_parser: argparse.ArgumentParser,
) -> None:
    argument_parser.add_argument(
        "--capability",
        dest="selected_capabilities",
        action="append",
        choices=CAPABILITY_EVALUATION_ORDER,
        metavar="NAME",
        help=(
            "Evaluate one named operation capability. Repeat to select "
            "several. Defaults to: " + ", ".join(DEFAULT_MUTATION_CAPABILITIES) + "."
        ),
    )


def add_output_presentation_arguments(
    argument_parser: argparse.ArgumentParser,
) -> None:
    presentation_overrides = argument_parser.add_mutually_exclusive_group()
    presentation_overrides.add_argument(
        "--tty",
        "--human",
        dest="requested_output_presentation",
        action="store_const",
        const=OUTPUT_PRESENTATION_TERMINAL_PATHS,
        help=(
            "Force compact human-readable path lines, even through redirected "
            "stdout or --output FILE. Labels identify model-allowed "
            "capabilities."
        ),
    )
    presentation_overrides.add_argument(
        "--json",
        "--machine",
        dest="requested_output_presentation",
        action="store_const",
        const=OUTPUT_PRESENTATION_JSON_LINES,
        help=(
            "Force self-contained JSON Lines records, even when stdout is "
            "attached to a terminal."
        ),
    )
    argument_parser.set_defaults(
        requested_output_presentation=OUTPUT_PRESENTATION_AUTOMATIC
    )


def add_report_publication_arguments(
    argument_parser: argparse.ArgumentParser,
) -> None:
    argument_parser.add_argument(
        "--output",
        dest="output_destination",
        default="-",
        metavar="FILE",
        help=(
            "Create a private report file instead of stdout. Its automatic "
            "presentation is JSONL; --tty/--human can force compact paths. "
            "Existing paths require --replace-output. Use - for stdout."
        ),
    )
    argument_parser.add_argument(
        "--replace-output",
        dest="replace_existing_output",
        action="store_true",
        help=(
            "Replace an existing regular report via a synchronized temporary "
            "sibling and atomic rename; symlinks/special files are refused."
        ),
    )


def add_audit_scope_arguments(
    argument_parser: argparse.ArgumentParser,
) -> None:
    argument_parser.add_argument(
        "--full-audit",
        dest="full_audit",
        action="store_true",
        help=(
            "Include every assessed path plus routine and material uncertainty "
            "evidence. Implies JSON unless --human is explicit; normal output "
            "stays focused on permission findings."
        ),
    )
    argument_parser.add_argument(
        "--include-nonmatching-records",
        dest="include_nonmatching_records",
        action="store_true",
        help=(
            "Include blocked, skipped, and both grades of uncertain records; "
            "the compatibility spelling of the full evidence view."
        ),
    )
    argument_parser.add_argument(
        "--fail-on-uncertainty",
        dest="fail_on_uncertainty",
        action="store_true",
        help=(
            "Write the complete report, then exit 5 if any selected capability "
            "or run-level evidence has material uncertainty."
        ),
    )
    argument_parser.add_argument(
        "--include-default-home-paths",
        dest="include_home_paths_in_default_scan",
        action="store_true",
        help="Include home paths in the default no-PATH root scan.",
    )
    argument_parser.add_argument(
        "--include-default-temporary-directory",
        dest="include_temporary_directory_in_default_scan",
        action="store_true",
        help="Include the active writable temp directory in the default scan.",
    )
    argument_parser.add_argument(
        "--include-default-proc-filesystem",
        dest="include_proc_filesystem_in_default_scan",
        action="store_true",
        help="Include /proc in the default scan.",
    )


def add_process_identity_arguments(
    argument_parser: argparse.ArgumentParser,
) -> None:
    argument_parser.add_argument(
        "--allow-root-audit",
        dest="allow_effective_root_execution",
        action="store_true",
        help="Explicitly allow an effective-UID-0 audit.",
    )
    argument_parser.add_argument(
        "--stay-on-starting-filesystem",
        dest="remain_on_starting_filesystem",
        action="store_true",
        help=(
            "Skip entries whose lstat device number differs from each "
            "starting path's lstat device number."
        ),
    )
    argument_parser.add_argument(
        "--exclude",
        dest="user_excluded_paths",
        action="append",
        default=[],
        metavar="PATH",
        help=(
            "Exclude exactly one kernel-resolved file path or observed directory "
            "subtree; repeat for multiple exclusions."
        ),
    )
    argument_parser.add_argument(
        "--uncertain-filesystem-type",
        dest="additional_uncertain_filesystem_types",
        action="append",
        default=[],
        metavar="FILESYSTEM_TYPE",
        help="Mark an additional filesystem type uncertain; repeatable.",
    )


def audit_argument_parser_epilog() -> str:
    capability_definition_lines = "\n".join(
        f"  {capability_name}\n    {operation_definition}"
        for capability_name, operation_definition in (
            CAPABILITY_OPERATION_DEFINITION_BY_NAME.items()
        )
    )
    terminal_label_definition_lines = "\n".join(
        f"  {TERMINAL_CAPABILITY_LABEL_BY_NAME[capability_name]}  {capability_name}"
        for capability_name in CAPABILITY_EVALUATION_ORDER
    )
    return f"""
Evidence boundary:
  The model observes access decisions, metadata, mount state, sticky rules, and
  immutable, append-only, and verity attributes. It does not execute a mutation.
  Normal output reports permission findings and material evidence failures;
  --full-audit adds blocked/skipped records and expected routine limitations.
  JSONL path records carry the run/source provenance needed when moved alone.

Capability names:
{capability_definition_lines}

Output presentation:
  With no presentation override:
    terminal stdout             compact human-readable path lines
    redirected or piped stdout  self-contained JSON Lines records
    --output FILE               self-contained JSON Lines records

  --tty and --human are aliases that force compact path lines.
  --json and --machine are aliases that force JSON Lines records.
  --full-audit selects JSON Lines unless a human override is explicit.

  Human path lines use [labels] before each path, append / to directories, and
  show resolved symbolic links as link -> target. An unlabeled line requested
  by --include-nonmatching-records has no model-allowed selected capability;
  use JSON Lines to distinguish blocked, uncertain, and skipped evidence.

Human capability labels:
{terminal_label_definition_lines}

Default no-PATH scan:
  Scans /. It excludes /proc and the first active writable temp directory and
  does not traverse discovered process-related home directories. Explicit roots
  are not auto-excluded.

Examples:
  %(prog)s --stay-on-starting-filesystem /explicit/path
  %(prog)s --human /explicit/path | less
  %(prog)s --machine /explicit/path
  %(prog)s --full-audit /var/tmp/project > full-audit.jsonl
  %(prog)s --capability {CAPABILITY_DELETE_ENTRY_OR_TREE} --include-nonmatching-records /var/tmp/project
  %(prog)s --exclude /tmp --exclude /proc /opt
  %(prog)s --output report.jsonl /srv/project
  %(prog)s --replace-output --output report.jsonl /srv/project
"""


@dataclass(frozen=True)
class AuditScopeEvidence:
    """Observed exclusions and internal artifacts bounding one traversal."""

    exclusion_rules: tuple[PathExclusionRule, ...]
    home_directory_discovery: HomeDirectoryDiscoveryEvidence | None
    temporary_directory_discovery: TemporaryDirectoryDiscoveryEvidence | None
    internally_ignored_paths: tuple[str, ...]
    observed_at_utc: str


@dataclass(frozen=True)
class ObservedToolSourceFileEvidence:
    """Digest and identity of the source file observed during this run."""

    source_file_path: str
    source_file_sha256: str | None
    source_file_identity: FilesystemObjectIdentity | None
    source_file_size_bytes: int | None
    source_file_modification_time_nanoseconds: int | None
    source_file_change_time_nanoseconds: int | None
    uncertainty_reason: EvidenceReason | None
    observed_at_utc: str


def observe_tool_source_file() -> ObservedToolSourceFileEvidence:
    source_file_path = os.path.abspath(__file__)
    observation_timestamp = current_utc_timestamp()
    try:
        with open(source_file_path, "rb") as source_file_stream:
            source_file_metadata_before_read = os.fstat(source_file_stream.fileno())
            source_file_bytes = source_file_stream.read()
            source_file_metadata_after_read = os.fstat(source_file_stream.fileno())
    except OSError as error:
        return ObservedToolSourceFileEvidence(
            source_file_path=source_file_path,
            source_file_sha256=None,
            source_file_identity=None,
            source_file_size_bytes=None,
            source_file_modification_time_nanoseconds=None,
            source_file_change_time_nanoseconds=None,
            uncertainty_reason=operating_system_error_reason(
                "cannot_observe_tool_source_file",
                error,
                evidence_source=source_file_path,
            ),
            observed_at_utc=observation_timestamp,
        )
    source_file_changed_during_read = (
        FilesystemObjectIdentity.from_stat_result(source_file_metadata_before_read)
        != FilesystemObjectIdentity.from_stat_result(source_file_metadata_after_read)
        or source_file_metadata_before_read.st_size
        != source_file_metadata_after_read.st_size
        or source_file_metadata_before_read.st_mtime_ns
        != source_file_metadata_after_read.st_mtime_ns
        or source_file_metadata_before_read.st_ctime_ns
        != source_file_metadata_after_read.st_ctime_ns
    )
    return ObservedToolSourceFileEvidence(
        source_file_path=source_file_path,
        source_file_sha256=hashlib.sha256(source_file_bytes).hexdigest(),
        source_file_identity=FilesystemObjectIdentity.from_stat_result(
            source_file_metadata_after_read
        ),
        source_file_size_bytes=source_file_metadata_after_read.st_size,
        source_file_modification_time_nanoseconds=(
            source_file_metadata_after_read.st_mtime_ns
        ),
        source_file_change_time_nanoseconds=(
            source_file_metadata_after_read.st_ctime_ns
        ),
        uncertainty_reason=(
            EvidenceReason(
                "tool_source_file_changed_while_its_digest_was_observed",
                evidence_source=source_file_path,
            )
            if source_file_changed_during_read
            else None
        ),
        observed_at_utc=observation_timestamp,
    )


@dataclass(frozen=True)
class AuditRunProvenance:
    """Evidence identifying one process run and its model inputs."""

    audit_run_id: str
    audit_started_at_utc: str
    tool_name: str
    tool_version: str
    capability_model_id: str
    process_id: int
    linux_kernel_release: str
    observed_tool_source_file: ObservedToolSourceFileEvidence
    process_credentials: LinuxProcessCredentialEvidence
    mount_table_read: LinuxMountTableReadEvidence
    audit_scope: AuditScopeEvidence
    scan_root_paths: tuple[str, ...]
    scan_roots_were_defaulted: bool
    selected_capabilities: tuple[str, ...]
    remain_on_starting_filesystem: bool
    path_record_emission_policy: str
    filesystem_types_with_unmodeled_mutation_semantics: tuple[str, ...]
    report_transport: str
    requested_report_destination_path: str | None
    existing_report_replacement_was_authorized: bool

    def as_serializable_dictionary(
        self,
        *,
        include_routine_uncertainty: bool,
    ) -> dict[str, object]:
        source_file_evidence = self.observed_tool_source_file
        source_file_dictionary: dict[str, object] = {
            "source_file_path": source_file_evidence.source_file_path,
            "source_file_sha256": source_file_evidence.source_file_sha256,
            "source_file_size_bytes": (source_file_evidence.source_file_size_bytes),
            "source_file_modification_time_nanoseconds": (
                source_file_evidence.source_file_modification_time_nanoseconds
            ),
            "source_file_change_time_nanoseconds": (
                source_file_evidence.source_file_change_time_nanoseconds
            ),
            "observed_at_utc": source_file_evidence.observed_at_utc,
        }
        if source_file_evidence.source_file_identity is not None:
            source_file_dictionary["source_file_identity"] = {
                "device_number": (
                    source_file_evidence.source_file_identity.device_number
                ),
                "inode_number": (
                    source_file_evidence.source_file_identity.inode_number
                ),
            }
        if source_file_evidence.uncertainty_reason is not None and (
            include_routine_uncertainty
            or evidence_reason_uncertainty_grade(
                source_file_evidence.uncertainty_reason
            )
            != UNCERTAINTY_GRADE_ROUTINE
        ):
            source_file_dictionary["uncertainty_reason"] = (
                source_file_evidence.uncertainty_reason.as_serializable_dictionary()
            )

        effective_capability_evidence = self.process_credentials.effective_capabilities
        filesystem_identifier_evidence = self.process_credentials.filesystem_identifiers
        credential_dictionary: dict[str, object] = {
            "observed_at_utc": self.process_credentials.observed_at_utc,
            "access_identity_model": (self.process_credentials.access_identity_model),
            "real_user_id": self.process_credentials.real_user_id,
            "effective_user_id": (self.process_credentials.effective_user_id),
            "saved_user_id": self.process_credentials.saved_user_id,
            "real_group_id": self.process_credentials.real_group_id,
            "effective_group_id": (self.process_credentials.effective_group_id),
            "saved_group_id": self.process_credentials.saved_group_id,
            "filesystem_user_id": (filesystem_identifier_evidence.filesystem_user_id),
            "filesystem_group_id": (filesystem_identifier_evidence.filesystem_group_id),
            "filesystem_identifier_source_path": (
                filesystem_identifier_evidence.source_path
            ),
            "filesystem_identifiers_observed_at_utc": (
                filesystem_identifier_evidence.observed_at_utc
            ),
            "supplementary_group_ids": list(
                self.process_credentials.supplementary_group_ids
            ),
            "effective_capability_mask_hexadecimal": (
                effective_capability_evidence.capability_mask_hexadecimal
            ),
            "effective_capability_source_path": (
                effective_capability_evidence.source_path
            ),
            "effective_capability_observed_at_utc": (
                effective_capability_evidence.observed_at_utc
            ),
        }
        if filesystem_identifier_evidence.uncertainty_reason is not None and (
            include_routine_uncertainty
            or evidence_reason_uncertainty_grade(
                filesystem_identifier_evidence.uncertainty_reason
            )
            != UNCERTAINTY_GRADE_ROUTINE
        ):
            credential_dictionary["filesystem_identifier_uncertainty_reason"] = (
                filesystem_identifier_evidence.uncertainty_reason.as_serializable_dictionary()
            )
        if effective_capability_evidence.uncertainty_reason is not None and (
            include_routine_uncertainty
            or evidence_reason_uncertainty_grade(
                effective_capability_evidence.uncertainty_reason
            )
            != UNCERTAINTY_GRADE_ROUTINE
        ):
            credential_dictionary["effective_capability_uncertainty_reason"] = (
                effective_capability_evidence.uncertainty_reason.as_serializable_dictionary()
            )

        visible_mount_uncertainty_reasons = [
            reason
            for reason in self.mount_table_read.uncertainty_reasons
            if include_routine_uncertainty
            or evidence_reason_uncertainty_grade(reason) != UNCERTAINTY_GRADE_ROUTINE
        ]
        mount_table_dictionary: dict[str, object] = {
            "source_path": self.mount_table_read.source_path,
            "source_sha256": self.mount_table_read.source_sha256,
            "observed_at_utc": self.mount_table_read.observed_at_utc,
            "parsed_mount_record_count": len(self.mount_table_read.mount_records),
        }
        if include_routine_uncertainty or visible_mount_uncertainty_reasons:
            mount_table_dictionary["uncertainty_reasons"] = [
                reason.as_serializable_dictionary()
                for reason in visible_mount_uncertainty_reasons
            ]
        serialized_exclusion_rules: list[dict[str, object]] = []
        for exclusion_rule in self.audit_scope.exclusion_rules:
            serialized_rule: dict[str, object] = {
                "excluded_path": exclusion_rule.excluded_path,
                "includes_descendants": (exclusion_rule.includes_descendants),
                "rule_origin": exclusion_rule.rule_origin,
            }
            if exclusion_rule.classification_uncertainty_reason is not None and (
                include_routine_uncertainty
                or evidence_reason_uncertainty_grade(
                    exclusion_rule.classification_uncertainty_reason
                )
                != UNCERTAINTY_GRADE_ROUTINE
            ):
                serialized_rule["classification_uncertainty_reason"] = (
                    exclusion_rule.classification_uncertainty_reason.as_serializable_dictionary()
                )
            serialized_exclusion_rules.append(serialized_rule)

        serialized_audit_scope: dict[str, object] = {
            "observed_at_utc": self.audit_scope.observed_at_utc,
            "exclusion_rules": serialized_exclusion_rules,
            "internally_ignored_report_paths": list(
                self.audit_scope.internally_ignored_paths
            ),
        }
        home_discovery = self.audit_scope.home_directory_discovery
        if home_discovery is None:
            serialized_audit_scope["home_directory_discovery"] = {
                "performed": False,
                "reason": "not_required_by_configured_scan_scope",
            }
        else:
            serialized_home_discovery: dict[str, object] = {
                "performed": True,
                "observed_at_utc": home_discovery.observed_at_utc,
                "accepted_home_directory_exclusion_paths": list(
                    home_discovery.accepted_home_directory_exclusion_paths
                ),
                "candidate_observations": [
                    observation.as_serializable_dictionary()
                    for observation in home_discovery.candidate_observations
                ],
            }
            visible_home_uncertainty_reasons = [
                reason
                for reason in home_discovery.uncertainty_reasons
                if include_routine_uncertainty
                or evidence_reason_uncertainty_grade(reason)
                != UNCERTAINTY_GRADE_ROUTINE
            ]
            if include_routine_uncertainty or visible_home_uncertainty_reasons:
                serialized_home_discovery["uncertainty_reasons"] = [
                    reason.as_serializable_dictionary()
                    for reason in visible_home_uncertainty_reasons
                ]
            serialized_audit_scope["home_directory_discovery"] = (
                serialized_home_discovery
            )
        temporary_discovery = self.audit_scope.temporary_directory_discovery
        if temporary_discovery is None:
            serialized_audit_scope["temporary_directory_discovery"] = {
                "performed": False,
                "reason": "not_required_by_configured_scan_scope",
            }
        else:
            serialized_temporary_discovery: dict[str, object] = {
                "performed": True,
                "observed_at_utc": temporary_discovery.observed_at_utc,
                "selected_writable_temporary_directory": (
                    temporary_discovery.selected_writable_temporary_directory
                ),
                "normalized_candidate_paths": list(
                    temporary_discovery.normalized_candidate_paths
                ),
                "candidate_observations": [
                    reason.as_serializable_dictionary()
                    for reason in temporary_discovery.candidate_observations
                ],
            }
            visible_temporary_uncertainty_reasons = [
                reason
                for reason in temporary_discovery.uncertainty_reasons
                if include_routine_uncertainty
                or evidence_reason_uncertainty_grade(reason)
                != UNCERTAINTY_GRADE_ROUTINE
            ]
            if include_routine_uncertainty or visible_temporary_uncertainty_reasons:
                serialized_temporary_discovery["uncertainty_reasons"] = [
                    reason.as_serializable_dictionary()
                    for reason in visible_temporary_uncertainty_reasons
                ]
            serialized_audit_scope["temporary_directory_discovery"] = (
                serialized_temporary_discovery
            )

        return {
            "audit_run_provenance_schema_id": (AUDIT_RUN_PROVENANCE_SCHEMA_ID),
            "audit_run_id": self.audit_run_id,
            "audit_started_at_utc": self.audit_started_at_utc,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "capability_model_id": self.capability_model_id,
            "process_id": self.process_id,
            "linux_kernel_release": self.linux_kernel_release,
            "linux_system_interface_support": {
                "machine_architecture": RUNNING_MACHINE_ARCHITECTURE,
                "libc_statx_wrapper_is_available": (_LINUX_STATX_FUNCTION is not None),
                "raw_statx_syscall_number": linux_syscall_number("statx"),
                "libc_renameat2_wrapper_is_available": (
                    _LINUX_RENAMEAT2_FUNCTION is not None
                ),
                "raw_renameat2_syscall_number": linux_syscall_number("renameat2"),
                "raw_faccessat2_syscall_number": linux_syscall_number("faccessat2"),
                "libc_faccessat_wrapper_is_available": (
                    _LINUX_FACCESSAT_FUNCTION is not None
                ),
                "faccessat_fallback_policy": (
                    "matching real/effective/filesystem IDs; non-root; "
                    "observed empty effective capability mask"
                ),
            },
            "observed_tool_source_file": source_file_dictionary,
            "process_credentials": credential_dictionary,
            "linux_mount_table": mount_table_dictionary,
            "audit_scope": serialized_audit_scope,
            **(
                {
                    "capability_model_boundaries": [
                        boundary_reason.as_serializable_dictionary()
                        for boundary_reason in CAPABILITY_MODEL_BOUNDARY_REASONS
                    ]
                }
                if include_routine_uncertainty
                else {}
            ),
            "requested_scan_root_paths": list(self.scan_root_paths),
            "scan_root_path_resolution_policy": (
                "kernel_component_resolution_before_descriptor_capture; "
                "dot components and trailing separators are preserved"
            ),
            "scan_roots_were_defaulted": self.scan_roots_were_defaulted,
            "selected_capabilities": list(self.selected_capabilities),
            "selected_capability_operation_definitions": {
                capability_name: CAPABILITY_OPERATION_DEFINITION_BY_NAME[
                    capability_name
                ]
                for capability_name in self.selected_capabilities
            },
            "remain_on_starting_filesystem": (self.remain_on_starting_filesystem),
            "path_record_emission_policy": (self.path_record_emission_policy),
            **(
                {
                    "filesystem_types_with_unmodeled_mutation_semantics": list(
                        self.filesystem_types_with_unmodeled_mutation_semantics
                    ),
                    "filesystem_type_prefixes_with_unmodeled_mutation_semantics": list(
                        FILESYSTEM_TYPE_PREFIXES_WITH_UNMODELED_MUTATION_SEMANTICS
                    ),
                }
                if include_routine_uncertainty
                else {}
            ),
            "report_output_configuration": {
                "report_transport": self.report_transport,
                "report_format": "json_lines",
                "requested_report_destination_path": (
                    self.requested_report_destination_path
                ),
                "existing_report_replacement_was_authorized": (
                    self.existing_report_replacement_was_authorized
                ),
            },
        }


def build_audit_run_provenance(
    *,
    audit_run_id: str,
    audit_started_at_utc: str,
    configuration: AuditCommandLineConfiguration,
    process_credentials: LinuxProcessCredentialEvidence,
    mount_table_read: LinuxMountTableReadEvidence,
    audit_scope: AuditScopeEvidence,
    observed_tool_source_file: ObservedToolSourceFileEvidence,
) -> AuditRunProvenance:
    return AuditRunProvenance(
        audit_run_id=audit_run_id,
        audit_started_at_utc=audit_started_at_utc,
        tool_name=AUDIT_TOOL_NAME,
        tool_version=AUDIT_TOOL_VERSION,
        capability_model_id=CAPABILITY_MODEL_ID,
        process_id=os.getpid(),
        linux_kernel_release=RUNNING_LINUX_KERNEL_RELEASE,
        observed_tool_source_file=observed_tool_source_file,
        process_credentials=process_credentials,
        mount_table_read=mount_table_read,
        audit_scope=audit_scope,
        scan_root_paths=configuration.scan_root_paths,
        scan_roots_were_defaulted=configuration.scan_roots_were_defaulted,
        selected_capabilities=configuration.selected_capabilities,
        remain_on_starting_filesystem=(configuration.remain_on_starting_filesystem),
        path_record_emission_policy=(
            "all_assessed_paths"
            if configuration.include_nonmatching_records
            else "paths_with_at_least_one_model_allowed_capability"
        ),
        filesystem_types_with_unmodeled_mutation_semantics=tuple(
            sorted(uncertain_filesystem_types_for_configuration(configuration))
        ),
        report_transport=(
            "standard_output"
            if configuration.output_destination == "-"
            else "private_jsonl_file"
        ),
        requested_report_destination_path=(
            None
            if configuration.output_destination == "-"
            else configuration.output_destination
        ),
        existing_report_replacement_was_authorized=(
            configuration.replace_existing_output
        ),
    )


def observe_audit_scope(
    configuration: AuditCommandLineConfiguration,
    *,
    process_credentials: LinuxProcessCredentialEvidence,
    internally_ignored_paths: Sequence[str],
) -> AuditScopeEvidence:
    scope_observation_timestamp = current_utc_timestamp()
    exclusion_rules = [
        path_exclusion_rule_from_user_argument(user_excluded_path)
        for user_excluded_path in configuration.user_excluded_paths
    ]

    if (
        configuration.scan_roots_were_defaulted
        and not configuration.include_home_paths_in_default_scan
    ):
        home_directory_discovery = discover_process_related_home_directories(
            process_credentials
        )
        exclusion_rules.extend(
            PathExclusionRule(
                excluded_path=home_directory,
                includes_descendants=True,
                rule_origin=(
                    "default no-PATH process-related home directory suppression"
                ),
            )
            for home_directory in (
                home_directory_discovery.accepted_home_directory_exclusion_paths
            )
        )
    else:
        home_directory_discovery = None

    if (
        configuration.scan_roots_were_defaulted
        and not configuration.include_proc_filesystem_in_default_scan
    ):
        exclusion_rules.append(
            PathExclusionRule(
                excluded_path=DEFAULT_PROC_FILESYSTEM_EXCLUSION_PATH,
                includes_descendants=True,
                rule_origin="default no-PATH /proc suppression",
            )
        )

    if (
        configuration.scan_roots_were_defaulted
        and not configuration.include_temporary_directory_in_default_scan
    ):
        temporary_directory_discovery = discover_active_writable_temporary_directory(
            process_credentials
        )
        active_temporary_directory = (
            temporary_directory_discovery.selected_writable_temporary_directory
        )
        if active_temporary_directory is not None:
            exclusion_rules.append(
                PathExclusionRule(
                    excluded_path=active_temporary_directory,
                    includes_descendants=True,
                    rule_origin=(
                        "default no-PATH active temporary directory suppression"
                    ),
                )
            )
    else:
        temporary_directory_discovery = None

    unique_rules: list[PathExclusionRule] = []
    observed_rule_keys: set[tuple[str, bool]] = set()
    for exclusion_rule in exclusion_rules:
        rule_key = (
            exclusion_rule.excluded_path,
            exclusion_rule.includes_descendants,
        )
        if rule_key in observed_rule_keys:
            continue
        observed_rule_keys.add(rule_key)
        unique_rules.append(exclusion_rule)
    return AuditScopeEvidence(
        exclusion_rules=tuple(unique_rules),
        home_directory_discovery=home_directory_discovery,
        temporary_directory_discovery=temporary_directory_discovery,
        internally_ignored_paths=tuple(
            lexically_normalize_absolute_path(path) for path in internally_ignored_paths
        ),
        observed_at_utc=scope_observation_timestamp,
    )


def uncertain_filesystem_types_for_configuration(
    configuration: AuditCommandLineConfiguration,
) -> set[str]:
    uncertain_filesystem_types = set(FILESYSTEM_TYPES_WITH_UNMODELED_MUTATION_SEMANTICS)
    uncertain_filesystem_types.update(
        configuration.additional_uncertain_filesystem_types
    )
    return uncertain_filesystem_types


def build_permission_auditor(
    configuration: AuditCommandLineConfiguration,
    *,
    mount_table_read: LinuxMountTableReadEvidence,
    process_credentials: LinuxProcessCredentialEvidence,
    audit_scope: AuditScopeEvidence,
) -> LinuxFilesystemMutationPermissionAuditor:
    return LinuxFilesystemMutationPermissionAuditor(
        VisibleLinuxMountTable(mount_table_read),
        process_credentials,
        remain_on_starting_filesystem=(configuration.remain_on_starting_filesystem),
        filesystem_types_with_unmodeled_semantics=(
            uncertain_filesystem_types_for_configuration(configuration)
        ),
        exclusion_rules=audit_scope.exclusion_rules,
        internally_ignored_paths=audit_scope.internally_ignored_paths,
    )


ENUMERATION_UNCERTAINTY_REASON_CODES = frozenset(
    {
        "cannot_open_requested_path_parent_directory",
        "cannot_capture_requested_path",
        "cannot_list_directory",
        "cannot_continue_directory_listing",
        "directory_traversal_file_descriptor_budget_exhausted",
        "directory_identity_changed_between_capture_and_listing",
        "directory_entry_changed_after_descriptor_capture",
        "directory_entry_identity_changed_after_descriptor_capture",
        "cannot_revalidate_requested_missing_path",
        "requested_missing_path_appeared_during_assessment",
        "path_disappeared_during_directory_scan",
        "cannot_capture_directory_entry",
    }
)


@dataclass
class AuditRunStatistics:
    assessed_path_count: int = 0
    emitted_path_record_count: int = 0
    filtered_path_count: int = 0
    allowed_path_count: int = 0
    blocked_path_count: int = 0
    uncertain_path_count: int = 0
    skipped_path_count: int = 0
    filtered_uncertain_path_count: int = 0
    selected_capability_uncertainty_path_count: int = 0
    enumeration_uncertainty_path_count: int = 0
    run_level_uncertainty_reason_count: int = 0
    material_uncertain_path_count: int = 0
    material_filtered_uncertain_path_count: int = 0
    material_selected_capability_uncertainty_path_count: int = 0
    material_enumeration_uncertainty_path_count: int = 0
    material_run_level_uncertainty_reason_count: int = 0
    routine_uncertain_path_count: int = 0
    routine_filtered_uncertain_path_count: int = 0
    routine_selected_capability_uncertainty_path_count: int = 0
    routine_enumeration_uncertainty_path_count: int = 0
    routine_run_level_uncertainty_reason_count: int = 0

    @property
    def uncertainty_was_observed(self) -> bool:
        return bool(
            self.uncertain_path_count
            or self.selected_capability_uncertainty_path_count
            or self.run_level_uncertainty_reason_count
            or self.enumeration_uncertainty_path_count
        )

    @property
    def material_uncertainty_was_observed(self) -> bool:
        return bool(
            self.material_uncertain_path_count
            or self.material_selected_capability_uncertainty_path_count
            or self.material_run_level_uncertainty_reason_count
            or self.material_enumeration_uncertainty_path_count
        )

    @property
    def filesystem_scope_enumeration_is_complete(self) -> bool:
        return self.enumeration_uncertainty_path_count == 0

    @property
    def material_filesystem_scope_enumeration_is_complete(self) -> bool:
        return self.material_enumeration_uncertainty_path_count == 0

    def _uncertainty_counts_for_grade(self, grade: str) -> dict[str, int]:
        if grade == UNCERTAINTY_GRADE_MATERIAL:
            return {
                "uncertain_path_count": self.material_uncertain_path_count,
                "filtered_uncertain_path_count": (
                    self.material_filtered_uncertain_path_count
                ),
                "selected_capability_uncertainty_path_count": (
                    self.material_selected_capability_uncertainty_path_count
                ),
                "enumeration_uncertainty_path_count": (
                    self.material_enumeration_uncertainty_path_count
                ),
                "run_level_uncertainty_reason_count": (
                    self.material_run_level_uncertainty_reason_count
                ),
            }
        if grade == UNCERTAINTY_GRADE_ROUTINE:
            return {
                "uncertain_path_count": self.routine_uncertain_path_count,
                "filtered_uncertain_path_count": (
                    self.routine_filtered_uncertain_path_count
                ),
                "selected_capability_uncertainty_path_count": (
                    self.routine_selected_capability_uncertainty_path_count
                ),
                "enumeration_uncertainty_path_count": (
                    self.routine_enumeration_uncertainty_path_count
                ),
                "run_level_uncertainty_reason_count": (
                    self.routine_run_level_uncertainty_reason_count
                ),
            }
        raise ValueError(f"unknown uncertainty grade: {grade!r}")

    def as_serializable_dictionary(
        self,
        *,
        include_routine_uncertainty: bool,
    ) -> dict[str, object]:
        serialized_statistics: dict[str, object] = {
            "assessed_path_count": self.assessed_path_count,
            "emitted_path_record_count": self.emitted_path_record_count,
            "filtered_path_count": self.filtered_path_count,
            "allowed_path_count": self.allowed_path_count,
            "blocked_path_count": self.blocked_path_count,
            "skipped_path_count": self.skipped_path_count,
        }
        if self.material_uncertainty_was_observed:
            serialized_statistics["material_uncertainty"] = (
                self._uncertainty_counts_for_grade(UNCERTAINTY_GRADE_MATERIAL)
            )
        if include_routine_uncertainty:
            serialized_statistics["uncertainty_by_grade"] = {
                UNCERTAINTY_GRADE_MATERIAL: self._uncertainty_counts_for_grade(
                    UNCERTAINTY_GRADE_MATERIAL
                ),
                UNCERTAINTY_GRADE_ROUTINE: self._uncertainty_counts_for_grade(
                    UNCERTAINTY_GRADE_ROUTINE
                ),
            }
        return serialized_statistics


@dataclass(frozen=True)
class AuditExecutionResult:
    statistics: AuditRunStatistics

    @property
    def uncertainty_was_observed(self) -> bool:
        return self.statistics.uncertainty_was_observed


def determine_assessment_model_status(
    assessment: PathCapabilityAssessment,
    selected_capabilities: Sequence[str],
) -> str:
    selected_inferences = [
        assessment.inference_for_capability(capability_name)
        for capability_name in selected_capabilities
    ]
    if any(
        inference.model_verdict == MODEL_VERDICT_INDICATES_ALLOWED
        for inference in selected_inferences
    ):
        return PATH_MODEL_STATUS_AT_LEAST_ONE_CAPABILITY_ALLOWED
    if all(
        inference.model_verdict == MODEL_VERDICT_SKIPPED
        for inference in selected_inferences
    ):
        return PATH_MODEL_STATUS_SKIPPED
    if any(
        inference.model_verdict == MODEL_VERDICT_INSUFFICIENT_EVIDENCE
        for inference in selected_inferences
    ):
        return PATH_MODEL_STATUS_INSUFFICIENT_EVIDENCE
    return PATH_MODEL_STATUS_NO_CAPABILITY_ALLOWED


def selected_capability_uncertainty_grade(
    assessment: PathCapabilityAssessment,
    selected_capabilities: Sequence[str],
) -> str | None:
    uncertainty_grades = {
        uncertainty_grade_for_reason_sequence(inference.evidence_reasons)
        for capability_name in selected_capabilities
        if (
            inference := assessment.inference_for_capability(capability_name)
        ).model_verdict
        == MODEL_VERDICT_INSUFFICIENT_EVIDENCE
    }
    if UNCERTAINTY_GRADE_MATERIAL in uncertainty_grades:
        return UNCERTAINTY_GRADE_MATERIAL
    if UNCERTAINTY_GRADE_ROUTINE in uncertainty_grades:
        return UNCERTAINTY_GRADE_ROUTINE
    return None


def assessment_enumeration_uncertainty_grade(
    assessment: PathCapabilityAssessment,
) -> str | None:
    enumeration_reasons: list[EvidenceReason] = []
    try:
        enumeration_reasons.extend(
            reason
            for reason in assessment.observation_notes
            if reason.reason_code in ENUMERATION_UNCERTAINTY_REASON_CODES
        )
    except (AttributeError, TypeError):
        pass
    try:
        enumeration_reasons.extend(
            reason
            for inference in assessment.inference_by_capability_name.values()
            for reason in inference.evidence_reasons
            if reason.reason_code in ENUMERATION_UNCERTAINTY_REASON_CODES
        )
    except TypeError:
        # Test doubles and third-party callers may provide only the documented
        # inference_for_capability interface.  Enumeration accounting is
        # supplemental and must not force allocation or introspection.
        pass
    if not enumeration_reasons:
        return None
    reason_grades = {
        evidence_reason_uncertainty_grade(reason) or UNCERTAINTY_GRADE_MATERIAL
        for reason in enumeration_reasons
    }
    if UNCERTAINTY_GRADE_MATERIAL in reason_grades:
        return UNCERTAINTY_GRADE_MATERIAL
    return UNCERTAINTY_GRADE_ROUTINE


def assessment_has_enumeration_uncertainty(
    assessment: PathCapabilityAssessment,
) -> bool:
    """Compatibility predicate for callers that do not need the grade."""
    return assessment_enumeration_uncertainty_grade(assessment) is not None


def structured_record_should_be_emitted(
    record: StructuredPathAuditRecord,
    *,
    configuration: AuditCommandLineConfiguration,
) -> bool:
    return not (
        not configuration.include_nonmatching_records
        and record.model_status != PATH_MODEL_STATUS_AT_LEAST_ONE_CAPABILITY_ALLOWED
    )


def path_assessment_should_be_emitted(
    assessment: PathCapabilityAssessment,
    *,
    configuration: AuditCommandLineConfiguration,
) -> bool:
    """Apply the default allowed-capability filter before record allocation."""
    if configuration.include_nonmatching_records:
        return True
    return any(
        assessment.inference_for_capability(capability_name).model_verdict
        == MODEL_VERDICT_INDICATES_ALLOWED
        for capability_name in configuration.selected_capabilities
    )


def output_stream_is_attached_to_terminal(output_stream: TextIO) -> bool:
    """Treat an unavailable or failed terminal query as noninteractive output."""
    try:
        return bool(output_stream.isatty())
    except (AttributeError, OSError, ValueError):
        return False


def resolve_audit_output_presentation(
    configuration: AuditCommandLineConfiguration,
    output_stream: TextIO,
) -> str:
    """Resolve explicit presentation intent before consulting output context."""
    if configuration.requested_output_presentation != OUTPUT_PRESENTATION_AUTOMATIC:
        return configuration.requested_output_presentation
    if configuration.full_audit:
        return OUTPUT_PRESENTATION_JSON_LINES
    if configuration.output_destination != "-":
        return OUTPUT_PRESENTATION_JSON_LINES
    if output_stream_is_attached_to_terminal(output_stream):
        return OUTPUT_PRESENTATION_TERMINAL_PATHS
    return OUTPUT_PRESENTATION_JSON_LINES


def iterate_structured_path_audit_records(
    configuration: AuditCommandLineConfiguration,
    permission_auditor: LinuxFilesystemMutationPermissionAuditor,
    *,
    statistics: AuditRunStatistics | None = None,
) -> Iterator[StructuredPathAuditRecord]:
    selected_capabilities = configuration.selected_capabilities
    active_statistics = statistics or AuditRunStatistics()

    for normalized_scan_root in configuration.scan_root_paths:
        for path_assessment in permission_auditor.assess_path_tree(
            normalized_scan_root,
            selected_capabilities=selected_capabilities,
        ):
            active_statistics.assessed_path_count += 1
            selected_uncertainty_grade = selected_capability_uncertainty_grade(
                path_assessment,
                selected_capabilities,
            )
            if selected_uncertainty_grade is not None:
                active_statistics.selected_capability_uncertainty_path_count += 1
                if selected_uncertainty_grade == UNCERTAINTY_GRADE_MATERIAL:
                    active_statistics.material_selected_capability_uncertainty_path_count += 1
                else:
                    active_statistics.routine_selected_capability_uncertainty_path_count += 1
            assessment_status = determine_assessment_model_status(
                path_assessment,
                selected_capabilities,
            )
            if assessment_status == PATH_MODEL_STATUS_AT_LEAST_ONE_CAPABILITY_ALLOWED:
                active_statistics.allowed_path_count += 1
            elif assessment_status == PATH_MODEL_STATUS_NO_CAPABILITY_ALLOWED:
                active_statistics.blocked_path_count += 1
            elif assessment_status == PATH_MODEL_STATUS_INSUFFICIENT_EVIDENCE:
                active_statistics.uncertain_path_count += 1
                if selected_uncertainty_grade == UNCERTAINTY_GRADE_ROUTINE:
                    active_statistics.routine_uncertain_path_count += 1
                else:
                    active_statistics.material_uncertain_path_count += 1
            else:
                active_statistics.skipped_path_count += 1
            enumeration_uncertainty_grade = assessment_enumeration_uncertainty_grade(
                path_assessment
            )
            if enumeration_uncertainty_grade is not None:
                active_statistics.enumeration_uncertainty_path_count += 1
                if enumeration_uncertainty_grade == UNCERTAINTY_GRADE_MATERIAL:
                    active_statistics.material_enumeration_uncertainty_path_count += 1
                else:
                    active_statistics.routine_enumeration_uncertainty_path_count += 1
            if not path_assessment_should_be_emitted(
                path_assessment,
                configuration=configuration,
            ):
                active_statistics.filtered_path_count += 1
                if assessment_status == PATH_MODEL_STATUS_INSUFFICIENT_EVIDENCE:
                    active_statistics.filtered_uncertain_path_count += 1
                    if selected_uncertainty_grade == UNCERTAINTY_GRADE_ROUTINE:
                        active_statistics.routine_filtered_uncertain_path_count += 1
                    else:
                        active_statistics.material_filtered_uncertain_path_count += 1
                continue
            structured_record = path_assessment.create_structured_record(
                selected_capabilities=selected_capabilities,
                originating_scan_root_path=normalized_scan_root,
            )
            if structured_record_should_be_emitted(
                structured_record,
                configuration=configuration,
            ):
                active_statistics.emitted_path_record_count += 1
                yield structured_record


def escape_linux_path_text_for_terminal(path_text: str) -> str:
    """Render arbitrary Linux filename bytes on exactly one terminal line."""
    # Most paths need no escaping.  str.isprintable performs its scan in C;
    # quotes and backslashes are the only printable characters transformed by
    # the complete encoder below.
    if path_text.isprintable() and "\\" not in path_text and '"' not in path_text:
        return path_text

    escaped_characters: list[str] = []
    short_control_escape_by_character = {
        "\b": r"\b",
        "\f": r"\f",
        "\n": r"\n",
        "\r": r"\r",
        "\t": r"\t",
    }

    for character in path_text:
        character_codepoint = ord(character)
        if character == "\\":
            escaped_characters.append(r"\\")
        elif character == '"':
            escaped_characters.append(r"\"")
        elif character in short_control_escape_by_character:
            escaped_characters.append(short_control_escape_by_character[character])
        elif 0xDC80 <= character_codepoint <= 0xDCFF:
            escaped_characters.append(f"\\x{character_codepoint - 0xDC00:02x}")
        elif (
            0xD800 <= character_codepoint <= 0xDFFF
            or character_codepoint < 0x20
            or character_codepoint == 0x7F
        ):
            escaped_characters.append(f"\\u{character_codepoint:04x}")
        else:
            escaped_characters.append(character)

    return "".join(escaped_characters)


def terminal_path_description(record: StructuredPathAuditRecord) -> str:
    """Describe the assessed entry with the compact terminal conventions."""
    displayed_audited_path = record.audited_path
    if (
        record.filesystem_object_kind == FILESYSTEM_OBJECT_KIND_DIRECTORY
        and displayed_audited_path != "/"
    ):
        displayed_audited_path += "/"

    if (
        record.filesystem_object_kind == FILESYSTEM_OBJECT_KIND_SYMBOLIC_LINK
        and record.resolved_symbolic_link_target_path is not None
    ):
        displayed_target_path = record.resolved_symbolic_link_target_path
        if (
            record.resolved_symbolic_link_target_kind
            == FILESYSTEM_OBJECT_KIND_DIRECTORY
            and displayed_target_path != "/"
        ):
            displayed_target_path += "/"
        displayed_audited_path += f" -> {displayed_target_path}"

    return escape_linux_path_text_for_terminal(displayed_audited_path)


def terminal_allowed_capability_label(record: StructuredPathAuditRecord) -> str:
    """Return stable compact labels for only model-allowed capabilities."""
    allowed_capability_names = set(record.model_indicated_capabilities)
    return "".join(
        TERMINAL_CAPABILITY_LABEL_BY_NAME[capability_name]
        for capability_name in CAPABILITY_EVALUATION_ORDER
        if capability_name in allowed_capability_names
    )


def write_complete_audit_output_unit(
    complete_output_text: str,
    *,
    output_stream: TextIO,
    output_unit_description: str,
) -> None:
    """Require one stream call to accept one complete line-oriented unit."""
    try:
        written_character_count = output_stream.write(complete_output_text)
    except BrokenPipeError:
        raise
    except (OSError, UnicodeError) as error:
        raise AuditReportTransportError(
            f"cannot write a complete {output_unit_description}: {error}"
        ) from error
    if written_character_count != len(complete_output_text):
        raise AuditReportTransportError(
            f"stream reported an incomplete {output_unit_description} write: "
            f"expected_characters={len(complete_output_text)}; "
            f"reported_characters={written_character_count!r}"
        )


def write_terminal_path_audit_record(
    record: StructuredPathAuditRecord,
    *,
    output_stream: TextIO,
) -> None:
    """Write one compact capability label and unambiguous displayed path."""
    allowed_capability_label = terminal_allowed_capability_label(record)
    displayed_path = terminal_path_description(record)
    terminal_line = (
        f"[{allowed_capability_label}] {displayed_path}\n"
        if allowed_capability_label
        else f"{displayed_path}\n"
    )
    write_complete_audit_output_unit(
        terminal_line,
        output_stream=output_stream,
        output_unit_description="terminal path record",
    )


def write_all_terminal_path_audit_records(
    configuration: AuditCommandLineConfiguration,
    permission_auditor: LinuxFilesystemMutationPermissionAuditor,
    output_stream: TextIO,
    *,
    statistics: AuditRunStatistics | None = None,
) -> None:
    """Write the concise interactive view without JSON provenance records."""
    for structured_record in iterate_structured_path_audit_records(
        configuration,
        permission_auditor,
        statistics=statistics,
    ):
        write_terminal_path_audit_record(
            structured_record,
            output_stream=output_stream,
        )


def write_structured_path_audit_record(
    record: StructuredPathAuditRecord,
    *,
    output_stream: TextIO,
    serialized_audit_run_provenance: Mapping[str, object],
    include_routine_uncertainty: bool,
) -> None:
    write_json_line_to_audit_report(
        record.as_serializable_dictionary(
            serialized_audit_run_provenance=serialized_audit_run_provenance,
            include_routine_uncertainty=include_routine_uncertainty,
        ),
        output_stream=output_stream,
    )


def write_all_audit_records(
    configuration: AuditCommandLineConfiguration,
    permission_auditor: LinuxFilesystemMutationPermissionAuditor,
    output_stream: TextIO,
    *,
    audit_run_provenance: AuditRunProvenance,
    statistics: AuditRunStatistics | None = None,
) -> None:
    active_statistics = statistics or AuditRunStatistics()
    serialized_audit_run_provenance = audit_run_provenance.as_serializable_dictionary(
        include_routine_uncertainty=configuration.include_nonmatching_records
    )
    write_audit_run_provenance_record(
        output_stream=output_stream,
        serialized_audit_run_provenance=(serialized_audit_run_provenance),
    )
    for structured_record in iterate_structured_path_audit_records(
        configuration,
        permission_auditor,
        statistics=active_statistics,
    ):
        write_structured_path_audit_record(
            structured_record,
            output_stream=output_stream,
            serialized_audit_run_provenance=(serialized_audit_run_provenance),
            include_routine_uncertainty=configuration.include_nonmatching_records,
        )
    write_audit_run_completion_record(
        output_stream=output_stream,
        audit_run_provenance=audit_run_provenance,
        statistics=active_statistics,
        fail_on_uncertainty=configuration.fail_on_uncertainty,
        include_routine_uncertainty=configuration.include_nonmatching_records,
    )


def write_audit_run_provenance_record(
    *,
    output_stream: TextIO,
    serialized_audit_run_provenance: Mapping[str, object],
) -> None:
    """Make even a zero-path JSONL report identify its evidence context."""
    write_json_line_to_audit_report(
        {
            "record_schema_id": STRUCTURED_RECORD_SCHEMA_ID,
            "record_type": "audit_run_provenance",
            "audit_run_provenance": serialized_audit_run_provenance,
        },
        output_stream=output_stream,
    )


def write_audit_run_completion_record(
    *,
    output_stream: TextIO,
    audit_run_provenance: AuditRunProvenance,
    statistics: AuditRunStatistics,
    fail_on_uncertainty: bool,
    include_routine_uncertainty: bool,
) -> None:
    """Mark a JSONL stream as fully generated and summarize filtered evidence."""
    write_json_line_to_audit_report(
        {
            "record_schema_id": STRUCTURED_RECORD_SCHEMA_ID,
            "record_type": "audit_run_completion",
            "audit_run_id": audit_run_provenance.audit_run_id,
            "audit_completed_at_utc": current_utc_timestamp(),
            "audit_algorithm_completed": True,
            **(
                {
                    "filesystem_scope_enumeration_is_complete": (
                        statistics.filesystem_scope_enumeration_is_complete
                        if include_routine_uncertainty
                        else False
                    )
                }
                if (
                    include_routine_uncertainty
                    or not statistics.material_filesystem_scope_enumeration_is_complete
                )
                else {}
            ),
            "statistics": statistics.as_serializable_dictionary(
                include_routine_uncertainty=include_routine_uncertainty
            ),
            **(
                {
                    "uncertainty_policy": {
                        "fail_on_uncertainty": fail_on_uncertainty,
                        "reported_uncertainty_grade": (
                            "routine_and_material"
                            if include_routine_uncertainty
                            else UNCERTAINTY_GRADE_MATERIAL
                        ),
                        "uncertainty_was_observed": (
                            statistics.uncertainty_was_observed
                            if include_routine_uncertainty
                            else statistics.material_uncertainty_was_observed
                        ),
                        "policy_was_satisfied": (
                            not fail_on_uncertainty
                            or not statistics.material_uncertainty_was_observed
                        ),
                    }
                }
                if (
                    include_routine_uncertainty
                    or fail_on_uncertainty
                    or statistics.material_uncertainty_was_observed
                )
                else {}
            ),
        },
        output_stream=output_stream,
    )


class AuditReportTransportError(Exception):
    """A failure to carry complete audit output to the selected stream."""


def write_json_line_to_audit_report(
    serializable_record: Mapping[str, object],
    *,
    output_stream: TextIO,
) -> None:
    """Serialize one complete record before attempting a single stream write."""
    serialized_json_line = (
        json.dumps(
            serializable_record,
            ensure_ascii=True,
            sort_keys=False,
        )
        + "\n"
    )
    write_complete_audit_output_unit(
        serialized_json_line,
        output_stream=output_stream,
        output_unit_description="JSONL record",
    )


class ReportPublicationError(Exception):
    """A user-actionable private-report lifecycle failure."""


def quote_path_for_diagnostic(path: str) -> str:
    """ASCII-safe representation for paths containing arbitrary Linux bytes."""
    return json.dumps(path, ensure_ascii=True)


def lstat_directory_entry_if_present(
    directory_file_descriptor: int,
    entry_name: str,
) -> os.stat_result | None:
    """Observe one entry relative to a stable, already-open directory."""
    try:
        return os.stat(
            entry_name,
            dir_fd=directory_file_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None


@dataclass(frozen=True)
class ReportDestinationObservation:
    """Identity/change snapshot used for conditional report replacement."""

    filesystem_identity: FilesystemObjectIdentity
    inode_change_time_nanoseconds: int
    content_modification_time_nanoseconds: int
    file_size_bytes: int
    permission_and_type_mode: int
    owner_user_id: int
    owner_group_id: int
    hard_link_count: int

    @classmethod
    def from_stat_result(
        cls,
        filesystem_metadata: os.stat_result,
    ) -> ReportDestinationObservation:
        return cls(
            filesystem_identity=(
                FilesystemObjectIdentity.from_stat_result(filesystem_metadata)
            ),
            inode_change_time_nanoseconds=filesystem_metadata.st_ctime_ns,
            content_modification_time_nanoseconds=(filesystem_metadata.st_mtime_ns),
            file_size_bytes=filesystem_metadata.st_size,
            permission_and_type_mode=filesystem_metadata.st_mode,
            owner_user_id=filesystem_metadata.st_uid,
            owner_group_id=filesystem_metadata.st_gid,
            hard_link_count=filesystem_metadata.st_nlink,
        )

    def matches_after_directory_entry_exchange(
        self,
        observation_before_exchange: ReportDestinationObservation,
    ) -> bool:
        """Compare fields that an entry exchange does not itself change."""
        return (
            self.filesystem_identity == observation_before_exchange.filesystem_identity
            and self.inode_change_time_nanoseconds
            >= observation_before_exchange.inode_change_time_nanoseconds
            and self.content_modification_time_nanoseconds
            == observation_before_exchange.content_modification_time_nanoseconds
            and self.file_size_bytes == observation_before_exchange.file_size_bytes
            and self.permission_and_type_mode
            == observation_before_exchange.permission_and_type_mode
            and self.owner_user_id == observation_before_exchange.owner_user_id
            and self.owner_group_id == observation_before_exchange.owner_group_id
            and self.hard_link_count == observation_before_exchange.hard_link_count
        )


class PrivateReportPublication:
    """
    Own one mode-0600 report from unpublished creation through durability.

    Every report is written to a same-directory sibling whose filename names
    the tool, run ID, unpublished state, and output presentation.  The
    destination directory remains open so creation, observation, rename,
    unlink, and fsync use one stable directory descriptor even if an ancestor
    pathname changes.

    Linux ``renameat2(RENAME_NOREPLACE)`` publishes when the destination was
    absent.  Replacing an observed regular file uses
    ``renameat2(RENAME_EXCHANGE)`` so the displaced entry survives until both
    sides of the exchange have been identity-checked.  A changed destination is
    exchanged back.  A process able to rename entries inside the destination
    directory can still race separate identity and unlink operations; hostile
    shared-directory publication is therefore not claimed to be transactional.
    """

    _TEMPORARY_NAME_CREATION_ATTEMPT_LIMIT = 128

    def __init__(
        self,
        requested_destination_path: str,
        *,
        audit_run_id: str,
        report_output_presentation: str,
        replacement_is_authorized: bool,
    ):
        if report_output_presentation not in (
            OUTPUT_PRESENTATION_TERMINAL_PATHS,
            OUTPUT_PRESENTATION_JSON_LINES,
        ):
            raise ValueError(
                "report output presentation must already be resolved: "
                f"{report_output_presentation!r}"
            )
        requested_components = split_requested_path_without_normalizing(
            requested_destination_path
        )
        self.requested_destination_path = (
            requested_components.absolute_path_with_dot_components
        )
        self.destination_path = self.requested_destination_path
        self.destination_parent_directory_path = (
            requested_components.parent_path_with_dot_components
        )
        self.destination_entry_name = requested_components.final_component
        if (
            requested_components.trailing_separator_requires_directory
            or requested_components.final_component_is_dot_or_dot_dot
        ):
            raise ReportPublicationError(
                "report destination has no filename: "
                f"{quote_path_for_diagnostic(self.destination_path)}"
            )
        self.audit_run_id = audit_run_id
        self.report_output_presentation = report_output_presentation
        self.replacement_is_authorized = replacement_is_authorized
        self.destination_directory_file_descriptor: int | None = None
        self.text_stream: TextIO | None = None
        self.unpublished_report_entry_name: str | None = None
        self.unpublished_report_path: str | None = None
        self.created_report_identity: FilesystemObjectIdentity | None = None
        self.destination_observation_before_audit: (
            ReportDestinationObservation | None
        ) = None
        self.paths_to_ignore_during_audit: tuple[str, ...] = ()
        self.temporary_entry_contains_created_report = False
        self.created_report_was_published_to_destination = False

    # Python 3.9 has no typing.Self; the concrete class is the runtime contract.
    def __enter__(self) -> PrivateReportPublication:  # noqa: PYI034
        try:
            self._open_destination_directory()
            self._open_unpublished_report()
        except BaseException:
            self._close_report_stream_without_masking_original_error()
            self._remove_unpublished_report_if_identity_still_matches()
            self._close_destination_directory_without_masking_original_error()
            raise
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        _exception_value: BaseException | None,
        _exception_traceback: TracebackType | None,
    ) -> bool:
        try:
            if exception_type is not None:
                self._close_report_stream_without_masking_original_error()
                self._remove_unpublished_report_if_identity_still_matches()
                return False

            try:
                self._flush_synchronize_and_close_complete_report()
                self._conditionally_publish_synchronized_report()
                self._synchronize_destination_directory()
            except ReportPublicationError:
                self._close_report_stream_without_masking_original_error()
                self._remove_unpublished_report_if_identity_still_matches()
                raise
            except (OSError, UnicodeError, ValueError) as error:
                self._close_report_stream_without_masking_original_error()
                self._remove_unpublished_report_if_identity_still_matches()
                raise ReportPublicationError(
                    "cannot finish report "
                    f"{quote_path_for_diagnostic(self.destination_path)}: "
                    f"{error}"
                ) from error
            except BaseException:
                self._close_report_stream_without_masking_original_error()
                self._remove_unpublished_report_if_identity_still_matches()
                raise
        finally:
            self._close_destination_directory_without_masking_original_error()
        return False

    def _open_destination_directory(self) -> None:
        directory_open_flags = os.O_RDONLY
        directory_open_flags |= getattr(os, "O_CLOEXEC", 0)
        directory_open_flags |= getattr(os, "O_DIRECTORY", 0)
        destination_directory_file_descriptor = os.open(
            self.destination_parent_directory_path,
            directory_open_flags,
        )
        try:
            opened_directory_metadata = os.fstat(destination_directory_file_descriptor)
            if not stat.S_ISDIR(opened_directory_metadata.st_mode):
                raise ReportPublicationError(
                    "report destination parent descriptor is not a directory"
                )
            shared_write_permission_bits = opened_directory_metadata.st_mode & (
                stat.S_IWGRP | stat.S_IWOTH
            )
            if (
                shared_write_permission_bits
                and not (opened_directory_metadata.st_mode & stat.S_ISVTX)
            ):
                destination_directory_diagnostic = quote_path_for_diagnostic(
                    self.destination_parent_directory_path
                )
                raise ReportPublicationError(
                    "refusing non-sticky group/other-writable report "
                    "destination directory "
                    f"{destination_directory_diagnostic}; "
                    "another user could replace a validated cleanup entry"
                )
        except BaseException:
            with contextlib.suppress(OSError):
                os.close(destination_directory_file_descriptor)
            raise
        self.destination_directory_file_descriptor = (
            destination_directory_file_descriptor
        )
        canonical_parent_path, canonical_path_note = (
            observe_canonical_path_for_file_descriptor(
                destination_directory_file_descriptor,
                fallback_path=self.destination_parent_directory_path,
            )
        )
        if canonical_path_note is not None:
            os.close(destination_directory_file_descriptor)
            self.destination_directory_file_descriptor = None
            raise ReportPublicationError(
                "cannot establish the canonical report destination parent: "
                f"{canonical_path_note.reason_code}"
            )
        self.destination_parent_directory_path = canonical_parent_path
        self.destination_path = lexically_normalize_absolute_path(
            os.path.join(canonical_parent_path, self.destination_entry_name)
        )

    def _require_destination_directory_file_descriptor(self) -> int:
        if self.destination_directory_file_descriptor is None:
            raise ReportPublicationError(
                "internal invariant failed: destination directory is not open"
            )
        return self.destination_directory_file_descriptor

    def _validate_observed_destination_kind(
        self,
        observed_destination_metadata: os.stat_result | None,
    ) -> None:
        if observed_destination_metadata is None:
            return

        observed_destination_kind = classify_filesystem_object_kind(
            observed_destination_metadata
        )
        if observed_destination_kind == FILESYSTEM_OBJECT_KIND_SYMBOLIC_LINK:
            raise ReportPublicationError(
                "refusing symbolic-link report destination "
                f"{quote_path_for_diagnostic(self.destination_path)}"
            )
        if observed_destination_kind != FILESYSTEM_OBJECT_KIND_REGULAR_FILE:
            raise ReportPublicationError(
                "refusing "
                f"{observed_destination_kind} report destination "
                f"{quote_path_for_diagnostic(self.destination_path)}; "
                "reports must be regular files"
            )
        if not self.replacement_is_authorized:
            raise ReportPublicationError(
                "report destination already exists: "
                f"{quote_path_for_diagnostic(self.destination_path)}; "
                "--replace-output is required to replace this regular file"
            )

    def _open_unpublished_report(self) -> None:
        try:
            destination_directory_file_descriptor = (
                self._require_destination_directory_file_descriptor()
            )
            initially_observed_destination = lstat_directory_entry_if_present(
                destination_directory_file_descriptor,
                self.destination_entry_name,
            )
            self._validate_observed_destination_kind(
                initially_observed_destination,
            )
            if initially_observed_destination is not None:
                self.destination_observation_before_audit = (
                    ReportDestinationObservation.from_stat_result(
                        initially_observed_destination
                    )
                )

            report_file_descriptor = self._create_unpublished_report_file_exclusively(
                destination_directory_file_descriptor
            )
            self._adopt_created_report_file_descriptor(report_file_descriptor)
        except ReportPublicationError:
            raise
        except (OSError, UnicodeError, ValueError) as error:
            raise ReportPublicationError(
                "cannot prepare unpublished report for "
                f"{quote_path_for_diagnostic(self.destination_path)}: "
                f"{error}"
            ) from error

        if self.unpublished_report_path is None:
            raise ReportPublicationError(
                "internal invariant failed: unpublished report path was not recorded"
            )
        self.paths_to_ignore_during_audit = (
            self.destination_path,
            self.unpublished_report_path,
        )

    def _create_unpublished_report_file_exclusively(
        self,
        destination_directory_file_descriptor: int,
    ) -> int:
        exclusive_create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        exclusive_create_flags |= getattr(os, "O_CLOEXEC", 0)
        exclusive_create_flags |= getattr(os, "O_NOFOLLOW", 0)

        for creation_attempt_number in range(
            1,
            self._TEMPORARY_NAME_CREATION_ATTEMPT_LIMIT + 1,
        ):
            candidate_entry_name = (
                f".{AUDIT_TOOL_NAME}.{self.audit_run_id}."
                "unpublished-report."
                f"{self.report_output_presentation}."
                f"attempt-{creation_attempt_number:03d}.tmp"
            )
            try:
                report_file_descriptor = os.open(
                    candidate_entry_name,
                    exclusive_create_flags,
                    0o600,
                    dir_fd=destination_directory_file_descriptor,
                )
            except FileExistsError:
                continue

            self.unpublished_report_entry_name = candidate_entry_name
            self.unpublished_report_path = lexically_normalize_absolute_path(
                os.path.join(
                    self.destination_parent_directory_path,
                    candidate_entry_name,
                )
            )
            self.temporary_entry_contains_created_report = True
            return report_file_descriptor

        raise ReportPublicationError(
            "cannot allocate a unique unpublished report filename after "
            f"{self._TEMPORARY_NAME_CREATION_ATTEMPT_LIMIT} attempts"
        )

    def _adopt_created_report_file_descriptor(
        self,
        report_file_descriptor: int,
    ) -> None:
        try:
            created_report_metadata = os.fstat(report_file_descriptor)
            if not stat.S_ISREG(created_report_metadata.st_mode):
                raise ReportPublicationError(
                    "created report descriptor does not identify a regular file"
                )
            self.created_report_identity = FilesystemObjectIdentity.from_stat_result(
                created_report_metadata
            )
            os.fchmod(report_file_descriptor, 0o600)
            self.text_stream = os.fdopen(
                report_file_descriptor,
                "w",
                encoding="utf-8",
                errors="strict",
                newline="",
            )
        except BaseException:
            with contextlib.suppress(OSError):
                os.close(report_file_descriptor)
            raise

    def _flush_synchronize_and_close_complete_report(self) -> None:
        if self.text_stream is None:
            raise ReportPublicationError(
                "internal invariant failed: report text stream was not opened"
            )

        report_stream = self.text_stream
        self.text_stream = None
        try:
            report_stream.flush()
            os.fsync(report_stream.fileno())
        except BaseException:
            with contextlib.suppress(OSError, UnicodeError, ValueError):
                report_stream.close()
            raise
        else:
            report_stream.close()

    def _conditionally_publish_synchronized_report(self) -> None:
        if self.unpublished_report_entry_name is None:
            raise ReportPublicationError(
                "internal invariant failed: unpublished report entry name is missing"
            )
        self._verify_temporary_entry_contains_created_report()

        pre_audit_destination_observation = self.destination_observation_before_audit
        if pre_audit_destination_observation is None:
            try:
                destination_directory_file_descriptor = (
                    self._require_destination_directory_file_descriptor()
                )
                rename_linux_directory_entry_with_flags(
                    destination_directory_file_descriptor,
                    self.unpublished_report_entry_name,
                    destination_directory_file_descriptor,
                    self.destination_entry_name,
                    RENAME_NOREPLACE,
                )
            except FileExistsError as error:
                raise ReportPublicationError(
                    "refusing to replace a destination created during the "
                    "audit: "
                    f"{quote_path_for_diagnostic(self.destination_path)}"
                ) from error
            self.temporary_entry_contains_created_report = False
            self._verify_destination_contains_created_report()
            self.created_report_was_published_to_destination = True
            return

        self._exchange_with_observed_destination_and_validate(
            pre_audit_destination_observation
        )

    def _exchange_with_observed_destination_and_validate(
        self,
        pre_audit_destination_observation: ReportDestinationObservation,
    ) -> None:
        if self.unpublished_report_entry_name is None:
            raise ReportPublicationError(
                "internal invariant failed: unpublished report entry name is missing"
            )
        destination_directory_file_descriptor = (
            self._require_destination_directory_file_descriptor()
        )
        destination_metadata_before_exchange = lstat_directory_entry_if_present(
            destination_directory_file_descriptor,
            self.destination_entry_name,
        )
        if (
            destination_metadata_before_exchange is None
            or ReportDestinationObservation.from_stat_result(
                destination_metadata_before_exchange
            )
            != pre_audit_destination_observation
        ):
            raise ReportPublicationError(
                "refusing to replace a destination whose identity or "
                "metadata changed during the audit: "
                f"{quote_path_for_diagnostic(self.destination_path)}"
            )

        rename_linux_directory_entry_with_flags(
            destination_directory_file_descriptor,
            self.unpublished_report_entry_name,
            destination_directory_file_descriptor,
            self.destination_entry_name,
            RENAME_EXCHANGE,
        )
        self.temporary_entry_contains_created_report = False

        try:
            self._verify_destination_contains_created_report()
            displaced_destination_metadata = os.stat(
                self.unpublished_report_entry_name,
                dir_fd=destination_directory_file_descriptor,
                follow_symlinks=False,
            )
            displaced_destination_observation = (
                ReportDestinationObservation.from_stat_result(
                    displaced_destination_metadata
                )
            )
            # Some Linux filesystems update inode ctime for RENAME_EXCHANGE.
            # The full observation was compared immediately before exchange;
            # afterward, accept only a forward ctime change while continuing
            # to validate identity and every other captured metadata field.
            if not displaced_destination_observation.matches_after_directory_entry_exchange(
                pre_audit_destination_observation
            ):
                raise ReportPublicationError(
                    "refusing to replace a destination whose identity or "
                    "metadata changed during the audit: "
                    f"{quote_path_for_diagnostic(self.destination_path)}"
                )
        except BaseException as publication_error:
            self._exchange_entries_back_after_failed_validation(publication_error)
            raise

        self.created_report_was_published_to_destination = True
        try:
            os.unlink(
                self.unpublished_report_entry_name,
                dir_fd=destination_directory_file_descriptor,
            )
        except BaseException as displaced_entry_removal_error:
            displaced_entry_metadata = lstat_directory_entry_if_present(
                destination_directory_file_descriptor,
                self.unpublished_report_entry_name,
            )
            if displaced_entry_metadata is None:
                raise
            current_displaced_destination_observation = (
                ReportDestinationObservation.from_stat_result(displaced_entry_metadata)
            )
            if not current_displaced_destination_observation.matches_after_directory_entry_exchange(
                pre_audit_destination_observation
            ):
                raise ReportPublicationError(
                    "the synchronized report is published, but the displaced "
                    "destination could not be removed and no longer matches "
                    "its validated identity/change snapshot: "
                    f"{quote_path_for_diagnostic(self.destination_path)}"
                ) from displaced_entry_removal_error
            self.created_report_was_published_to_destination = False
            self._exchange_entries_back_after_failed_validation(
                displaced_entry_removal_error
            )
            raise

    def _exchange_entries_back_after_failed_validation(
        self,
        publication_error: BaseException,
    ) -> None:
        if self.unpublished_report_entry_name is None:
            raise ReportPublicationError(
                "cannot restore the observed report destination because the "
                "temporary entry name is missing"
            ) from publication_error
        destination_directory_file_descriptor = (
            self._require_destination_directory_file_descriptor()
        )
        try:
            rename_linux_directory_entry_with_flags(
                destination_directory_file_descriptor,
                self.unpublished_report_entry_name,
                destination_directory_file_descriptor,
                self.destination_entry_name,
                RENAME_EXCHANGE,
            )
        # Interrupts and process-exit exceptions must attempt the same atomic
        # reversal as ordinary validation failures before they propagate.
        except BaseException as rollback_error:  # noqa: BLE001
            raise ReportPublicationError(
                "report destination validation failed and the atomic exchange "
                "could not be reversed; both directory entries were retained: "
                f"validation_error={publication_error}; "
                f"exchange_reversal_error={rollback_error}"
            ) from publication_error
        self.temporary_entry_contains_created_report = True

    def _verify_temporary_entry_contains_created_report(self) -> None:
        if self.unpublished_report_entry_name is None:
            raise ReportPublicationError(
                "internal invariant failed: unpublished report entry name is missing"
            )
        destination_directory_file_descriptor = (
            self._require_destination_directory_file_descriptor()
        )
        temporary_entry_metadata = os.stat(
            self.unpublished_report_entry_name,
            dir_fd=destination_directory_file_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(temporary_entry_metadata.st_mode)
            or FilesystemObjectIdentity.from_stat_result(temporary_entry_metadata)
            != self.created_report_identity
        ):
            raise ReportPublicationError(
                "unpublished report entry identity changed before publication: "
                f"{quote_path_for_diagnostic(self.unpublished_report_path or '')}"
            )

    def _verify_destination_contains_created_report(self) -> None:
        destination_directory_file_descriptor = (
            self._require_destination_directory_file_descriptor()
        )
        destination_metadata = lstat_directory_entry_if_present(
            destination_directory_file_descriptor,
            self.destination_entry_name,
        )
        if (
            destination_metadata is None
            or not stat.S_ISREG(destination_metadata.st_mode)
            or FilesystemObjectIdentity.from_stat_result(destination_metadata)
            != self.created_report_identity
        ):
            raise ReportPublicationError(
                "published destination does not identify the synchronized "
                "report that this process created: "
                f"{quote_path_for_diagnostic(self.destination_path)}"
            )

    def _synchronize_destination_directory(self) -> None:
        os.fsync(self._require_destination_directory_file_descriptor())

    def _close_report_stream_without_masking_original_error(self) -> None:
        if self.text_stream is None:
            return
        report_stream = self.text_stream
        self.text_stream = None
        with contextlib.suppress(OSError, UnicodeError, ValueError):
            report_stream.close()

    def _remove_unpublished_report_if_identity_still_matches(self) -> None:
        if (
            self.created_report_was_published_to_destination
            or not self.temporary_entry_contains_created_report
            or self.unpublished_report_entry_name is None
            or self.created_report_identity is None
            or self.destination_directory_file_descriptor is None
        ):
            return

        try:
            current_artifact_metadata = os.stat(
                self.unpublished_report_entry_name,
                dir_fd=self.destination_directory_file_descriptor,
                follow_symlinks=False,
            )
            current_artifact_identity = FilesystemObjectIdentity.from_stat_result(
                current_artifact_metadata
            )
            if current_artifact_identity != self.created_report_identity:
                return
            # lstat and unlink are necessarily separate pathname operations.
            # Identity checking avoids deleting an already replaced artifact;
            # an actively hostile final-component swap remains a named limit.
            os.unlink(
                self.unpublished_report_entry_name,
                dir_fd=self.destination_directory_file_descriptor,
            )
            self.temporary_entry_contains_created_report = False
            self._synchronize_destination_directory()
        except OSError:
            # Cleanup is best effort and must not hide the primary failure.
            pass

    def _close_destination_directory_without_masking_original_error(
        self,
    ) -> None:
        if self.destination_directory_file_descriptor is None:
            return
        destination_directory_file_descriptor = (
            self.destination_directory_file_descriptor
        )
        self.destination_directory_file_descriptor = None
        with contextlib.suppress(OSError):
            os.close(destination_directory_file_descriptor)


def write_diagnostic_to_standard_error(message: str) -> None:
    """Best-effort write arbitrary Linux path text under any stderr locale."""
    try:
        sys.stderr.write(message)
        sys.stderr.flush()
        return
    except UnicodeEncodeError:
        pass
    except OSError:
        return

    standard_error_encoding = getattr(sys.stderr, "encoding", None) or "ascii"
    safely_encoded_message = message.encode(
        standard_error_encoding,
        errors="backslashreplace",
    ).decode(
        standard_error_encoding,
        errors="strict",
    )
    try:
        sys.stderr.write(safely_encoded_message)
        sys.stderr.flush()
    except OSError:
        return


def configure_standard_output_for_human_readable_paths() -> None:
    """Backslash-escape characters unsupported by the active terminal codec."""
    reconfigure_standard_output = getattr(sys.stdout, "reconfigure", None)
    if reconfigure_standard_output is None:
        return
    try:
        reconfigure_standard_output(errors="backslashreplace")
    except (OSError, ValueError):
        return


def runtime_compatibility_error() -> str | None:
    """Return a user-facing reason this process cannot run the Linux backend."""
    if sys.version_info < (3, 9):  # noqa: UP036 - explicit runtime diagnostic
        return (
            "Python 3.9 or newer is required; running "
            f"{sys.version_info.major}.{sys.version_info.minor}"
        )
    if not sys.platform.startswith("linux"):
        return (
            "this release implements only the Linux evidence backend; "
            f"running platform is {sys.platform!r}. Darwin and BSD require "
            "native credential, mount, inode-flag, and access-query backends"
        )
    required_runtime_features = (
        (pwd is not None, "the POSIX pwd module"),
        (hasattr(os, "getresuid"), "os.getresuid"),
        (hasattr(os, "getresgid"), "os.getresgid"),
        (_LINUX_C_LIBRARY is not None, "the process C library"),
        (_LINUX_SYSCALL_FUNCTION is not None, "libc syscall(2)"),
    )
    missing_features = [
        feature_name
        for feature_is_available, feature_name in required_runtime_features
        if not feature_is_available
    ]
    if missing_features:
        return "Linux runtime is missing: " + ", ".join(missing_features)
    return None


def collect_run_level_uncertainty_reasons(
    *,
    process_credentials: LinuxProcessCredentialEvidence,
    mount_table_read: LinuxMountTableReadEvidence,
    audit_scope: AuditScopeEvidence,
    observed_tool_source_file: ObservedToolSourceFileEvidence,
) -> tuple[EvidenceReason, ...]:
    uncertainty_reasons: list[EvidenceReason] = list(
        mount_table_read.uncertainty_reasons
    )
    if process_credentials.filesystem_identifiers.uncertainty_reason is not None:
        uncertainty_reasons.append(
            process_credentials.filesystem_identifiers.uncertainty_reason
        )
    if process_credentials.effective_capabilities.uncertainty_reason is not None:
        uncertainty_reasons.append(
            process_credentials.effective_capabilities.uncertainty_reason
        )
    if observed_tool_source_file.uncertainty_reason is not None:
        uncertainty_reasons.append(observed_tool_source_file.uncertainty_reason)
    uncertainty_reasons.extend(
        rule.classification_uncertainty_reason
        for rule in audit_scope.exclusion_rules
        if rule.classification_uncertainty_reason is not None
    )
    if audit_scope.home_directory_discovery is not None:
        uncertainty_reasons.extend(
            audit_scope.home_directory_discovery.uncertainty_reasons
        )
    if audit_scope.temporary_directory_discovery is not None:
        uncertainty_reasons.extend(
            audit_scope.temporary_directory_discovery.uncertainty_reasons
        )
    return tuple(deduplicate_preserving_first_occurrence(uncertainty_reasons))


def execute_audit_to_stream(
    configuration: AuditCommandLineConfiguration,
    output_stream: TextIO,
    *,
    output_presentation: str,
    audit_run_id: str,
    audit_started_at_utc: str,
    internally_ignored_paths: Sequence[str],
) -> AuditExecutionResult:
    if output_presentation not in (
        OUTPUT_PRESENTATION_TERMINAL_PATHS,
        OUTPUT_PRESENTATION_JSON_LINES,
    ):
        raise ValueError(
            "audit output presentation must already be resolved: "
            f"{output_presentation!r}"
        )
    process_credentials = observe_linux_process_credentials()
    mount_table_read = read_current_process_linux_mount_table()
    audit_scope = observe_audit_scope(
        configuration,
        process_credentials=process_credentials,
        internally_ignored_paths=internally_ignored_paths,
    )
    observed_tool_source_file = observe_tool_source_file()
    permission_auditor = build_permission_auditor(
        configuration,
        mount_table_read=mount_table_read,
        process_credentials=process_credentials,
        audit_scope=audit_scope,
    )
    run_level_uncertainty_reasons = collect_run_level_uncertainty_reasons(
        process_credentials=process_credentials,
        mount_table_read=mount_table_read,
        audit_scope=audit_scope,
        observed_tool_source_file=observed_tool_source_file,
    )
    routine_run_level_reason_count = sum(
        evidence_reason_uncertainty_grade(reason) == UNCERTAINTY_GRADE_ROUTINE
        for reason in run_level_uncertainty_reasons
    )
    statistics = AuditRunStatistics(
        run_level_uncertainty_reason_count=len(run_level_uncertainty_reasons),
        material_run_level_uncertainty_reason_count=(
            len(run_level_uncertainty_reasons) - routine_run_level_reason_count
        ),
        routine_run_level_uncertainty_reason_count=(routine_run_level_reason_count),
    )
    if output_presentation == OUTPUT_PRESENTATION_TERMINAL_PATHS:
        write_all_terminal_path_audit_records(
            configuration,
            permission_auditor,
            output_stream,
            statistics=statistics,
        )
        return AuditExecutionResult(statistics=statistics)

    audit_run_provenance = build_audit_run_provenance(
        audit_run_id=audit_run_id,
        audit_started_at_utc=audit_started_at_utc,
        configuration=configuration,
        process_credentials=process_credentials,
        mount_table_read=mount_table_read,
        audit_scope=audit_scope,
        observed_tool_source_file=observed_tool_source_file,
    )
    write_all_audit_records(
        configuration,
        permission_auditor,
        output_stream,
        audit_run_provenance=audit_run_provenance,
        statistics=statistics,
    )
    return AuditExecutionResult(statistics=statistics)


def run_audit_command(command_line_arguments: Sequence[str]) -> int:
    audit_run_id = str(uuid.uuid4())
    audit_started_at_utc = current_utc_timestamp()
    configuration = parse_audit_command_line_arguments(command_line_arguments)
    compatibility_error = runtime_compatibility_error()
    if compatibility_error is not None:
        write_diagnostic_to_standard_error(
            f"{AUDIT_TOOL_NAME}: unsupported runtime: {compatibility_error}\n"
        )
        return EXIT_COMMAND_LINE_REFUSED
    output_presentation = resolve_audit_output_presentation(
        configuration,
        sys.stdout,
    )

    if os.geteuid() == 0 and not configuration.allow_effective_root_execution:
        write_diagnostic_to_standard_error(
            "Refusing an implicit effective-UID-0 audit. This tool models the\n"
            "current process identity, so unrestricted root usually describes\n"
            "root rather than the user whose exposure matters. Run as that\n"
            "identity, or add --allow-root-audit when root-context evidence is\n"
            "deliberately requested.\n"
        )
        return EXIT_COMMAND_LINE_REFUSED

    audit_execution_result: AuditExecutionResult | None = None
    try:
        if configuration.output_destination == "-":
            if output_presentation == OUTPUT_PRESENTATION_TERMINAL_PATHS:
                configure_standard_output_for_human_readable_paths()
            audit_execution_result = execute_audit_to_stream(
                configuration,
                sys.stdout,
                output_presentation=output_presentation,
                audit_run_id=audit_run_id,
                audit_started_at_utc=audit_started_at_utc,
                internally_ignored_paths=(),
            )
            try:
                sys.stdout.flush()
            except BrokenPipeError:
                raise
            except (OSError, UnicodeError) as error:
                raise AuditReportTransportError(
                    f"cannot flush standard-output report: {error}"
                ) from error
        else:
            with PrivateReportPublication(
                configuration.output_destination,
                audit_run_id=audit_run_id,
                report_output_presentation=output_presentation,
                replacement_is_authorized=(configuration.replace_existing_output),
            ) as report_publication:
                if report_publication.text_stream is None:
                    raise ReportPublicationError(
                        "internal invariant failed: report stream unavailable"
                    )
                audit_execution_result = execute_audit_to_stream(
                    configuration,
                    report_publication.text_stream,
                    output_presentation=output_presentation,
                    audit_run_id=audit_run_id,
                    audit_started_at_utc=audit_started_at_utc,
                    internally_ignored_paths=(
                        report_publication.paths_to_ignore_during_audit
                    ),
                )
    except BrokenPipeError:
        raise
    except ReportPublicationError as error:
        write_diagnostic_to_standard_error(
            f"{AUDIT_TOOL_NAME}: report publication failed: {error}\n"
        )
        return EXIT_REPORT_OUTPUT_FAILED
    except AuditReportTransportError as error:
        write_diagnostic_to_standard_error(
            f"{AUDIT_TOOL_NAME}: report transport failed: {error}\n"
        )
        return EXIT_REPORT_OUTPUT_FAILED
    except MemoryError:
        write_diagnostic_to_standard_error(
            f"{AUDIT_TOOL_NAME}: audit runtime failed: process memory was exhausted\n"
        )
        return EXIT_AUDIT_RUNTIME_FAILED
    except (OSError, RuntimeError, UnicodeError, ValueError) as error:
        write_diagnostic_to_standard_error(
            f"{AUDIT_TOOL_NAME}: audit runtime failed: {error}\n"
        )
        return EXIT_AUDIT_RUNTIME_FAILED

    if audit_execution_result is None:
        write_diagnostic_to_standard_error(
            f"{AUDIT_TOOL_NAME}: audit runtime failed: no completion result\n"
        )
        return EXIT_AUDIT_RUNTIME_FAILED

    statistics = audit_execution_result.statistics
    if (
        configuration.fail_on_uncertainty
        and statistics.material_uncertainty_was_observed
    ):
        write_diagnostic_to_standard_error(
            f"{AUDIT_TOOL_NAME}: audit completed with material uncertainty; "
            f"assessed={statistics.assessed_path_count}; "
            "material_uncertain_paths="
            f"{statistics.material_uncertain_path_count}; "
            "paths_with_material_selected_capability_uncertainty="
            f"{statistics.material_selected_capability_uncertainty_path_count}; "
            "see the completed report for details\n"
        )
        return EXIT_AUDIT_EVIDENCE_UNCERTAIN
    return EXIT_AUDIT_COMPLETED


def redirect_standard_output_to_devnull_after_broken_pipe() -> None:
    """Prevent Python shutdown from reporting a second broken-pipe error."""
    with contextlib.suppress(OSError, ValueError):
        sys.stdout.flush()

    devnull_file_descriptor: int | None = None
    try:
        devnull_file_descriptor = os.open(
            os.devnull,
            os.O_WRONLY | getattr(os, "O_CLOEXEC", 0),
        )
        os.dup2(devnull_file_descriptor, sys.stdout.fileno())
    except (OSError, ValueError, AttributeError):
        pass
    finally:
        if devnull_file_descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(devnull_file_descriptor)


if __name__ == "__main__":
    try:
        raise SystemExit(run_audit_command(sys.argv[1:]))
    except BrokenPipeError:
        redirect_standard_output_to_devnull_after_broken_pipe()
        raise SystemExit(EXIT_AUDIT_COMPLETED) from None
    except KeyboardInterrupt:
        with contextlib.suppress(OSError, UnicodeError):
            write_diagnostic_to_standard_error("\n")
        raise SystemExit(EXIT_INTERRUPTED) from None
