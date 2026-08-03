# Linux filesystem permission auditor

`check_permissions.py` is a standalone, best-effort Linux filesystem mutation
permission auditor for the current process identity. It models whether that
identity could delete entries, append or overwrite regular-file content,
create directory entries, or satisfy permission-layer checks for special-file
writes.

The auditor observes metadata, effective credentials, mount state, sticky-bit
rules, kernel access decisions, and immutable, append-only, and verity inode
attributes. It does not execute the modeled mutations.

Requirements: Linux and Python 3.9 or newer. The tool uses only the Python
standard library.

## Quick start

Run the executable as the identity whose permissions matter:

```bash
./check_permissions.py /explicit/path
```

When standard output is a terminal, results use compact human-readable lines.
Redirected output is self-contained JSON Lines:

```bash
./check_permissions.py /srv/project
./check_permissions.py --json /srv/project > permissions.jsonl
./check_permissions.py --human /srv/project | less
```

Effective UID 0 is refused unless the audit is explicitly authorized:

```bash
sudo ./check_permissions.py --allow-root-audit /srv/project
```

Use `--help` for the complete evidence boundary, default-scan behavior, and
option reference.

## Capabilities

By default the auditor evaluates these four mutation capabilities:

| Label | Capability | Meaning |
|---|---|---|
| `d` | `delete_entry_or_tree` | Remove an entry without following its final symlink, or remove an assessed directory tree. |
| `a` | `append_regular_file_content` | Append to an existing regular file, including through a symlink. |
| `o` | `overwrite_regular_file_content` | Modify or truncate regular-file content outside append-only constraints. |
| `c` | `create_directory_entry` | Create a child in an existing directory or an explicitly requested missing final path. |
| `s` | `special_file_write_permission` | Satisfy permission-layer checks for a FIFO, socket, character device, or block device without exercising it. |

Select capabilities by repeating `--capability`:

```bash
./check_permissions.py \
  --capability delete_entry_or_tree \
  --capability overwrite_regular_file_content \
  /etc /opt
```

Only paths with at least one model-allowed selected capability are emitted by
default. Add `--include-nonmatching-records` with JSON output to inspect
blocked, uncertain, and skipped conclusions.

## Scope and exclusions

With no path argument, the auditor scans `/`. The default root scan excludes
`/proc` and the first active writable temporary directory and does not traverse
discovered process-related home directories. These default exclusions do not
apply to explicitly supplied roots.

Prefer explicit roots for bounded, interpretable audits:

```bash
./check_permissions.py --stay-on-starting-filesystem /srv/application
./check_permissions.py --exclude /srv/application/cache /srv/application
```

The include switches shown by `--help` can opt default scans back into home,
temporary-directory, or `/proc` traversal.

## Structured evidence

Each JSONL path record carries the complete run and source provenance needed
when records are moved independently, including:

- tool version and observed source digest;
- process credentials and effective capabilities;
- mount-table identity and uncertainty;
- capability-model and record-schema identifiers;
- allowed, blocked, uncertain, and skipped inference evidence;
- the model boundaries that can disagree with a future real syscall.

The v3 implementation retains the `/v2` capability-model and record-schema
identifiers because it optimizes the same model and record shape. Tool name,
tool version `3.0.0`, source digest, and run provenance identify the new
implementation.

## Read and write boundaries

Audited paths are never intentionally opened for writing, created, removed,
renamed, chmodded, chowned, or assigned inode flags. Directory listing requests
Linux `O_NOATIME`; a clearly reported fallback read may update access time.
Reads can also trigger automount, network, FUSE, device, or filesystem-specific
effects. Use a snapshot or read-only mount when forensic non-interference is
required.

`--output FILE` is the deliberate mutation exception. It privately writes and
synchronizes a new report before publishing it without replacing an existing
entry. `--replace-output` explicitly authorizes guarded replacement of an
existing regular report. Symlink and special-file destinations are refused.
Use stdout when report publication itself must not mutate the filesystem.

## v3 performance

Safe optimization work retained every permission check, mount constraint,
inode-attribute observation, uncertainty rule, and provenance field. On the
development host:

| Audit | v2 | v3 | Improvement |
|---|---:|---:|---:|
| 862-entry project tree | 0.51-0.52 s | 0.22 s | about 57% faster |
| `/usr/include` | 9.07 s | 3.60 s | about 60% faster |

The project-tree syscall profile used 70% fewer `lstat`, 24% fewer `statx`, and
50% fewer `faccessat2` calls. Compact output matched v2 byte-for-byte, and
modeled JSON evidence matched after removing only timestamps, run/process
identity, and implementation source provenance.

The optimizations are deliberately assessment-local. Evidence is not cached
across separate paths, where live-filesystem staleness would weaken integrity.

## Migration from the legacy CLI

The old implementation remains available through Git history. Common option
replacements are:

| Legacy option | Current option |
|---|---|
| `--run-as-root` | `--allow-root-audit` |
| `--format paths` | `--human`, or automatic terminal output |
| `--format jsonl` | `--json`, or automatic redirected output |
| `--one-file-system` | `--stay-on-starting-filesystem` |
| `--force-output` | `--replace-output` |
| `--all-results` | `--include-nonmatching-records` |
| `--can-*-only` modes | one or more `--capability NAME` options |

## Tests

Run the standard-library suite:

```bash
python3 -m unittest discover -s tests -v
```

The suite covers controlled permissions and path kinds, every capability,
mount topology, symlinks and loops, sticky directories, inode attributes,
arbitrary Linux filename bytes, depth-safe traversal, report publication and
rollback, output contracts, explicit uncertainty, optimization cache
boundaries, and provenance. When `strace` is installed, a stdout-mode smoke
test rejects target-mutating syscalls and mutating open flags.

CI runs the suite on Linux against Python 3.9 and a current Python release.

## Exit status

- `0`: audit and output completed
- `2`: command-line or root-execution refusal
- `3`: report destination or output failure
- `4`: unexpected audit runtime failure
- `130`: interrupted

Broken stdout pipes exit successfully for pipelines such as `... | head`.

## Model boundaries

This is evidence-backed modeling, not proof that a future mutation syscall will
succeed. Live races, MAC/LSM and seccomp decisions, ACL/idmapped-mount details,
leases, quotas, resource limits, remote filesystems, and special endpoint
behavior can disagree with the model. The auditor preserves explicit
uncertainty instead of converting unavailable evidence into permission.
