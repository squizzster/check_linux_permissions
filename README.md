# check_permissions.py

`check_permissions.py` is a best-effort **Linux filesystem mutation capability auditor**. 

It models the permissions that usually decide whether the current process context could mutate filesystem state. The tool does not open files for writing, does not create files, and does not remove anything. It is designed for security reviews, host hardening checks, and detecting permission drift over time.

Three things matter here:
* **Does no harm:** Uses metadata, mountinfo, `statx`, and access checks.
* **Changes nothing:** Never modifies file contents, size, atime, mtime, or ctime.
* **Detects drift:** Highlights paths where broad permissions exist outside expected boundaries.

---

## Capabilities Analyzed

The tool treats "write" not as a single primitive, but as distinct mutation capabilities. When using the default `--format paths`, these capabilities are prefixed to the output using compact labels.

| Label | Capability | Description |
| :--- | :--- | :--- |
| `[d]` | Delete | Delete an existing path, or recursively remove a directory tree. |
| `[a]` | Append | Append to an existing regular file. |
| `[o]` | Overwrite | Overwrite or truncate an existing regular file. |
| `[c]` | Create | Create a child entry in an existing directory, or create an explicit missing path whose parent permits creation. |
| `[s]` | Special Write | Write permission on a special file/device node. (Opt-in only for the default audit). |

---

## Execution Modes

You can tailor the tool to look for specific types of filesystem mutation vulnerabilities.

| Flag | Emitted Status | Purpose |
| :--- | :--- | :--- |
| `--can-mutate` | `WOULD_MUTATE` | **Default.** Shows paths with delete, append, overwrite, or create capability. |
| `--can-delete-only` | `WOULD_DELETE` | `rm -rf` simulator. Shows only paths that would likely be removable. |
| `--can-append-only` | `WOULD_APPEND` | Shows existing regular files appendable by the process context. |
| `--can-overwrite-only` | `WOULD_OVERWRITE` | Shows existing regular files overwritable/truncatable by the process context. |
| `--can-content-write-only` | `WOULD_CONTENT_WRITE` | Shows existing regular files that are appendable or overwritable. |
| `--can-create-only` | `WOULD_CREATE` | Shows directories, symlinked directories, and explicit missing paths where creation is possible. |
| `--can-special-write-only` | `WOULD_SPECIAL_WRITE` | Shows writable special files/device nodes. |
| `--can-write-only` | `WOULD_WRITE` | Broad write audit: append, overwrite, create. |

---

## Default Behavior and Auto-Exclusions

By default, executing the tool with no arguments behaves as a general security audit:

```bash
python check_permissions.py
```

* **Target:** Scans `/` recursively.
* **Auto-skips:** `/proc` and the active writable temp directory (e.g., `TMPDIR`, `/tmp`) are skipped to reduce noisy, expected output.
* **Suppresses:** Paths lexically under discovered home directories are hidden from the final output.
* **Special Files:** Ignored by default to avoid noisy `/dev` output.

To perform a totally unrestricted audit encompassing all default-suppressed areas and special-write checks, use the `--include-all` (or `--all`) flag.

---

## Important Model Choices

* **Symlinks:** Deletion is checked on the symlink itself. Content and creation checks follow the symlink, because `open("link", O_WRONLY)` normally writes to the target. Dangling symlinks are evaluated for "create-through-symlink" risk.
* **Directory "Write":** Reported as a `create` capability (requires write + search on the directory, a writable mount, and no immutable flag).
* **Append-Only Inodes:** Regular-file appendability is accurately reported even when overwrite/truncate would be blocked by the Linux append-only inode flag (via `statx`).
* **Reality Constraints:** This is a simulator. MAC policy (SELinux/AppArmor), idmapped mounts, network/FUSE semantics, or live race conditions can still make real-world operations differ.

---

## Output Formats

Control output structuring via the `--format` argument:

| Format | Description |
| :--- | :--- |
| `paths` | **Default.** Compact output displaying the file path, optionally prefixed with capability labels (e.g., `[dao] /etc/config`). |
| `jsonl` | One structured JSON object per line. Ideal for passing into `jq` or SIEM ingestion. |
| `tsv` | Tab-separated values including status, mode, capabilities, and explicit block/skip reasons. |

*Note: By default, only passing results are printed. Use `--all-results` to view paths that returned `WOULD_FAIL`, `UNKNOWN`, or `SKIP`.*

---

## Common Usage Examples

**Run the default audit as nobody:**
```bash
setpriv --reuid nobody --regid nogroup --clear-groups -- python check_permissions.py
```

**Find exactly what can be deleted in a specific directory:**
```bash
python check_permissions.py --can-delete-only /var/tmp/project
```

**Find existing configuration files that can be tampered with:**
```bash
python check_permissions.py --can-content-write-only /etc /usr/bin
```

**Structured report of overwritable files, saving to disk:**
```bash
python check_permissions.py --can-overwrite-only --format jsonl --output risk_report.jsonl /opt
```

**Include special files and temp directories in the audit:**
```bash
python check_permissions.py --include-special-write --include-tmp /
```

**Only print vulnerable directories, excluding specific subtrees:**
```bash
python check_permissions.py --directories-only --exclude /var/cache /srv
```

---

## Operational Guidance

**No output is generally good. Some output is not automatically bad.**

A non-empty result can be legitimate depending on how the system is administered, local service accounts, or container layouts. Treat the output as a **security signal for review**, not an immediate declaration of compromise. 

If you are running the script as `root`, execution will be blocked unless you explicitly pass `--run-as-root`. Running as an unrestricted root user usually just reports root's power rather than ordinary-user risk. Use this flag only if you are explicitly auditing a restricted capability bounding set or rootless container.
