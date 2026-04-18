# check_linux_permissions

Best-effort **Linux security auditing tool** for recursively identifying paths that appear **deletable**, **writable**, or **writable-or-deletable** — **without actually deleting anything and without opening regular files for writing**.

**This TOOL is ENTIRELY NON-HARMFUL**

For regular files, the tool is designed to avoid changing:
- file contents
- size
- atime
- mtime
- ctime

Its default use is simple:

```bash
python check_permissions.py
```

On a well-locked-down production system, that will often print **nothing at all**.

If it does print paths, that means the current user appears able to remove entries **outside the current home directory**. That is often worth reviewing from a security and hardening perspective. It does **not** automatically mean the system is broken or insecure, but it *does* mean there are paths with broader permissions than many production environments would normally allow.

## What this tool is for

This tool is intended for:
- security reviews
- host hardening checks
- privilege boundary auditing
- finding unexpectedly removable or writable paths
- quickly spotting filesystem areas that may deserve closer investigation

It is especially useful when you want a conservative, low-impact check that does **not** mutate the filesystem.

## Default behavior

By default, the tool behaves like a best-effort `rm -rf` simulator:

- recursively scans from `/`
- reports only paths that would likely be **removable**
- suppresses output under the current user's home directory
- streams results as it walks
- exits cleanly if stdout is closed early
- exits cleanly on `Ctrl-C`

So this command:

```bash
python check_permissions.py
```

roughly answers:

> “Outside my home directory, what paths could I probably remove right now?”

If the answer is empty, that is usually a good sign.

## Important interpretation note

**No output is generally good.**

**Some output is not automatically bad.**

A non-empty result can be completely legitimate depending on:
- how the system is administered
- whether you are root or have elevated privileges
- local service accounts and service-owned writable trees
- temporary directories
- container / mount namespace layout
- unusual filesystems or security policies

Treat the output as a **security signal for review**, not as a formal proof of misconfiguration.

## What it checks

Depending on the mode, the tool estimates whether a path is:

- **deletable**
- **writable**
- **writable or deletable**

It accounts for a number of Linux-specific behaviors, including:
- parent directory write + search permission for deletion
- sticky bit behavior
- `CAP_FOWNER`
- read-only mounts
- immutable / append-only inode flags when available
- mount visibility within the current mount namespace
- special pseudo-filesystems that may deserve downgraded confidence
- symlink handling without treating symlink mode bits as normal writability

## What it does *not* do

This is a **best-effort simulator**, not a formal guarantee.

Reality can still differ because of:
- SELinux / AppArmor / Landlock
- races while the filesystem changes during the scan
- FUSE / NFS / network filesystem oddities
- privilege changes during execution
- namespace differences
- kernel or filesystem-specific behavior

This tool should be used for **auditing and triage**, not as a replacement for policy enforcement.

## Usage

### Default scan

```bash
python check_permissions.py
```

Scan from `/` and print removable paths outside the current home directory.

### Show writable paths instead

```bash
python check_permissions.py --can-write-only
```

### Show paths that are writable **or** deletable

```bash
python check_permissions.py --can-write-or-delete
```

### Include home-directory paths in output

```bash
python check_permissions.py --include-home
```

### Add simple labels to path output

```bash
python check_permissions.py --label --can-write-or-delete
```

Labels are shown only in `--format paths` output:
- `[d]` = deletable
- `[w]` = writable but not deletable

### Show all results, including failures and unknowns

```bash
python check_permissions.py --all-results --format tsv
```

### Restrict to directories only

```bash
python check_permissions.py --directories-only
```

### Scan specific paths

```bash
python check_permissions.py /etc /var /srv
```

## Output modes

### `paths` (default)

Prints matching paths only.

### `jsonl`

One JSON object per line.

### `tsv`

Tab-separated output with status, kind, mode, path, and reasons.

## Why the default excludes `~/`

The tool suppresses paths under the current user’s home directory by default because those are usually expected to be writable or removable by that user. The default output is meant to focus attention on **interesting paths outside normal user-owned space**.

## Operational guidance

For a quick hardening check, start with:

```bash
python check_permissions.py
```

Interpret results like this:

- **no output**: generally reassuring
- **a few expected paths**: likely normal, but worth confirming
- **many unexpected system paths**: investigate further

A practical review flow is:
1. run the default scan
2. inspect any findings outside expected temp or service-owned locations
3. rerun with `--all-results --format tsv` if you want reasons
4. rerun with `--can-write-only` or `--can-write-or-delete` for broader auditing

## Exit behavior

The tool is designed to:
- exit cleanly when piped into tools like `head`
- exit with status `130` on `Ctrl-C`

## Scope

- Linux-focused
- best used on local filesystems and Linux mount namespaces
- intended as a low-impact security inspection tool

## Example

```bash
python check_permissions.py
```

If nothing is printed, that usually means the current user does **not** appear able to remove anything outside their home directory that the tool considers likely removable.

If paths are printed, review them. They may be expected, or they may identify a permissions boundary worth tightening.

## Summary

`check_linux_permissions` is a low-impact Linux security auditing tool for answering:

> “What can this account probably delete or write, outside normal user-owned space, without actually touching anything?”

That makes it useful for production reviews, hardening checks, and permission-boundary audits.
