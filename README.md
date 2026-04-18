# check_linux_permissions

In one sentence:

**`check_permissions.py` is a safe, non-intrusive UNIX/Linux filesystem audit tool for finding the places where a user account can write or delete outside the tight boundaries it should normally be limited to.**

That is what it does.

Not in theory.
Not by trial and error.
Not by doing anything destructive.

It audits a live UNIX/Linux filesystem from a **real user perspective** and shows you where permissions have drifted.

## What matters

This tool is about three things:

- **does no harm**
- **changes nothing**
- **detects drift**

Over time, systems change.

Directories get repurposed.
Ownership gets altered.
Temporary fixes stay in place.
Service trees are left broader than intended.
Writable areas spread.
Old paths are never tightened back down.

That is how filesystem weakness appears on otherwise respectable systems: not always through one huge mistake, but through slow permission drift.

And that is exactly what this tool is meant to find.

## Why you would run it

A normal user account should usually be able to modify or delete only a **small, tightly controlled** set of paths.

When that stops being true, bad actors gain room to move.

This tool helps you spot:

- unexpectedly removable paths
- unexpectedly writable paths
- weak privilege boundaries
- filesystem areas that have become too permissive over time
- places an attacker could use as a foothold after landing in an account

It is useful for:

- security reviews
- host hardening checks
- privilege boundary auditing
- finding unexpectedly removable or writable paths
- quickly spotting filesystem areas that deserve closer investigation

## Why it is safe

This is the point.

The tool does **not** delete anything.
It does **not** open regular files for writing.
It does **not** mutate the filesystem while auditing it.

For regular files, it is designed not to change:

- file contents
- size
- atime
- mtime
- ctime

So you can inspect a live system from the point of view that matters — the current account — without doing harm in the process.

## Its default use is simple

```bash
python check_permissions.py
```

On a well-locked-down production system, that will often print **nothing at all**.

If it does print paths, that means the current user can remove entries **outside the current home directory** under the conditions checked by the tool.

That is often worth reviewing from a security and hardening perspective.
It does **not** automatically mean the system is broken or insecure, but it **does** mean there are paths with broader permissions than many production environments would normally allow.

## What the output means

This should be read very plainly.

If the tool prints a path in normal passing output, then the account you ran it as **can** do that thing in the selected mode.

- in default mode, printed paths are paths the account can remove
- in `--can-write-only`, printed paths are paths the account can write to
- in `--can-write-or-delete`, printed paths are paths the account can write to or remove

That is why the output matters.
It is showing you where that account has filesystem power.

## Quick start

### Audit for deletable paths

```bash
python check_permissions.py
```

### Audit for writable paths

```bash
python check_permissions.py --can-write-only
```

### Audit for writable-or-deletable paths

```bash
python check_permissions.py --can-write-or-delete
```

### Include home-directory paths too

```bash
python check_permissions.py --include-home
```

### Add compact labels to path output

```bash
python check_permissions.py --label --can-write-or-delete
```

Labels are shown only with `--format paths`:

- `[d]` = deletable
- `[w]` = writable but not deletable

### Show failures, unknowns, and reasons

```bash
python check_permissions.py --all-results --format tsv
```

### Audit only specific roots

```bash
python check_permissions.py /etc /var /srv
```

## Default behaviour

By default, the tool:

- scans from `/`
- behaves like a best-effort `rm -rf` simulator
- prints only paths that pass the delete check
- suppresses paths under the current user’s home directory
- streams results as it walks
- exits cleanly if piped into tools like `head`
- exits cleanly on `Ctrl-C`

That makes the default scan a very strong first-pass audit for permission drift outside normal user-owned space.

## What it actually checks

This is not a naive “find writable files” script.
It models the things that actually matter on UNIX/Linux.

### Delete checks

For deletion, Linux cares about the **parent directory** as much as the target itself.

The tool checks things such as:

- parent directory write + search permission
- sticky-bit restrictions
- `CAP_FOWNER` when effective-ID mode is in use
- read-only mounts
- mountpoint handling
- immutable and append-only inode flags when available
- whether descendants would stop a directory from becoming removable

### Write checks

For writability, the tool is path-type aware:

- non-directories are checked for writability
- directories count as writable only when they are both **writable and searchable**
- symlink writability is reported as `UNKNOWN`

### Special filesystems

By default, some kernel pseudo-filesystems are treated conservatively and may be downgraded to `UNKNOWN`, including:

- `proc`
- `sysfs`
- `cgroup`
- `cgroup2`
- `securityfs`
- `configfs`
- `debugfs`
- `tracefs`
- `pstore`
- `bpf`
- `fusectl`
- `autofs`

Disable that behaviour with:

```bash
python check_permissions.py --no-special-fs-unknown
```

## Output formats

### `paths` (default)

Prints escaped path strings only.

Notes:

- directories are printed with a trailing `/` except for `/` itself
- labels affect only this format

### `jsonl`

Prints one JSON object per line.

### `tsv`

Prints tab-separated fields:

- `status`
- `kind`
- `mode`
- `path`
- `reasons`

Use this when you want to inspect failures, unknowns, and the exact reasons behind a result.

## Useful options

### `--exclude PATH ...`

Skip specific files or whole directory subtrees before scanning and before output.

Example:

```bash
python check_permissions.py / --exclude /var/cache /tmp/somefile
```

### `--one-file-system`

Do not descend into entries on a different device.

### `--preserve-root`

Skip `/` entirely, similar in spirit to GNU `rm --preserve-root`.

### `--real-ids`

Use real IDs instead of effective IDs for access checks and sticky-bit ownership tests.

### `--output FILE`

Write results to a file instead of stdout.

Example:

```bash
python check_permissions.py --all-results --format tsv --output audit.tsv
```

## Running as root

By default, the script refuses to run as root.

That is deliberate.

This tool is primarily meant to audit filesystem permissions from a **non-root user perspective**, because root can write or delete many paths that an ordinary user cannot.

If you really want root-context results, use:

```bash
python check_permissions.py --run-as-root --exclude /proc
```

## Scope and limits

This tool is designed for UNIX/Linux auditing, triage, and hardening work.

It is strong because it is low impact, but it is still an audit tool, not a magical oracle.

Reality can still differ because of things like:

- SELinux, AppArmor, or Landlock
- races during the scan
- unusual FUSE or NFS behaviour
- namespace differences
- kernel or filesystem-specific behaviour

That does **not** make the tool weak.
It just means you should use it the way it was meant to be used: as a serious, safe audit of the filesystem from a user account’s point of view.

## Summary

`check_permissions.py` does three valuable things well:

- it **does no harm**
- it **changes nothing**
- it **detects drift**

And that makes it a very practical way to audit a UNIX/Linux filesystem for the quiet permission weaknesses that should not really be there, but over time often are.
