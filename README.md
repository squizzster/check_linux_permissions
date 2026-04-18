# check_linux_permissions

`check_permissions.py` audits a UNIX/Linux system from a **real user perspective** and shows you where the filesystem has become more permissive than it should be.

That is the whole point.

On a properly controlled system, a user should only be able to write to, modify, or remove a **small, tightly controlled** set of paths.

But real systems do not stay clean forever.

Permissions drift.
Directories get repurposed.
Service trees get left writable.
Ownership changes.
Mount layouts change.
Temporary fixes become permanent.
And over time, the filesystem often ends up allowing things that nobody meant to allow.

That is what this tool is for.

It helps you find the places where an ordinary account can do things it should not be able to do — exactly the kind of quiet filesystem weakness that bad actors take advantage of.

---

## What makes it special

Most filesystem checks are unsatisfying.

They either:

- test the wrong thing
- make too much noise
- or do something intrusive you do not want to run on a live machine

This tool is different.

It audits the real filesystem **without deleting anything** and **without opening regular files for writing**.

For regular files, it is designed not to change:

- contents
- size
- atime
- mtime
- ctime

That is why it is so useful.

You get a serious filesystem audit from the point of view that matters — the current account — without poking the machine in a dangerous way.

---

## What the output means

This part should be simple.

If the tool prints a path in normal passing output, then the account you ran it as **can** do that thing under the selected mode.

- in default mode, printed paths are paths the account can remove
- in `--can-write-only`, printed paths are paths the account can write to
- in `--can-write-or-delete`, printed paths are paths the account can write to or remove

That is why the output matters.

It is not trivia.
It is not theory.
It is telling you where the account has filesystem power.

And if that power exists in places it should not, you have found a real weakness.

---

## Why this matters

Attackers do not need the whole machine to be wide open.

They need footholds.

A writable directory in the wrong place.
A removable file outside normal user-owned space.
A service path that stayed broader than intended.
A deployment tree that was never tightened back down.
A mount that ended up more permissive than anyone realised.

Those are exactly the sorts of weaknesses this tool helps uncover.

It is a **filesystem weakness / permission-drift audit tool**.

---

## Default behaviour

Run this:

```bash
python check_permissions.py
```

By default, the tool:

- scans from `/`
- behaves like a best-effort `rm -rf` simulator
- prints only paths that pass the delete check
- suppresses paths under the current user’s home directory
- streams results as it walks
- exits cleanly if piped into tools like `head`
- exits cleanly on `Ctrl-C`

So the default scan answers a very direct question:

> **Outside the user’s normal space, what can this account delete right now?**

If it prints nothing, that is usually reassuring.

If it prints something, you have found something worth understanding.

---

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

---

## What it actually checks

This is not a naive “find writable files” script.

It models the things that actually matter on Linux.

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

---

## Output formats

### `paths` (default)

Prints escaped path strings only.

Notes:

- directories are printed with a trailing `/` except for `/` itself
- labels affect only this format

### `jsonl`

Prints one JSON object per line.

Example:

```json
{"status":"WOULD_REMOVE","kind":"file","path":"/tmp/example","reasons":[],"mode":"can_delete_only"}
```

### `tsv`

Prints tab-separated output with this header:

```text
status    kind    mode    path    reasons
```

The `reasons` column is a JSON array inside one TSV field.

---

## Status values

Depending on mode, records can have these statuses:

- `WOULD_REMOVE`
- `WOULD_WRITE`
- `WOULD_WRITE_OR_DELETE`
- `WOULD_FAIL`
- `UNKNOWN`
- `SKIP`

By default, only the passing status for the selected mode is printed.
Use `--all-results` to see everything.

---

## Useful options

### Exclude paths from scanning

```bash
python check_permissions.py / --exclude /proc /sys /run
```

`--exclude` skips matching files and whole directory subtrees before scanning and before output.
It may be repeated.

### Preserve `/`

```bash
python check_permissions.py --preserve-root /
```

Skips `/` itself, similar in spirit to GNU `rm --preserve-root`.

### Stay on one filesystem

```bash
python check_permissions.py --one-file-system /
```

Prevents descent into entries on a different `st_dev`.

### Use real IDs instead of effective IDs

```bash
python check_permissions.py --real-ids
```

Uses real IDs for `os.access()` checks and sticky-bit ownership checks, and ignores effective capabilities in this mode.

### Write results to a file

```bash
python check_permissions.py --all-results --format jsonl --output audit.jsonl
```

---

## Root behaviour

This tool is mainly meant to answer this question:

> **What can a non-root account do on this system that it should not be able to do?**

So if you run it as root **without** `--run-as-root`, it refuses to scan and exits with status `2`.

That is deliberate.

If you really do want a root-context audit, opt in explicitly:

```bash
python check_permissions.py --run-as-root --exclude /proc /
```

Excluding `/proc` is strongly recommended for root scans because it can be noisy and misleading.

---

## Important note

This tool is built to be non-intrusive.
It does not delete.
It does not open regular files for writing.
It audits the filesystem as it stands.

That makes it extremely useful for live-system review, hardening work, service-account audits, and general security sanity checks.

There can still be edge cases on unusual filesystems or under external security controls, which is why `UNKNOWN` exists and why special filesystems are handled conservatively.
But the core purpose of this tool is not fuzzy:

> **find places where an account has filesystem power that it should not have**

---

## In one sentence

`check_permissions.py` is a **safe, non-intrusive UNIX/Linux filesystem audit tool** for finding the places where a user account can write or delete outside the tight boundaries it should normally be limited to.
