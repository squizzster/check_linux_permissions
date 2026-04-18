# check_linux_permissions

`check_permissions.py` is a best-effort **Linux security auditing tool** for recursively identifying paths that are **deletable**, **writable**, or **writable-or-deletable** from the perspective of the account running it — **without actually deleting anything and without opening regular files for writing**.

Three things matter here:

- **does no harm**
- **changes nothing**
- **detects drift**

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

If it does print paths, that means the current user can remove entries **outside the current home directory** under the conditions the tool checks. That is often worth reviewing from a security and hardening perspective. It does **not** automatically mean the system is broken or insecure, but it *does* mean there are paths with broader permissions than many production environments would normally allow.

## What this tool is for

This tool is intended for:

- security reviews
- host hardening checks
- privilege boundary auditing
- finding unexpectedly removable or writable paths
- quickly spotting filesystem areas that may deserve closer investigation

It is especially useful when you want a conservative, low-impact check that does **not** mutate the filesystem.

## Why it matters

Permission drift is real.

A system may start out tight and sensible, then gradually loosen over time:

- a directory gets made group-writable for a quick fix
- a service tree stays broader than intended
- an old deployment path never gets tightened again
- writable space appears where nobody expects it
- removable files exist outside the places users should normally control

That is exactly the kind of drift this tool helps surface.

A user account should usually only be able to modify or delete a **highly restricted** set of files and directories. When that boundary widens over time, bad actors can take advantage of it.

This tool helps you audit that boundary from a user perspective, safely.

## Default behavior

By default, the tool behaves like a best-effort `rm -rf` simulator:

- recursively scans from `/`
- reports only paths that pass the delete check
- suppresses output under the current user's home directory
- streams results as it walks
- exits cleanly if stdout is closed early
- exits cleanly on `Ctrl-C`
- refuses to run as root unless `--run-as-root` is given

So this command:

```bash
python check_permissions.py
```

answers:

> “Outside my home directory, what can this account remove right now?”

If the answer is empty, that is usually a good sign.

## Important interpretation note

**No output is generally good.**

**Some output is not automatically bad.**

A non-empty result can still be legitimate depending on things like:

- how the system is administered
- local service accounts and service-owned writable trees
- temporary directories
- container or mount-namespace layout
- unusual filesystems or security policies
- whether you intentionally run in a more privileged context

Treat the output as a **security signal for review**, not as a replacement for judgment.

## What it checks

Depending on the mode, the tool checks whether a path is:

- **deletable**
- **writable**
- **writable or deletable**

It accounts for a number of Linux-specific behaviors, including:

- parent directory write + search permission for deletion
- sticky-bit behavior
- `CAP_FOWNER`
- read-only mounts
- immutable / append-only inode flags when available
- mount visibility within the current mount namespace
- special pseudo-filesystems that may deserve downgraded confidence
- symlink handling without treating symlink mode bits as normal writability

## What it does *not* do

This is a **best-effort simulator**, not a formal policy engine.

Reality can still differ because of:

- SELinux / AppArmor / Landlock
- races while the filesystem changes during the scan
- FUSE / NFS / network filesystem oddities
- privilege changes during execution
- namespace differences
- kernel or filesystem-specific behavior

Use it for **auditing and triage**. It is there to show you where to look harder.

## Quick start

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

### Show all results, including failures, unknowns, and skips

```bash
python check_permissions.py --all-results --format tsv
```

### Restrict output to directories only

```bash
python check_permissions.py --directories-only
```

### Scan specific paths

```bash
python check_permissions.py /etc /var /srv
```

## Useful options

### Exclude paths from both scanning and output

```bash
python check_permissions.py / --exclude /proc /sys /var/cache
```

Directories are excluded recursively. `--exclude` may be repeated.

### Write results to a file

```bash
python check_permissions.py --format jsonl --output results.jsonl
```

Use `-` for stdout.

### Stay on one filesystem

```bash
python check_permissions.py --one-file-system /
```

This prevents descent into entries on a different `st_dev`.

### Skip `/` entirely

```bash
python check_permissions.py --preserve-root /
```

This behaves similarly to GNU `rm --preserve-root`.

### Use real IDs instead of effective IDs

```bash
python check_permissions.py --real-ids
```

This changes how `os.access()` and sticky-bit ownership checks are evaluated.

### Do not downgrade pseudo-filesystems to UNKNOWN

```bash
python check_permissions.py --no-special-fs-unknown
```

### Run in root context anyway

```bash
python check_permissions.py --run-as-root --exclude /proc
```

By default the script refuses to run as root, because root-context results are usually not helpful when you are trying to understand the system from an ordinary-user perspective.

## Output modes

### `paths` (default)

Prints matching paths only.

Directory paths are printed with a trailing `/`.

### `jsonl`

One JSON object per line, with:

- `status`
- `kind`
- `path`
- `reasons`
- `mode`

### `tsv`

Tab-separated output with:

- `status`
- `kind`
- `mode`
- `path`
- `reasons`

## Status values

Depending on mode, you may see:

- `WOULD_REMOVE`
- `WOULD_WRITE`
- `WOULD_WRITE_OR_DELETE`
- `WOULD_FAIL`
- `UNKNOWN`
- `SKIP`

By default, only passing results are printed. Use `--all-results` to include the others.

## Why the default excludes `~/`

The tool suppresses paths under the current user’s home directory by default because those are usually expected to be writable or removable by that user.

Those paths are still scanned.

They are just hidden from the default output so attention stays on **interesting paths outside normal user-owned space**.

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
2. inspect findings outside expected temp or service-owned locations
3. rerun with `--all-results --format tsv` if you want reasons
4. rerun with `--can-write-only` or `--can-write-or-delete` for a broader audit
5. rerun against specific trees if you are investigating a particular boundary

## Exit behavior

The tool is designed to:

- exit cleanly when piped into tools like `head`
- exit with status `130` on `Ctrl-C`
- return exit status `2` if run as root without `--run-as-root`

## Scope

- Linux-focused
- best used on local filesystems and Linux mount namespaces
- intended as a low-impact filesystem security inspection tool

## Summary

`check_permissions.py` is a low-impact Linux audit tool for finding the places where a user account can write or delete outside the tight boundaries it would normally be expected to stay within.

It does no harm.
It changes nothing.
It helps you detect drift.
