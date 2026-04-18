# check_linux_permissions

`check_permissions.py` is a best-effort Linux auditing tool for recursively estimating whether paths are:

- deletable
- writable
- writable or deletable

It does this **without deleting anything** and **without opening regular files for writing**.

For regular files, the implementation is designed not to change:

- contents
- size
- atime
- mtime
- ctime

The default command is:

```bash
python check_permissions.py
```

That performs a recursive scan starting at `/` and prints only paths that the current process would likely be able to remove, while suppressing paths under the current user's home directory.

## What it is for

This tool is useful for:

- permission-boundary audits
- host hardening reviews
- finding unexpectedly removable paths
- finding unexpectedly writable paths
- low-impact triage on production or sensitive systems

It is a simulator, not an enforcement tool.

## Default behavior

With no arguments, the script:

- scans from `/`
- uses **delete-only** mode (`--can-delete-only`)
- prints only passing results
- suppresses output under the invoking user's home directory unless `--include-home` is given
- emits output as it walks
- exits cleanly on broken pipes such as `head`
- exits with code `130` on `Ctrl-C`

So this:

```bash
python check_permissions.py
```

roughly answers:

> Outside normal home-directory space, what paths could this account probably remove right now?

## Important limitations

This is a **best-effort estimate**, not a formal guarantee.

Reality can differ because of:

- SELinux, AppArmor, Landlock, and other MAC policies
- races while the filesystem is changing
- FUSE, NFS, and other unusual filesystem behavior
- namespace differences
- kernel- or filesystem-specific corner cases

A printed path is a signal to review. It is not proof that the system is misconfigured.

## What the script checks

### Delete simulation

Delete checks are modeled around Linux directory-entry removal rules, not file content modification. In practice the script looks at things such as:

- parent directory write + search permission
- sticky-bit restrictions
- `CAP_FOWNER` when effective-ID mode is used
- read-only mounts
- immutable and append-only inode flags when available
- mountpoint detection
- child failures when deciding whether a directory would become removable

### Write simulation

Write checks are path-type aware:

- regular files and other non-directories are checked for writability
- directories are treated as writable only when they are both writable **and** searchable (`x`)
- symlink writability is reported as `UNKNOWN`

### Filesystem confidence downgrades

By default, several kernel pseudo-filesystems are treated conservatively and may be downgraded to `UNKNOWN`, including:

- `proc`
- `sysfs`
- `cgroup` / `cgroup2`
- `securityfs`
- `configfs`
- `debugfs`
- `tracefs`
- `pstore`
- `bpf`
- `fusectl`
- `autofs`

Use `--no-special-fs-unknown` to disable that downgrade.

## Root behavior

The script is primarily intended for **non-root perspective** auditing.

If it is started with effective UID 0 and `--run-as-root` is **not** supplied, it does not scan. Instead it prints a warning and exits with status `2`.

If you really want root-context results, run something like:

```bash
python check_permissions.py --run-as-root --exclude /proc /
```

Excluding `/proc` is strongly recommended for root scans because it can be noisy and misleading.

## Usage

### Default scan

```bash
python check_permissions.py
```

### Scan specific roots

```bash
python check_permissions.py /etc /var /srv
```

### Show writable paths only

```bash
python check_permissions.py --can-write-only
```

### Show paths that are writable or deletable

```bash
python check_permissions.py --can-write-or-delete
```

### Include home-directory results

```bash
python check_permissions.py --include-home
```

### Show all results, including failures, unknowns, and skips

```bash
python check_permissions.py --all-results --format tsv
```

### Restrict printed output to directories

```bash
python check_permissions.py --directories-only
```

### Exclude specific paths or subtrees

```bash
python check_permissions.py / --exclude /var/cache /tmp/scratch
```

`--exclude` may be repeated. Directories are excluded recursively.

### Stay on the same filesystem

```bash
python check_permissions.py --one-file-system /
```

### Skip `/` itself

```bash
python check_permissions.py --preserve-root /
```

### Use real IDs instead of effective IDs

```bash
python check_permissions.py --real-ids /some/path
```

By default the script uses effective-ID semantics where supported. `--real-ids` switches `os.access` and sticky-bit ownership tests to real-ID behavior and ignores effective capabilities.

### Write results to a file

```bash
python check_permissions.py --format jsonl --output results.jsonl /etc /var
```

## Output formats

### `paths` (default)

Prints escaped path strings only.

Notes:

- directories are printed with a trailing `/` except for `/` itself
- labels affect only this format

### `jsonl`

Prints one JSON object per line with this schema:

```json
{"status":"WOULD_REMOVE","kind":"file","path":"/tmp/example","reasons":[],"mode":"can_delete_only"}
```

### `tsv`

Prints tab-separated rows with this header:

```text
status    kind    mode    path    reasons
```

`reasons` is a JSON array serialized into one TSV field.

## Status values

Depending on mode, a record can have one of these statuses:

- `WOULD_REMOVE`
- `WOULD_WRITE`
- `WOULD_WRITE_OR_DELETE`
- `WOULD_FAIL`
- `UNKNOWN`
- `SKIP`

By default, only the passing status for the selected mode is printed. Use `--all-results` to include failures, unknowns, and skips.

## Kind values

The script classifies paths as:

- `file`
- `dir`
- `symlink`
- `fifo`
- `socket`
- `char`
- `block`
- `other`

## Labels

`--label`, `--add-label`, and `--add-labels` are the same feature.

When used with `--format paths`, passing entries are prefixed with:

- `[d]` for deletable entries
- `[w]` for writable-only entries

In `--can-write-or-delete` mode, `[d]` wins if both checks would pass.

Examples:

```bash
python check_permissions.py --label /tmp
python check_permissions.py --add-labels --can-write-or-delete /dev
```

Structured formats (`jsonl`, `tsv`) are unchanged by labels.

## Home-directory suppression

By default, output under the current user's home directory is suppressed.

This suppression is more robust than simply checking `$HOME`: the script also considers the real and effective users and `SUDO_USER` when discovering likely home directories, and it also checks resolved realpaths so symlinked-home paths are usually suppressed too.

This affects **printing only**. It does **not** prevent scanning those paths.

## Exclusions

Excluded paths are skipped **before scanning** and **before output filtering**.

Behavior:

- excluding a directory excludes the whole subtree
- excluding a non-directory excludes that exact path
- realpath fallbacks are also considered, so symlink-resolved paths can be excluded too

## Interpretation guidance

Some findings are normal. Examples include:

- temp directories
- service-owned writable working trees
- intentionally shared directories
- writable content inside containers or chroots

A useful workflow is:

1. run the default scan
2. inspect anything surprising
3. rerun with `--all-results --format tsv` to see reasons
4. rerun with `--can-write-only` or `--can-write-or-delete` for broader coverage
5. add `--exclude` or `--one-file-system` when you want a tighter review scope

## Examples

Default non-root audit:

```bash
python check_permissions.py
```

Broader capability sweep with labels:

```bash
python check_permissions.py --can-write-or-delete --label /tmp /var
```

TSV output including failures and unknowns:

```bash
python check_permissions.py --all-results --format tsv /etc /var
```

Root-context scan with an explicit opt-in:

```bash
python check_permissions.py --run-as-root --exclude /proc --one-file-system /
```

## Summary

`check_permissions.py` is a low-impact Linux auditing tool for answering questions like:

> What could this account probably delete?
>
> What could it probably write?
>
> What looks unexpectedly broad outside normal user-owned space?

It is most useful as a fast review tool for hardening and permission-boundary checks, not as a substitute for actually enforcing policy.
