# check_linux_permissions

`check_permissions.py` answers a deceptively powerful question:

> **What could this account actually change or remove on this Linux system right now — without me poking files, writing test data, or deleting anything?**

That is what makes it useful.

Most permission checks are either too shallow to be trusted or too invasive to feel safe on a real machine. This tool sits in the sweet spot:

- it **walks the real filesystem**
- it **models Linux deletion and writability rules**
- it **does not delete anything**
- it **does not open regular files for writing**
- for regular files, it is designed not to change **contents, size, atime, mtime, or ctime**

So instead of asking Linux “please let me try something dangerous,” it asks a better question:

> **If I tried right now, what would probably work?**

That makes it great for:

- permission reviews
- security hardening
- checking what a service account can really do
- spotting unexpectedly broad access
- sanity-checking a host before you trust it

---

## Why this is special

This is not just a “find writable files” script.

For deletion, Linux usually cares more about the **parent directory** than the file itself. That trips people up all the time. A file can be non-writable and still removable. A file can be writable and still not removable. A directory can look fine until the sticky bit, mount flags, or immutable flags change the answer.

This tool handles that kind of logic for you.

It does a best-effort simulation of what Linux would likely allow for:

- **delete**
- **write**
- **write or delete**

And it does it while staying deliberately low-impact.

---

## The default behavior is intentionally useful

Run this:

```bash
python check_permissions.py
```

By default it:

- scans from `/`
- behaves like a best-effort `rm -rf` simulator
- prints only paths that look **deletable**
- hides paths under the current user's home directory
- streams results as it walks
- exits cleanly if you pipe into `head` or stop with `Ctrl-C`

In plain English, the default scan asks:

> **Outside normal user-owned space, what could this account probably remove right now?**

That is an excellent first-pass hardening check.

If it prints **nothing**, that is often a very reassuring result.

If it prints **something**, that does **not** automatically mean the system is bad — but it does mean you have found something worth understanding.

---

## Quick start

### See what this account could probably delete

```bash
python check_permissions.py
```

### See what it could probably write

```bash
python check_permissions.py --can-write-only
```

### See what it could probably write **or** delete

```bash
python check_permissions.py --can-write-or-delete
```

### Include your home directory too

```bash
python check_permissions.py --include-home
```

### Show labels in path output

```bash
python check_permissions.py --label --can-write-or-delete
```

### Show failures, unknowns, and reasons

```bash
python check_permissions.py --all-results --format tsv
```

### Limit the scan to a few roots

```bash
python check_permissions.py /etc /var /srv
```

---

## What it really checks

### Delete checks

Deletion on Linux is mostly about whether you can remove a **directory entry**, not whether you can modify file contents.

So for delete simulation, the script checks things like:

- whether the **parent directory** is writable and searchable
- sticky-bit restrictions
- `CAP_FOWNER` when effective-ID mode is in use
- read-only mounts
- mountpoint handling
- immutable and append-only inode flags when available
- whether child entries would stop a directory from becoming removable

### Write checks

Write simulation is path-type aware:

- regular files and other non-directories are checked for writability
- directories count as writable only when they are both **writable and searchable**
- symlink writability is reported as **UNKNOWN** rather than pretending the mode bits mean something useful

### Confidence downgrades on special filesystems

By default, some special kernel pseudo-filesystems are treated conservatively and can be downgraded to `UNKNOWN`, including:

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

You can disable that behavior with:

```bash
python check_permissions.py --no-special-fs-unknown
```

---

## What it does **not** promise

This tool is careful. It is not magical.

It is a **best-effort simulator**, not a formal proof.

Real-world results can still differ because of:

- SELinux, AppArmor, Landlock, or other MAC systems
- races while the filesystem is changing
- FUSE, NFS, and other odd filesystems
- namespace differences
- kernel- or filesystem-specific corner cases

So the right mental model is:

> **This is an extremely useful signal, not a legal guarantee.**

---

## Root behavior

This tool is mainly meant to answer:

> **What can a non-root account get away with?**

So if you run it as root **without** `--run-as-root`, it refuses to do the scan and exits with status `2`.

That is deliberate.

Root can often write or delete things that an ordinary user never could, so defaulting to root-mode results would make the tool much less useful for normal auditing.

If you really do want a root-context scan, opt in explicitly:

```bash
python check_permissions.py --run-as-root --exclude /proc /
```

Excluding `/proc` is strongly recommended for root scans because it can be noisy and misleading.

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

The `reasons` field is a JSON array stored inside one TSV column.

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

Use `--all-results` if you want the whole picture.

---

## Labels

`--label`, `--add-label`, and `--add-labels` all do the same thing.

When used with `--format paths`, passing entries are prefixed with:

- `[d]` = deletable
- `[w]` = writable but not deletable

In `--can-write-or-delete` mode, `[d]` wins if both checks would pass.

Examples:

```bash
python check_permissions.py --label /tmp
python check_permissions.py --add-labels --can-write-or-delete /dev
```

Structured formats (`jsonl` and `tsv`) do not change.

---

## Useful options

### Exclude paths or whole subtrees

```bash
python check_permissions.py / --exclude /var/cache /tmp/scratch
```

You can repeat `--exclude`.

Directories are excluded recursively.

### Stay on one filesystem

```bash
python check_permissions.py --one-file-system /
```

### Skip `/` itself

```bash
python check_permissions.py --preserve-root /
```

### Only print directories

```bash
python check_permissions.py --directories-only
```

### Use real IDs instead of effective IDs

```bash
python check_permissions.py --real-ids /some/path
```

By default, the script prefers effective-ID semantics where supported.
`--real-ids` switches access and sticky-bit ownership tests to real-ID behavior and ignores effective capabilities.

### Write output to a file

```bash
python check_permissions.py --format jsonl --output results.jsonl /etc /var
```

---

## Why home-directory paths are hidden by default

Because they are usually boring.

Your own home directory is often expected to be writable or deletable by you. The default output is trying to show you the **interesting** stuff outside that normal zone.

The script still scans those paths. It just suppresses them from output unless you ask for them with `--include-home`.

It also tries to detect home directories robustly by considering:

- `$HOME`
- the real user
- the effective user
- `SUDO_USER`
- resolved realpaths

So symlinked-home paths are usually hidden too.

---

## A good way to use it

Start simple:

```bash
python check_permissions.py
```

Then, if needed:

1. inspect anything surprising
2. rerun with `--all-results --format tsv` to see why something passed, failed, or is unknown
3. rerun with `--can-write-only` if you care about write exposure
4. rerun with `--can-write-or-delete` for a broader capability view
5. add `--exclude` or `--one-file-system` to focus the scan

This workflow is fast, safe, and genuinely useful on real systems.

---

## Example commands

Default non-root audit:

```bash
python check_permissions.py
```

Broader capability scan with labels:

```bash
python check_permissions.py --can-write-or-delete --label /tmp /var
```

Show everything with reasons in TSV:

```bash
python check_permissions.py --all-results --format tsv /etc /var
```

Root-context scan with explicit opt-in:

```bash
python check_permissions.py --run-as-root --exclude /proc --one-file-system /
```

---

## In one sentence

`check_permissions.py` is a low-impact Linux permissions reality-check:

> **It shows what an account could probably delete or write without actually touching regular file contents or deleting anything.**

That is why it is useful, and that is why it is a bit special.
