# check_linux_permissions

`check_permissions.py` is a **non-intrusive UNIX/Linux filesystem audit tool**.

Its job is simple, and genuinely useful:

> **audit a system from a normal user’s point of view and show where filesystem permissions may have drifted into places they probably should not have.**

On a well-kept system, an ordinary account should only be able to modify or remove a **very restricted** set of files and directories.

But real systems change over time.

Permissions get loosened.
Directories get repurposed.
Service trees get left writable.
Temp areas spread.
Ownership changes.
Mount layouts evolve.
And slowly, almost invisibly, the filesystem can become more permissive than anyone intended.

That is exactly the kind of thing this tool is meant to catch.

It helps you answer questions like:

- **What can this account probably delete that it really should not be able to delete?**
- **What can this account probably modify that it really should not be able to modify?**
- **Where have permissions become broader than they ought to be?**
- **If an attacker landed in this account, where could they start causing damage?**

That is why this is not just a convenience script. It is a **filesystem weakness / permissions-drift audit tool**.

---

## Why it matters

A lot of security problems are not dramatic one-off mistakes.

They are the result of **permission drift**.

Not one catastrophic change, just years of small ones:

- a directory made group-writable for a quick fix
- a service path left broader than intended
- an old deployment tree never tightened back down
- a writable location appearing in a place nobody expects
- removable files outside the spaces users should normally control

Those things are easy to miss.

And when they are missed, they create opportunities.
A bad actor does not need the whole system to be wide open. They only need a few filesystem footholds in the wrong places.

This tool is meant to help you find those footholds **safely**.

---

## Why this tool is unusual

Most ways of answering “can this account really do this?” are unsatisfying:

- they are too shallow to trust
- too noisy to use on a real machine
- or too intrusive to feel comfortable running on a live system

This tool takes a different approach.

It walks the real filesystem and models what Linux would likely allow, **without actually deleting anything and without opening regular files for writing**.

For regular files, it is designed not to change:

- contents
- size
- atime
- mtime
- ctime

That is the whole point.

It lets you inspect the system from a user perspective while staying deliberately low-impact.

So the real question it answers is not:

> “Can I run a dangerous test?”

It is:

> **“Looking at the filesystem as it exists right now, where does this account appear to have powers it probably should not have?”**

---

## What the default scan tells you

Run this:

```bash
python check_permissions.py
```

By default, the tool:

- scans from `/`
- behaves like a best-effort `rm -rf` simulator
- prints only paths that appear **deletable**
- suppresses paths under the current user’s home directory
- streams results as it walks
- exits cleanly if piped into tools like `head`
- exits cleanly on `Ctrl-C`

In practice, that means the default run is asking:

> **Outside the user’s normal space, what could this account probably remove right now?**

That is a very strong first-pass audit.

If it prints **nothing**, that is often reassuring.

If it prints **something**, that does **not** automatically mean the machine is broken — but it does mean you have found something worth understanding.

---

## Quick start

### Audit for paths this account could probably delete

```bash
python check_permissions.py
```

### Audit for paths this account could probably modify

```bash
python check_permissions.py --can-write-only
```

### Audit for paths this account could probably modify **or** delete

```bash
python check_permissions.py --can-write-or-delete
```

### Include the home directory in output too

```bash
python check_permissions.py --include-home
```

### Add compact labels to path output

```bash
python check_permissions.py --label --can-write-or-delete
```

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

This is not just “find writable files”.

Linux permission behavior is more subtle than that, especially for deletion.

### Delete checks

For deletion, Linux usually cares about whether you can remove a **directory entry**, which means the **parent directory** matters a lot.

The tool models things like:

- parent directory write + search permission
- sticky-bit restrictions
- `CAP_FOWNER` when effective-ID mode is used
- read-only mounts
- mountpoint handling
- immutable and append-only inode flags when available
- whether descendants would stop a directory from becoming removable

### Write checks

For writability, the tool is path-type aware:

- non-directories are checked for writability
- directories count as writable only when they are both **writable and searchable**
- symlink writability is reported as **UNKNOWN** rather than pretending symlink mode bits answer the question

### Confidence downgrades on special filesystems

By default, some kernel pseudo-filesystems are handled conservatively and may be downgraded to `UNKNOWN`, including:

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

You can disable that behavior with:

```bash
python check_permissions.py --no-special-fs-unknown
```

---

## What makes the results valuable

The point of this tool is not to prove the kernel will definitely allow every action.

The point is to show you where the filesystem appears to give an account **more reach than you expected**.

That makes it useful for:

- host hardening
- privilege-boundary reviews
- service-account audits
- production sanity checks
- security investigations
- finding dangerous permission drift before somebody else does

This is exactly the kind of information you want when you are trying to understand:

> **Where am I exposed from this account’s position?**

---

## What it does not promise

This tool is deliberately careful, but it is still a **best-effort simulator**, not a formal proof.

Reality can still differ because of:

- SELinux, AppArmor, Landlock, or other MAC systems
- races while the filesystem changes during the scan
- FUSE, NFS, and other odd filesystems
- namespace differences
- kernel- or filesystem-specific corner cases

So the right way to think about it is:

> **a strong audit signal, not a mathematical guarantee**

---

## Root behavior

This tool is mainly intended to answer:

> **What can a non-root account get away with on this system?**

So if you run it as root **without** `--run-as-root`, it refuses to scan and exits with status `2`.

That is deliberate.

If you do want a root-context audit, opt in explicitly:

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

## In one sentence

`check_permissions.py` is a **safe, low-impact UNIX/Linux filesystem audit tool** that helps you find places where an account appears able to write or delete more than it should — exactly the kind of quiet permission drift that turns into security trouble over time.
