# check_permissions.py

`check_permissions.py` finds filesystem paths that the current Linux process
appears able to change.

Use it to answer questions such as:

- Which configuration files could this account overwrite?
- Which files could it append to without being able to replace existing data?
- Which entries or directory trees could it delete?
- Where could it create new files or directories?
- Does a service account have more filesystem access than intended?

The tool asks the kernel about the process that runs it. Run it as the user,
service account, container identity, or restricted root context whose access you
want to inspect.

## Run it

Requirements: Linux and Python 3.9 or newer. There are no third-party Python
dependencies.

```bash
./check_permissions.py /path/to/check
```

You can provide more than one path:

```bash
./check_permissions.py /etc /opt/my-service /srv/data
```

Run it as a service account to inspect that account's effective access:

```bash
sudo -u www-data -- ./check_permissions.py /etc/my-service /srv/my-service
```

An effective-root audit requires explicit confirmation because unrestricted
root normally has access to almost everything:

```bash
sudo ./check_permissions.py --allow-root-audit /path/to/check
```

Use `./check_permissions.py --help` for every option.

## Reading the output

Interactive terminal output is a list of paths with capability labels:

```text
[dao] /srv/application/settings.ini
[dc] /srv/application/cache/
```

The labels mean:

| Label | The permission model indicates the process can... |
|---|---|
| `d` | Delete the entry, or delete an assessed directory tree |
| `a` | Append to an existing regular file |
| `o` | Overwrite or truncate an existing regular file |
| `c` | Create a new entry inside a directory |
| `s` | Pass permission checks for writing a special file or device |

Only paths with at least one allowed selected capability are printed by
default. No output means the model did not find an allowed selected capability
in the emitted results; it does not prove that the system is secure or that
every possible mutation was modeled.

## Why the checks are separate

Linux does not have one universal "can write this path" permission.

- Deleting a file is usually controlled by write and search permission on its
  parent directory, plus sticky-directory and mount rules. The file's own write
  bit does not decide whether its name can be removed.
- Creating an entry requires write and search permission on the destination
  directory.
- Appending and overwriting are different when an inode is append-only.
- Read-only mounts and immutable or verity-protected inodes can block changes
  that ordinary mode bits appear to allow.
- Symlink deletion applies to the link entry. Content checks follow the link to
  the regular-file target.

Keeping these operations separate makes the result more useful than a simple
search for world-writable files.

## Choose what to check

The default capabilities are delete, append, overwrite, and create. Select a
smaller set by repeating `--capability`:

```bash
./check_permissions.py \
  --capability overwrite_regular_file_content \
  --capability append_regular_file_content \
  /etc /opt
```

Find deletable entries only:

```bash
./check_permissions.py \
  --capability delete_entry_or_tree \
  /srv/application
```

Check permission-layer access to special files explicitly:

```bash
./check_permissions.py \
  --capability special_file_write_permission \
  /dev
```

The special-file result does not exercise a device, FIFO, or socket and does
not predict endpoint-specific behavior.

## Control the scan

With no path argument, the tool scans `/`. That default root scan excludes
`/proc` and the first active writable temporary directory, and it does not
traverse discovered process-related home directories. Explicitly provided
roots are not automatically excluded.

For faster, easier-to-interpret results, prefer explicit paths and optionally
stay on each starting filesystem:

```bash
./check_permissions.py --stay-on-starting-filesystem /srv/application
```

Exclude an exact path or directory subtree by repeating `--exclude`:

```bash
./check_permissions.py \
  --exclude /srv/application/cache \
  --exclude /srv/application/log \
  /srv/application
```

The `--include-default-home-paths`,
`--include-default-temporary-directory`, and
`--include-default-proc-filesystem` options add those locations back to a
default no-path scan.

## JSON output

When stdout is redirected or piped, output automatically becomes JSON Lines.
Use `--json` to request it explicitly:

```bash
./check_permissions.py --json /srv/application > permissions.jsonl
```

Add `--include-nonmatching-records` when you also need blocked, uncertain, and
skipped conclusions:

```bash
./check_permissions.py \
  --json \
  --include-nonmatching-records \
  /srv/application > complete-assessment.jsonl
```

Each JSON path record includes its capability evidence and the run, process,
mount-table, and source identity needed to interpret it independently.

Use `--human` to force compact path output through a pipe or into a file:

```bash
./check_permissions.py --human /srv/application | less
```

## Saving a report

Shell redirection is the simplest way to save output. The tool also supports a
guarded report destination:

```bash
./check_permissions.py --output permissions.jsonl /srv/application
```

An existing destination is refused unless `--replace-output` is supplied.
Replacement is limited to a regular file and uses a synchronized temporary
sibling plus atomic rename checks. Symlink and special-file destinations are
refused.

Writing a report file is the tool's deliberate filesystem-mutation exception.
Use stdout when even report creation is not acceptable.

## What the model examines

The audit combines:

- real, effective, saved, filesystem, and supplementary process identities;
- effective Linux capabilities;
- kernel access checks using effective IDs when supported;
- file type, ownership, mode bits, sticky-directory rules, and link targets;
- the visible Linux mount table and read-only mount state;
- immutable, append-only, and verity inode attributes reported by `statx`;
- parent and descendant results needed for delete-tree conclusions.

Unavailable or insufficient evidence is reported as uncertainty rather than
silently treated as permission.

## Safety and limitations

The tool does not test its conclusions by modifying audited paths. It does not
intentionally open them for writing, create or remove entries, rename them,
change ownership or permissions, or set inode flags.

Scanning is still not forensically side-effect free. Directory reads request
`O_NOATIME`, but a reported fallback read may update access time. Reads can also
trigger automounts, network or FUSE activity, and device- or
filesystem-specific behavior. Use a snapshot or read-only mount when strict
non-interference is required.

Results are a best-effort model, not proof that a future syscall will succeed.
Live filesystem races, ACL and idmapped-mount details, SELinux/AppArmor or other
LSM policy, seccomp, leases, quotas, resource limits, remote filesystems, and
special endpoint behavior can differ from the modeled result.

## Tests

The test suite uses the Python standard library:

```bash
python3 -m unittest discover -s tests -v
```

When `strace` is installed, the suite also verifies that stdout-mode auditing
does not issue target-mutating syscalls or open audited targets with mutating
flags.

## Exit status

| Status | Meaning |
|---:|---|
| `0` | Audit and output completed |
| `2` | Command-line input or root execution was refused |
| `3` | Report destination or output failed |
| `4` | An unexpected audit runtime failure occurred |
| `130` | The process was interrupted |

Broken stdout pipes exit successfully so commands such as
`./check_permissions.py /path | head` behave normally.
