# check_permissions.py

**Your Linux user is only a sandbox if the filesystem agrees.**

`check_permissions.py` is a Linux-only tool that shows where a process
identity appears able to change the filesystem: what it can delete, append to,
overwrite, or create.

That matters for ordinary service accounts. It matters even more for autonomous
AI agents.

## Why this exists

Linux systems accumulate permission mistakes.

Packages and system tools are commonly installed as `root`. Installation
scripts are not perfect. Neither are deployment scripts, old `chmod` commands,
shared groups, copied directories, or one-off fixes made during an incident. A
single wrongly owned directory or writable parent can leave an ordinary account
with far more reach than anyone intended.

Most of the time, nobody notices. The service keeps running, the file looks
read-only, and the machine appears healthy. The mistake becomes important only
when the account is compromised, a tool behaves unexpectedly, or a human makes
the wrong change.

AI agents make that problem harder to ignore. Agents are often most useful when
they can use a shell, edit files, run tools, build software, and operate with
broad freedom. A prompt injection, malicious dependency, faulty tool call, or
ordinary model error can turn that freedom into destructive action.

A practical containment model is:

```text
one purpose or workflow
        ↓
one dedicated Linux user
        ↓
one intentionally writable workspace
        ↓
the Linux kernel is expected to enforce the boundary
```

In this model, the user account is the sandbox and the kernel is the
enforcement layer.

The idea is not to make an agent uselessly constrained. It is to give the
agent broad control inside its own account while keeping that account narrow at
the operating-system boundary.

This is a strong way to reduce blast radius—but only when the user really is
contained. If that account can alter another service's configuration, replace a
startup script, delete shared data, or create files in a privileged directory,
then the supposed sandbox already has holes.

**This tool audits that assumption.** Run it as the user, service account,
container identity, or restricted root context you care about. It asks the
kernel and examines filesystem evidence to find the paths that identity appears
able to mutate.

It does not prove that an agent can never escape its account by every possible
route. It answers a narrower and extremely practical question:

> If this process became malicious, compromised, or simply wrong right now,
> which filesystem paths could it plausibly damage or change?

## The kinds of mistakes it can expose

For example, it can help find cases where:

- an agent account can overwrite a system or application configuration file;
- a service can delete another service's files because the parent directory is
  writable;
- a supposedly isolated workflow can create files inside another workflow's
  tree;
- an account can replace a read-only file by deleting its directory entry and
  creating a new one;
- a file can be appended to even though ordinary replacement or truncation is
  blocked;
- a package or deployment process left an unexpected group-writable path;
- an old shared directory gives several unrelated service accounts mutual
  destructive access.

The goal is not to prove that a machine is perfectly secure. The goal is to
make unintended filesystem reach visible before an incident relies on it.

## A real-world first check

Suppose an AI workflow runs as `invoice-agent` and should only change files
inside `/srv/invoice-agent`.

Run a focused audit as that identity against the places where cross-boundary
access would matter:

```bash
sudo -u invoice-agent -- ./check_permissions.py \
  /etc \
  /usr/local \
  /opt \
  /srv \
  /var/lib \
  /var/spool \
  /home
```

Expected results might include the agent's own workspace, cache, or log
location. Results under another service's directory, a system configuration
path, a shared executable directory, or another user's home should be treated
as questions that need answers.

No output for a path means the model did not find an allowed selected
capability in the emitted results. It is useful evidence, but it is not proof
that the account is harmless or that every possible mutation route was
modeled. The default human presentation stays focused on actionable paths and
does not print an uncertainty summary. Default JSON is permission-focused too:
expected background limitations are omitted rather than reported as if the run
failed. Use `--full-audit` when you deliberately want every conclusion and
routine limitation.

Uncertainty is graded:

- **routine** covers expected whole-system-scan conditions such as access-denied
  directory listing, derivative descendant caveats, and conservative branches
  where the owner might first change mode or inode flags. It is retained by the
  audit but omitted from normal human and JSON output;
- **material** covers unexpected evidence or coverage failures such as I/O
  errors, descriptor exhaustion, identity races, malformed kernel evidence, or
  unresolved credential and mount state. Material uncertainty remains visible
  in JSON and is what `--fail-on-uncertainty` enforces.

## Install and run

Requirements:

- Linux;
- Python 3.9 or newer;
- no third-party Python dependencies.

The command performs an explicit runtime check. macOS, the BSDs, and Windows
receive an unsupported-backend diagnostic rather than failing inside a
Linux-specific import or syscall. Their credential, mount, inode-flag, and
access semantics need native backends; this release does not pretend that a
generic Unix approximation is equivalent to the Linux audit.

Clone the repository and inspect the available options:

```bash
git clone https://github.com/squizzster/check_linux_permissions.git
cd check_linux_permissions
chmod +x check_permissions.py
./check_permissions.py --help
```

You can also run it explicitly with Python:

```bash
python3 check_permissions.py --help
```

### Scan one or more paths

Focused scans are usually faster and easier to interpret:

```bash
./check_permissions.py /path/to/check
./check_permissions.py /etc /opt/my-service /srv/data
```

### Scan the system from `/`

With no path argument, the tool scans `/` recursively:

```bash
./check_permissions.py
```

The default no-path scan excludes `/proc` and the first active writable
temporary directory, and it does not traverse discovered process-related home
directories. Discovered home and temporary paths are resolved as directories
with kernel component semantics; a candidate that cannot be resolved is not
silently excluded and contributes run-level uncertainty. Explicitly provided
roots are not automatically excluded.

For containment reviews, explicitly naming sensitive roots is often clearer
than relying only on the default scan.

### Run it as the identity you actually want to inspect

The result describes the process that runs the tool—not the user reading the
report.

Audit a service account:

```bash
sudo -u www-data -- ./check_permissions.py /etc/my-service /srv/my-service
```

Audit a dedicated agent account:

```bash
sudo -u build-agent -- ./check_permissions.py \
  /etc /usr/local /opt /srv /var/lib /home
```

The script itself must be readable or executable as appropriate, and every
parent directory needed to reach it must be searchable by the audited
identity. Placing a reviewed copy in
a neutral, non-writable location can make repeated service-account audits
easier.

### Root audits are deliberately explicit

Unrestricted root normally has access to almost everything, so an accidental
root audit is usually noise. Effective-UID-0 execution is refused unless you
confirm that root-context evidence is what you want:

```bash
sudo ./check_permissions.py --allow-root-audit /path/to/check
```

A root audit can still be meaningful for a restricted container, capability
set, namespace, or other deliberately constrained root context.

## Reading the output

Interactive terminal output is a compact list of paths with capability labels:

```text
[dao] "/srv/application/settings.ini"
[dc] "/srv/application/cache/"
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
default.

A directory has a trailing `/`. Paths are individually quoted; every
non-ASCII or non-printable character is escaped so bidi text, combining marks,
variation selectors, and invisible formatting cannot alter neighboring text.
A symbolic link is displayed as
`"link" -> "target"`, with each side escaped separately. Labels show only the
selected capabilities that the model indicates are allowed.

## What a good result looks like

There is no universal clean output. It depends on the identity's purpose.

For a tightly scoped agent or service account, a healthy result normally has a
recognizable shape:

- writable paths are concentrated in its own workspace, state, cache, log, or
  spool directories;
- other users' homes and other services' state trees do not appear;
- system configuration and executable locations do not appear;
- shared directories expose only the operations that were deliberately
  granted;
- every unexpected path has an understood and documented reason.

Treat the output as a blast-radius map. The important question is not merely
“can this account write something?” It is “can it change anything outside the
boundary we intended?”

## A practical containment workflow

1. Give each agent, workflow, or service its own Linux identity where practical.
2. Define the paths that identity is expected to change.
3. Audit sensitive system paths, shared trees, other users' workspaces, and the
   identity's intended workspace.
4. Investigate every unexpected delete, append, overwrite, or create result.
5. Correct ownership, group membership, directory modes, mount design, or
   deployment behavior as appropriate, then run the same audit again.
6. Repeat after package installations, deployment changes, account changes, or
   any update that may alter filesystem ownership and permissions.

This is especially useful as a deployment or image-build check: create the
runtime identity, install the software, apply the intended permissions, and
then audit the finished filesystem as that identity.

## Useful focused checks

### Could this account change configuration or installed software?

```bash
sudo -u my-agent -- ./check_permissions.py \
  --capability overwrite_regular_file_content \
  --capability append_regular_file_content \
  /etc /usr/local /opt
```

### Could it delete or replace names in shared data trees?

Deletion and creation are separate checks. Together they are particularly
important because a file that is not writable may still be replaceable when its
parent directory permits removing and recreating the name.

```bash
sudo -u my-agent -- ./check_permissions.py \
  --capability delete_entry_or_tree \
  --capability create_directory_entry \
  /srv /var/lib /home
```

### Where can it create new files or directories?

```bash
sudo -u my-agent -- ./check_permissions.py \
  --capability create_directory_entry \
  /etc /usr/local /opt /srv /var/lib
```

### Which entries or trees can it delete?

```bash
sudo -u my-agent -- ./check_permissions.py \
  --capability delete_entry_or_tree \
  /srv/application
```

### Can it pass permission checks for special files?

```bash
./check_permissions.py \
  --capability special_file_write_permission \
  /dev
```

This special-file result does not exercise a device, FIFO, or socket and does
not predict endpoint-specific behavior.

## Why there is no single “writable” answer

Linux does not have one universal “can write this path” permission.

- **Deleting a file** is usually controlled by write and search permission on
  its parent directory, plus sticky-directory, inode, and mount rules. The
  file's own write bit does not decide whether its name can be removed.
- **Creating an entry** requires write and search permission on the destination
  directory.
- **Appending and overwriting** are different operations when an inode is
  append-only.
- **Read-only mounts and protected inodes** can block changes that ordinary mode
  bits appear to allow.
- **An inode owner can often change its mode first.** A current access denial
  therefore becomes routine uncertainty when ownership or possible
  `CAP_FOWNER` authority could permit a preceding `chmod`; the tool does not
  execute that metadata change or claim it would succeed. `--full-audit`
  exposes that conservative branch.
- **Symbolic links behave differently by operation.** Deletion applies to the
  link entry; content checks follow the link to the target.
- **Deleting a directory tree** requires the assessed descendants to be
  removable too, not just the top-level directory name.

Keeping these operations separate makes the result much more useful than a
simple search for world-writable files.

## Choose exactly what to check

The default capabilities are delete, append, overwrite, and create. Select a
smaller set by repeating `--capability`:

```bash
./check_permissions.py \
  --capability overwrite_regular_file_content \
  --capability append_regular_file_content \
  /etc /opt
```

Available capability names are:

```text
delete_entry_or_tree
append_regular_file_content
overwrite_regular_file_content
create_directory_entry
special_file_write_permission
```

Use `./check_permissions.py --help` for the full operation definitions and
every command-line option.

## Control the scan

Stay on each starting path's filesystem:

```bash
./check_permissions.py --stay-on-starting-filesystem /srv/application
```

Exclude an exact path or observed directory subtree by repeating `--exclude`:

```bash
./check_permissions.py \
  --exclude /srv/application/cache \
  --exclude /srv/application/log \
  /srv/application
```

A trailing slash makes an observed directory exclusion recursive. If the final
component is a symbolic link, the rule excludes that link entry exactly rather
than following it into the target tree.

The following options add locations back to a default no-path scan:

```text
--include-default-home-paths
--include-default-temporary-directory
--include-default-proc-filesystem
```

Explicitly provided scan roots are not automatically excluded.

Input paths retain kernel-significant `.` and `..` components and trailing
slashes until Linux resolves them. For example, if an intermediate component
is a symbolic link, `link/../target` is not rewritten lexically before the
kernel sees it.

A final symbolic link followed by a trailing slash remains identified as a
symbolic link in the report. Target-following capabilities are modeled, but
deletion of that requested spelling is blocked because `unlink`/`rmdir` cannot
remove either the link entry or its target through the trailing slash. The
target identity is captured during preflight and revalidated after assessment;
a change makes every target-following inference materially uncertain.

Mark an additional filesystem type as uncertain when its mutation semantics
need conservative treatment beyond the built-in set:

```bash
./check_permissions.py \
  --uncertain-filesystem-type myfs \
  /mnt/myfs
```

Use `./check_permissions.py --version` to print the tool version.

Require a nonzero result whenever selected-capability or run-level evidence has
material uncertainty:

```bash
./check_permissions.py --fail-on-uncertainty /srv/application
```

The report is completed first, then the command exits with status `5`, so the
material evidence remains available for diagnosis. Routine uncertainty does
not make this option fail.

## JSON output and complete evidence

When stdout is redirected or piped, output automatically becomes JSON Lines.
Use `--json` (or its alias `--machine`) to request it explicitly:

```bash
./check_permissions.py --json /srv/application > permissions.jsonl
```

By default, only records with at least one model-allowed selected capability
are emitted, and routine uncertainty fields are omitted. Request a full audit
when you need blocked, skipped, and both grades of uncertain conclusions:

```bash
./check_permissions.py \
  --full-audit \
  /srv/application > complete-assessment.jsonl
```

`--full-audit` implies all assessed records and selects JSON automatically
unless `--human` is explicitly requested. `--include-nonmatching-records`
remains available as the older explicit spelling for including the complete
record set and its routine evidence.

Each JSON path record includes capability evidence and the run, process,
mount-table, scope, and code/source identity needed to interpret it independently.
The loaded-module digest identifies the executing marshaled Python code object.
The source-file digest is separately labeled as a later pathname snapshot, not
as proof that those bytes are the code already loaded by the process.
Every filesystem-path field also has a neighboring `*_bytes_base64` field (or
list of fields) containing the reversible Linux filename bytes. Consumers that
must identify exact objects should use that byte representation rather than
assuming the JSON display string is valid UTF-8. Mountpoint evidence includes
the same base64 representation.
A provenance record is emitted even when no path record matches. A successful
JSONL generation ends with an `audit_run_completion` record. Normal output adds
material-uncertainty fields only when material uncertainty occurred; full-audit
output includes counts split into `routine` and `material` grades. A stream
that ends without the completion marker is incomplete, regardless of how many
individually valid JSON lines precede it.

Use `--human` (or its alias `--tty`) to force compact path output through a
pipe or into a file:

```bash
./check_permissions.py --human /srv/application | less
```

## Saving a report safely

Shell redirection is the simplest way to save output. The tool also supports a
guarded report destination:

```bash
./check_permissions.py --output permissions.jsonl /srv/application
```

An existing destination is refused unless `--replace-output` is supplied:

```bash
./check_permissions.py \
  --replace-output \
  --output permissions.jsonl \
  /srv/application
```

Replacement is limited to a regular file and uses a synchronized temporary
sibling plus atomic rename checks. Symlink and special-file destinations are
refused. Non-sticky destination directories writable by group or other users
are also refused because another user could swap a checked temporary entry
before cleanup. Sticky shared directories remain supported; processes running
under the same user identity remain within the publication trust boundary.
The report destination cannot also be an exact scan root. Encountering a
symbolic link whose resolved target is the destination or unpublished report
also aborts publication, including when the target did not exist before the
audit. Report artifacts inside a larger scanned tree are omitted from path
records and do not alter descendant deletion aggregation.

The destination parent must be openable for reading as a directory in addition
to allowing write and search. The readable directory descriptor is required
for directory `fsync`; write-and-search-only directories are reported as output
failures. During replacement, the validated exchange is synchronized before
the displaced file is removed, then the cleanup is synchronized again. If the
new report is visible but final cleanup durability cannot be confirmed, the
diagnostic explicitly reports partial publication.
A first-time destination whose post-rename identity validation fails is moved
back to its private temporary name before cleanup; failure to reverse that
visibility is reported as partial publication.

Writing the report file is the tool's deliberate filesystem-mutation exception.
Use stdout when even report creation is not acceptable.

## What the model examines

The audit combines:

- real, effective, saved, filesystem, and supplementary process identities;
- effective Linux capabilities;
- errno-preserving `faccessat2` access checks using effective IDs and stable
  descriptors;
- file type, ownership, mode bits, sticky-directory rules, and link targets;
- the visible Linux mount table and read-only mount state;
- immutable, append-only, and verity inode attributes reported by `statx`;
- parent and descendant results needed for delete-tree conclusions.

Traversal keeps an `O_PATH` descriptor chain. Child capture, metadata,
`statx`, access, and mount-ID observations are relative to those stable
descriptors, so renaming a scanned parent cannot redirect the walk into a
replacement tree. Directory entries are consumed lazily in filesystem order;
the tool does not allocate a list proportional to the number of children in a
flat directory. Descriptor use grows with active directory depth. If the
process or system descriptor limit is reached, enumeration stops at that
directory with named material incomplete-scope uncertainty instead of retrying
through racy absolute paths.

When libc lacks `statx` or `renameat2`, verified per-architecture raw syscall
fallbacks are used. On kernels without `faccessat2`, `faccessat` is used only
when real, effective, and filesystem IDs match, the identity is non-root, and
the observed effective capability mask is empty. That restricted case preserves
both kernel ACL evaluation and the needed identity/capability semantics. Other
legacy or unfamiliar ABI cases remain explicit uncertainty.

Unavailable or insufficient evidence is retained rather than silently treated
as permission. Expected limitations are graded routine and shown only by a
full audit; unexpected evidence failures are graded material.

## What this tool does not tell you

This is a filesystem mutation audit, not a complete security audit or universal
sandbox verifier.

It does not inventory whether the process can:

- read secrets or private files;
- use the network or reach remote services;
- signal, trace, inject into, or otherwise control another process;
- use `sudo`, set-user-ID programs, privileged helpers, or another escalation
  path;
- misuse credentials already available in environment variables, files,
  agents, sockets, or keyrings;
- exploit the kernel, a driver, a service, or a device endpoint;
- cause harm through an application protocol even when filesystem writes are
  blocked.

Those are separate boundaries and need separate controls. A dedicated Linux
user is a valuable layer of defense, but it is not automatically equivalent to
a container, virtual machine, or complete sandbox.

## Safety and limitations

The tool does not test its conclusions by modifying audited paths. It does not
intentionally open audited targets for writing, create or remove entries,
rename them, change ownership or permissions, or set inode flags.

Scanning is still not forensically side-effect free. Directory reads request
`O_NOATIME`, but a reported fallback read may update access time. Reads can also
trigger automounts, network or FUSE activity, and device- or
filesystem-specific behavior. Use a snapshot or read-only mount when strict
non-interference is required.

Results are a best-effort model, not proof that a future system call will
succeed. Descriptor-relative traversal prevents parent-name redirection but
does not create an atomic namespace snapshot: entries, credentials, mounts,
ACLs, and policy can still change between observations. Idmapped-mount details,
SELinux/AppArmor or other operation-specific LSM policy, seccomp, leases,
quotas, resource limits, remote filesystems, and special endpoint behavior can
differ from the modeled result.

Run the tool from a trusted copy. An audit performed with a modified script or
under a different identity does not describe the boundary you intended to
check. Structured reports include both executing-code and observed-source
identity evidence to help preserve that context.

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
| `5` | Audit/report completed, but `--fail-on-uncertainty` found material uncertainty |
| `6` | Standard-output transport ended before the complete audit was delivered |
| `130` | The process was interrupted |

A broken stdout pipe before the completion record exits with status `6`.
Scripts can therefore distinguish a deliberately truncated pipeline from a
completed audit without parsing a partial stream as success.
