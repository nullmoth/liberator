# Beta 5: stock macOS 27

Goal: every Apple file on the 27 system volume stays byte-for-byte Apple's, so users can take Apple updates.
Our own files are added beside Apple's; none of Apple's is replaced.

## Pieces

| piece | file | what it does |
|---|---|---|
| exec hook | `hook/` (full source + `Makefile`) | the kernel extension that hands an arm64 program to the interpreter at exec time. `make selftest` builds the decision logic in userspace (`-DA2X_SELFTEST`, plain clang, no VM) and runs its arms; `make kext` builds the extension for x86_64. With boot-arg `a2xbootarm=1` it arms itself inside the kernel as soon as AMFI's sandbox sysctl exists, before launchd, so Apple's arm64-only boot tasks (cc_fips_test and others) start under it. Sysctl `a2x.exec_hook_bootarm_result`: -1 not tried, 0 armed. Two entry programs: `/usr/libexec/xpcproxy` runs in the interpreter itself; everything else goes to the small launcher at `/usr/libexec/a2x/a2xlaunch`. `a2x.board_id` sets the board name Software Update reads. |
| boot-arm patch | `hook/patch_bootarm.py` | superseded: the boot-arm feature it added is now part of the full `hook/` source above. Kept for reference; it is not applied when the full source is built. |
| keepalive stock mode | `patch_keepalive.py`, `kit/a2x-keepalive.sh` | when the kernel armed the hook (result 0), the exec-storm guard only logs and the dead-man window is 3600 s. Disarming on a stock system stops shutdown and every arm64-only Apple program. |
| update payload | `vm/syspatch.sh`, `vm/sys_added.txt` | the 403 files we add to the system volume (x86_64 dyld shared cache, kernel collections, boot.efi, `/usr/libexec/a2x/*`, auxkcload, AMD bundles, DefaultLocalDB, …). |

Why some files must be on the system volume: launchd is PID 1 and starts before any other volume is mounted, so
the host it runs on and the x86_64 dyld cache it links against have to be on the system volume.

## After an Apple update

An update rewrites the system volume and removes our additions. Liberator puts them back in the same step as the
kernel collection rebuild:

1. Before the update (or at install): `syspatch.sh save` copies every path in `sys_added.txt` to
   `/Library/NullMoth/syspatch` on the Data volume.
2. After the update, from the recovery/installer step that already relinks the KCs: `syspatch.sh apply` copies
   them back onto the system volume (`ditto`, owners, modes and flags kept).
3. Check: `sysctl a2x.exec_hook_bootarm_result` = 0 and PID 1 is launchd.

If a future update changes an Apple file we depend on (the x86_64 cache is built from Apple's libraries), the
payload must be rebuilt for that build, not only re-applied.

## Proof in the VM (QEMU HVF, same 27.2 build as the reference Mac)

- All 449 replaced Apple files restored: boots, PID 1 = Apple's launchd via the hook, stock sshd login, 0 crash
  reports, clean restart (19 s).
- System volume = Apple's files byte-identical + 403 additions, 0 differing, 0 missing.
- Wipe the additions (simulated update): does not boot (negative control fires).
- Re-apply from the payload: see `vm/RESULT.txt`.

`vm/` holds the harness: `run3.sh`/`boot.sh` start the VM, `vmedit.sh` edits its disk offline, `stage.sh`
restores Apple originals, `trial.sh` boots and runs `health.sh` + `exectest.sh`, `updtest.sh` runs save, wipe,
apply, fsck and a boot. Keep at least 12 GB free on the host: a full host disk corrupts the VM's APFS container
(seen once; `updtest.sh` stops below that).
