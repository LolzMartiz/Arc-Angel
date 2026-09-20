# Invoke-PostMigrationCleanup.ps1 v4.0.0

Modular replacement for `clearFreeCache.ps1` v3.0.0. Pick what runs with `-Modules`.
Nothing runs that you did not ask for.

```powershell
.\Invoke-PostMigrationCleanup.ps1 -ListModules          # what exists
.\Invoke-PostMigrationCleanup.ps1 -Modules Delta -DryRun
.\Invoke-PostMigrationCleanup.ps1 -Modules Delta
.\Invoke-PostMigrationCleanup.ps1 -Modules DeltaAccount,AppCache    # your example
```

---

## Read this before choosing modules

Three of v3's functions deleted **every** work account on the device, not just the old
tenant's. On any machine already signed in to the new tenant, running v3 removed that
account too.

| v3 function | What it actually did |
|---|---|
| `Invoke-WamAccountCleanup` | `Clear-FolderContent` on the whole `TokenBroker\Accounts` folder |
| `Invoke-OfficeIdentityReset` | removed the whole `Office\<ver>\Common\Identity` key |
| `Invoke-WorkplaceJoinLeave` | bare `dsregcmd /leave`, tenant-agnostic |
| `Invoke-OutlookProfileReset` | removed every Outlook mail profile |
| `Invoke-OneDriveUnlink` | unlinked every `Business\d+` account |
| `Invoke-CredentialManagerCleanup` | service-keyed allow-list, so new-tenant tokens went too |

v4 walks each of those stores **item by item** and applies the UPN suffix gate to every
one. The four that genuinely cannot be scoped to one tenant are separated out, kept out
of every preset, and refuse to run without `-IAcceptAllAccountImpact`.

Two more v3 bugs are fixed:

- **The SID filter.** v3 tested `^S-1-5-21-` only, so every Entra ID logon (`S-1-12-1-*`)
  was skipped silently. That is why Manav's 20 delta files survived every run on
  DESKTOP-VP6IKCC while the script reported success. v4 enumerates both families.
- **`HKCU:` under SYSTEM.** Several v3 reads used `HKCU:`. Under the RMM the script runs
  as SYSTEM, where `HKCU` is SYSTEM's own hive — those reads found nothing and reported
  success. v4 never touches `HKCU`; every per-user read goes through the profile list,
  loading `NTUSER.DAT` offline when the user is logged off.

---

## Modules

| Module | Scope | What it does |
|---|---|---|
| `DeltaAccount` | delta only | WAM broker files, WorkplaceJoin + TenantInfo, Office connected identity. This is what clears the account from Settings. |
| `DeltaCredentials` | delta only | Credential Manager entries whose user or target names the old tenant. Everything else kept. |
| `DeltaOneDrive` | delta only | Unlinks only the old-tenant business account. Synced files are never deleted. |
| `DeltaBrowser` | delta only | Deletes the Edge/Chrome profile signed in with the old tenant — bookmarks and saved passwords in that profile go with it, backed up first. A profile holding both tenants is reported and left alone. |
| `AppCache` | cache only | Teams / Office scratch caches and per-user Temp. Nothing signs out. |
| `OutlookCache` | cache only | RoamCache and the forms cache. No profiles, no mail, no OST. |
| `TokenCache` | signs out | OneAuth / IdentityCache / TokenBroker **Cache**. Every account re-authenticates. No account is removed. |
| `BrowserCache` | signs out | Browser cache and cookies for all profiles. |
| `OutlookProfileAll` | **all accounts** | Deletes every Outlook mail profile. Gated. |
| `CredentialsAll` | **all accounts** | Deletes every Microsoft credential. Gated. |
| `OneDriveAll` | **all accounts** | Unlinks every business account. Gated. |
| `OstFiles` | **all accounts** | Deletes `.ost` offline caches. Gated. |

**Presets** describe breadth, not risk — all three are tenant-scoped:

```
Delta = DeltaAccount, DeltaCredentials, DeltaOneDrive
        remove the old account and nothing else - the fleet default
Safe  = Delta + DeltaBrowser + AppCache + OutlookCache
        plus every cache that loses nothing
Full  = Safe + TokenCache + BrowserCache
        every account signs in again
```

`-Modules All` resolves to `Full` and says so. The four gated modules are never in a
preset — name them explicitly and pass `-IAcceptAllAccountImpact`, or the script exits 2
without touching anything.

---

## Never touched, in any module

```
*.pst  *.olm  *.nst  *.mbox  *.eml  *.msg     mail data
*.ost                                         unless -Modules OstFiles
Desktop / Documents / Downloads / Pictures
Every OneDrive folder, and every KFM target read from the registry
AppData\Local\Packages\Microsoft.OutlookForWindows_*    new Outlook's local mail store
Office upload cache (OfficeFileCache)         can hold edits not yet on the server
The device-level Entra join, the AD domain join, MDM enrolment
Any account whose UPN does not end in @<TargetDomain>
```

New Outlook's store is called out because it keeps mail in a SQLite database with no
mail extension — the extension guard alone would not have caught it. That is the same
failure mode as the macOS run that destroyed an "On My Computer" mailbox.

Every `.pst` found is written to `PstInventory-<host>-<stamp>.csv` before anything runs,
so there is always a re-attach list.

---

## One-liners

Audit first (read-only, unchanged):

```
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; New-Item -ItemType Directory 'C:\ProgramData\PMC' -Force | Out-Null; Invoke-WebRequest 'https://raw.githubusercontent.com/LolzMartiz/Arc-Angel/refs/heads/main/Invoke-WorkAccountAudit.ps1' -OutFile 'C:\ProgramData\PMC\Invoke-WorkAccountAudit.ps1' -UseBasicParsing; & powershell -NoProfile -ExecutionPolicy Bypass -File 'C:\ProgramData\PMC\Invoke-WorkAccountAudit.ps1'"
```

Dry run:

```
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; New-Item -ItemType Directory 'C:\ProgramData\PMC' -Force | Out-Null; Invoke-WebRequest 'https://raw.githubusercontent.com/LolzMartiz/Arc-Angel/refs/heads/main/Invoke-PostMigrationCleanup.ps1' -OutFile 'C:\ProgramData\PMC\Invoke-PostMigrationCleanup.ps1' -UseBasicParsing; & powershell -NoProfile -ExecutionPolicy Bypass -File 'C:\ProgramData\PMC\Invoke-PostMigrationCleanup.ps1' -Modules Delta -DryRun"
```

Live — swap `-Modules Delta -DryRun` for whichever set you want:

```
... -File 'C:\ProgramData\PMC\Invoke-PostMigrationCleanup.ps1' -Modules Delta"
... -File 'C:\ProgramData\PMC\Invoke-PostMigrationCleanup.ps1' -Modules DeltaAccount,AppCache"
... -File 'C:\ProgramData\PMC\Invoke-PostMigrationCleanup.ps1' -Modules Safe"
```

Use `raw.githubusercontent.com/.../refs/heads/main/...`, never a `github.com/.../blob/...`
URL — the blob URL downloads the HTML page and PowerShell chokes on GitHub's CSS.

Quotes around argument values are stripped on the way in, so
`-Modules "Delta"` and `-TargetDomain "delta.mainettigroup.onmicrosoft.com"` both work
even though `powershell.exe -File` passes them through verbatim.

---

## Output

```
C:\ProgramData\PMC\Logs\Cleanup-<host>-<stamp>.log       full transcript
C:\ProgramData\PMC\Logs\Cleanup-<host>-<stamp>.json      receipt: every decision, kept and removed
C:\ProgramData\PMC\Logs\PstInventory-<host>-<stamp>.csv  re-attach list
C:\ProgramData\PMC\Cleanup\<stamp>\                      backups of everything removed
C:\ProgramData\PMC\FleetSummary.csv                      one row per run, appended
```

Exit codes: `0` clean · `1` at least one removal failed · `2` refused (bad or gated
module) · `5` a target item survived (see below).

---

## After the run

A **restart** is still required before Settings stops listing the account. That page
caches its list; a stale entry there is not a failed removal. Exit code 5 with
`Recreated > 0` in the receipt means something re-created the files *after* the script
started — an app still signed in with the old account in a live session. Sign that app
out, or log the user off, then run again. Running the remover a second time will not fix
it on its own.

---

## Still open before the fleet rollout

1. **Test one RMM-deployed machine.** Every run so far has been interactive. Under the
   RMM this runs as SYSTEM and takes the offline-hive path for every profile. That path
   works, and the hive is now held open across discovery and removal, but it has not been
   exercised in the field.
2. **`Remove-DeltaAccount.ps1` has a latent version of that same hive bug.** Its
   `Invoke-WithUserHive` unloads the hive in a `finally` block, so a WorkplaceJoin or
   Office identity discovered in a logged-off profile has an invalid registry path by the
   time the removal pass reaches it. It fails safe — `Remove-Item` errors, nothing wrong
   is deleted — and the field run never hit it because every removal there was a broker
   file. It is still worth patching if you keep that script alongside v4. The fix is the
   one in v4: drop the `finally` unload, unload everything at the end instead.
3. Retire the deployed v3, or at minimum fix its SID filter. Until then any run on a
   device with Entra logons does a fraction of its job and reports success.

---

## Verification

68 tests, all passing:

- **Gate, 29 tests** — the exact UPN set from DESKTOP-VP6IKCC plus the near-miss cases
  (`notdelta.…`, `sub.delta.…`, `delta.….evil.net`, empty, no `@`, trailing `@`).
- **Data guards, 23 tests** — a mock profile tree with a `.pst`, an `.ost`, a `.msg` in
  Temp, a new-Outlook `mail.db` and a OneDrive document. Every one survives; the Teams
  cache and RoamCache still clear. This caught a real v4 bug: registering the profile
  root as protected made every cache path "inside a protected folder", so the cache
  modules cleared nothing.
- **Replay, 16 tests** — all 57 rows of the real audit JSON through v4's decision logic.
  Result: 32 removed, 25 kept, matching the audit's own `IsTarget` column row for row,
  with `abhishek@mainetti.com`, both Sasitharan domains, `kotteshwar.raju-c@mathco.com`
  and the `152848e0` WorkplaceJoin all kept.
