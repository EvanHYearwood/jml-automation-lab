# Automated JML W/ Cert-Based Authentication (JWT)
**Yearwood.Local | Active Directory + Okta | PowerShell**

A hands-on IAM lab automating the full Joiner-Mover-Leaver identity lifecycle across a hybrid Active Directory and Okta environment. Built across three sessions — from certificate-based API authentication through to CSV-driven provisioning, offboarding, and ticket closure simulation.

---

## Table of Contents
1. [Lab Overview](#lab-overview)
2. [Environment](#environment)
3. [Architecture](#architecture)
4. [Phase 0 — Certificate-Based Okta Authentication](#phase-0--certificate-based-okta-authentication)
5. [Phase 1 — Joiner Provisioning](#phase-1--joiner-provisioning)
6. [Phase 2 — Post-Provisioning Verification](#phase-2--post-provisioning-verification)
7. [Phase 3 — Mover Provisioning](#phase-3--mover-provisioning)
8. [Phase 4 — Leaver Offboarding](#phase-4--leaver-offboarding)
9. [Phase 5 — Ticket Closure Simulation](#phase-5--ticket-closure-simulation)
10. [CSV-Driven Architecture Upgrade](#csv-driven-architecture-upgrade)
11. [Key Lessons Learned](#key-lessons-learned)
12. [Script Inventory](#script-inventory)
13. [What I'd Do Differently in Production](#what-id-do-differently-in-production)

---

## Lab Overview

The goal of this lab was to build a realistic IAM automation system covering the full identity lifecycle:

- **Joiners** — new hires provisioned in AD, assigned to the correct role group, synced to Okta, SAML app access granted automatically via group membership
- **Movers** — role changes handled by reassigning AD group membership and updating profile attributes, Okta reflects the change on next sync
- **Leavers** — accounts disabled, moved to DisabledUsers OU, stripped of all group memberships, Okta syncs the revocation

Active Directory is the **source of truth for identity**. Okta is the **access layer** that reads from it. No user is provisioned directly in Okta — every change flows through AD first.

> **<img width="1673" height="894" alt="image" src="https://github.com/user-attachments/assets/6ec5fc0a-e9ad-4a85-a8cf-1ebb0dbd5f6b" />** — Zendesk mock showing all 6 JML tickets with live SLA timers

---

## Environment

| Component | Detail |
|---|---|
| Domain | `yearwood.local` |
| Server | ARM Windows Server VM |
| Shell | PowerShell 7.5.4 |
| AD module | RSAT ActiveDirectory |
| Okta org | Trial — `trial-6085580.okta.com` |
| Okta auth | Certificate-based `private_key_jwt` |
| SAML apps | Slack, Google Workspace, SharePoint (Python Flask, hosted on `yearwood.local`) |
| Okta sync | AD agent — pull model, on-demand via Import Now |

### AD Structure
```
yearwood.local
└── _NA
    ├── Users          ← active accounts
    ├── DisabledUsers  ← leavers moved here
    ├── Groups         ← V2_Cloud_Engineer, V2_Finance, V2_Helpdesk, V2_HR
    ├── Admins
    ├── ServiceAccounts
    └── Workstations
```
<img width="913" height="712" alt="image" src="https://github.com/user-attachments/assets/0423eea0-de0f-4651-ba18-19db34d2d7cf" />


### RBAC Matrix
<img width="629" height="151" alt="Screenshot 2026-03-12 at 7 08 21 PM" src="https://github.com/user-attachments/assets/35931226-a5d0-47c0-a7aa-c2d3a24c9faf" />


Group membership in AD drives SAML app access in Okta automatically. No direct user-to-app assignments anywhere in the system.

---

## Architecture

```
CSV input  (Joiners.csv / Movers.csv / Leavers.csv)
     │
     ▼
Invoke-JMLProvisioning.ps1
     │
     ├── Detect type from filename
     ├── Validate required fields per type
     │
     ├── Joiner  →  New-ADUser  →  Add-ADGroupMember  →  Log
     ├── Mover   →  Remove-ADGroupMember  →  Add-ADGroupMember  →  Set-ADUser  →  Log
     └── Leaver  →  Disable-ADAccount  →  Move-ADObject  →  Remove all groups  →  Log
                                                    │
                                              Okta AD Agent
                                              (pull model — syncs on next poll)
                                                    │
                                              Okta Universal Directory
                                              (group membership → SAML app access)
```

> **<img width="704" height="932" alt="Screenshot 2026-03-19 at 6 54 22 PM" src="https://github.com/user-attachments/assets/45c44eea-d2ad-4513-93e0-cafefc352768" />** — JML branching logic diagram

---

## Phase 0 — Certificate-Based Okta Authentication

Before any provisioning script could run, secure authentication to the Okta API had to be established. The goal: no plaintext credentials anywhere in the codebase.

### Why certificate-based auth

The simplest approach would be to generate an Okta API token and paste it into the script. That's also the most common IAM automation security failure — credentials hardcoded in scripts, committed to repos, or stored in plaintext files.

The approach used here: the script proves its identity using a private RSA key that never leaves the Windows Certificate Store. It builds a short-lived signed JWT, exchanges it with Okta for an access token, and uses that token for the session. No secrets in the code. No standing credentials.

### Setup

1. Created an **API Services app** in Okta (`JML-PowerShell-Automation`)
2. Generated an RSA key pair in the Okta console
3. Imported the public key into the Okta app's JWKS configuration
4. Imported the private key into the Windows Certificate Store (`Cert:\CurrentUser\My`)
5. Configured scopes: `okta.users.manage`, `okta.groups.manage`

<img width="682" height="464" alt="Screenshot 2026-03-18 at 6 10 19 PM" src="https://github.com/user-attachments/assets/1aeb46a6-8a7e-4c27-bfc5-9af130a2c982" />
<img width="896" height="902" alt="Screenshot 2026-03-18 at 1 16 41 PM" src="https://github.com/user-attachments/assets/41f1952c-33c0-48d0-a23a-8d01a07af527" />


### The auth function

`Get-OktaAccessToken.ps1` is a dot-sourced function library. Every script that needs to call Okta loads it first:

```powershell
. "C:\JML-Lab\Get-OktaAccessToken.ps1"

$token = Get-OktaAccessToken `
    -OktaDomain "your-okta-domain.okta.com" `
    -ClientId   "your-client-id" `
    -Thumbprint "your-cert-thumbprint"
```

The function:
1. Loads the RSA private key from the certificate store by thumbprint
2. Builds a JWT with claims: `iss`, `sub`, `aud`, `iat`, `exp`, `jti`
3. Signs it with RS256
4. POSTs it to the Okta token endpoint as a `client_assertion`
5. Returns the short-lived access token

### Errors hit and resolved

> ⚠️ **`invalid_client — The parsing of the client_assertion failed`**
>
> **Cause:** The `client_id` was present in the JWT claims but missing from the POST body. Okta reads the POST body first to identify which app is making the request — it needs `client_id` in the body to locate the app before it can read and verify the JWT.
>
> **Fix:** Added `client_id = $ClientId` as an explicit key in the `$body` hashtable.

> ⚠️ **JWT length 344 chars instead of expected ~638**
>
> **Cause:** Helper functions `ConvertTo-Base64Url` and `ConvertTo-Base64UrlBytes` were defined outside the function body. In a fresh terminal session they weren't in scope when the function ran, causing the JWT to be built from empty strings.
>
> **Fix:** Moved both helper functions inside the main function body so they're always in scope regardless of how the function is invoked.

### Verification

```powershell
& "C:\JML-Lab\Test-OktaAuth-v2.ps1"
```

```
[0] Pre-flight: checking certificate store... [OK]
[1] Requesting access token from Okta...      [OK]
[2] Checking token scopes...                  [OK]
[3] Making live API call...                   [OK]
Phase 0 PASSED
```

> **[Insert here]** — PowerShell terminal showing Test-OktaAuth-v2.ps1 passing all four checks

---

## Phase 1 — Joiner Provisioning

**Ticket:** ITS-30101 — Jordan Mills, Cloud Engineer I, starting March 23 2026

> **[Insert here]** — ITS-30101 ticket detail showing HR email, auto-triage note, and manager approval confirmation

### What the script does

Three stages, in order — each depends on the previous completing successfully:

**Stage 1 — Create AD account**
```powershell
New-ADUser `
    -Name                  $Row.FullName `
    -GivenName             $Row.FirstName `
    -Surname               $Row.LastName `
    -SamAccountName        $Row.SamAccount `
    -UserPrincipalName     $Row.UPN `
    -Path                  $Row.OU `
    -Department            $Row.Department `
    -Title                 $Row.Title `
    -EmployeeID            $Row.EmployeeId `
    -AccountPassword       $TempPassword `
    -Enabled               $true `
    -ChangePasswordAtLogon $true
```

**Stage 2 — Assign AD group**
```powershell
Add-ADGroupMember -Identity $Row.ADGroup -Members $Row.SamAccount
```

**Stage 3 — Log sync note**

The Okta AD agent picks up the new user on the next poll cycle. Group membership at sync time determines app access — Jordan lands in Okta as a member of `V2_Cloud_Engineer` with Slack, Google Workspace, and SharePoint access granted automatically.

### Why order matters

The account must exist before group assignment. The group assignment must be complete before Okta syncs. Okta reads the final state of AD during import — syncing before group assignment would create the user in Okta with no group membership and no app access.

### Error hit during development

> ⚠️ **`Property 'SamAccount' not found in object of type Hashtable`**
>
> The pre-flight check used `Get-ADUser -Filter { SamAccountName -eq $Ticket.SamAccount }`.
>
> **Cause:** PowerShell `-Filter` scriptblocks have restricted scoping. Hashtable dot notation doesn't resolve inside them.
>
> **Fix:**
> ```powershell
> $sam = $Ticket.SamAccount
> Get-ADUser -Filter { SamAccountName -eq $sam }
> ```

> **[Insert here]** — AD Users and Computers showing Jordan Mills in `OU=Users,OU=_NA`

> **[Insert here]** — V2_Cloud_Engineer Members tab showing Jordan Mills

### Okta sync

> 💡 **The Okta AD agent is a pull model.** It polls Okta's servers for jobs every 30 seconds. There is no REST endpoint to push an on-demand sync from outside for AD integrations. The `/api/v1/apps/{id}/connections/default/lifecycle/import` endpoint returns `405` for AD app types.
>
> **To sync immediately:** Okta Admin → Directory → Directory Integrations → yearwood.local → Import Now

> **[Insert here]** — Okta user profile for Jordan Mills post-sync showing AD-sourced attributes

> **[Insert here]** — Okta V2_Cloud_Engineer group showing synced members

---

## Phase 2 — Post-Provisioning Verification

After provisioning, the verification script queries AD and Okta to confirm the account is in the expected state and exports a CSV proof artifact.

**What gets verified:**
- AD account exists and is enabled
- Correct OU placement
- Group membership matches ticket
- Okta user profile attributes match AD

**Output:** Timestamped CSV in `C:\JML-Lab\Logs\` capturing post-provisioning account state. This becomes the audit trail attached to the ticket on closure.

> **[Insert here]** — CSV proof export showing account state, group membership, and timestamp columns

---

## Phase 3 — Mover Provisioning

**Ticket:** ITS-30103 — Emily Clark, Helpdesk → Cloud Engineer

> **[Insert here]** — ITS-30103 ticket detail showing group delta and approval confirmation

### What the script does

Three stages — remove first, add second, then update attributes:

```powershell
# Stage 1 — remove old group
Remove-ADGroupMember -Identity $Row.RemoveGroup -Members $Row.SamAccount -Confirm:$false

# Stage 2 — add new group
Add-ADGroupMember -Identity $Row.AddGroup -Members $Row.SamAccount

# Stage 3 — update profile attributes
Set-ADUser -Identity $Row.SamAccount -Title $Row.NewTitle -Department $Row.NewDepartment
```

### App access delta

Emily was in `V2_Helpdesk` — SharePoint + Slack. Moving to `V2_Cloud_Engineer` adds Google Workspace. The group reassignment in AD is all that's needed — Okta's group-to-app policy handles the rest automatically on the next sync.

> ⚠️ **Why remove before add**
>
> In environments with conflicting group policies, a user simultaneously in both old and new groups can trigger unexpected access. Remove first, add second keeps the transition clean with no ambiguous policy overlap window.

> ⚠️ **`Set-ADUser` only modifies what you explicitly pass**
>
> Unlike `New-ADUser` which sets all attributes at creation, `Set-ADUser` only changes the fields passed in. Emily's password, UPN, OU placement, and every other attribute stay exactly as they were — only title and department are updated.

> **[Insert here]** — V2_Cloud_Engineer Members tab showing Emily Clark after the move

---

## Phase 4 — Leaver Offboarding

**Ticket:** ITS-30105 — James King, V2_Finance, immediate termination

The Leaver workflow is the most security-critical phase. A terminated employee with active access is an immediate risk. The script executes three stages — and Stage 3 (group removal) runs independently of Stage 2, so group access is never blocked by a failed OU move.

> **[Insert here]** — ITS-30105 ticket detail showing Critical SLA, dual authorization (HR Director + Legal), and URGENT triage note

### What the script does

```powershell
# Stage 1 — disable account immediately
Disable-ADAccount -Identity $Row.SamAccount

# Stage 2 — move to DisabledUsers OU
Move-ADObject -Identity $adUser.DistinguishedName -TargetPath $DisabledOU

# Stage 3 — strip all group memberships
foreach ($group in $adUser.MemberOf) {
    $groupName = ($group -split ',')[0] -replace 'CN=', ''
    Remove-ADGroupMember -Identity $groupName -Members $Row.SamAccount -Confirm:$false
}
```

### Stage independence

Stage 3 runs even if Stage 2 fails. An account in the wrong OU with no group memberships is safe. An account in the right OU but still a member of `V2_Finance` is a risk. Group revocation is never made dependent on the OU move succeeding.

> **[Insert here]** — AD DisabledUsers OU showing James King post-offboarding

> **[Insert here]** — Okta showing James King deactivated post-sync

---

## Phase 5 — Ticket Closure Simulation

With provisioning verified and CSV proof exported, each ticket is closed in the Zendesk mock.

The Zendesk mock (`/mock/zendesk-jml-v3.html`) is a standalone HTML file simulating a real ticketing queue — built as a portfolio artifact to demonstrate the end-to-end JML workflow.

**Features:**
- 6 tickets — 2 Joiners, 2 Movers, 2 Leavers — using real `yearwood.local` users and V2_ group names
- Live SLA timers recalculated from `Date.now()` on every page open — never expire regardless of date
- Manager approval auto-posted as an internal note on all tickets with approval reference numbers
- Full status workflow — New / Open / Pending / Solved with real-time sidebar count updates
- Submit as Open / Pending / Solved via split-button dropdown
- SLA banner transitions to Resolved state when a ticket is solved

> **[Insert here]** — Zendesk mock with a ticket marked Solved and SLA showing Resolved

---

## CSV-Driven Architecture Upgrade

The original scripts hardcoded ticket data directly in the script body — one script per ticket, manually edited for each new request. This was replaced with a single CSV-driven master script.

### Why this is closer to production

In real enterprise environments, IAM automation consumes data from HR system exports or ticketing API responses — never from scripts that get manually edited per request. Workday, BambooHR, and ServiceNow all export CSV. A single master script that reads from a CSV and branches on type is the correct pattern.

> *In production, `Import-Csv` would be replaced by `Invoke-RestMethod` against the Zendesk or ServiceNow API. The branching logic, field validation, and error handling are identical — only the data source changes.*

### CSV schemas

**Joiners.csv**
```
TicketId, ApprovalRef, FullName, FirstName, LastName, SamAccount, UPN,
OU, ADGroup, Title, Department, EmployeeId, StartDate, PersonalEmail
```

**Movers.csv**
```
TicketId, ApprovalRef, FullName, SamAccount, UPN,
RemoveGroup, AddGroup, NewTitle, NewDepartment
```

**Leavers.csv**
```
TicketId, ApprovalRef, FullName, SamAccount, UPN,
TerminationType, MailboxRetentionDays
```

### Running the master script

```powershell
& "C:\JML-Lab\Invoke-JMLProvisioning.ps1" -CsvPath "C:\JML-Lab\CSV\Joiners.csv"
& "C:\JML-Lab\Invoke-JMLProvisioning.ps1" -CsvPath "C:\JML-Lab\CSV\Movers.csv"
& "C:\JML-Lab\Invoke-JMLProvisioning.ps1" -CsvPath "C:\JML-Lab\CSV\Leavers.csv"
```

### Type detection from filename

The script reads the filename — not the file content — to determine the JML type. No `Type` column needed in the CSV. `Joiners_March2026.csv` resolves correctly because the word `Joiner` is in the name.

```powershell
$JmlType = switch -Wildcard ($fileName) {
    "*Joiner*" { "Joiner" }
    "*Mover*"  { "Mover"  }
    "*Leaver*" { "Leaver" }
    default    { $null    }
}
```

### Continue-on-failure execution model

Each row runs inside its own `try/catch`. A failed row logs a structured error and skips — all other rows continue. A Leavers batch with five terminations should never stall because one SAM account has a typo.

Every error follows a three-part format:

```
[ITS-30105] STAGE 1 FAILED — Disable-ADAccount
  Reason  : No AD account found with SamAccountName 'James.King'
  Action  : Verify SamAccount value in CSV matches the account in AD exactly
  Impact  : All stages skipped for this row. No changes were made.
```

> **[Insert here]** — PowerShell terminal showing master script output with per-row logging and summary report

---

## Key Lessons Learned

### 1. `client_id` must appear in both the JWT and the POST body
Okta processes the token request in two steps. It reads the POST body first to identify which app is making the request using `client_id`. Only after locating the app can it retrieve the stored public key and verify the JWT. The `client_id` in the body and the `iss` claim in the JWT are the same value — they serve different purposes. One tells Okta where to look. The other gets cryptographically verified.

### 2. PowerShell `-Filter` scriptblocks have restricted scoping
Variables inside `-Filter { }` blocks must be simple variables — not hashtable dot notation. `$Ticket.SamAccount` doesn't resolve inside the filter. Extract to `$sam = $Ticket.SamAccount` and use `$sam` instead.

### 3. The Okta AD agent is a pull model — there is no external push trigger
The agent polls Okta every 30 seconds for jobs. There is no REST endpoint to push an on-demand sync from outside for AD integrations. The `/lifecycle/import` endpoint returns `405` for AD app types. Sync is triggered manually via the admin console or waits for the next scheduled poll.

### 4. Stale session variables break auth scripts
Variables and functions defined interactively in a PowerShell terminal persist for the entire session. Running auth scripts after debug sessions can cause the JWT to be built from stale data. Always test auth in a fresh terminal.

### 5. `Set-ADUser` only modifies what you explicitly pass
Unlike `New-ADUser`, `Set-ADUser` only changes the attributes you explicitly include. Every other attribute on the account stays exactly as it was.

### 6. Leaver Stage 3 must never depend on Stage 2
Group revocation is the security-critical action. OU move is administrative housekeeping. If the move fails, group removal must still run. Never chain them such that a failed OU move blocks the revocation.

---

## Script Inventory

| Script | Purpose |
|---|---|
| `Invoke-JMLProvisioning.ps1` | Master CSV-driven script. All three JML types from a single entry point. Continue-on-failure, three-part error format, summary report. |
| `Get-OktaAccessToken.ps1` | Certificate-based Okta auth function. Dot-sourced by any script making API calls. No plaintext credentials. |
| `Test-OktaAuth-v2.ps1` | Auth health check. Validates cert, token, scopes, and live API call. Run this when auth breaks before debugging provisioning scripts. |
| `Invoke-JoinerProvisioning.ps1` | Original hardcoded Joiner script. Superseded by master script. Retained to show progression from hardcoded to data-driven design. |
| `Invoke-MoverProvisioning.ps1` | Original hardcoded Mover script. Superseded by master script. Retained for the same reason. |

---

## What I'd Do Differently in Production

**Replace CSV input with a ticketing API integration.**
The CSV schema mirrors what a Zendesk or ServiceNow API would return. In production `Import-Csv` becomes `Invoke-RestMethod`. The branching logic and field validation are identical — only the data source changes.

**Add a file watcher for automated triggering.**
Rather than running manually, a PowerShell file watcher would trigger the script automatically when a new CSV lands in the input folder — removing the manual execution step.

**Expand the CSV proof to include Okta state.**
The current proof captures AD state. In production it would also query Okta to confirm group membership and app assignments synced correctly — producing a single unified audit record per ticket.

**Store environment config externally.**
Okta domain, client ID, and thumbprint are currently in the script header. A production script reads these from a config file or environment variable so they can be rotated without touching script logic.

**Full idempotency at every stage.**
Every operation should be safe to re-run without side effects. The current scripts have basic duplicate checks — a production system enforces this at every stage so interrupted runs can always be safely retried.

---

*Yearwood.Local IAM Lab — Built as a portfolio project for hands-on identity and access management experience.*

**Evan Yearwood**
[LinkedIn](https://linkedin.com/in/evan-yearwood/) · [GitHub](https://github.com/EvanHYearwood)
