<#
.SYNOPSIS
    Master JML provisioning script — CSV-driven.

.DESCRIPTION
    Reads a CSV file and executes the correct JML action for each row.
    JML type is detected from the filename — Joiners.csv, Movers.csv, Leavers.csv.

    Joiner  → New-ADUser → Add-ADGroupMember → Log
    Mover   → Remove-ADGroupMember → Add-ADGroupMember → Set-ADUser → Log
    Leaver  → Disable-ADAccount → Move to DisabledUsers OU → Remove all groups → Log

    Execution model: continue-on-failure. A failed row is logged and skipped.
    All other rows in the batch continue processing. Summary report at the end.

.PARAMETER CsvPath
    Full path to the CSV file.
    Example: C:\JML-Lab\CSV\Joiners.csv

.EXAMPLE
    & "C:\JML-Lab\Invoke-JMLProvisioning.ps1" -CsvPath "C:\JML-Lab\CSV\Joiners.csv"
    & "C:\JML-Lab\Invoke-JMLProvisioning.ps1" -CsvPath "C:\JML-Lab\CSV\Movers.csv"
    & "C:\JML-Lab\Invoke-JMLProvisioning.ps1" -CsvPath "C:\JML-Lab\CSV\Leavers.csv"

.NOTES
    Prerequisites:
      - PowerShell 7+
      - ActiveDirectory module (RSAT)
      - Get-OktaAccessToken.ps1 in C:\JML-Lab\
      - CSVs in C:\JML-Lab\CSV\
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$CsvPath
)

# ─── CONFIG ───────────────────────────────────────────────────────────────────
. "C:\JML-Lab\Get-OktaAccessToken.ps1"

$OktaDomain    = "trial-6085580.okta.com"
$ClientId      = "0oa11277uiqqdhS1M698"
$Thumbprint    = "565A23430D01E83EE7268FE049547674191493E1"
$OktaAdAppId   = "0oa10kgfjai1AqSmZ698"
$DisabledOU    = "OU=DisabledUsers,OU=_NA,DC=yearwood,DC=local"
$DefaultOU     = "OU=Users,OU=_NA,DC=yearwood,DC=local"
$TempPassword  = "JML-Temp2026!" | ConvertTo-SecureString -AsPlainText -Force

# ─── LOGGING SETUP ────────────────────────────────────────────────────────────
$LogDir  = "C:\JML-Lab\Logs"
$RunId   = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogFile = "$LogDir\JML_Run_$RunId.log"

if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Add-Content -Path $LogFile -Value $entry
    switch ($Level) {
        "INFO"    { Write-Host $entry -ForegroundColor Cyan }
        "SUCCESS" { Write-Host $entry -ForegroundColor Green }
        "WARN"    { Write-Host $entry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $entry -ForegroundColor Red }
        default   { Write-Host $entry }
    }
}

# Three-part error format: what failed / why / what to do
# Every error in this script follows this structure.
function Write-RowError {
    param(
        [string]$TicketId,
        [string]$Stage,
        [string]$Reason,
        [string]$Action,
        [string]$Impact
    )
    Write-Log "" "ERROR"
    Write-Log "[$TicketId] $Stage" "ERROR"
    Write-Log "  Reason  : $Reason" "ERROR"
    Write-Log "  Action  : $Action" "ERROR"
    Write-Log "  Impact  : $Impact" "ERROR"
    Write-Log "" "ERROR"
}

# ─── STEP 1: VALIDATE CSV PATH ────────────────────────────────────────────────
if (-not (Test-Path $CsvPath)) {
    Write-Log "CSV file not found: $CsvPath" "ERROR"
    Write-Log "  Reason  : The path provided does not exist on disk" "ERROR"
    Write-Log "  Action  : Verify the path and filename, then re-run" "ERROR"
    exit 1
}

# ─── STEP 2: DETECT JML TYPE FROM FILENAME ────────────────────────────────────
#
# The filename IS the type declaration. No "Type" column needed in the CSV.
# If the filename doesn't match a known type, we exit before touching anything.
#
$fileName = [System.IO.Path]::GetFileNameWithoutExtension($CsvPath)

$JmlType = switch -Wildcard ($fileName) {
    "*Joiner*"  { "Joiner" }
    "*Mover*"   { "Mover"  }
    "*Leaver*"  { "Leaver" }
    default     { $null    }
}

if (-not $JmlType) {
    Write-Log "Cannot determine JML type from filename: $fileName" "ERROR"
    Write-Log "  Reason  : Filename must contain Joiner, Mover, or Leaver" "ERROR"
    Write-Log "  Action  : Rename the file to match the pattern and re-run" "ERROR"
    exit 1
}

# ─── STEP 3: DEFINE REQUIRED FIELDS PER TYPE ──────────────────────────────────
#
# Each type has a different schema. Validation checks these fields exist and
# are not empty before any AD operation runs. A row missing a required field
# is logged and skipped — it never reaches AD.
#
$RequiredFields = switch ($JmlType) {
    "Joiner" { @("TicketId","ApprovalRef","FullName","FirstName","LastName",
                  "SamAccount","UPN","OU","ADGroup","Title","Department","EmployeeId") }
    "Mover"  { @("TicketId","ApprovalRef","FullName","SamAccount","UPN",
                  "RemoveGroup","AddGroup","NewTitle","NewDepartment") }
    "Leaver" { @("TicketId","ApprovalRef","FullName","SamAccount","UPN",
                  "TerminationType","MailboxRetentionDays") }
}

# ─── STEP 4: IMPORT CSV ───────────────────────────────────────────────────────
$Rows = Import-Csv -Path $CsvPath

if ($Rows.Count -eq 0) {
    Write-Log "CSV file is empty: $CsvPath" "WARN"
    Write-Log "  Action  : Add at least one data row and re-run" "WARN"
    exit 0
}

# ─── BANNER ───────────────────────────────────────────────────────────────────
Write-Log "=========================================================="
Write-Log "JML AUTOMATION — MASTER PROVISIONING SCRIPT"
Write-Log "Run ID   : $RunId"
Write-Log "Type     : $JmlType"
Write-Log "CSV      : $CsvPath"
Write-Log "Rows     : $($Rows.Count)"
Write-Log "Log file : $LogFile"
Write-Log "=========================================================="

# ─── STEP 5: ROW VALIDATION FUNCTION ─────────────────────────────────────────
#
# Runs before any AD operation. Returns $true if the row is valid.
# Any missing or empty required field logs a clear error and returns $false.
#
function Test-RowValid {
    param($Row, [string[]]$Fields)
    $valid = $true
    foreach ($field in $Fields) {
        if (-not $Row.PSObject.Properties.Name.Contains($field) -or
            [string]::IsNullOrWhiteSpace($Row.$field)) {
            Write-RowError `
                -TicketId ($Row.TicketId ?? "UNKNOWN") `
                -Stage    "VALIDATION FAILED — missing field: $field" `
                -Reason   "The column '$field' is empty or missing in the CSV row" `
                -Action   "Open the CSV, fix row for $($Row.FullName ?? 'unknown user'), re-run" `
                -Impact   "This row was skipped. All other rows continue processing."
            $valid = $false
        }
    }
    return $valid
}

# ─── STEP 6: BRANCH FUNCTIONS ─────────────────────────────────────────────────

function Invoke-Joiner {
    param($Row)

    Write-Log "----------------------------------------------------------"
    Write-Log "JOINER: $($Row.FullName) | $($Row.TicketId)"
    Write-Log "----------------------------------------------------------"

    # Pre-flight: check account doesn't already exist
    $sam = $Row.SamAccount
    $existing = Get-ADUser -Filter { SamAccountName -eq $sam } -ErrorAction SilentlyContinue

    if ($existing) {
        Write-Log "[$($Row.TicketId)] AD account '$sam' already exists — skipping creation." "WARN"
    } else {
        try {
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

            Write-Log "[$($Row.TicketId)] AD account created: $($Row.UPN)" "SUCCESS"
        }
        catch {
            Write-RowError `
                -TicketId $Row.TicketId `
                -Stage    "STAGE 1 FAILED — New-ADUser" `
                -Reason   $_.Exception.Message `
                -Action   "Check OU path '$($Row.OU)' exists and account name is unique" `
                -Impact   "Stages 2 (group assignment) were skipped for this row."
            return
        }
    }

    # Stage 2: assign AD group
    try {
        Add-ADGroupMember -Identity $Row.ADGroup -Members $Row.SamAccount
        Write-Log "[$($Row.TicketId)] Added '$($Row.SamAccount)' to '$($Row.ADGroup)'" "SUCCESS"
    }
    catch {
        Write-RowError `
            -TicketId $Row.TicketId `
            -Stage    "STAGE 2 FAILED — Add-ADGroupMember" `
            -Reason   $_.Exception.Message `
            -Action   "Verify group '$($Row.ADGroup)' exists in AD and SamAccount is correct" `
            -Impact   "User account was created but has no group membership."
        return
    }

    Write-Log "[$($Row.TicketId)] Joiner complete. Okta will sync on next AD agent poll." "SUCCESS"
    Write-Log "[$($Row.TicketId)] To sync now: Okta Admin -> Directory -> Directory Integrations -> Import Now" "INFO"
    return $true
}

function Invoke-Mover {
    param($Row)

    Write-Log "----------------------------------------------------------"
    Write-Log "MOVER: $($Row.FullName) | $($Row.TicketId)"
    Write-Log "----------------------------------------------------------"

    # Pre-flight: confirm user exists
    $sam = $Row.SamAccount
    $adUser = Get-ADUser -Filter { SamAccountName -eq $sam } `
        -Properties MemberOf, Title, Department -ErrorAction SilentlyContinue

    if (-not $adUser) {
        Write-RowError `
            -TicketId $Row.TicketId `
            -Stage    "PRE-FLIGHT FAILED — user not found" `
            -Reason   "No AD account found with SamAccountName '$($Row.SamAccount)'" `
            -Action   "Verify SamAccount value in CSV matches the account in AD exactly" `
            -Impact   "All stages skipped for this row. No changes were made."
        return
    }

    # Stage 1: remove old group
    $isMember = $adUser.MemberOf | Where-Object { $_ -match [regex]::Escape($Row.RemoveGroup) }

    if (-not $isMember) {
        Write-Log "[$($Row.TicketId)] '$($Row.SamAccount)' is not in '$($Row.RemoveGroup)' — skipping removal." "WARN"
    } else {
        try {
            Remove-ADGroupMember -Identity $Row.RemoveGroup -Members $Row.SamAccount -Confirm:$false
            Write-Log "[$($Row.TicketId)] Removed '$($Row.SamAccount)' from '$($Row.RemoveGroup)'" "SUCCESS"
        }
        catch {
            Write-RowError `
                -TicketId $Row.TicketId `
                -Stage    "STAGE 1 FAILED — Remove-ADGroupMember" `
                -Reason   $_.Exception.Message `
                -Action   "Verify '$($Row.RemoveGroup)' exists in AD and user is a member" `
                -Impact   "Stages 2 and 3 were skipped. No further changes made for this row."
            return
        }
    }

    # Stage 2: add new group
    try {
        Add-ADGroupMember -Identity $Row.AddGroup -Members $Row.SamAccount
        Write-Log "[$($Row.TicketId)] Added '$($Row.SamAccount)' to '$($Row.AddGroup)'" "SUCCESS"
    }
    catch {
        Write-RowError `
            -TicketId $Row.TicketId `
            -Stage    "STAGE 2 FAILED — Add-ADGroupMember" `
            -Reason   $_.Exception.Message `
            -Action   "Verify '$($Row.AddGroup)' exists in AD" `
            -Impact   "Old group was removed but new group was not assigned. User has no group membership."
        return
    }

    # Stage 3: update AD attributes
    try {
        Set-ADUser -Identity $Row.SamAccount -Title $Row.NewTitle -Department $Row.NewDepartment
        Write-Log "[$($Row.TicketId)] Updated title: '$($Row.NewTitle)' | dept: '$($Row.NewDepartment)'" "SUCCESS"
    }
    catch {
        Write-RowError `
            -TicketId $Row.TicketId `
            -Stage    "STAGE 3 FAILED — Set-ADUser" `
            -Reason   $_.Exception.Message `
            -Action   "Run Set-ADUser manually for '$($Row.SamAccount)' with the correct title and department" `
            -Impact   "Group reassignment succeeded but AD profile attributes were not updated."
        return
    }

    Write-Log "[$($Row.TicketId)] Mover complete. Okta will sync on next AD agent poll." "SUCCESS"
    Write-Log "[$($Row.TicketId)] To sync now: Okta Admin -> Directory -> Directory Integrations -> Import Now" "INFO"
    return $true
}

function Invoke-Leaver {
    param($Row)

    Write-Log "----------------------------------------------------------"
    Write-Log "LEAVER: $($Row.FullName) | $($Row.TicketId) | $($Row.TerminationType)"
    Write-Log "----------------------------------------------------------"

    # Pre-flight: confirm user exists
    $sam = $Row.SamAccount
    $adUser = Get-ADUser -Filter { SamAccountName -eq $sam } `
        -Properties MemberOf, Enabled -ErrorAction SilentlyContinue

    if (-not $adUser) {
        Write-RowError `
            -TicketId $Row.TicketId `
            -Stage    "PRE-FLIGHT FAILED — user not found" `
            -Reason   "No AD account found with SamAccountName '$($Row.SamAccount)'" `
            -Action   "Verify SamAccount value in CSV matches the account in AD exactly" `
            -Impact   "All stages skipped. No changes were made."
        return
    }

    # Stage 1: disable AD account
    try {
        Disable-ADAccount -Identity $Row.SamAccount
        Write-Log "[$($Row.TicketId)] AD account disabled: '$($Row.SamAccount)'" "SUCCESS"
    }
    catch {
        Write-RowError `
            -TicketId $Row.TicketId `
            -Stage    "STAGE 1 FAILED — Disable-ADAccount" `
            -Reason   $_.Exception.Message `
            -Action   "Manually disable the account in AD Users and Computers immediately" `
            -Impact   "Account is still active. Stages 2 and 3 were skipped."
        return
    }

    # Stage 2: move to DisabledUsers OU
    try {
        Move-ADObject -Identity $adUser.DistinguishedName -TargetPath $DisabledOU
        Write-Log "[$($Row.TicketId)] Moved '$($Row.SamAccount)' to $DisabledOU" "SUCCESS"
    }
    catch {
        Write-RowError `
            -TicketId $Row.TicketId `
            -Stage    "STAGE 2 FAILED — Move-ADObject" `
            -Reason   $_.Exception.Message `
            -Action   "Verify '$DisabledOU' exists in AD, then move manually" `
            -Impact   "Account is disabled but remains in original OU. Stage 3 (group removal) will still run."
    }

    # Stage 3: strip all group memberships
    # We continue even if stage 2 failed — removing group access is the priority
    $groups = $adUser.MemberOf
    if ($groups) {
        foreach ($group in $groups) {
            try {
                $groupName = ($group -split ',')[0] -replace 'CN=', ''
                Remove-ADGroupMember -Identity $groupName -Members $Row.SamAccount -Confirm:$false
                Write-Log "[$($Row.TicketId)] Removed from group: $groupName" "SUCCESS"
            }
            catch {
                Write-Log "[$($Row.TicketId)] Could not remove from group '$group': $($_.Exception.Message)" "WARN"
            }
        }
    } else {
        Write-Log "[$($Row.TicketId)] No group memberships found to remove." "INFO"
    }

    Write-Log "[$($Row.TicketId)] Mailbox retention: $($Row.MailboxRetentionDays) days ($($Row.TerminationType))" "INFO"
    Write-Log "[$($Row.TicketId)] Leaver complete. Okta will sync on next AD agent poll." "SUCCESS"
    Write-Log "[$($Row.TicketId)] To sync now: Okta Admin -> Directory -> Directory Integrations -> Import Now" "INFO"
    return $true
}

# ─── STEP 7: PROCESS EACH ROW ─────────────────────────────────────────────────
$Results = @{ Succeeded = @(); Failed = @(); Skipped = @() }

foreach ($Row in $Rows) {

    # Validate required fields before touching AD
    if (-not (Test-RowValid -Row $Row -Fields $RequiredFields)) {
        $Results.Failed += "$($Row.TicketId ?? 'UNKNOWN') — validation failed"
        continue
    }

    # Branch to the correct function
    $outcome = switch ($JmlType) {
        "Joiner" { Invoke-Joiner -Row $Row }
        "Mover"  { Invoke-Mover  -Row $Row }
        "Leaver" { Invoke-Leaver -Row $Row }
    }

    if ($outcome -eq $true) {
        $Results.Succeeded += $Row.TicketId
    } else {
        $Results.Failed += $Row.TicketId
    }
}

# ─── STEP 8: SUMMARY REPORT ───────────────────────────────────────────────────
Write-Log "=========================================================="
Write-Log "RUN SUMMARY"
Write-Log "Type      : $JmlType"
Write-Log "Total rows: $($Rows.Count)"
Write-Log "Succeeded : $($Results.Succeeded.Count) — $($Results.Succeeded -join ', ')"
Write-Log "Failed    : $($Results.Failed.Count) — $($Results.Failed -join ', ')"
Write-Log "Log file  : $LogFile"
Write-Log "=========================================================="

if ($Results.Failed.Count -gt 0) {
    Write-Log "One or more rows failed. Review the log file for details." "WARN"
    Write-Log "Failed rows require manual review before the ticket can be closed." "WARN"
}