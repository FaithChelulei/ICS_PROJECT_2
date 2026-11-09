# Interactive walkthrough with REAL multi-factor authentication: the one
# kind of check the automated suites can't do (their test accounts have MFA
# switched off). Uses your real demo accounts; every login emails a 6-digit
# code that you type in when asked.
#
#   cd backend
#   .\test\manual_test.ps1      (asks for the demo accounts' password, hidden)
#
# Covers: MFA login for all three roles, generic login errors, registering
# a child with the privacy notice and records consent, encryption round
# trip, role checks, the public account request (with and without the
# privacy notice), SysAdmin approval, and the new account's forced password
# change. Nothing existing is deleted; it adds one child to the caregiver
# and one approved account per run.
#
# Emails you'll receive: 3 MFA codes (caregiver, auditor, admin) and one
# approval email with a temporary password for the new account.
param([SecureString]$SecurePassword, [string]$EmailBase)

# Never stored in this file: asked for at run time, typing hidden.
if (-not $SecurePassword) { $SecurePassword = Read-Host 'Password for the demo accounts' -AsSecureString }
$Password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword))

$base = 'https://localhost:4000'
# Accounts come from DEMO_EMAIL_BASE in backend/.env (you@example.com gives
# you+caregiver@example.com, ...), or -EmailBase; nothing personal is kept here.
if (-not $EmailBase) {
  $envLine = Select-String -Path (Join-Path $PSScriptRoot '..\.env') -Pattern '^DEMO_EMAIL_BASE=' -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($envLine) { $EmailBase = $envLine.Line.Split('=', 2)[1].Trim() }
}
if (-not $EmailBase -or $EmailBase -notmatch '^[^@\s]+@[^@\s]+$') { throw 'Set DEMO_EMAIL_BASE in backend/.env (or pass -EmailBase you@example.com).' }
$inboxLocal, $inboxDomain = $EmailBase.Split('@')
$caregiver = "$inboxLocal+caregiver@$inboxDomain"
$auditor = "$inboxLocal+auditor@$inboxDomain"
$admin = "$inboxLocal+admin@$inboxDomain"
$noticeVersion = '2026-10'   # must match backend/src/services/privacyNotice.js
$script:passed = 0
$script:failed = 0

# One request; never throws. Returns .Status and .Body (parsed JSON or $null).
function Invoke-Api([string]$Path, [string]$Method = 'GET', $Body = $null, [string]$Token = '', [string]$Device = 'FAITH-TEST-PC') {
  $headers = @{ 'X-Device-Name' = $Device }
  if ($Token) { $headers.Authorization = "Bearer $Token" }
  $params = @{ Uri = "$base$Path"; Method = $Method; Headers = $headers; ContentType = 'application/json'; UseBasicParsing = $true }
  if ($null -ne $Body) { $params.Body = ($Body | ConvertTo-Json -Depth 5) }
  try {
    $r = Invoke-WebRequest @params
    $parsed = $null; try { $parsed = $r.Content | ConvertFrom-Json } catch {}
    return [pscustomobject]@{ Status = [int]$r.StatusCode; Body = $parsed }
  } catch {
    $status = 0; if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
    $parsed = $null; try { $parsed = $_.ErrorDetails.Message | ConvertFrom-Json } catch {}
    return [pscustomobject]@{ Status = $status; Body = $parsed }
  }
}

function Check([string]$Label, [bool]$Ok, [string]$Detail = '') {
  if ($Ok) { $script:passed++; Write-Host "  PASS - $Label" -ForegroundColor Green }
  else { $script:failed++; Write-Host "  FAIL - $Label" -ForegroundColor Red }
  if ($Detail) { Write-Host "         $Detail" -ForegroundColor DarkGray }
}

function Step([string]$Title) { Write-Host "`n--- $Title ---" -ForegroundColor Cyan }

# Password + emailed MFA code -> session token (or $null).
function Connect-WithMfa([string]$Email, [string]$Pw, [string]$Device = 'FAITH-TEST-PC') {
  $one = Invoke-Api '/auth/login' 'POST' @{ identifier = $Email; password = $Pw } -Device $Device
  if ($one.Status -ne 200 -or -not $one.Body.mfaRequired) {
    Check "Password accepted for $Email, MFA code requested" $false "status $($one.Status): $($one.Body.error)"
    return $null
  }
  Write-Host "  A 6-digit code was emailed to $($one.Body.email)." -ForegroundColor Yellow
  $code = Read-Host '  Type the code'
  $two = Invoke-Api '/auth/verify-mfa' 'POST' @{ challengeId = $one.Body.challengeId; code = $code.Trim() } -Device $Device
  Check "MFA code accepted, session issued for $Email" ($two.Status -eq 200 -and $two.Body.token) "status $($two.Status)"
  return $two.Body.token
}

Step '1. Caregiver signs in (password + emailed MFA code)'
$cg = Connect-WithMfa $caregiver $Password
if (-not $cg) { Write-Host 'Cannot continue without a caregiver session.' -ForegroundColor Red; exit 1 }

Step '2. Wrong password and unknown email get the SAME answer'
$wrong = Invoke-Api '/auth/login' 'POST' @{ identifier = $caregiver; password = 'wrong-password' }
$nobody = Invoke-Api '/auth/login' 'POST' @{ identifier = 'nobody@example.com'; password = 'wrong-password' }
Check 'Both refused with one generic message (no account discovery)' ($wrong.Status -eq 401 -and $nobody.Status -eq 401 -and $wrong.Body.error -eq $nobody.Body.error) "`"$($wrong.Body.error)`""

Step '3. Caregiver registers a child (privacy notice + records consent)'
$noNotice = Invoke-Api '/children' 'POST' @{ fullName = 'Walkthrough Child'; dateOfBirth = '2021-04-04' } -Token $cg
Check 'Without accepting the privacy notice: refused' ($noNotice.Status -eq 400 -and $noNotice.Body.code -eq 'PRIVACY_NOTICE_REQUIRED')
$child = Invoke-Api '/children' 'POST' @{ fullName = 'Walkthrough Child'; dateOfBirth = '2021-04-04'; familyBackground = 'Lives with both parents'; developmentalRecordsConsent = $true; privacyNoticeVersion = $noticeVersion } -Token $cg
Check 'With the notice accepted: child registered' ($child.Status -eq 201) "child profile #$($child.Body.childProfileId)"
$childId = $child.Body.childProfileId

Step '4. Encryption round trip: stored encrypted, shown decrypted to its owner'
$list = Invoke-Api '/children' -Token $cg
$mine = $list.Body.children | Where-Object { $_.childProfileId -eq $childId }
Check 'Name and date of birth come back exactly as entered' ($mine -and $mine.fullName -eq 'Walkthrough Child' -and $mine.dateOfBirth -eq '2021-04-04')
$rec = Invoke-Api "/children/$childId/records" 'POST' @{ milestone = 'Says first words'; healthIndicator = 'Healthy'; assessmentScore = 8; progressNotes = 'Doing well' } -Token $cg
Check 'Developmental record added' ($rec.Status -eq 201)
$recs = Invoke-Api "/children/$childId/records" -Token $cg
Check 'Record reads back decrypted' ($recs.Status -eq 200 -and ($recs.Body.records | Where-Object { $_.milestone -eq 'Says first words' }))

Step '5. Security Auditor signs in (MFA) -- and cannot see child data'
$au = Connect-WithMfa $auditor $Password
if ($au) {
  $peek = Invoke-Api '/children' -Token $au
  Check 'Auditor asking for child data is refused (403)' ($peek.Status -eq 403) $peek.Body.error
  $queue = Invoke-Api '/auditor/flagged-sessions?status=all' -Token $au
  Check 'Auditor can open the flagged-session queue' ($queue.Status -eq 200) "$(@($queue.Body.flaggedSessions).Count) flagged session(s) on record"
}

Step '6. Someone requests an account on the public form'
$email = "$inboxLocal+walkthrough$(Get-Date -Format 'yyyyMMddHHmmss')@$inboxDomain"
$reqNo = Invoke-Api '/auth/register' 'POST' @{ fullName = 'Walkthrough Caregiver'; email = $email; requestedRole = 'Caregiver' }
Check 'Without accepting the privacy notice: refused' ($reqNo.Status -eq 400 -and $reqNo.Body.code -eq 'PRIVACY_NOTICE_REQUIRED')
$req = Invoke-Api '/auth/register' 'POST' @{ fullName = 'Walkthrough Caregiver'; email = $email; requestedRole = 'Caregiver'; reason = 'Walkthrough test'; privacyNoticeVersion = $noticeVersion }
Check 'With the notice accepted: request submitted, pending review' ($req.Status -eq 201) $email

Step '7. SysAdmin signs in (MFA) and approves it'
$ad = Connect-WithMfa $admin $Password
if ($ad) {
  $pending = Invoke-Api '/admin/registration-requests?status=pending' -Token $ad
  $requestId = (@($pending.Body.requests) | Where-Object { $_.email -eq $email }).id
  Check 'The new request is in the admin''s queue' ([bool]$requestId)
  if ($requestId) {
    $ok = Invoke-Api "/admin/registration-requests/$requestId/approve" 'POST' -Token $ad
    Check 'Approved -- account created, temporary password emailed' ($ok.Status -eq 200)
    Write-Host "  Check $EmailBase for the approval email to $email." -ForegroundColor Yellow
    $temp = Read-Host '  Paste the temporary password from it'
    $new = Invoke-Api '/auth/login' 'POST' @{ identifier = $email; password = $temp.Trim() }
    Write-Host '  New accounts use MFA too -- a code has just been emailed to the same inbox.' -ForegroundColor Yellow
    $code = Read-Host '  Type the code'
    $newSession = Invoke-Api '/auth/verify-mfa' 'POST' @{ challengeId = $new.Body.challengeId; code = $code.Trim() }
    Check 'The new caregiver can sign in with the temporary password' ($newSession.Status -eq 200 -and $newSession.Body.mustChangePassword)
    $blocked = Invoke-Api '/children' -Token $newSession.Body.token
    Check '...but sees no data until the temporary password is changed' ($blocked.Status -eq 403 -and $blocked.Body.code -eq 'MUST_CHANGE_PASSWORD')
    $adminTry = Invoke-Api '/admin/registration-requests' -Token $newSession.Body.token
    Check '...and can''t reach admin functions either' ($adminTry.Status -eq 403)
  }
}

Write-Host "`n=== Walkthrough complete: $($script:passed) passed, $($script:failed) failed ===" -ForegroundColor $(if ($script:failed) { 'Red' } else { 'Green' })
