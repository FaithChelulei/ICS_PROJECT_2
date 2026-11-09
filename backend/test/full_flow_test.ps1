# Full incident lifecycle with REAL emails, MFA codes and email links -- all
# three roles, one story:
#
#   the caregiver works normally on their own computer
#   -> someone with the caregiver's login signs in from an UNKNOWN device
#   -> the risk model flags it: that session is ended on the spot
#   -> the Security Auditor sees it in the review queue
#   -> the owner clicks "This was NOT me" in the alert email
#   -> the account is locked and the alert escalated
#   -> the auditor records the breach decision (KDPA s.43)
#   -> the SysAdmin unlocks the account; a temporary password is emailed
#   -> the owner signs in with it and sets their password back
#
#   cd backend
#   .\test\full_flow_test.ps1      (asks for the demo accounts' password, hidden)
#
# Nothing is deleted. The caregiver account is locked and unlocked during
# the run, and its password is set back to the one you typed at the end.
# Emails: 5 MFA codes, 1 risk alert, 1 account-unlocked notice.
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
$ownDevice = 'FAITH-TEST-PC'
$unknownDevice = "UNKNOWN-LAPTOP-$(Get-Random -Maximum 99999)"
$script:passed = 0
$script:failed = 0

function Invoke-Api([string]$Path, [string]$Method = 'GET', $Body = $null, [string]$Token = '', [string]$Device = $ownDevice) {
  $headers = @{ 'X-Device-Name' = $Device }
  if ($Token) { $headers.Authorization = "Bearer $Token" }
  $params = @{ Uri = "$base$Path"; Method = $Method; Headers = $headers; ContentType = 'application/json'; UseBasicParsing = $true }
  if ($null -ne $Body) { $params.Body = ($Body | ConvertTo-Json -Depth 5) }
  try {
    $r = Invoke-WebRequest @params
    $parsed = $null; try { $parsed = $r.Content | ConvertFrom-Json } catch {}
    return [pscustomobject]@{ Status = [int]$r.StatusCode; Body = $parsed; Text = $r.Content }
  } catch {
    $status = 0; if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
    $parsed = $null; try { $parsed = $_.ErrorDetails.Message | ConvertFrom-Json } catch {}
    return [pscustomobject]@{ Status = $status; Body = $parsed; Text = $_.ErrorDetails.Message }
  }
}

function Check([string]$Label, [bool]$Ok, [string]$Detail = '') {
  if ($Ok) { $script:passed++; Write-Host "  PASS - $Label" -ForegroundColor Green }
  else { $script:failed++; Write-Host "  FAIL - $Label" -ForegroundColor Red }
  if ($Detail) { Write-Host "         $Detail" -ForegroundColor DarkGray }
}

function Step([string]$Title) { Write-Host "`n=== $Title ===" -ForegroundColor Cyan }

function Connect-WithMfa([string]$Email, [string]$Pw, [string]$Device = $ownDevice) {
  $one = Invoke-Api '/auth/login' 'POST' @{ identifier = $Email; password = $Pw } -Device $Device
  if ($one.Status -ne 200 -or -not $one.Body.mfaRequired) {
    Check "Password accepted for $Email" $false "status $($one.Status): $($one.Body.error)"
    return $null
  }
  Write-Host "  A 6-digit code was emailed to $($one.Body.email)." -ForegroundColor Yellow
  $code = Read-Host '  Type the code'
  $two = Invoke-Api '/auth/verify-mfa' 'POST' @{ userId = $one.Body.userId; code = $code.Trim() } -Device $Device
  Check "Signed in as $Email (device: $Device)" ($two.Status -eq 200 -and $two.Body.token) "status $($two.Status)"
  return $two.Body
}

function Stop-Here([string]$Why) {
  Write-Host "`n$Why -- stopping." -ForegroundColor Red
  Write-Host "=== $($script:passed) passed, $($script:failed) failed ===" -ForegroundColor Red
  exit 1
}

Write-Host 'This run locks and then unlocks the caregiver account, and sets its password back at the end.' -ForegroundColor Yellow
if ((Read-Host 'Type YES to continue') -ne 'YES') { Write-Host 'Cancelled -- nothing changed.'; exit }

Step '1. The caregiver works normally on their own computer'
$own = Connect-WithMfa $caregiver $Password
if (-not $own) { Stop-Here 'No caregiver session' }
$child = Invoke-Api '/children' 'POST' @{ fullName = 'Lifecycle Child'; dateOfBirth = '2020-09-09'; developmentalRecordsConsent = $true; privacyNoticeVersion = $noticeVersion } -Token $own.token
Check 'Registers a child -- normal work, not flagged' ($child.Status -eq 201 -and -not $child.Body.riskNotice)
$childId = $child.Body.childProfileId

Step '2. Someone with the caregiver''s login signs in from an UNKNOWN device'
Write-Host "  (Simulated attacker device: $unknownDevice)" -ForegroundColor DarkGray
$thief = Connect-WithMfa $caregiver $Password $unknownDevice
if (-not $thief) { Stop-Here 'No attacker session' }
$flag = $null
for ($i = 1; $i -le 3 -and -not $flag; $i++) {
  $r = Invoke-Api "/children/$childId/records" -Token $thief.token -Device $unknownDevice
  if ($r.Body.riskNotice -or $r.Body.code -eq 'SESSION_REVOKED_RISK') { $flag = $i }
}
Check 'The risk model flags the unknown device' ([bool]$flag) "flagged on action #$flag"
if (-not $flag) { Stop-Here 'Not flagged' }
$again = Invoke-Api '/children' -Token $thief.token -Device $unknownDevice
Check 'That session is ended on the spot -- its next request is refused' ($again.Status -eq 401 -and $again.Body.code -eq 'SESSION_REVOKED_RISK')

Step '3. The Security Auditor sees it in the review queue'
$au = Connect-WithMfa $auditor $Password
if (-not $au) { Stop-Here 'No auditor session' }
$queue = Invoke-Api '/auditor/flagged-sessions?status=pending' -Token $au.token
$alert = @($queue.Body.flaggedSessions) | Where-Object { $_.email -eq $caregiver } | Select-Object -First 1
Check 'The flagged session is waiting for review' ([bool]$alert) $(if ($alert) { "alert #$($alert.risk_score_id), score $($alert.combined_score) vs $($alert.role_threshold), device $($alert.pc_name)" })
if (-not $alert) { Stop-Here 'Alert not in the queue' }

Step '4. The owner answers the alert email: "This was NOT me"'
Write-Host "  Open $caregiver's inbox, find 'Unusual activity on your account'," -ForegroundColor Yellow
Write-Host '  right-click "This was NOT me" -> Copy link address, and paste it here.' -ForegroundColor Yellow
$denyUrl = (Read-Host '  Link').Trim()
try { $page = Invoke-WebRequest -Uri $denyUrl -UseBasicParsing; $denyOk = $page.StatusCode -eq 200 } catch { $denyOk = $false }
Check 'The link is accepted' $denyOk
$locked = Invoke-Api '/auth/login' 'POST' @{ identifier = $caregiver; password = $Password }
Check 'The account is now LOCKED -- even the right password is refused' ($locked.Status -eq 403) $locked.Body.error

Step '5. The auditor records the breach decision (KDPA s.43, 72-hour rule)'
$escalated = Invoke-Api '/auditor/flagged-sessions?status=escalated' -Token $au.token
$now = @($escalated.Body.flaggedSessions) | Where-Object { $_.risk_score_id -eq $alert.risk_score_id }
Check 'The alert was escalated automatically by the owner''s answer' ([bool]$now)
$decision = Invoke-Api "/auditor/flagged-sessions/$($alert.risk_score_id)/breach-decision" 'POST' @{ decision = 'no_real_risk'; reason = 'Lifecycle test: simulated attacker, contained within seconds, no data left the system' } -Token $au.token
Check 'Breach decision recorded within the 72-hour window' ($decision.Status -eq 200 -and $decision.Body.withinWindow) "$($decision.Body.hoursAfterFlag) h after detection"

Step '6. The SysAdmin unlocks the account'
$ad = Connect-WithMfa $admin $Password
if (-not $ad) { Stop-Here 'No admin session' }
$lockedList = Invoke-Api '/admin/users/locked' -Token $ad.token
$target = @($lockedList.Body.lockedUsers) | Where-Object { $_.email -eq $caregiver }
Check 'The caregiver appears in the locked-accounts list' ([bool]$target) $target.locked_reason
if (-not $target) { Stop-Here 'Caregiver not locked' }
$unlock = Invoke-Api "/admin/users/$($target.id)/unlock" 'POST' -Token $ad.token
Check 'Unlocked -- a temporary password is emailed to the owner' ($unlock.Status -eq 200)

Step '7. The owner signs back in and sets their password'
Write-Host "  Check $caregiver's inbox for 'Your account has been unlocked'." -ForegroundColor Yellow
$temp = (Read-Host '  Paste the temporary password').Trim()
$back = Connect-WithMfa $caregiver $temp
if (-not $back) { Stop-Here 'Could not sign in with the temporary password' }
Check 'Must change the temporary password first' ([bool]$back.mustChangePassword)
$changed = Invoke-Api '/auth/change-password' 'POST' @{ currentPassword = $temp; newPassword = $Password } -Token $back.token
Check 'Password set back -- account fully working again' ($changed.Status -eq 200)
$works = Invoke-Api '/children' -Token $back.token
Check 'Their children are visible again' ($works.Status -eq 200)

Write-Host "`n=== Lifecycle complete: $($script:passed) passed, $($script:failed) failed ===" -ForegroundColor $(if ($script:failed) { 'Red' } else { 'Green' })
Write-Host 'flagged -> session ended -> auditor queue -> owner says NOT me -> locked -> breach decision -> unlocked -> working again' -ForegroundColor DarkGray
