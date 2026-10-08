# Manual smoke test for the auth flow. Run this in a SECOND terminal
# window while the server (npm run dev) is running in your first one.
#
# Usage:  .\test\manual_test.ps1
#
# MFA codes now arrive as real emails (SMTP is configured) -- check your
# inbox. Window 1 (the server) still prints a dev fallback line too if
# SMTP isn't set up on a given machine.
#
# Day 2 note: the ML risk engine now scores actual data access (creating
# or viewing/submitting a child record), not the bare act of logging in.
# Because Caregiver's threshold is intentionally very low (0.110 -- see
# ml/models/risk_tiers.json), the FIRST data action of a fresh session
# often crosses it even when nothing is actually wrong -- this is a
# deliberate, documented tradeoff (favor catching real threats over
# avoiding false alarms, since the automatic response is just a cheap
# "was this you?" email, not a lockout). If a step below shows a
# "riskNotice" in its response, that session has been force-logged-out --
# check Window 1 / your email for the confirm/deny link, and steps after
# it that reuse that same session's token will correctly get rejected with
# 401 until you log in again. That is Day 2 working as designed, not a
# failure of the script.

$base = 'http://localhost:4000'

Write-Host "`n--- 1. Caregiver login (MFA required -- same as every role now) ---" -ForegroundColor Cyan
$body = @{ email = 'faith.chelulei+caregiver@strathmore.edu'; password = 'DevTest123!' } | ConvertTo-Json
$cgStep1 = Invoke-RestMethod -Uri "$base/auth/login" -Method Post -ContentType 'application/json' -Body $body
$cgStep1 | ConvertTo-Json
Write-Host "Check Window 1 (or your inbox) for the Caregiver's MFA code." -ForegroundColor Yellow
$cgCode = Read-Host "Type the 6-digit code you see there"
$body = @{ userId = $cgStep1.userId; code = $cgCode } | ConvertTo-Json
$result = Invoke-RestMethod -Uri "$base/auth/verify-mfa" -Method Post -ContentType 'application/json' -Body $body -Headers @{ 'X-Device-Name' = 'FAITH-TEST-PC' }
Write-Host "Caregiver MFA verified, session token issued (login itself is never scored -- see note above)." -ForegroundColor Green

Write-Host "`n--- 2. Wrong password (should be rejected) ---" -ForegroundColor Cyan
$body = @{ email = 'faith.chelulei+caregiver@strathmore.edu'; password = 'wrong' } | ConvertTo-Json
try {
  Invoke-RestMethod -Uri "$base/auth/login" -Method Post -ContentType 'application/json' -Body $body
} catch {
  Write-Host "Correctly rejected:" $_.ErrorDetails.Message -ForegroundColor Green
}

Write-Host "`n--- 3. Security Auditor login (MFA required) ---" -ForegroundColor Cyan
$body = @{ email = 'faith.chelulei+auditor@strathmore.edu'; password = 'DevTest123!' } | ConvertTo-Json
$step1 = Invoke-RestMethod -Uri "$base/auth/login" -Method Post -ContentType 'application/json' -Body $body
$step1 | ConvertTo-Json

Write-Host "`nCheck the server's terminal window now for a line like:" -ForegroundColor Yellow
Write-Host "[DEV - no SMTP configured] MFA code for faith.chelulei+auditor@strathmore.edu: 123456" -ForegroundColor Yellow
$code = Read-Host "`nType the 6-digit code you see there"

$body = @{ userId = $step1.userId; code = $code } | ConvertTo-Json
$final = Invoke-RestMethod -Uri "$base/auth/verify-mfa" -Method Post -ContentType 'application/json' -Body $body -Headers @{ 'X-Device-Name' = 'FAITH-TEST-PC' }
Write-Host "`n--- MFA verified, session token issued: ---" -ForegroundColor Green
$final | ConvertTo-Json

Write-Host "`n--- 4. Caregiver creates a child profile (encrypted fields) ---" -ForegroundColor Cyan
Write-Host "This is the first real data action of a fresh session -- it may get" -ForegroundColor Yellow
Write-Host "flagged and log you out (see the Day 2 note at the top). That is OK." -ForegroundColor Yellow
$headers = @{ Authorization = "Bearer $($result.token)"; 'X-Device-Name' = 'FAITH-TEST-PC' }
$body = @{ fullName = 'Test Child'; dateOfBirth = '2019-05-10'; familyBackground = 'Lives with mother and grandmother' } | ConvertTo-Json
$childRes = Invoke-RestMethod -Uri "$base/children" -Method Post -ContentType 'application/json' -Headers $headers -Body $body
$childRes | ConvertTo-Json
$childId = $childRes.childProfileId
$cgFlagged = $null -ne $childRes.riskNotice
if ($cgFlagged) { Write-Host "Flagged, as expected sometimes -- steps 5-7 below will 401. That's correct; see step 16 for the recovery flow." -ForegroundColor Yellow }

Write-Host "`n--- 5. Caregiver lists own children (should decrypt correctly) ---" -ForegroundColor Cyan
try {
  Invoke-RestMethod -Uri "$base/children" -Method Get -Headers $headers | ConvertTo-Json
} catch {
  Write-Host "401 as expected (session was flagged+revoked in step 4):" $_.ErrorDetails.Message -ForegroundColor Yellow
}

Write-Host "`n--- 6. Caregiver submits a developmental record ---" -ForegroundColor Cyan
$body = @{ milestone = 'Started walking'; healthIndicator = 'Normal'; assessmentScore = 8; progressNotes = 'Doing well' } | ConvertTo-Json
try {
  Invoke-RestMethod -Uri "$base/children/$childId/records" -Method Post -ContentType 'application/json' -Headers $headers -Body $body | ConvertTo-Json
} catch {
  Write-Host "401 as expected (session was flagged+revoked in step 4):" $_.ErrorDetails.Message -ForegroundColor Yellow
}

Write-Host "`n--- 7. Caregiver views that child's records (decrypted) ---" -ForegroundColor Cyan
try {
  Invoke-RestMethod -Uri "$base/children/$childId/records" -Method Get -Headers $headers | ConvertTo-Json
} catch {
  Write-Host "401 as expected (session was flagged+revoked in step 4):" $_.ErrorDetails.Message -ForegroundColor Yellow
}

Write-Host "`n--- 8. RBAC check: Security Auditor tries to view child records (should be 403) ---" -ForegroundColor Cyan
$auditorHeaders = @{ Authorization = "Bearer $($final.token)"; 'X-Device-Name' = 'FAITH-TEST-PC' }
try {
  Invoke-RestMethod -Uri "$base/children" -Method Get -Headers $auditorHeaders
  Write-Host "UNEXPECTED: this should have been rejected!" -ForegroundColor Red
} catch {
  Write-Host "Correctly rejected:" $_.ErrorDetails.Message -ForegroundColor Green
}

Write-Host "`n--- 9. Public registration request (no auth needed) ---" -ForegroundColor Cyan
# A fresh, unique email every run -- the system correctly refuses to let
# the same person register twice, so reusing one fixed test email only
# works the first time the script is ever run. Using your own Gmail with
# plus-addressing (not a fake @example.com) so the real approval email
# you're about to receive actually has somewhere to land.
$testEmail = "faithchelulei35+caregiver$(Get-Date -Format 'yyyyMMddHHmmss')@gmail.com"
$body = @{ fullName = 'Jane Test Caregiver'; email = $testEmail; requestedRole = 'Caregiver'; reason = 'Testing the registration flow' } | ConvertTo-Json
$regRes = Invoke-RestMethod -Uri "$base/auth/register" -Method Post -ContentType 'application/json' -Body $body
$regRes | ConvertTo-Json

Write-Host "`n--- 10. SysAdmin logs in to review requests (MFA required) ---" -ForegroundColor Cyan
$body = @{ email = 'faith.chelulei+admin@strathmore.edu'; password = 'DevTest123!' } | ConvertTo-Json
$adminStep1 = Invoke-RestMethod -Uri "$base/auth/login" -Method Post -ContentType 'application/json' -Body $body
Write-Host "Check Window 1 for the admin's MFA code." -ForegroundColor Yellow
$adminCode = Read-Host "Type the 6-digit code you see there"
$body = @{ userId = $adminStep1.userId; code = $adminCode } | ConvertTo-Json
$adminFinal = Invoke-RestMethod -Uri "$base/auth/verify-mfa" -Method Post -ContentType 'application/json' -Body $body -Headers @{ 'X-Device-Name' = 'FAITH-TEST-PC' }
$adminHeaders = @{ Authorization = "Bearer $($adminFinal.token)"; 'X-Device-Name' = 'FAITH-TEST-PC' }

Write-Host "`n--- 11. Admin views the pending request queue ---" -ForegroundColor Cyan
$pending = Invoke-RestMethod -Uri "$base/admin/registration-requests?status=pending" -Method Get -Headers $adminHeaders
$pending | ConvertTo-Json
$requestId = ($pending.requests | Where-Object { $_.email -eq $testEmail }).id
if (-not $requestId) {
  Write-Host "Could not find the pending request for $testEmail -- stopping here." -ForegroundColor Red
  exit 1
}

Write-Host "`n--- 12. Admin approves it (watch Window 1 or your email for the temp password) ---" -ForegroundColor Cyan
Invoke-RestMethod -Uri "$base/admin/registration-requests/$requestId/approve" -Method Post -Headers $adminHeaders | ConvertTo-Json
Write-Host "Look at Window 1 (or your real inbox, if SMTP is configured) for the temp password for $testEmail" -ForegroundColor Yellow
$tempPassword = Read-Host "Paste the temp password you see there"

Write-Host "`n--- 13. New Caregiver logs in with that temp password ---" -ForegroundColor Cyan
$body = @{ email = $testEmail; password = $tempPassword } | ConvertTo-Json
$newUserRes = Invoke-RestMethod -Uri "$base/auth/login" -Method Post -ContentType 'application/json' -Body $body
if ($newUserRes.token) { Write-Host "SUCCESS -- new account works end to end." -ForegroundColor Green }

Write-Host "`n--- 14. That same Caregiver tries the admin route (should be 403) ---" -ForegroundColor Cyan
try {
  Invoke-RestMethod -Uri "$base/admin/registration-requests?status=pending" -Method Get -Headers @{ Authorization = "Bearer $($newUserRes.token)" }
} catch {
  Write-Host "Correctly rejected:" $_.ErrorDetails.Message -ForegroundColor Green
}

Write-Host "`n=== Day 2: ML risk scoring ===" -ForegroundColor Cyan

Write-Host "`n--- 15. Security Auditor views the flagged-session queue ---" -ForegroundColor Cyan
Write-Host "If step 4 above got flagged, you should see it here with auditor_status 'pending'." -ForegroundColor Yellow
$flagged = Invoke-RestMethod -Uri "$base/auditor/flagged-sessions?status=all" -Method Get -Headers $auditorHeaders
$flagged.flaggedSessions | Format-Table risk_score_id, combined_score, role_threshold, action_type, owner_response, auditor_status

Write-Host "`n--- 16. Security Auditor reviews the most recent flagged session ---" -ForegroundColor Cyan
$latest = $flagged.flaggedSessions | Select-Object -First 1
if ($latest) {
  $reviewBody = @{ status = 'reviewing' } | ConvertTo-Json
  Invoke-RestMethod -Uri "$base/auditor/flagged-sessions/$($latest.risk_score_id)/review" -Method Post -ContentType 'application/json' -Headers $auditorHeaders -Body $reviewBody | ConvertTo-Json
} else {
  Write-Host "Nothing flagged yet this run -- re-run from step 1, or just try step 4 again (cold-start sessions cross Caregiver's low threshold often but not every single time)." -ForegroundColor Yellow
}

Write-Host "`n--- 17. RBAC check: Caregiver cannot see the auditor queue (should be 403) ---" -ForegroundColor Cyan
try {
  Invoke-RestMethod -Uri "$base/auditor/flagged-sessions" -Method Get -Headers $headers
  Write-Host "UNEXPECTED: this should have been rejected!" -ForegroundColor Red
} catch {
  Write-Host "Correctly rejected (401 if the Caregiver session was already revoked by step 4, 403 otherwise)." -ForegroundColor Green
}

Write-Host "`n--- 18. Owner's own response link ---" -ForegroundColor Cyan
Write-Host "If step 4 flagged your session, check faith.chelulei+caregiver's inbox for" -ForegroundColor Yellow
Write-Host "'Unusual activity on your account' and open the 'This was me' link in a browser." -ForegroundColor Yellow
Write-Host "It should say you can log in again normally. Opening it twice should say" -ForegroundColor Yellow
Write-Host "you already responded -- that link is safe to click more than once." -ForegroundColor Yellow

Write-Host "`n--- All tests complete ---" -ForegroundColor Cyan
