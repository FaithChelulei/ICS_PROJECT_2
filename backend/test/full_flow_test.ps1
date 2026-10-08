# Full lifecycle demo: all 3 roles, one pass.
# Caregiver gets flagged on a cold first action -> Security Auditor sees
# it in their queue -> Caregiver clicks "This was NOT me" -> account locks
# -> SysAdmin sees it in the locked-accounts list and unlocks it -> new
# temp password works.
#
# Real emails WILL be sent to your inbox this run: 3 MFA codes (one per
# role), 1 risk alert ("This was NOT me" link), 1 account-unlocked notice
# with a new temp password. Have your inbox open.
#
# Run from backend/: .\test\full_flow_test.ps1

$base = 'http://localhost:4000'

Write-Host "`n=== Step 0: cleaning test data for a truly cold run ===" -ForegroundColor Cyan
node db\cleanup_test_data.js

Write-Host "`n=== Step 1: Caregiver logs in (MFA required) ===" -ForegroundColor Cyan
$body = @{ email = 'faith.chelulei+caregiver@strathmore.edu'; password = 'DevTest123!' } | ConvertTo-Json
$cg1 = Invoke-RestMethod -Uri "$base/auth/login" -Method Post -ContentType 'application/json' -Body $body
Write-Host "Check faith.chelulei+caregiver's inbox for the MFA code." -ForegroundColor Yellow
$cgCode = Read-Host "6-digit code"
$body = @{ userId = $cg1.userId; code = $cgCode } | ConvertTo-Json
$cg = Invoke-RestMethod -Uri "$base/auth/verify-mfa" -Method Post -ContentType 'application/json' -Body $body -Headers @{ 'X-Device-Name' = 'FAITH-TEST-PC' }
$cgHeaders = @{ Authorization = "Bearer $($cg.token)"; 'X-Device-Name' = 'FAITH-TEST-PC' }
Write-Host "Logged in. This login was NOT scored (see Day 2 notes) -- nothing flagged yet." -ForegroundColor Green

Write-Host "`n=== Step 2: Caregiver creates a child profile (first-ever scored action) ===" -ForegroundColor Cyan
$body = @{ fullName = 'Test Child'; dateOfBirth = '2019-05-10'; familyBackground = 'Lives with mother and grandmother' } | ConvertTo-Json
$childRes = Invoke-RestMethod -Uri "$base/children" -Method Post -ContentType 'application/json' -Headers $cgHeaders -Body $body
$childRes | ConvertTo-Json
if ($childRes.riskNotice) {
  Write-Host "FLAGGED, as expected for a cold first action (borderline score vs Caregiver's 0.11 threshold)." -ForegroundColor Yellow
  Write-Host "The session was revoked right then -- any further request with this token will 401 from here on." -ForegroundColor Yellow
} else {
  Write-Host "Not flagged this time (it's borderline, so it won't be 100% of runs). Re-run the script to see the flagged path." -ForegroundColor Yellow
}

Write-Host "`n=== Step 3: Caregiver tries to list children with that same session (expect 401 if flagged) ===" -ForegroundColor Cyan
try {
  Invoke-RestMethod -Uri "$base/children" -Method Get -Headers $cgHeaders | ConvertTo-Json
} catch {
  Write-Host "401 as expected -- the session was revoked the moment it got flagged:" $_.ErrorDetails.Message -ForegroundColor Green
}

Write-Host "`n=== Step 4: Security Auditor logs in (MFA required) ===" -ForegroundColor Cyan
$body = @{ email = 'faith.chelulei+auditor@strathmore.edu'; password = 'DevTest123!' } | ConvertTo-Json
$au1 = Invoke-RestMethod -Uri "$base/auth/login" -Method Post -ContentType 'application/json' -Body $body
Write-Host "Check faith.chelulei+auditor's inbox for the MFA code." -ForegroundColor Yellow
$auCode = Read-Host "6-digit code"
$body = @{ userId = $au1.userId; code = $auCode } | ConvertTo-Json
$au = Invoke-RestMethod -Uri "$base/auth/verify-mfa" -Method Post -ContentType 'application/json' -Body $body -Headers @{ 'X-Device-Name' = 'FAITH-TEST-PC' }
$auHeaders = @{ Authorization = "Bearer $($au.token)"; 'X-Device-Name' = 'FAITH-TEST-PC' }

Write-Host "`n=== Step 5: Security Auditor views the flagged-session queue ===" -ForegroundColor Cyan
$flagged = Invoke-RestMethod -Uri "$base/auditor/flagged-sessions?status=all" -Method Get -Headers $auHeaders
$flagged.flaggedSessions | Format-Table risk_score_id, email, role, combined_score, role_threshold, action_type, owner_response, auditor_status
$latest = $flagged.flaggedSessions | Select-Object -First 1
if (-not $latest) {
  Write-Host "Nothing flagged this run -- step 2 didn't cross threshold this time. Re-run the whole script to try again." -ForegroundColor Yellow
  exit 0
}
Write-Host "That's the Caregiver action from step 2, visible to the Auditor independently of whatever the owner does next." -ForegroundColor Green

Write-Host "`n=== Step 6: open the risk-alert email and click 'This was NOT me' ===" -ForegroundColor Cyan
Write-Host "Check faith.chelulei+caregiver's inbox for 'Unusual activity on your account'." -ForegroundColor Yellow
Write-Host "Copy the 'This was NOT me' link and paste it below (the whole URL)." -ForegroundColor Yellow
$denyUrl = Read-Host "Deny URL"
Invoke-RestMethod -Uri $denyUrl -Method Get

Write-Host "`n=== Step 7: Caregiver tries to log in again (expect 403, account locked) ===" -ForegroundColor Cyan
$body = @{ email = 'faith.chelulei+caregiver@strathmore.edu'; password = 'DevTest123!' } | ConvertTo-Json
try {
  Invoke-RestMethod -Uri "$base/auth/login" -Method Post -ContentType 'application/json' -Body $body
  Write-Host "UNEXPECTED: login should have been blocked!" -ForegroundColor Red
} catch {
  Write-Host "Correctly blocked:" $_.ErrorDetails.Message -ForegroundColor Green
}

Write-Host "`n=== Step 8: SysAdmin logs in (MFA required) ===" -ForegroundColor Cyan
$body = @{ email = 'faith.chelulei+admin@strathmore.edu'; password = 'DevTest123!' } | ConvertTo-Json
$ad1 = Invoke-RestMethod -Uri "$base/auth/login" -Method Post -ContentType 'application/json' -Body $body
Write-Host "Check faith.chelulei+admin's inbox for the MFA code." -ForegroundColor Yellow
$adCode = Read-Host "6-digit code"
$body = @{ userId = $ad1.userId; code = $adCode } | ConvertTo-Json
$ad = Invoke-RestMethod -Uri "$base/auth/verify-mfa" -Method Post -ContentType 'application/json' -Body $body -Headers @{ 'X-Device-Name' = 'FAITH-TEST-PC' }
$adHeaders = @{ Authorization = "Bearer $($ad.token)"; 'X-Device-Name' = 'FAITH-TEST-PC' }

Write-Host "`n=== Step 9: SysAdmin lists locked accounts ===" -ForegroundColor Cyan
$locked = Invoke-RestMethod -Uri "$base/admin/users/locked" -Method Get -Headers $adHeaders
$locked.lockedUsers | Format-Table id, email, role, locked_reason
$target = $locked.lockedUsers | Where-Object { $_.email -eq 'faith.chelulei+caregiver@strathmore.edu' }
if (-not $target) {
  Write-Host "Caregiver account isn't showing as locked -- step 6's deny link may not have gone through. Stopping here." -ForegroundColor Red
  exit 1
}

Write-Host "`n=== Step 10: SysAdmin unlocks the Caregiver account ===" -ForegroundColor Cyan
Invoke-RestMethod -Uri "$base/admin/users/$($target.id)/unlock" -Method Post -Headers $adHeaders | ConvertTo-Json
Write-Host "Check faith.chelulei+caregiver's inbox for 'Your account has been unlocked' -- it has a new temp password." -ForegroundColor Yellow
$newPassword = Read-Host "New temp password"

Write-Host "`n=== Step 11: Caregiver logs in with the new password (MFA required) ===" -ForegroundColor Cyan
$body = @{ email = 'faith.chelulei+caregiver@strathmore.edu'; password = $newPassword } | ConvertTo-Json
$cg2_1 = Invoke-RestMethod -Uri "$base/auth/login" -Method Post -ContentType 'application/json' -Body $body
Write-Host "Check faith.chelulei+caregiver's inbox again for a fresh MFA code." -ForegroundColor Yellow
$cgCode2 = Read-Host "6-digit code"
$body = @{ userId = $cg2_1.userId; code = $cgCode2 } | ConvertTo-Json
$cg2 = Invoke-RestMethod -Uri "$base/auth/verify-mfa" -Method Post -ContentType 'application/json' -Body $body -Headers @{ 'X-Device-Name' = 'FAITH-TEST-PC' }
if ($cg2.token) { Write-Host "SUCCESS -- full loop complete: flagged -> escalated -> locked -> unlocked -> working again." -ForegroundColor Green }

Write-Host "`n=== All steps complete ===" -ForegroundColor Cyan
Write-Host "Note: the Caregiver test account's password is now the new temp password above (not DevTest123! anymore) until you change it." -ForegroundColor Yellow
