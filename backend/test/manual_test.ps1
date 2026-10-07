# Manual smoke test for the auth flow. Run this in a SECOND terminal
# window while the server (npm run dev) is running in your first one.
#
# Usage:  .\test\manual_test.ps1
#
# Watch the server's own terminal window while this runs -- that's where
# the MFA code gets printed (no real email is sent yet).

$base = 'http://localhost:4000'

Write-Host "`n--- 1. Caregiver login (no MFA) ---" -ForegroundColor Cyan
$body = @{ email = 'caregiver.test@example.com'; password = 'DevTest123!' } | ConvertTo-Json
$result = Invoke-RestMethod -Uri "$base/auth/login" -Method Post -ContentType 'application/json' -Body $body
$result | ConvertTo-Json

Write-Host "`n--- 2. Wrong password (should be rejected) ---" -ForegroundColor Cyan
$body = @{ email = 'caregiver.test@example.com'; password = 'wrong' } | ConvertTo-Json
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
$final = Invoke-RestMethod -Uri "$base/auth/verify-mfa" -Method Post -ContentType 'application/json' -Body $body
Write-Host "`n--- MFA verified, session token issued: ---" -ForegroundColor Green
$final | ConvertTo-Json

Write-Host "`n--- 4. Caregiver creates a child profile (encrypted fields) ---" -ForegroundColor Cyan
$headers = @{ Authorization = "Bearer $($result.token)" }
$body = @{ fullName = 'Test Child'; dateOfBirth = '2019-05-10'; familyBackground = 'Lives with mother and grandmother' } | ConvertTo-Json
$childRes = Invoke-RestMethod -Uri "$base/children" -Method Post -ContentType 'application/json' -Headers $headers -Body $body
$childRes | ConvertTo-Json
$childId = $childRes.childProfileId

Write-Host "`n--- 5. Caregiver lists own children (should decrypt correctly) ---" -ForegroundColor Cyan
Invoke-RestMethod -Uri "$base/children" -Method Get -Headers $headers | ConvertTo-Json

Write-Host "`n--- 6. Caregiver submits a developmental record ---" -ForegroundColor Cyan
$body = @{ milestone = 'Started walking'; healthIndicator = 'Normal'; assessmentScore = 8; progressNotes = 'Doing well' } | ConvertTo-Json
Invoke-RestMethod -Uri "$base/children/$childId/records" -Method Post -ContentType 'application/json' -Headers $headers -Body $body | ConvertTo-Json

Write-Host "`n--- 7. Caregiver views that child's records (decrypted) ---" -ForegroundColor Cyan
Invoke-RestMethod -Uri "$base/children/$childId/records" -Method Get -Headers $headers | ConvertTo-Json

Write-Host "`n--- 8. RBAC check: Security Auditor tries to view child records (should be 403) ---" -ForegroundColor Cyan
$auditorHeaders = @{ Authorization = "Bearer $($final.token)" }
try {
  Invoke-RestMethod -Uri "$base/children" -Method Get -Headers $auditorHeaders
  Write-Host "UNEXPECTED: this should have been rejected!" -ForegroundColor Red
} catch {
  Write-Host "Correctly rejected:" $_.ErrorDetails.Message -ForegroundColor Green
}

Write-Host "`n--- 9. Public registration request (no auth needed) ---" -ForegroundColor Cyan
$body = @{ fullName = 'Jane Test Caregiver'; email = 'jane.test.caregiver@example.com'; requestedRole = 'Caregiver'; reason = 'Testing the registration flow' } | ConvertTo-Json
$regRes = Invoke-RestMethod -Uri "$base/auth/register" -Method Post -ContentType 'application/json' -Body $body
$regRes | ConvertTo-Json

Write-Host "`n--- 10. SysAdmin logs in to review requests (MFA required) ---" -ForegroundColor Cyan
$body = @{ email = 'faith.chelulei+admin@strathmore.edu'; password = 'DevTest123!' } | ConvertTo-Json
$adminStep1 = Invoke-RestMethod -Uri "$base/auth/login" -Method Post -ContentType 'application/json' -Body $body
Write-Host "Check Window 1 for the admin's MFA code." -ForegroundColor Yellow
$adminCode = Read-Host "Type the 6-digit code you see there"
$body = @{ userId = $adminStep1.userId; code = $adminCode } | ConvertTo-Json
$adminFinal = Invoke-RestMethod -Uri "$base/auth/verify-mfa" -Method Post -ContentType 'application/json' -Body $body
$adminHeaders = @{ Authorization = "Bearer $($adminFinal.token)" }

Write-Host "`n--- 11. Admin views the pending request queue ---" -ForegroundColor Cyan
$pending = Invoke-RestMethod -Uri "$base/admin/registration-requests?status=pending" -Method Get -Headers $adminHeaders
$pending | ConvertTo-Json
$requestId = ($pending.requests | Where-Object { $_.email -eq 'jane.test.caregiver@example.com' }).id

Write-Host "`n--- 12. Admin approves it (watch Window 1 for the temp password) ---" -ForegroundColor Cyan
Invoke-RestMethod -Uri "$base/admin/registration-requests/$requestId/approve" -Method Post -Headers $adminHeaders | ConvertTo-Json
Write-Host "Look at Window 1 for: '[DEV - no SMTP configured] Account approved for jane.test.caregiver@example.com ... Temp password: ...'" -ForegroundColor Yellow
$tempPassword = Read-Host "Paste the temp password you see there"

Write-Host "`n--- 13. New Caregiver logs in with that temp password ---" -ForegroundColor Cyan
$body = @{ email = 'jane.test.caregiver@example.com'; password = $tempPassword } | ConvertTo-Json
$newUserRes = Invoke-RestMethod -Uri "$base/auth/login" -Method Post -ContentType 'application/json' -Body $body
if ($newUserRes.token) { Write-Host "SUCCESS -- new account works end to end." -ForegroundColor Green }

Write-Host "`n--- 14. That same Caregiver tries the admin route (should be 403) ---" -ForegroundColor Cyan
try {
  Invoke-RestMethod -Uri "$base/admin/registration-requests?status=pending" -Method Get -Headers @{ Authorization = "Bearer $($newUserRes.token)" }
} catch {
  Write-Host "Correctly rejected:" $_.ErrorDetails.Message -ForegroundColor Green
}

Write-Host "`n--- All tests complete ---" -ForegroundColor Cyan
