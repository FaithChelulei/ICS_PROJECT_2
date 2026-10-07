# Manual smoke test for the auth flow. Run this in a SECOND terminal
# window while the server (npm run dev) is running in your first one.
#
# Usage:  .\test\manual_test.ps1
#
# Watch the server's own terminal window while this runs — that's where
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
