# Schedules ONE real night-time run of the anomaly-injection test
# (npm run test:anomaly), so the night scenarios are tested live at an
# actual after-hours time instead of with a simulated clock.
#
#   .\scripts\schedule-night-test.ps1                    # next 02:00
#   .\scripts\schedule-night-test.ps1 -At "2026-11-05 02:00"
#   .\scripts\schedule-night-test.ps1 -Remove            # cancel it
#
# Output goes to backend\test\results\night_run.log (plus the usual
# anomaly_night_*.json). For the run to work at that time:
#   - the laptop is on, plugged in and NOT asleep (Settings > System >
#     Power: set "sleep" to Never for the night), and you are signed in;
#   - PostgreSQL, the backend (npm start or npm run dev) and the ML
#     service are running.
param(
    [string]$At,
    [switch]$Remove
)

$taskName = 'ChildGuard night anomaly test'
$backend = Split-Path -Parent $PSScriptRoot

if ($Remove) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Removed scheduled task '$taskName' (if it existed)."
    return
}

if ($At) {
    $when = [datetime]::Parse($At)
} else {
    $when = (Get-Date).Date.AddHours(2)
    if ($when -le (Get-Date)) { $when = $when.AddDays(1) }
}

$command = "cd /d `"$backend`" && npm run test:anomaly > test\results\night_run.log 2>&1"
$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c $command"
$trigger = New-ScheduledTaskTrigger -Once -At $when
$settings = New-ScheduledTaskSettingsSet -WakeToRun -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings `
    -Description 'One real after-hours run of the ChildGuard anomaly-injection test (night scenarios, live).' -Force | Out-Null

Write-Host "Scheduled '$taskName' for $($when.ToString('dddd d MMMM yyyy, HH:mm'))."
Write-Host "Results: $backend\test\results\night_run.log"
Write-Host 'Keep the laptop on, plugged in and awake, with the database, backend and ML service running.'
