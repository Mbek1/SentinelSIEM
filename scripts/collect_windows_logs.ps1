
# SentinelSIEM - Windows Security Log Collector

$OutputFolder = Join-Path $PSScriptRoot "..\data"
$OutputFile = Join-Path $OutputFolder "windows_security_logs.csv"

New-Item -ItemType Directory -Force -Path $OutputFolder | Out-Null

$EventIds = @(4624, 4625, 4672, 4720, 4728, 4732, 4740)
$StartTime = (Get-Date).AddHours(-24)

Write-Host "Collecting Windows Security Events..." -ForegroundColor Cyan

try {
    $Events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = $EventIds
        StartTime = $StartTime
    } -MaxEvents 5000 -ErrorAction Stop

    $Results = foreach ($Event in $Events) {
        [xml]$Xml = $Event.ToXml()

        $Data = @{}
        foreach ($Item in $Xml.Event.EventData.Data) {
            if ($Item.Name) {
                $Data[$Item.Name] = [string]$Item.'#text'
            }
        }

        $EventType = switch ($Event.Id) {
            4624 { "login_success" }
            4625 { "login_failed" }
            4672 { "privilege_escalation" }
            4720 { "account_created" }
            4728 { "account_group_change" }
            4732 { "account_group_change" }
            4740 { "account_locked" }
            default { "unknown" }
        }

        $Username = $Data["TargetUserName"]
        if ([string]::IsNullOrWhiteSpace($Username)) {
            $Username = $Data["SubjectUserName"]
        }

        $IP = $Data["IpAddress"]
        if ([string]::IsNullOrWhiteSpace($IP)) {
            $IP = "Unknown"
        }

        $Message = "Windows Event ID $($Event.Id)"
        if ($Data["PrivilegeList"]) {
            $Message += " - Privileges: $($Data["PrivilegeList"])"
        }
        if ($Data["TargetUserName"]) {
            $Message += " - Target: $($Data["TargetUserName"])"
        }

        [PSCustomObject]@{
            timestamp  = $Event.TimeCreated.ToUniversalTime().ToString("o")
            event_type = $EventType
            username   = $Username
            source_ip  = $IP
            message    = $Message
            event_id   = $Event.Id
        }
    }

    $Results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8

    Write-Host "Collection complete!" -ForegroundColor Green
    Write-Host "Events collected: $($Results.Count)"
    Write-Host "Saved to: $OutputFile"
}
catch {
    Write-Host "Collection failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Try running PowerShell as Administrator."
}
