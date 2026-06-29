# ========================================================================
# NETWORK TOOLKIT MASTER SUITE (UNIFIED & OPTIMIZED ARCHITECTURE)
# ========================================================================
$Host.UI.RawUI.WindowTitle = "Network Toolkit Master Menu"
$Global:OriginalTitle = $Host.UI.RawUI.WindowTitle

# --- SERVICE MAPPING DICTIONARY ---
$Global:KnownPorts = @{
    20    = "FTP-Data"
    21    = "FTP"
    22    = "SSH"
    23    = "Telnet"
    80    = "HTTP"
    110   = "POP3"
    135   = "RPC"
    139   = "NetBIOS"
    143   = "IMAP"
    443   = "HTTPS"
    445   = "SMB"
    1433  = "MSSQL"
    2000  = "Cisco-SCCP"      
    3121  = "Xilinx-HW-Server" 
    3389  = "RDP"
    4440  = "Rundeck"          
    4444  = "Metasploit"       
    5660  = " "  
    5800  = "VNC-HTTP"         
    5900  = "VNC"
    7361  = "RDP Alt"          
    8080  = "HTTP-Alt"
    8443  = "HTTPS-Alt"        
    9055  = "Oracle-WebLogic"  
    9903  = "Blackberry-Router" 
}

# --- CENTRALIZED GLOBAL LIBRARIES ---
function Get-IPRange {
    param ([string]$InputTarget)

    if ([string]::IsNullOrWhiteSpace($InputTarget)) { return $null }
    $InputTarget = $InputTarget.Trim()
    
    if ($InputTarget -notmatch '\b(?:\d{1,3}\.){1,3}\d{1,3}\b') {
        Write-Host "`n[CRITICAL ERROR]: '$InputTarget' is not a valid IPv4 format!" -ForegroundColor Red
        return $null
    }

    if ($InputTarget -match '\b0\d+\b') {
        Write-Host "`n[CRITICAL ERROR]: '$InputTarget' contains invalid leading zeros!" -ForegroundColor Red
        return $null
    }

    if ($InputTarget -match '^([\d\.]+)/(\d+)$') {
        $baseIP = $Matches[1]; $cidr = [int]$Matches[2]
        if ($cidr -lt 0 -or $cidr -gt 32) { return $null }
        
        $ipBytes = [System.Net.IPAddress]::Parse($baseIP).GetAddressBytes()
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($ipBytes) }
        $ipAsInt = [BitConverter]::ToUInt32($ipBytes, 0)
        
        $totalHosts = [System.Math]::Pow(2, (32 - $cidr))
        $mask = if ($cidr -eq 0) { 0x00000000 } else { [uint32]::MaxValue - [uint32]($totalHosts - 1) }
        $networkInt = $ipAsInt -band $mask
        
        $RangeResults = for ($i = 0; $i -lt $totalHosts; $i++) {
            $currentBytes = [BitConverter]::GetBytes($networkInt + $i)
            if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($currentBytes) }
            ([System.Net.IPAddress]$currentBytes).IPAddressToString
        }
        return $RangeResults
    } elseif ($InputTarget -match '^([\d\.]+)\.(\d+)-(\d+)$') {
        $prefix = $Matches[1]; $start = [int]$Matches[2]; $end = [int]$Matches[3]
        if ($start -gt $end -or $end -gt 255) { return $null }
        return ($start..$end | ForEach-Object { "$prefix.$_" })
    } else {
        if ([System.Net.IPAddress]::TryParse($InputTarget, [ref]$null)) { return $InputTarget }
        return $null
    }
}

function Get-ParsedPorts {
    param ([string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    $raw = Get-Content $Path | Where-Object { $_ -match '^\d+(-\d+)?$' }
    $finalPorts = foreach ($line in $raw) {
        if ($line -match '^(\d+)-(\d+)$') {
            [int]::Parse($Matches[1])..[int]::Parse($Matches[2])
        } else {
            [int]::Parse($line)
        }
    }
    return ($finalPorts | Select-Object -Unique)
}

function Assert-PortsFile {
    $PortsFile = Join-Path $PSScriptRoot "ports.txt"
    if (-not (Test-Path $PortsFile)) { 
        Write-Host "[!] ports.txt missing. Auto-generating baseline profiles..." -ForegroundColor Yellow
        "21`n22`n23`n80`n443`n445`n1433`n3389`n8080" | Out-File $PortsFile -Encoding ascii
    }
    return $PortsFile
}

# ========================================================================
# INTEGRATED ENGINE FUNCTIONS
# ========================================================================

function Invoke-PortScanner {
    param([string]$IPInput)
    $Host.UI.RawUI.WindowTitle = "Toolkit Engine // Port Scanner"
    
    $Timeout = 350   
    $MaxThreads = 64 

    $PortsFile = Assert-PortsFile
    $PortsArray = Get-ParsedPorts -Path $PortsFile
    if ($null -eq $PortsArray) {
        Write-Host "`n[CRITICAL ERROR] ports.txt contains no valid ports." -ForegroundColor Red
        return $false
    }
    $PortsStringSerialized = $PortsArray -join ','

    $IPList = [System.Collections.Generic.List[string]]::new()
    foreach ($Target in ($IPInput -split '[,\|]')) {
        if (-not [string]::IsNullOrWhiteSpace($Target)) {
            $ResolvedIPs = Get-IPRange -InputTarget $Target.Trim()
            if ($null -eq $ResolvedIPs) { return $false } 
            $IPList.AddRange([string[]]$ResolvedIPs)
        }
    }

    $CleanIPList = $IPList | Select-Object -Unique
    if ($CleanIPList.Count -eq 0) {
        Write-Host "`n[CRITICAL ERROR] No valid scan targets generated." -ForegroundColor Red
        return $false
    }

    if ($CleanIPList.Count -gt 512) {
        Write-Host "`n[CRITICAL SCOPE ERROR] Target range ($($CleanIPList.Count) IPs) exceeds permitted boundaries!" -ForegroundColor Red
        return $false
    }

    Write-Host "[*] Analyzing network path latency..." -ForegroundColor DarkGray
    $PathPing = New-Object System.Net.NetworkInformation.Ping
    $DetectedLatency = 0
    try {
        $PingTest = $PathPing.Send($CleanIPList[0], 600)
        if ($PingTest.Status -eq "Success") { $DetectedLatency = $PingTest.RoundtripTime }
    } catch {} finally { $PathPing.Dispose() }

    $MinPacing = 15; $MaxPacing = 30
    if ($DetectedLatency -gt 150) {
        Write-Host "[!] High-Latency Path Detected ($($DetectedLatency)ms). Enabling Anti-Throttling Mode." -ForegroundColor Yellow
        $MinPacing = 45; $MaxPacing = 75
    } else {
        Write-Host "[+] Low-Latency Path Confirmed ($($DetectedLatency)ms). Enabling High-Speed Mode." -ForegroundColor Green
    }

    Write-Host "Targeting $($CleanIPList.Count) total IPs across $($PortsArray.Count) unique ports." -ForegroundColor Cyan
    Write-Host "Scanning... (Showing Active & Open hosts only; Press Ctrl+C to stop)`n" -ForegroundColor Yellow

    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $InitialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $LocalRunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $MaxThreads, $InitialSessionState, $Host)
    
    try {
        $LocalRunspacePool.Open()

        $ScriptBlock = {
            param($IP, $SerializedPorts, $Timeout)
            $IpResult = [PSCustomObject]@{
                IPAddress  = $IP
                HostStatus = "UNREACHABLE"
                OpenPorts  = [System.Collections.Generic.List[int]]::new()
                Timestamp  = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }
            $LocalPorts = [int[]]($SerializedPorts -split ',')

            $ping = New-Object System.Net.NetworkInformation.Ping
            try {
                $pingTask = $ping.SendPingAsync($IP, 550)
                if ($pingTask -and $pingTask.Wait(550)) {
                    if ($pingTask.Result.Status -eq "Success") { $IpResult.HostStatus = "ONLINE" }
                }
            } catch {} finally { $ping.Dispose() }

            $ParsedIP = [System.Net.IPAddress]::Parse($IP)
            foreach ($Port in $LocalPorts) {
                $socket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
                $socket.NoDelay = $true 
                $socket.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
                try {
                    $endpoint = New-Object System.Net.IPEndPoint($ParsedIP, [int]$Port)
                    $ar = $socket.BeginConnect($endpoint, $null, $null)
                    if ($ar.AsyncWaitHandle.WaitOne($Timeout, $false)) {
                        $socket.EndConnect($ar)
                        $null = $IpResult.OpenPorts.Add($Port)
                        if ($IpResult.HostStatus -eq "UNREACHABLE") { $IpResult.HostStatus = "PORT_ONLY" }
                    }
                    $ar.AsyncWaitHandle.Dispose()
                } catch {} finally {
                    try { $socket.Shutdown([System.Net.Sockets.SocketShutdown]::Both) } catch {}
                    $socket.Close(); $socket.Dispose()
                }
            }
            return $IpResult
        }

        $Jobs = New-Object System.Collections.Generic.List[object]
        foreach ($IP in $CleanIPList) {
            $PowerShell = [PowerShell]::Create().AddScript($ScriptBlock).AddArgument($IP).AddArgument($PortsStringSerialized).AddArgument($Timeout)
            $PowerShell.RunspacePool = $LocalRunspacePool
            $Jobs.Add([PSCustomObject]@{ Pipe = $PowerShell; Handle = $PowerShell.BeginInvoke() })
            Start-Sleep -Milliseconds (Get-Random -Minimum $MinPacing -Maximum $MaxPacing)
        }

        $ScanResults = [System.Collections.Generic.List[object]]::new()
        $TotalTargets = $CleanIPList.Count; $CompletedTargets = 0; $AliveHostsCount = 0

        while ($Jobs.Count -gt 0) {
            $FinishedJobs = $Jobs | Where-Object { $_.Handle.IsCompleted }
            foreach ($Job in $FinishedJobs) {
                $item = $Job.Pipe.EndInvoke($Job.Handle)
                $CompletedTargets++
                if ($item) {
                    if ($item.HostStatus -eq "ONLINE" -or $item.HostStatus -eq "PORT_ONLY") {
                        $AliveHostsCount++
                        if ($item.OpenPorts.Count -gt 0) {
                            $FormattedPortsArray = foreach ($p in $item.OpenPorts) {
                                if ($Global:KnownPorts.ContainsKey($p)) { "$p/$($Global:KnownPorts[$p])" } else { "$p" }
                            }
                            $PortString = $FormattedPortsArray -join ", "
                            
                            $Tag = if ($item.HostStatus -eq "PORT_ONLY") { "[+ (FIREWALLED)]" } else { "[+] OPEN" }
                            Write-Host "$Tag $($item.IPAddress): $PortString" -ForegroundColor Green
                            foreach ($OpenPort in $item.OpenPorts) {
                                $RowObj = [PSCustomObject]@{
                                    IPAddress  = $item.IPAddress
                                    HostStatus = $item.HostStatus
                                    Port       = $OpenPort
                                    PortStatus = "OPEN"
                                    Timestamp  = $item.Timestamp
                                }
                                $null = $ScanResults.Add($RowObj)
                            }
                        } else {
                            Write-Host "[*] ALIVE (ICMP): $($item.IPAddress)" -ForegroundColor Gray
                            $RowObj = [PSCustomObject]@{
                                IPAddress  = $item.IPAddress
                                HostStatus = "ONLINE"
                                Port       = "None"
                                PortStatus = "CLOSED"
                                Timestamp  = $item.Timestamp
                            }
                            $null = $ScanResults.Add($RowObj)
                        }
                    }
                }
                $Job.Pipe.Dispose(); $null = $Jobs.Remove($Job)
            }
            $PercentComplete = [Math]::Round(($CompletedTargets / $TotalTargets) * 100)
            $Host.UI.RawUI.WindowTitle = "Scan Status: $PercentComplete% complete"
            Start-Sleep -Milliseconds 10
        }
    }
    finally {
        if ($null -ne $LocalRunspacePool) {
            $LocalRunspacePool.Close()
            $LocalRunspacePool.Dispose()
        }
    }

    $Stopwatch.Stop(); $ElapsedTime = "{0:mm\:ss}" -f $Stopwatch.Elapsed
    $DeadHosts = $TotalTargets - $AliveHostsCount

    Write-Host "`n+----------------------------------------------+" -ForegroundColor Cyan
    Write-Host "|                SCAN SUMMARY                  |" -ForegroundColor Cyan
    Write-Host "+----------------------------------------------+" -ForegroundColor Cyan
    Write-Host "|  Total IPs Targeted  : $TotalTargets"            -ForegroundColor White
    Write-Host "|  Hosts Responsive    : $AliveHostsCount"         -ForegroundColor Green
    Write-Host "|  Hosts Unreachable   : $DeadHosts"                -ForegroundColor DarkGray
    Write-Host "|  Scan Duration       : $ElapsedTime"              -ForegroundColor White
    Write-Host "+----------------------------------------------+" -ForegroundColor Cyan

    if ($ScanResults.Count -gt 0) {
        $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $TargetFolder = Join-Path $PSScriptRoot "report"
        if (-not (Test-Path $TargetFolder)) { 
            New-Item -Path $TargetFolder -ItemType Directory -Force | Out-Null
        }
        $OutputFile = Join-Path $TargetFolder "scan_report_$Timestamp.csv"
        $ScanResults | Export-Csv -Path $OutputFile -NoTypeInformation
        Write-Host "[!] Spreadsheet Saved: $OutputFile`n" -ForegroundColor Yellow
    }
    [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers()
    return $true
}

function Invoke-PortScannerDte {
    param([string]$IPInput)
    $Host.UI.RawUI.WindowTitle = "Toolkit Engine // DTE Fast Scan"
    
    $Timeout = 300   
    $MaxThreads = 64 

    $PortsFile = Assert-PortsFile
    $PortsArray = Get-ParsedPorts -Path $PortsFile
    if ($null -eq $PortsArray) {
        Write-Host "`n[CRITICAL ERROR] ports.txt contains no valid ports." -ForegroundColor Red
        return $false
    }
    $PortsStringSerialized = $PortsArray -join ','

    $IPList = [System.Collections.Generic.List[string]]::new()
    foreach ($Target in ($IPInput -split '[,\|]')) {
        if (-not [string]::IsNullOrWhiteSpace($Target)) {
            $ResolvedIPs = Get-IPRange -InputTarget $Target.Trim()
            if ($null -eq $ResolvedIPs) { return $false }
            $IPList.AddRange([string[]]$ResolvedIPs)
        }
    }

    $CleanIPList = $IPList | Select-Object -Unique
    if ($CleanIPList.Count -eq 0) {
        Write-Host "`n[CRITICAL ERROR] No valid scan targets generated." -ForegroundColor Red
        return $false
    }

    if ($CleanIPList.Count -gt 512) {
        Write-Host "`n[CRITICAL SCOPE ERROR] Target range ($($CleanIPList.Count) IPs) exceeds permitted boundaries!" -ForegroundColor Red
        return $false
    }

    Write-Host "Targeting $($CleanIPList.Count) total IPs [Mode: DTE Lightning Discovery]" -ForegroundColor Cyan
    Write-Host "Scanning... (Press Ctrl+C to stop)`n" -ForegroundColor Yellow

    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $InitialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $LocalRunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $MaxThreads, $InitialSessionState, $Host)
    
    try {
        $LocalRunspacePool.Open()

        $ScriptBlock = {
            param($IP, $SerializedPorts, $Timeout)
            $IpResult = [PSCustomObject]@{
                IPAddress  = $IP
                HostStatus = "UNREACHABLE"
                OpenPorts  = [System.Collections.Generic.List[int]]::new()
                Timestamp  = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }
            $LocalPorts = [int[]]($SerializedPorts -split ',')

            $ping = New-Object System.Net.NetworkInformation.Ping
            $PingSuccess = $false
            try {
                $pingTask = $ping.SendPingAsync($IP, 450)
                if ($pingTask -and $pingTask.Wait(450)) {
                    if ($pingTask.Result.Status -eq "Success") { 
                        $PingSuccess = $true
                        $IpResult.HostStatus = "ONLINE"
                    }
                }
            } catch {} finally { $ping.Dispose() }

            if ($PingSuccess) {
                return $IpResult
            } else {
                $ParsedIP = [System.Net.IPAddress]::Parse($IP)
                foreach ($Port in $LocalPorts) {
                    $socket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
                    $socket.NoDelay = $true 
                    try {
                        $endpoint = New-Object System.Net.IPEndPoint($ParsedIP, [int]$Port)
                        $ar = $socket.BeginConnect($endpoint, $null, $null)
                        if ($ar.AsyncWaitHandle.WaitOne($Timeout, $false)) {
                            $socket.EndConnect($ar)
                            $null = $IpResult.OpenPorts.Add($Port)
                            $IpResult.HostStatus = "PORT_ONLY"
                            $ar.AsyncWaitHandle.Dispose()
                            break 
                        }
                        $ar.AsyncWaitHandle.Dispose()
                    } catch {} finally {
                        try { $socket.Shutdown([System.Net.Sockets.SocketShutdown]::Both) } catch {}
                        $socket.Close(); $socket.Dispose()
                    }
                }
            }
            return $IpResult
        }

        $Jobs = New-Object System.Collections.Generic.List[object]
        foreach ($IP in $CleanIPList) {
            $PowerShell = [PowerShell]::Create().AddScript($ScriptBlock).AddArgument($IP).AddArgument($PortsStringSerialized).AddArgument($Timeout)
            $PowerShell.RunspacePool = $LocalRunspacePool
            $Jobs.Add([PSCustomObject]@{ Pipe = $PowerShell; Handle = $PowerShell.BeginInvoke() })
            Start-Sleep -Milliseconds 15
        }

        $ScanResults = [System.Collections.Generic.List[object]]::new()
        $TotalTargets = $CleanIPList.Count; $CompletedTargets = 0; $AliveHostsCount = 0

        while ($Jobs.Count -gt 0) {
            $FinishedJobs = $Jobs | Where-Object { $_.Handle.IsCompleted }
            foreach ($Job in $FinishedJobs) {
                $item = $Job.Pipe.EndInvoke($Job.Handle)
                $CompletedTargets++
                if ($item) {
                    if ($item.HostStatus -eq "ONLINE") {
                        $AliveHostsCount++
                        Write-Host "[*] ALIVE [$AliveHostsCount Found] (Ping Only): $($item.IPAddress)" -ForegroundColor Gray
                        $RowObj = [PSCustomObject]@{
                            IPAddress  = $item.IPAddress
                            HostStatus = "ONLINE"
                            Port       = "None"
                            PortStatus = "SKIPPED_ON_PING"
                            Timestamp  = $item.Timestamp
                        }
                        $null = $ScanResults.Add($RowObj)
                    } elseif ($item.HostStatus -eq "PORT_ONLY") {
                        $AliveHostsCount++
                        $p = $item.OpenPorts[0]
                        $Mapping = if ($Global:KnownPorts.ContainsKey($p)) { "$p/$($Global:KnownPorts[$p])" } else { "$p" }
                        Write-Host "[+ (DTE MATCH)] [$AliveHostsCount Found] $($item.IPAddress): Verified active via $Mapping" -ForegroundColor Green
                        $RowObj = [PSCustomObject]@{
                            IPAddress  = $item.IPAddress
                            HostStatus = "FIREWALLED_DTE"
                            Port       = $p
                            PortStatus = "FIRST_MATCH_OPEN"
                            Timestamp  = $item.Timestamp
                        }
                        $null = $ScanResults.Add($RowObj)
                    }
                }
                $Job.Pipe.Dispose(); $null = $Jobs.Remove($Job)
            }
            $PercentComplete = [Math]::Round(($CompletedTargets / $TotalTargets) * 100)
            $Host.UI.RawUI.WindowTitle = "DTE Status: $PercentComplete% complete"
            Start-Sleep -Milliseconds 10
        }
    }
    finally {
        if ($null -ne $LocalRunspacePool) {
            $LocalRunspacePool.Close()
            $LocalRunspacePool.Dispose()
        }
    }

    $Stopwatch.Stop(); $ElapsedTime = "{0:mm\:ss}" -f $Stopwatch.Elapsed
    $DeadHosts = $TotalTargets - $AliveHostsCount

    Write-Host "`n+----------------------------------------------+" -ForegroundColor Cyan
    Write-Host "|              DTE FAST SCAN SUMMARY           |" -ForegroundColor Cyan
    Write-Host "+----------------------------------------------+" -ForegroundColor Cyan
    Write-Host "|  Total IPs Targeted  : $TotalTargets"            -ForegroundColor White
    Write-Host "|  Total Active Assets : $AliveHostsCount"         -ForegroundColor Green
    Write-Host "|  Unresponsive IPs    : $DeadHosts"                -ForegroundColor DarkGray
    Write-Host "|  Scan Duration       : $ElapsedTime"              -ForegroundColor White
    Write-Host "+----------------------------------------------+" -ForegroundColor Cyan

    if ($ScanResults.Count -gt 0) {
        $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $TargetFolder = Join-Path $PSScriptRoot "report"
        if (-not (Test-Path $TargetFolder)) { 
            New-Item -Path $TargetFolder -ItemType Directory -Force | Out-Null
        }
        $OutputFile = Join-Path $TargetFolder "dte_discovery_$Timestamp.csv"
        $ScanResults | Export-Csv -Path $OutputFile -NoTypeInformation
        Write-Host "[!] Asset Spreadsheet Saved: $OutputFile`n" -ForegroundColor Yellow
    }
    [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers()
    return $true
}

function Invoke-BannerGrabber {
    param([string]$Target, [string]$Port)
    $Host.UI.RawUI.WindowTitle = "Toolkit Engine // Banner Grabber"
    
    if ([string]::IsNullOrWhiteSpace($Target) -or [string]::IsNullOrWhiteSpace($Port)) {
        Write-Host "[!] Error: Missing target IP or port specification." -ForegroundColor Red
        return
    }

    $IP = $Target.Trim()
    $PortNum = [int]$Port.Trim()

    Write-Host "Connecting to $IP on port $PortNum... (Timeout: 2 seconds)" -ForegroundColor Cyan

    $client = New-Object System.Net.Sockets.TcpClient
    $timeoutMilliSec = 2000
    $stream = $null
    $sslStream = $null

    try {
        $task = $client.ConnectAsync($IP, $PortNum)
        if (-not $task.Wait($timeoutMilliSec) -or -not $client.Connected) {
            Write-Host "[!] Connection timed out or port is closed." -ForegroundColor Red
            return
        }

        $stream = $client.GetStream()
        $stream.ReadTimeout = 2500
        
        $payload = $null
        $isSsl = $false

        if ($PortNum -eq 80 -or $PortNum -eq 8080 -or $PortNum -eq 5660) {
            $httpRequest = "HEAD / HTTP/1.1`r`nHost: $IP`r`nConnection: Close`r`n`r`n"
            $payload = [System.Text.Encoding]::ASCII.GetBytes($httpRequest)
            $stream.Write($payload, 0, $payload.Length)

        } elseif ($PortNum -eq 443) {
            $isSsl = $true
            $sslStream = New-Object System.Net.Security.SslStream($stream, $false, ({ $true }))
            $sslStream.AuthenticateAsClient($IP)
            
            $httpRequest = "HEAD / HTTP/1.1`r`nHost: $IP`r`nConnection: Close`r`n`r`n"
            $payload = [System.Text.Encoding]::ASCII.GetBytes($httpRequest)
            $sslStream.Write($payload, 0, $payload.Length)

        } elseif ($PortNum -eq 3389) {
            $hexString = "030000130EE000000000000100080003000000"
            $payload = [byte[]] -split ($hexString -replace '..', '0x$& ')
            $stream.Write($payload, 0, $payload.Length)

        } elseif ($PortNum -eq 445) {
            $hexString = "00000044FF534D4272000000001853C80000000000000000000000000000FFFF00004000001100024E54204C4D20302E120002534D4220322E3030320002534D4220322E3F3F00"
            $payload = [byte[]] -split ($hexString -replace '..', '0x$& ')
            $stream.Write($payload, 0, $payload.Length)

        } elseif ($PortNum -eq 1433) {
            $hexString = "1201002F0000010000001A0006010020000102002100060300270004FF0800015500000000000100B80D0000000000"
            $payload = [byte[]] -split ($hexString -replace '..', '0x$& ')
            $stream.Write($payload, 0, $payload.Length)
        }

        $readBuffer = New-Object byte[] 2048
        $bytesRead = if ($isSsl) { $sslStream.Read($readBuffer, 0, $readBuffer.Length) } else { $stream.Read($readBuffer, 0, $readBuffer.Length) }
        
        if ($bytesRead -gt 0) {
            Write-Host "`n[+] HANDSHAKE SUCCESSFUL / LIVE APPLICATION VERIFIED:" -ForegroundColor Green
            Write-Host "--------------------------------------------------------" -ForegroundColor Gray
            
            switch ($PortNum) {
                3389 {
                    Write-Host "Service: Microsoft Remote Desktop (RDP)" -ForegroundColor White
                    $hex = ($readBuffer[0..($bytesRead-1)] | ForEach-Object { "{0:X2}" -f $_ }) -join " "
                    Write-Host "Raw Packet Token: $hex" -ForegroundColor DarkGray
                }
                445 {
                    Write-Host "Service: Microsoft Directory Services / SMB File Share" -ForegroundColor White
                    if ($readBuffer[4..7] -contains 0xfe -and $readBuffer[5..7] -contains 0x53) {
                        Write-Host "Protocol dialect confirmation: SMBv2/v3 Protocol Native Listener Active" -ForegroundColor DarkYellow
                    }
                }
                1433 {
                    Write-Host "Service: Microsoft SQL Server (MS-SQL)" -ForegroundColor White
                    Write-Host "Database listener responded successfully to connection sequence." -ForegroundColor DarkYellow
                }
                Default {
                    $rawText = [System.Text.Encoding]::ASCII.GetString($readBuffer, 0, $bytesRead).Trim()
                    $rawText -split "`n" | ForEach-Object {
                        $line = $_.Trim()
                        if (-not [string]::IsNullOrWhiteSpace($line)) { Write-Host "  $line" -ForegroundColor White }
                    }
                }
            }
            Write-Host "--------------------------------------------------------" -ForegroundColor Gray
        } else {
            Write-Host "`n[+] Port is OPEN, but the application didn't send data back." -ForegroundColor Yellow
        }

    } catch {
        Write-Host "[x] Connection closed or failed to respond during text retrieval." -ForegroundColor Red
        Write-Host "Details: $($_.Exception.Message)" -ForegroundColor DarkRed
    } finally {
        if ($null -ne $sslStream) { $sslStream.Close(); $sslStream.Dispose() }
        if ($null -ne $stream) { $stream.Close(); $stream.Dispose() }
        $client.Close(); $client.Dispose()
    }
}

function Invoke-MtuCalculator {
    param([string]$Target)
    $Host.UI.RawUI.WindowTitle = "Toolkit Engine // MTU Analyzer"
    
    if ([string]::IsNullOrWhiteSpace($Target)) {
        Write-Host "[!] Error: Missing target host for MTU evaluation." -ForegroundColor Red
        return
    }

    if ($Target -match '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b') {
        $CleanedHost = $Matches[0]
    } else {
        Write-Host "[CRITICAL ERROR]: The input '$Target' does not contain a valid IPv4 address!" -ForegroundColor Red
        return
    }

    Write-Host "`nChecking reachability for: $CleanedHost..." -NoNewline
    & ping.exe -n 2 -w 1000 $CleanedHost > $null

    if ($LASTEXITCODE -ne 0) {
        Write-Host "`n[CRITICAL ERROR]: Target host $CleanedHost is completely unreachable!" -ForegroundColor Red
        return
    }
    Write-Host " Host is Alive." -ForegroundColor Green

    $Low  = 1200
    $High = 1472
    $Best = 0
    $Rounds = 0

    & ping.exe -n 1 -w 800 -f -l 1300 $CleanedHost > $null
    if ($LASTEXITCODE -eq 0) {
        $Low = 1300
        Write-Host "[*] Baseline 1300 bytes passed. Optimizing search window..." -ForegroundColor DarkGray
    }

    Write-Host "Launching High-Precision Sweep...`n"
    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    while ($Low -le $High) {
        $Rounds++
        $Mid = [int](($Low + $High) / 2)
        
        Write-Host "Step #${Rounds}: Testing payload $Mid bytes... " -NoNewline
        
        $PassCount = 0
        for ($i = 1; $i -le 3; $i++) {
            & ping.exe -n 1 -w 1000 -f -l $Mid $CleanedHost > $null
            if ($LASTEXITCODE -eq 0) { $PassCount++ }
            Start-Sleep -Milliseconds 40 
        }
        
        if ($PassCount -lt 3) {
            Start-Sleep -Milliseconds 400 
            $RetryCount = 0
            for ($i = 1; $i -le 3; $i++) {
                & ping.exe -n 1 -w 1000 -f -l $Mid $CleanedHost > $null
                if ($LASTEXITCODE -eq 0) { $RetryCount++ }
                Start-Sleep -Milliseconds 40
            }
            if ($RetryCount -eq 3) { $PassCount = 3 }
        }

        if ($PassCount -eq 3) {
            Write-Host "STABLE" -ForegroundColor Green
            $Best = $Mid
            $Low  = $Mid + 1
        } else {
            Write-Host "FAILED" -ForegroundColor Red
            $High = $Mid - 1
            Start-Sleep -Milliseconds 250
        }
    }

    $Stopwatch.Stop()

    if ($Best -eq 0) {
        Write-Host "`nError: Path MTU could not be determined." -ForegroundColor Red
        return
    }

    $CalculatedMTU = $Best + 28
    $CalculatedMSS = $CalculatedMTU - 40

    Write-Host "`n=================================================" -ForegroundColor Cyan
    Write-Host "                FINAL SWEEP RESULTS" -ForegroundColor Cyan
    Write-Host "=================================================" -ForegroundColor Cyan
    Write-Host "Target Host:       $CleanedHost"
    Write-Host "Total Rounds:      $Rounds"
    Write-Host "Execution Time:    $([Math]::Round($Stopwatch.Elapsed.TotalSeconds, 2)) seconds" -ForegroundColor Yellow
    Write-Host "Exact Max Payload: $Best bytes"
    Write-Host "Closest Path MTU:  $CalculatedMTU bytes"
    Write-Host "Recommended MSS:   $CalculatedMSS bytes (for TCP path-mtu)"
    Write-Host "-------------------------------------------------" -ForegroundColor Cyan

    if ($CalculatedMSS -ge 1360) {
        Write-Host "[STATUS]: MSS is healthy. No firewall adjustment required.`n" -ForegroundColor Green
    } else {
        Write-Host "[WARNING]: MTU bottleneck detected! MSS is below 1360." -ForegroundColor Yellow
        Write-Host "Apply the following rules to your Alpine firewall/routing engine:`n"
        Write-Host "nft replace rule inet routing postrouting handle 8 tcp flags syn / syn,rst tcp option maxseg size set $CalculatedMSS" -ForegroundColor Magenta
        Write-Host "nft replace rule inet firewall postrouting handle 48 tcp flags syn / syn,rst tcp option maxseg size set $CalculatedMSS" -ForegroundColor Magenta
    }
    Write-Host "=================================================" -ForegroundColor Cyan

    $MtuReportFolder = Join-Path $PSScriptRoot "report"
    if (-not (Test-Path $MtuReportFolder)) { 
        New-Item -Path $MtuReportFolder -ItemType Directory -Force | Out-Null
    }

    $MtuLogFile = Join-Path $MtuReportFolder "mtu_audit_log.csv"
    $LogEntry = [PSCustomObject]@{
        Timestamp     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        TargetHost    = $CleanedHost
        MaxPayload    = $Best
        CalculatedMTU = $CalculatedMTU
        OptimalMSS    = $CalculatedMSS
        Status        = if ($CalculatedMSS -ge 1360) { "Healthy" } else { "Bottleneck" }
    }

    if (Test-Path $MtuLogFile) {
        $LogEntry | Export-Csv -Path $MtuLogFile -NoTypeInformation -Append -ErrorAction SilentlyContinue
    } else {
        $LogEntry | Export-Csv -Path $MtuLogFile -NoTypeInformation -ErrorAction SilentlyContinue
    }
    Write-Host "[!] Results recorded to central log: $MtuLogFile`n" -ForegroundColor Yellow
}

function Invoke-QuickPing {
    param([string]$Target)
    $Host.UI.RawUI.WindowTitle = "Toolkit Engine // Quick Ping"
    if ([string]::IsNullOrWhiteSpace($Target)) { return }
    Write-Host "`n[*] Executing 4-packet diagnostic validation to $Target..." -ForegroundColor Cyan
    & ping.exe -n 4 $Target
}

function Invoke-ContinuousPing {
    param([string]$Target)
    $Host.UI.RawUI.WindowTitle = "Toolkit Engine // Continuous Ping"
    if ([string]::IsNullOrWhiteSpace($Target)) { return }
    Write-Host "`n[*] Initiating persistent tracking tunnel to $Target. Use Ctrl+C to break loop.`n" -ForegroundColor Yellow
    & ping.exe -t $Target
}

function Start-ErrorCountdown {
    for ($i = 5; $i -gt 0; $i--) {
        Write-Host "`rReturning to menu input selection in $i seconds... " -NoNewline -ForegroundColor Yellow
        Start-Sleep -Seconds 1
    }
    Write-Host "`n"
}

# ========================================================================
# UI COORDINATOR & MASTER MENU ENGINE
# ========================================================================
function Show-Menu-Layout {
    Clear-Host
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "                NETWORK TOOLKIT MASTER MENU             " -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Run Port Scanner" -ForegroundColor White
    Write-Host "  [2] Run DTE Fast Scan" -ForegroundColor White
    Write-Host "  [3] Run Banner Grabber" -ForegroundColor White
    Write-Host "  [4] Run MTU Test Script" -ForegroundColor White
    Write-Host "  [5] Run Quick Ping Utility" -ForegroundColor White
    Write-Host "  [6] Run Continuous Ping Utility (-t)" -ForegroundColor White
    Write-Host "  [7] Exit" -ForegroundColor White
    Write-Host ""
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host ""
}

while ($true) {
    # Clear out trailing keystrokes from prior scans
    while ([Console]::KeyAvailable) { $null = [Console]::ReadKey($true) }

    $Host.UI.RawUI.WindowTitle = $Global:OriginalTitle
    Show-Menu-Layout
    Write-Host "Select an option [1-7] (Defaulting to [1] in 5s): " -NoNewline

    $Selection = $null 
    $MenuTimeout = 5       
    $KeyElapsed = 0

    while ($KeyElapsed -lt ($MenuTimeout * 10)) {
        if ([Console]::KeyAvailable) {
            $KeyInfo = [Console]::ReadKey($true)
            $Selection = $KeyInfo.KeyChar
            break
        }
        Start-Sleep -Milliseconds 100
        $KeyElapsed++
    }

    if ($null -eq $Selection) {
        $Selection = "1"
    }

    switch ($Selection) {
        "1" {
            Show-Menu-Layout
            Write-Host "--------------------------------------------------------" -ForegroundColor Green
            Write-Host "Launching Port Scanner..." -ForegroundColor Green
            Write-Host "--------------------------------------------------------" -ForegroundColor Green
            
            do {
                # USING NATIVE READ-HOST: History recall via Up-Arrow works natively again.
                $TargetInput = Read-Host "Enter Subnet/Range (or type 'b' to go back)"
                
                if ($TargetInput.Trim().ToLower() -eq "b" -or $TargetInput.Trim().ToLower() -eq "back" -or [string]::IsNullOrWhiteSpace($TargetInput)) { 
                    break 
                }
                
                $ScanStatus = Invoke-PortScanner -IPInput $TargetInput
                if (-not $ScanStatus) { 
                    Start-ErrorCountdown
                    break 
                }
                Write-Host "`n"
            } while ($true)
        }
        "2" {
            Show-Menu-Layout
            Write-Host "--------------------------------------------------------" -ForegroundColor Green
            Write-Host "Launching DTE Fast Scan..." -ForegroundColor Green
            Write-Host "--------------------------------------------------------" -ForegroundColor Green
            
            do {
                $TargetInput = Read-Host "Enter Discovery Target Subnet/Range (or type 'b' to go back)"
                
                if ($TargetInput.Trim().ToLower() -eq "b" -or $TargetInput.Trim().ToLower() -eq "back" -or [string]::IsNullOrWhiteSpace($TargetInput)) { 
                    break 
                }

                $ScanStatus = Invoke-PortScannerDte -IPInput $TargetInput
                if (-not $ScanStatus) { 
                    Start-ErrorCountdown
                    break
                }
                Write-Host "`n"
            } while ($true)
        }
        "3" {
            Show-Menu-Layout
            Write-Host "--------------------------------------------------------" -ForegroundColor Green
            Write-Host "Launching Banner Grabber..." -ForegroundColor Green
            Write-Host "--------------------------------------------------------" -ForegroundColor Green
            $T = Read-Host "Enter Target IP"
            $P = Read-Host "Enter Port Number"
            Invoke-BannerGrabber -Target $T -Port $P
            Read-Host "`nPress Enter to return to menu..."
        }
        "4" {
            Show-Menu-Layout
            Write-Host "--------------------------------------------------------" -ForegroundColor Green
            Write-Host "Launching MTU Analyzer..." -ForegroundColor Green
            Write-Host "--------------------------------------------------------" -ForegroundColor Green
            $T = Read-Host "Enter Target IP for MTU Sweep"
            Invoke-MtuCalculator -Target $T
            Read-Host "`nPress Enter to return to menu..."
        }
        "5" {
            Show-Menu-Layout
            Write-Host "--------------------------------------------------------" -ForegroundColor Green
            Write-Host "Launching Quick Ping..." -ForegroundColor Green
            Write-Host "--------------------------------------------------------" -ForegroundColor Green
            $T = Read-Host "Enter Target IP/Hostname for Quick Ping"
            Invoke-QuickPing -Target $T
            Read-Host "`nDiagnostic sequence concluded. Press Enter to return to menu..."
        }
        "6" {
            Show-Menu-Layout
            Write-Host "--------------------------------------------------------" -ForegroundColor Green
            Write-Host "Launching Continuous Ping..." -ForegroundColor Green
            Write-Host "--------------------------------------------------------" -ForegroundColor Green
            $T = Read-Host "Enter Target IP/Hostname for Continuous Tracking"
            Invoke-ContinuousPing -Target $T
            Read-Host "`nPersistent tunnel stopped. Press Enter to return to menu..."
        }
        "7" {
            Clear-Host
            Write-Host "[*] Tearing down session variables... Goodbye.`n" -ForegroundColor Cyan
            break
        }
    }
}
