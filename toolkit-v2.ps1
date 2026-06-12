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
    2000  = "Cisco-SCCP"      # Cisco Skinny Client Control Protocol
    3121  = "Xilinx-HW-Server" # Xilinx Hardware Server
    3389  = "RDP"
    4440  = "Rundeck"          # Rundeck Automation Web Console
    4444  = "Metasploit"       # Metasploit Default Reverse Shell Listener
    5660  = "LogMeIn-Hamachi"  # Hamachi VPN Control Service
    5800  = "VNC-HTTP"         # VNC Web Viewer over HTTP
    5900  = "VNC"
    8080  = "HTTP-Alt"
    8443  = "HTTPS-Alt"        # Common Tomcat/Plesk SSL Console port
    9055  = "Oracle-WebLogic"  # Oracle WebLogic Management Service
    9903  = "Blackberry-Router" # Blackberry Enterprise Server Router
}

# --- CENTRALIZED GLOBAL LIBRARIES ---
function Get-IPRange {
    param ([string]$InputTarget)

    $InputTarget = $InputTarget.Trim()
    if ($InputTarget -notmatch '\b(?:\d{1,3}\.){1,3}\d{1,3}\b') {
        Write-Host "`n[CRITICAL ERROR]: '$InputTarget' is not a valid IPv4 format!" -ForegroundColor Red
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

# ========================================================================
# INTEGRATED ENGINE FUNCTIONS
# ========================================================================

function Invoke-PortScanner {
    param([string]$IPInput)
    $Host.UI.RawUI.WindowTitle = "Toolkit Engine // Port Scanner"
    
    $Timeout = 350   
    $MaxThreads = 64 

    $PortsFile = Join-Path $PSScriptRoot "ports.txt"
    if (-not (Test-Path $PortsFile)) { 
        Write-Host "`n[CRITICAL ERROR] Missing ports.txt in the toolkit folder." -ForegroundColor Red
        return 
    }
    $PortsArray = Get-ParsedPorts -Path $PortsFile
    if ($null -eq $PortsArray) {
        Write-Host "`n[CRITICAL ERROR] ports.txt contains no valid ports." -ForegroundColor Red
        return
    }
    $PortsStringSerialized = $PortsArray -join ','

    $IPList = [System.Collections.Generic.List[string]]::new()
    foreach ($Target in ($IPInput -split '[,\|]')) {
        if (-not [string]::IsNullOrWhiteSpace($Target)) {
            $ResolvedIPs = Get-IPRange -InputTarget $Target.Trim()
            if ($ResolvedIPs) { $IPList.AddRange([string[]]$ResolvedIPs) }
        }
    }

    $CleanIPList = $IPList | Select-Object -Unique
    if ($CleanIPList.Count -eq 0) {
        Write-Host "`n[CRITICAL ERROR] No valid scan targets generated." -ForegroundColor Red
        return
    }

    # --- SAFETY LIMIT GUARDRAIL (/23 threshold restriction) ---
    if ($CleanIPList.Count -gt 512) {
        Write-Host "`n[CRITICAL SCOPE ERROR] Target range ($($CleanIPList.Count) IPs) exceeds permitted allocation boundaries!" -ForegroundColor Red
        Write-Host "[!] Scanning networks broader than a /23 block is disabled to prevent resource exhaustion." -ForegroundColor Yellow
        return
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
                        
                        # --- ENHANCED PORT/SERVICE DICTIONARY RESOLVER ---
                        $FormattedPortsArray = foreach ($p in $item.OpenPorts) {
                            if ($Global:KnownPorts.ContainsKey($p)) {
                                "$p/$($Global:KnownPorts[$p])"
                            } else {
                                "$p"
                            }
                        }
                        $PortString = $FormattedPortsArray -join ", "
                        
                        $Tag = if ($item.HostStatus -eq "PORT_ONLY") { "[+ (FIREWALLED)]" } else { "[+] OPEN" }
                        Write-Host "$Tag $($item.IPAddress): $PortString" -ForegroundColor Green
                        foreach ($OpenPort in $item.OpenPorts) {
                            $null = $ScanResults.Add([PSCustomObject]@{ IPAddress = $item.IPAddress; HostStatus = $item.HostStatus; Port = $OpenPort; PortStatus = "OPEN"; Timestamp = $item.Timestamp })
                        }
                    } else {
                        Write-Host "[*] ALIVE (Ping Only): $($item.IPAddress)" -ForegroundColor Gray
                        $null = $ScanResults.Add([PSCustomObject]@{ IPAddress = $item.IPAddress; HostStatus = "ONLINE"; Port = "None"; PortStatus = "CLOSED"; Timestamp = $item.Timestamp })
                    }
                }
            }
            $Job.Pipe.Dispose(); $null = $Jobs.Remove($Job)
        }
        $PercentComplete = [Math]::Round(($CompletedTargets / $TotalTargets) * 100)
        $Host.UI.RawUI.WindowTitle = "Scan Status: $PercentComplete% complete [$CompletedTargets / $TotalTargets IPs]"
        Start-Sleep -Milliseconds 10
    }

    $LocalRunspacePool.Close(); $LocalRunspacePool.Dispose()
    $Stopwatch.Stop(); $ElapsedTime = "{0:mm\:ss}" -f $Stopwatch.Elapsed
    $DeadHosts = $TotalTargets - $AliveHostsCount

    Write-Host "`n+----------------------------------------------+" -ForegroundColor Cyan
    Write-Host "|                SCAN SUMMARY                  |" -ForegroundColor Cyan
    Write-Host "+----------------------------------------------+" -ForegroundColor Cyan
    Write-Host "|  Total IPs Targeted  : $TotalTargets"            -ForegroundColor White
    Write-Host "|  Hosts Responsive    : $AliveHostsCount"         -ForegroundColor Green
    Write-Host "|  Hosts Unreachable   : $DeadHosts"               -ForegroundColor DarkGray
    Write-Host "|  Scan Duration       : $ElapsedTime"             -ForegroundColor White
    Write-Host "+----------------------------------------------+" -ForegroundColor Cyan

    if ($ScanResults.Count -gt 0) {
        $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $TargetFolder = Join-Path $PSScriptRoot "report"
        if (-not (Test-Path $TargetFolder)) { $null = New-Item -Path $TargetFolder -ItemType Directory -Force }
        $OutputFile = Join-Path $TargetFolder "scan_report_$Timestamp.csv"
        $ScanResults | Export-Csv -Path $OutputFile -NoTypeInformation
        Write-Host "[!] Spreadsheet Saved: $OutputFile`n" -ForegroundColor Yellow
    } else {
        Write-Host "[*] No open ports or active hosts logged.`n" -ForegroundColor DarkGray
    }

    [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers()
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

        # --- PROTOCOL EVALUATION ENGINE ---
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
            $payload = [byte[]](0x03,0x00,0x00,0x13,0x0e,0xe0,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x08,0x00,0x03,0x00,0x00,0x00)
            $stream.Write($payload, 0, $payload.Length)

        } elseif ($PortNum -eq 445) {
            $payload = [byte[]](0x00,0x00,0x00,0x44,0xff,0x53,0x4d,0x42,0x72,0x00,0x00,0x00,0x00,0x18,0x53,0xc8,0x00,0x00,
                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xfe,0x00,0x00,0x40,0x00,
                                0x00,0x11,0x00,0x02,0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x12,0x00,0x02,0x53,0x4d,0x42,
                                0x20,0x32,0x2e,0x30,0x30,0x32,0x00,0x02,0x53,0x4d,0x42,0x20,0x32,0x2e,0x3f,0x3f,0x00)
            $stream.Write($payload, 0, $payload.Length)

        } elseif ($PortNum -eq 1433) {
            $payload = [byte[]](0x12,0x01,0x00,0x2f,0x00,0x00,0x01,0x00,0x00,0x00,0x1a,0x00,0x06,0x01,0x00,0x20,0x00,0x01,
                                0x02,0x00,0x21,0x00,0x06,0x03,0x00,0x27,0x00,0x04,0xff,0x08,0x00,0x01,0x55,0x00,0x00,0x00,
                                0x00,0x00,0x01,0x00,0xb8,0x0d,0x00,0x00,0x00,0x00,0x00)
            $stream.Write($payload, 0, $payload.Length)
        }

        # --- READ RESPONSE LAYER ---
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
    if (-not (Test-Path $MtuReportFolder)) { $null = New-Item -Path $MtuReportFolder -ItemType Directory -Force }

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

# ========================================================================
# UI COORDINATOR & MASTER MENU ENGINE
# ========================================================================
function Show-Menu-Layout {
    Clear-Host
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "                NETWORK TOOLKIT MASTER MENU             " -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Run Port Scanner (DEFAULT option in 5 seconds)" -ForegroundColor White
    Write-Host "  [2] Run Banner Grabber (Port Connect)" -ForegroundColor White
    Write-Host "  [3] Run MTU Test Script" -ForegroundColor White
    Write-Host "  [4] Run Quick Ping Utility" -ForegroundColor White
    Write-Host "  [5] Exit" -ForegroundColor White
    Write-Host ""
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host ""
}

while ($true) {
    $Host.UI.RawUI.WindowTitle = $Global:OriginalTitle
    Show-Menu-Layout
    Write-Host "Select an option [1-5] (Defaulting to [1] in 5s): " -NoNewline

    $Selection = $null 
    $Timeout = 5       
    $KeyElapsed = 0

    while ($KeyElapsed -lt ($Timeout * 10)) {
        if ([Console]::KeyAvailable) {
            $KeyInfo = [Console]::ReadKey($true)
            $Selection = $KeyInfo.KeyChar
            break
        }
        Start-Sleep -Milliseconds 100
        $KeyElapsed++
    }

    if ($null -eq $Selection) { $Selection = "1" }
    $ToolExecuted = $false

    switch ($Selection) {
        "1" {
            $ToolExecuted = $true
            Write-Host "`n`n--------------------------------------------------------" -ForegroundColor Green
            Write-Host "Launching Port Scanner..." -ForegroundColor Green
            Write-Host "--------------------------------------------------------" -ForegroundColor Green
            $TargetNet = Read-Host "Enter Subnet/Range (e.g., 100.111.44.0/26)"
            if (-not [string]::IsNullOrWhiteSpace($TargetNet)) {
                Invoke-PortScanner -IPInput $TargetNet
            }
        }
        "2" {
            $ToolExecuted = $true
            Write-Host "`n`n--------------------------------------------------------" -ForegroundColor Green
            Write-Host "Launching Banner Grabber..." -ForegroundColor Green
            Write-Host "--------------------------------------------------------" -ForegroundColor Green
            $GrabInput = Read-Host "Enter target and port (e.g., 10.10.1.1:3389)"
            if (-not [string]::IsNullOrWhiteSpace($GrabInput)) {
                $ParsedArgs = $GrabInput -split '[\s:]' | Where-Object { $_ }
                if ($ParsedArgs.Count -ge 2) {
                    Invoke-BannerGrabber -Target $ParsedArgs[0] -Port $ParsedArgs[1]
                } else {
                    Write-Host "[!] Format invalid. Use Target:Port layout." -ForegroundColor Red
                }
            }
        }
        "3" {
            $ToolExecuted = $true
            Write-Host "`n`n--------------------------------------------------------" -ForegroundColor Green
            Write-Host "Launching MTU Test Script..." -ForegroundColor Green
            Write-Host "--------------------------------------------------------" -ForegroundColor Green
            $MtuTarget = Read-Host "Enter target IP to test MTU against"
            if (-not [string]::IsNullOrWhiteSpace($MtuTarget)) {
                Invoke-MtuCalculator -Target $MtuTarget
            }
        }
        "4" {
            $ToolExecuted = $true
            Write-Host "`n`n--------------------------------------------------------" -ForegroundColor Green
            Write-Host "Launching Quick Ping Utility..." -ForegroundColor Green
            Write-Host "--------------------------------------------------------" -ForegroundColor Green
            $PingTarget = Read-Host "Enter target IP or Domain to ping"
            if (-not [string]::IsNullOrWhiteSpace($PingTarget)) {
                Write-Host "`nSending 4 ICMP echo requests to $PingTarget...`n" -ForegroundColor Yellow
                & ping.exe $PingTarget.Trim()
            }
        }
        "5" {
            Write-Host "`nExiting Suite Terminal..." -ForegroundColor Yellow
            break 
        }
        Default {
            Write-Host "`n`n[!] Invalid entry. Refreshing menu..." -ForegroundColor Red
            Start-Sleep -Seconds 1
            while ([Console]::KeyAvailable) { [Console]::ReadKey($true) | Out-Null }
        }
    }

    if ($Selection -eq "5") { break }

    if ($ToolExecuted) {
        while ([Console]::KeyAvailable) { [Console]::ReadKey($true) | Out-Null }
        Write-Host "`nPress any key to return to menu..." -ForegroundColor DarkGray
        [Console]::ReadKey($true) | Out-Null
    }
}
