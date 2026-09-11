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
    5660  = "LOTS (EP-ICE, Universal)"  
    5800  = "VNC-HTTP"         
    5900  = "VNC"
    7361  = "RDP Alt"          
    8080  = "HTTP-Alt"
    8443  = "HTTPS-Alt"        
    9055  = "Oracle-WebLogic"  
    9903  = "Blackberry-Router" 
}

# Ports that require special visual highlighting in scan output.
# TCP/2000 is highlighted in red because it is a path/NAT investigation indicator
# in this environment. An open port alone does not prove NAT is present.
$Global:AlertPorts = @(2000)
$Global:MaxScanTargets = 512
$Global:DefaultPorts = @(20,21,22,23,80,135,139,443,445,2000,3121,3389,4440,4444,5660,5800,5900,7361,8443,9055)

# Alert metadata. These are investigation indicators, not proof of NAT/path translation.
$Global:PortAlerts = @{
    2000 = @{
        Severity    = "ALERT"
        Indicator   = "NAT/PATH INVESTIGATION"
        Description = "TCP/2000 is reachable; investigate possible NAT/path translation."
    }
}

# --- CENTRALIZED GLOBAL LIBRARIES ---
function Get-IPRange {
    param ([string]$InputTarget)

    if ([string]::IsNullOrWhiteSpace($InputTarget)) { return $null }
    $InputTarget = $InputTarget.Trim()

    if ($InputTarget -notmatch '^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2}|-\d{1,3})?$') {
        Write-Host "`n[CRITICAL ERROR]: '$InputTarget' is not a valid IPv4/range format!" -ForegroundColor Red
        return $null
    }

    $basePart = $InputTarget
    if ($InputTarget -match '^([\d\.]+)/(\d+)$') {
        $basePart = $Matches[1]
        $cidr = [int]$Matches[2]
        $octets = $basePart -split '\.'
        if (($octets | Where-Object { [int]$_ -gt 255 }).Count -gt 0 -or $cidr -lt 0 -or $cidr -gt 32) {
            Write-Host "[CRITICAL ERROR]: Invalid IPv4/CIDR: $InputTarget" -ForegroundColor Red
            return $null
        }

        # Enforce the scan boundary before expanding a CIDR into an address list.
        $totalHosts = [uint64]1 -shl (32 - $cidr)
        if ($totalHosts -gt [uint64]$Global:MaxScanTargets) {
            Write-Host "[CRITICAL SCOPE ERROR]: $InputTarget contains $totalHosts addresses; maximum allowed is $Global:MaxScanTargets." -ForegroundColor Red
            return $null
        }

        try {
            $ipBytes = [System.Net.IPAddress]::Parse($basePart).GetAddressBytes()
            if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($ipBytes) }
            $ipAsInt = [BitConverter]::ToUInt32($ipBytes, 0)
            $hostCount = [uint32]$totalHosts

            # NOTE: previously computed as [uint64]0xFFFFFFFF - (...). PowerShell
            # parses an 8-hex-digit literal like 0xFFFFFFFF by fitting the BIT
            # PATTERN into the smallest signed type first - so 0xFFFFFFFF is
            # actually Int32 -1, not the decimal value 4294967295. Casting that
            # -1 to [uint64] then throws ("Value was either too large or too
            # small for a UInt64"), which is exactly the CIDR expansion error.
            # Deriving the same value arithmetically avoids the literal
            # entirely, so it can't be misparsed.
            $allOnes32 = ([uint64]1 -shl 32) - 1  # = 4294967295, computed safely
            $mask = if ($cidr -eq 0) { [uint32]0 } else { [uint32]($allOnes32 - ([uint64]$hostCount - 1)) }
            $networkInt = [uint32]($ipAsInt -band $mask)

            return @(for ($i = [uint32]0; $i -lt $hostCount; $i++) {
                $currentBytes = [BitConverter]::GetBytes([uint32]($networkInt + $i))
                if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($currentBytes) }
                ([System.Net.IPAddress]$currentBytes).IPAddressToString
            })
        } catch {
            Write-Host "[CRITICAL ERROR]: Could not expand CIDR '$InputTarget'. $($_.Exception.Message)" -ForegroundColor Red
            return $null
        }
    }
    elseif ($InputTarget -match '^([\d\.]+)\.(\d+)-(\d+)$') {
        $prefix = $Matches[1]
        $startOctet = [int]$Matches[2]
        $endOctet = [int]$Matches[3]
        $prefixOctets = $prefix -split '\.'
        if (($prefixOctets | Where-Object { [int]$_ -gt 255 }).Count -gt 0 -or $startOctet -gt $endOctet -or $startOctet -lt 0 -or $endOctet -gt 255) {
            Write-Host "[CRITICAL ERROR]: Invalid IPv4 range: $InputTarget" -ForegroundColor Red
            return $null
        }
        $count = $endOctet - $startOctet + 1
        if ($count -gt $Global:MaxScanTargets) {
            Write-Host "[CRITICAL SCOPE ERROR]: $InputTarget contains $count addresses; maximum allowed is $Global:MaxScanTargets." -ForegroundColor Red
            return $null
        }
        return @($startOctet..$endOctet | ForEach-Object { "$prefix.$_" })
    }
    else {
        $octets = $InputTarget -split '\.'
        if (($octets | Where-Object { [int]$_ -gt 255 }).Count -gt 0) {
            Write-Host "[CRITICAL ERROR]: Invalid IPv4 address: $InputTarget" -ForegroundColor Red
            return $null
        }
        try {
            $parsed = [System.Net.IPAddress]::Parse($InputTarget)
            if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $null }
            return @($InputTarget)
        } catch {
            return $null
        }
    }
}

# Helper to automatically strip web prefix formats like http:// or https://
function Sanitize-TargetString ([string]$Value) {
    $Value = $Value.Trim()
    if ($Value -match '^https?://([^/]+)') {
        $Value = $Matches[1]
    }
    return $Value.Split(':')[0].Trim() # Drop explicit port tails like :8080 if accidentally pasted
}

# Validates single targets strictly (Hostnames, IPs - NO ranges, NO CIDR)
function Get-ValidSingleTarget {
    param ([string]$PromptMessage)
    while ($true) {
        $RawInput = Read-Host $PromptMessage
        if ([string]::IsNullOrWhiteSpace($RawInput)) { return "back" }
        $Cleaned = Sanitize-TargetString $RawInput
        
        if ($Cleaned.ToLower() -eq "b" -or $Cleaned.ToLower() -eq "back") { return "back" }

        # Verify single IP structure boundaries
        if ($Cleaned -match '^(\d{1,3}\.){3}\d{1,3}$') {
            $Octets = $Cleaned -split '\.'
            if ([int]$Octets[0] -le 255 -and [int]$Octets[1] -le 255 -and [int]$Octets[2] -le 255 -and [int]$Octets[3] -le 255) {
                return $Cleaned
            }
        }
        # Verify standard domain hostname framework rules
        elseif ($Cleaned -match '^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$') {
            return $Cleaned
        }
        Write-Host "[!] Invalid input. Provide one specific IPv4 address or clean standard Hostname domain." -ForegroundColor Red
    }
}

# Validates scanning networks (Allows single IPs, ranges, CIDR blocks, comma-separated clusters)
function Get-ValidNetworkInput {
    param ([string]$PromptMessage)
    while ($true) {
        $RawInput = Read-Host $PromptMessage
        if ([string]::IsNullOrWhiteSpace($RawInput)) { return "back" }
        $Cleaned = Sanitize-TargetString $RawInput

        if ($Cleaned.ToLower() -eq "b" -or $Cleaned.ToLower() -eq "back") { return "back" }

        $Segments = $Cleaned -split '[,\|]'
        $AllValid = $true

        # Bounded value patterns so acceptance here actually matches what
        # Get-IPRange will accept downstream - the previous version only
        # range-checked the first 4 split tokens (missing the end octet of
        # an a-b range entirely) and didn't bound CIDR to 0-32 at all, so
        # e.g. "10.0.0.5-999" or ".../99" would "validate" here and then
        # bounce back with a different error one step later.
        $OctetPattern = '(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
        $CidrPattern  = '(?:3[0-2]|[12]?[0-9])'
        $SegmentPattern = "^(?:$OctetPattern\.){3}$OctetPattern(?:/$CidrPattern|-$OctetPattern)?$"

        foreach ($Seg in $Segments) {
            $Target = $Seg.Trim()
            if ([string]::IsNullOrWhiteSpace($Target)) { continue }

            if ($Target -notmatch $SegmentPattern) {
                $AllValid = $false
            }
        }

        if ($AllValid) { return $Cleaned }
        Write-Host "[!] Invalid scope configuration. Formats allowed: 10.0.0.1, 192.168.1.0/24, or 172.16.1.5-250" -ForegroundColor Red
    }
}

function Get-ParsedPorts {
    param ([string]$Path)
    if (-not (Test-Path $Path)) { return $null }

    $lines = Get-Content $Path
    $finalPorts = New-Object System.Collections.Generic.List[int]
    $invalidLines = New-Object System.Collections.Generic.List[string]

    foreach ($lineRaw in $lines) {
        $line = $lineRaw.Trim()
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { continue }

        if ($line -match '^(\d+)-(\d+)$') {
            $startPort = [int]$Matches[1]
            $endPort = [int]$Matches[2]
            if ($startPort -lt 1 -or $endPort -gt 65535 -or $startPort -gt $endPort) {
                $invalidLines.Add($line); continue
            }
            foreach ($p in $startPort..$endPort) { $finalPorts.Add($p) }
        }
        elseif ($line -match '^\d+$') {
            $port = [int]$line
            if ($port -lt 1 -or $port -gt 65535) {
                $invalidLines.Add($line); continue
            }
            $finalPorts.Add($port)
        }
        else {
            $invalidLines.Add($line)
        }
    }

    if ($invalidLines.Count -gt 0) {
        Write-Host "[!] Ignoring invalid ports.txt entries: $($invalidLines -join ', ')" -ForegroundColor Yellow
    }

    # A file that exists but parses to zero usable ports (all comments,
    # blank, or hand-edited empty) must also read as "unusable" to the
    # callers, which only check `$null -eq $PortsArray`. Returning @()
    # here previously slipped past that check and failed later inside the
    # scan runspace with a confusing int-cast error on an empty string.
    if ($finalPorts.Count -eq 0) { return $null }

    return @($finalPorts | Select-Object -Unique)
}

function Assert-PortsFile {
    $PortsFile = Join-Path $PSScriptRoot "ports.txt"
    if (-not (Test-Path $PortsFile)) {
        Write-Host "[!] ports.txt missing. Auto-generating standard infrastructure profile..." -ForegroundColor Yellow
        ($Global:DefaultPorts | ForEach-Object { $_.ToString() }) | Set-Content $PortsFile -Encoding ascii
    }
    return $PortsFile
}

function Get-PortAlertInfo {
    param([int]$Port)
    if ($Global:PortAlerts.ContainsKey($Port)) { return $Global:PortAlerts[$Port] }
    return $null
}

function Get-PortDisplayText {
    param([int]$Port)
    if ($Global:KnownPorts.ContainsKey($Port)) { return "$Port/$($Global:KnownPorts[$Port])" }
    return "$Port"
}

function Write-OpenPortLine {
    param(
        [string]$Tag,
        [string]$IPAddress,
        [int[]]$OpenPorts,
        [int[]]$ConfirmedPorts = @()
    )

    Write-Host "$Tag ${IPAddress}: " -NoNewline -ForegroundColor Green
    for ($i = 0; $i -lt $OpenPorts.Count; $i++) {
        $port = [int]$OpenPorts[$i]
        $text = Get-PortDisplayText -Port $port
        $alert = Get-PortAlertInfo -Port $port
        $isConfirmed = $ConfirmedPorts -contains $port
        $color = if ($null -ne $alert) { "Red" } elseif ($isConfirmed) { "Green" } else { "DarkYellow" }
        $suffix = if ($isConfirmed) { "" } else { "*" }
        Write-Host "$text$suffix" -NoNewline -ForegroundColor $color
        if ($i -lt ($OpenPorts.Count - 1)) {
            Write-Host ", " -NoNewline -ForegroundColor DarkGray
        }
    }
    Write-Host ""

    foreach ($port in $OpenPorts) {
        $alert = Get-PortAlertInfo -Port ([int]$port)
        if ($null -ne $alert) {
            Write-Host "    [!] $($alert.Severity): TCP/$port detected - $($alert.Description)" -ForegroundColor Red
        }
    }
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

    if ($CleanIPList.Count -gt $Global:MaxScanTargets) {
        Write-Host "`n[CRITICAL SCOPE ERROR] Target range ($($CleanIPList.Count) IPs) exceeds the configured maximum of $Global:MaxScanTargets!" -ForegroundColor Red
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

    Write-Host "Scan Profile: Standard Infrastructure | Alert Ports: $($Global:AlertPorts -join ", ") | Max Targets: $Global:MaxScanTargets" -ForegroundColor DarkGray
    Write-Host "Port List: $($PortsArray -join ", ")" -ForegroundColor DarkGray
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
                IPAddress      = $IP
                HostStatus     = "UNREACHABLE"
                OpenPorts      = [System.Collections.Generic.List[int]]::new()
                ConfirmedPorts = [System.Collections.Generic.List[int]]::new()
                Timestamp      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
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

            # Fire every port's connect attempt at once instead of one at a
            # time. Sequentially, a dead host costs (port count x Timeout)  -
            # 21 ports x 350ms ~ 7.4s of mostly just waiting. Batched, it
            # costs roughly one Timeout period total, since we're waiting
            # for the slowest of N concurrent attempts, not the sum of N
            # sequential ones.
            $Attempts = @{}
            foreach ($Port in $LocalPorts) {
                $client = New-Object System.Net.Sockets.TcpClient
                try {
                    $client.NoDelay = $true
                    $client.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
                    $task = $client.ConnectAsync($ParsedIP, $Port)
                    $Attempts[$Port] = [PSCustomObject]@{ Client = $client; Task = $task }
                } catch {
                    try { $client.Close() } catch {}
                    $client.Dispose()
                }
            }

            if ($Attempts.Count -gt 0) {
                $AllTasks = [System.Threading.Tasks.Task[]]($Attempts.Values | ForEach-Object { $_.Task })
                [System.Threading.Tasks.Task]::WaitAll($AllTasks, $Timeout) | Out-Null
            }

            foreach ($Port in $LocalPorts) {
                if (-not $Attempts.ContainsKey($Port)) { continue }
                $Entry = $Attempts[$Port]
                $client = $Entry.Client
                try {
                    if ($Entry.Task.IsFaulted) {
                        $null = $Entry.Task.Exception # mark observed
                    } elseif ($Entry.Task.IsCompleted -and $client.Connected) {
                        $null = $IpResult.OpenPorts.Add($Port)
                        if ($IpResult.HostStatus -eq "UNREACHABLE") { $IpResult.HostStatus = "PORT_ONLY" }

                        # Confirmation pass: many services (SSH, FTP, Telnet,
                        # SMTP...) send an unsolicited banner the instant a
                        # connection completes. A short, non-blocking read
                        # here catches that - and its absence is a useful
                        # signal too. On overlay/CGNAT networks (e.g.
                        # 100.64.0.0/10, which Tailscale uses by default) the
                        # local handshake can complete even when nothing
                        # real is listening on the other end, so "connect
                        # succeeded" alone isn't proof of a live service the
                        # way it is on a normally-routed network. Ports that
                        # stay silent here are reported separately below
                        # rather than folded into a flat "OPEN" claim.
                        try {
                            $stream = $client.GetStream()
                            $stream.ReadTimeout = 400
                            $peekBuffer = New-Object byte[] 1
                            $bytesPeeked = $stream.Read($peekBuffer, 0, 1)
                            if ($bytesPeeked -gt 0) {
                                $null = $IpResult.ConfirmedPorts.Add($Port)
                            }
                        } catch {}
                    }
                    # Task still pending past Timeout (slow/dead path): the
                    # Dispose below aborts the in-flight attempt. It can't
                    # be more gracefully cancelled - .NET Framework's
                    # ConnectAsync predates the CancellationToken overload.
                } catch {} finally {
                    try { $client.Close() } catch {}
                    $client.Dispose()
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
                            $Tag = if ($item.HostStatus -eq "PORT_ONLY") { "[+ (FIREWALLED)]" } else { "[+] OPEN" }
                            Write-OpenPortLine -Tag $Tag -IPAddress $item.IPAddress -OpenPorts ([int[]]$item.OpenPorts) -ConfirmedPorts ([int[]]$item.ConfirmedPorts)

                            foreach ($OpenPort in $item.OpenPorts) {
                                $alert = Get-PortAlertInfo -Port ([int]$OpenPort)
                                $RowObj = [PSCustomObject]@{
                                    IPAddress  = $item.IPAddress
                                    HostStatus = $item.HostStatus
                                    Port       = $OpenPort
                                    Service    = Get-PortDisplayText -Port ([int]$OpenPort)
                                    PortStatus = "OPEN"
                                    Confirmed  = if ($item.ConfirmedPorts -contains $OpenPort) { "YES" } else { "NO (TCP-only)" }
                                    Severity   = if ($null -ne $alert) { $alert.Severity } else { "NORMAL" }
                                    Indicator  = if ($null -ne $alert) { $alert.Indicator } else { "" }
                                    Timestamp  = $item.Timestamp
                                }
                                $null = $ScanResults.Add($RowObj)
                            }
                        } else {
                            Write-Host "[*] ALIVE (Ping Only): $($item.IPAddress)" -ForegroundColor Gray
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
    $AlertCount = @($ScanResults | Where-Object { $_.Severity -eq "ALERT" }).Count

    Write-Host "`n+----------------------------------------------+" -ForegroundColor Cyan
    Write-Host "|                SCAN SUMMARY                  |" -ForegroundColor Cyan
    Write-Host "+----------------------------------------------+" -ForegroundColor Cyan
    Write-Host "|  Total IPs Targeted  : $TotalTargets"            -ForegroundColor White
    Write-Host "|  Hosts Responsive    : $AliveHostsCount"         -ForegroundColor Green
    Write-Host "|  Hosts Unreachable   : $DeadHosts"                -ForegroundColor DarkGray
    Write-Host "|  Scan Duration       : $ElapsedTime"              -ForegroundColor White
    Write-Host "|  Alert Findings      : $AlertCount"              -ForegroundColor $(if ($AlertCount -gt 0) { "Red" } else { "Green" })
    Write-Host "+----------------------------------------------+" -ForegroundColor Cyan

    if ($ScanResults.Count -gt 0) {
        $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $TargetFolder = Join-Path $PSScriptRoot "report"
        if (-not (Test-Path $TargetFolder)) { 
            New-Item -Path $TargetFolder -ItemType Directory -Force | Out-Null
        }
        $OutputFile = Join-Path $TargetFolder "scan_report_$Timestamp.csv"
        try {
            $ScanResults | Export-Csv -Path $OutputFile -NoTypeInformation -ErrorAction Stop
            Write-Host "[!] Spreadsheet Saved: $OutputFile`n" -ForegroundColor Yellow
        } catch {
            Write-Host "[!] Failed to save report to $OutputFile - $($_.Exception.Message)`n" -ForegroundColor Red
        }
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
    $AlertPortsSerialized = @($Global:AlertPorts | Where-Object { $PortsArray -contains $_ }) -join ','

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

    if ($CleanIPList.Count -gt $Global:MaxScanTargets) {
        Write-Host "`n[CRITICAL SCOPE ERROR] Target range ($($CleanIPList.Count) IPs) exceeds the configured maximum of $Global:MaxScanTargets!" -ForegroundColor Red
        return $false
    }

    Write-Host "Scan Profile: DTE Alert-Aware | Alert Ports: $($Global:AlertPorts -join ", ") | Max Targets: $Global:MaxScanTargets" -ForegroundColor DarkGray
    Write-Host "Port List: $($PortsArray -join ", ")" -ForegroundColor DarkGray
    Write-Host "Targeting $($CleanIPList.Count) total IPs [Mode: DTE Lightning Discovery]" -ForegroundColor Cyan
    Write-Host "Scanning... (Press Ctrl+C to stop)`n" -ForegroundColor Yellow

    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $InitialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $LocalRunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $MaxThreads, $InitialSessionState, $Host)
    
    try {
        $LocalRunspacePool.Open()

        $ScriptBlock = {
            param($IP, $SerializedPorts, $SerializedAlertPorts, $Timeout)
            $IpResult = [PSCustomObject]@{
                IPAddress  = $IP
                HostStatus = "UNREACHABLE"
                OpenPorts  = [System.Collections.Generic.List[int]]::new()
                Timestamp  = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }
            $LocalPorts = [int[]]($SerializedPorts -split ',')
            $AlertPortsLocal = @()
            if (-not [string]::IsNullOrWhiteSpace($SerializedAlertPorts)) {
                $AlertPortsLocal = [int[]]($SerializedAlertPorts -split ',')
            }

            $ParsedIP = [System.Net.IPAddress]::Parse($IP)

            function Test-SinglePort {
                param($TargetIP, [int]$Port, [int]$ConnectTimeout)
                $found = $false
                $sock = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
                $sock.NoDelay = $true
                try {
                    $ep = New-Object System.Net.IPEndPoint($TargetIP, $Port)
                    $ar = $sock.BeginConnect($ep, $null, $null)
                    if ($ar.AsyncWaitHandle.WaitOne($ConnectTimeout, $false)) {
                        $sock.EndConnect($ar)
                        $found = $true
                    }
                    $ar.AsyncWaitHandle.Dispose()
                } catch {} finally {
                    try { $sock.Shutdown([System.Net.Sockets.SocketShutdown]::Both) } catch {}
                    $sock.Close(); $sock.Dispose()
                }
                return $found
            }

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
                # Ping alone confirms the host is alive, so skip the full
                # port sweep for speed - but still run the (usually
                # single-port) alert-port check. Without this, a host that
                # answers ICMP would never get checked for TCP/2000 at all,
                # which is backwards: most live hosts answer ping even when
                # firewalled, so this is the common case, not the exception.
                foreach ($AlertPort in $AlertPortsLocal) {
                    if ($LocalPorts -notcontains $AlertPort) { continue }
                    if (Test-SinglePort -TargetIP $ParsedIP -Port $AlertPort -ConnectTimeout $Timeout) {
                        $null = $IpResult.OpenPorts.Add($AlertPort)
                    }
                }
                return $IpResult
            }

            $FirstMatchFound = $false
            foreach ($Port in $LocalPorts) {
                if (Test-SinglePort -TargetIP $ParsedIP -Port $Port -ConnectTimeout $Timeout) {
                    $null = $IpResult.OpenPorts.Add($Port)
                    $IpResult.HostStatus = "PORT_ONLY"
                    $FirstMatchFound = $true
                }

                # DTE remains fast: after the first normal match, only continue
                # far enough to check configured alert ports (e.g. TCP/2000).
                if ($FirstMatchFound -and $AlertPortsLocal.Count -gt 0) {
                    $RemainingAlerts = $AlertPortsLocal | Where-Object { $IpResult.OpenPorts -notcontains $_ }
                    foreach ($AlertPort in $RemainingAlerts) {
                        if ($LocalPorts -notcontains $AlertPort) { continue }
                        if (Test-SinglePort -TargetIP $ParsedIP -Port $AlertPort -ConnectTimeout $Timeout) {
                            $null = $IpResult.OpenPorts.Add($AlertPort)
                        }
                    }
                    break
                }
            }
            return $IpResult
        }

        $Jobs = New-Object System.Collections.Generic.List[object]
        foreach ($IP in $CleanIPList) {
            $PowerShell = [PowerShell]::Create().AddScript($ScriptBlock).AddArgument($IP).AddArgument($PortsStringSerialized).AddArgument($AlertPortsSerialized).AddArgument($Timeout)
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

                        if ($item.OpenPorts.Count -gt 0) {
                            # Ping succeeded AND an alert port (e.g. TCP/2000)
                            # was also found - surface it instead of hiding
                            # it behind a generic "ping only" line.
                            Write-Host "[* (ALERT ON PING-ONLY HOST)] [$AliveHostsCount Found] $($item.IPAddress): " -NoNewline -ForegroundColor Yellow
                            for ($AlertIdx = 0; $AlertIdx -lt $item.OpenPorts.Count; $AlertIdx++) {
                                $AlertPortFound = [int]$item.OpenPorts[$AlertIdx]
                                Write-Host (Get-PortDisplayText -Port $AlertPortFound) -NoNewline -ForegroundColor Red
                                if ($AlertIdx -lt ($item.OpenPorts.Count - 1)) { Write-Host ", " -NoNewline -ForegroundColor DarkGray }
                            }
                            Write-Host ""
                            foreach ($AlertPortFound in $item.OpenPorts) {
                                $alert = Get-PortAlertInfo -Port ([int]$AlertPortFound)
                                $RowObj = [PSCustomObject]@{
                                    IPAddress  = $item.IPAddress
                                    HostStatus = "ONLINE"
                                    Port       = $AlertPortFound
                                    Service    = Get-PortDisplayText -Port ([int]$AlertPortFound)
                                    PortStatus = "ALERT_PORT_CHECK_OPEN"
                                    Severity   = if ($null -ne $alert) { $alert.Severity } else { "NORMAL" }
                                    Indicator  = if ($null -ne $alert) { $alert.Indicator } else { "" }
                                    Timestamp  = $item.Timestamp
                                }
                                $null = $ScanResults.Add($RowObj)
                            }
                        } else {
                            Write-Host "[*] ALIVE [$AliveHostsCount Found] (Ping Only): $($item.IPAddress)" -ForegroundColor Gray
                            $RowObj = [PSCustomObject]@{
                                IPAddress  = $item.IPAddress
                                HostStatus = "ONLINE"
                                Port       = "None"
                                Service    = ""
                                PortStatus = "SKIPPED_ON_PING"
                                Severity   = "NORMAL"
                                Indicator  = ""
                                Timestamp  = $item.Timestamp
                            }
                            $null = $ScanResults.Add($RowObj)
                        }
                    } elseif ($item.HostStatus -eq "PORT_ONLY") {
                        $AliveHostsCount++
                        $p = [int]$item.OpenPorts[0]
                        Write-Host "[+ (DTE MATCH)] [$AliveHostsCount Found] $($item.IPAddress): " -NoNewline -ForegroundColor Green
                        for ($DteIndex = 0; $DteIndex -lt $item.OpenPorts.Count; $DteIndex++) {
                            $DetectedPort = [int]$item.OpenPorts[$DteIndex]
                            $DteText = Get-PortDisplayText -Port $DetectedPort
                            $DteAlert = Get-PortAlertInfo -Port $DetectedPort
                            $DteColor = if ($null -ne $DteAlert) { "Red" } else { "Green" }
                            Write-Host $DteText -NoNewline -ForegroundColor $DteColor
                            if ($DteIndex -lt ($item.OpenPorts.Count - 1)) { Write-Host ", " -NoNewline -ForegroundColor DarkGray }
                        }
                        Write-Host ""
                        foreach ($DetectedPort in $item.OpenPorts) {
                            $alert = Get-PortAlertInfo -Port ([int]$DetectedPort)
                            $RowObj = [PSCustomObject]@{
                                IPAddress  = $item.IPAddress
                                HostStatus = "FIREWALLED_DTE"
                                Port       = $DetectedPort
                                Service    = Get-PortDisplayText -Port ([int]$DetectedPort)
                                PortStatus = if ([int]$DetectedPort -eq $p) { "FIRST_MATCH_OPEN" } else { "ALERT_PORT_CHECK_OPEN" }
                                Severity   = if ($null -ne $alert) { $alert.Severity } else { "NORMAL" }
                                Indicator  = if ($null -ne $alert) { $alert.Indicator } else { "" }
                                Timestamp  = $item.Timestamp
                            }
                            $null = $ScanResults.Add($RowObj)
                        }
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
    $AlertCount = @($ScanResults | Where-Object { $_.Severity -eq "ALERT" }).Count

    Write-Host "`n+----------------------------------------------+" -ForegroundColor Cyan
    Write-Host "|              DTE FAST SCAN SUMMARY           |" -ForegroundColor Cyan
    Write-Host "+----------------------------------------------+" -ForegroundColor Cyan
    Write-Host "|  Total IPs Targeted  : $TotalTargets"            -ForegroundColor White
    Write-Host "|  Total Active Assets : $AliveHostsCount"         -ForegroundColor Green
    Write-Host "|  Unresponsive IPs    : $DeadHosts"                -ForegroundColor DarkGray
    Write-Host "|  Scan Duration       : $ElapsedTime"              -ForegroundColor White
    Write-Host "|  Alert Findings      : $AlertCount"              -ForegroundColor $(if ($AlertCount -gt 0) { "Red" } else { "Green" })
    Write-Host "+----------------------------------------------+" -ForegroundColor Cyan

    if ($ScanResults.Count -gt 0) {
        $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $TargetFolder = Join-Path $PSScriptRoot "report"
        if (-not (Test-Path $TargetFolder)) { 
            New-Item -Path $TargetFolder -ItemType Directory -Force | Out-Null
        }
        $OutputFile = Join-Path $TargetFolder "dte_discovery_$Timestamp.csv"
        try {
            $ScanResults | Export-Csv -Path $OutputFile -NoTypeInformation -ErrorAction Stop
            Write-Host "[!] Asset Spreadsheet Saved: $OutputFile`n" -ForegroundColor Yellow
        } catch {
            Write-Host "[!] Failed to save report to $OutputFile - $($_.Exception.Message)`n" -ForegroundColor Red
        }
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

    # AUTOMATED DNS RESOLUTION LOOKUP
    $IP = $Target.Trim()
    if ($IP -notmatch '^(\d{1,3}\.){3}\d{1,3}$') {
        try {
            $ResolvedList = [System.Net.Dns]::GetHostAddresses($IP)
            $IP = $ResolvedList[0].IPAddressToString
            Write-Host "[*] Hostname resolved successfully to underlying IP address: $IP" -ForegroundColor DarkGray
        } catch {
            Write-Host "[!] DNS Resolution Error: Could not resolve the host target '$IP'." -ForegroundColor Red
            return
        }
    }
    
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

    # AUTOMATED DNS RESOLUTION LOOKUP
    $CleanedHost = $Target.Trim()
    if ($CleanedHost -notmatch '^(\d{1,3}\.){3}\d{1,3}$') {
        try {
            $CleanedHost = [System.Net.Dns]::GetHostAddresses($CleanedHost)[0].IPAddressToString
        } catch {
            Write-Host "[CRITICAL ERROR]: Could not run MTU lookup. Unable to resolve '$Target'." -ForegroundColor Red
            return
        }
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

    try {
        if (Test-Path $MtuLogFile) {
            $LogEntry | Export-Csv -Path $MtuLogFile -NoTypeInformation -Append -ErrorAction Stop
        } else {
            $LogEntry | Export-Csv -Path $MtuLogFile -NoTypeInformation -ErrorAction Stop
        }
        Write-Host "[!] Results recorded to central log: $MtuLogFile`n" -ForegroundColor Yellow
    } catch {
        Write-Host "[!] Failed to write to central log $MtuLogFile - $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "    (Is the file open in Excel or another program?)`n" -ForegroundColor DarkGray
    }
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

:MainMenuLoop
while ($true) {
    while ([Console]::KeyAvailable) { $null = [Console]::ReadKey($true) }

    $Host.UI.RawUI.WindowTitle = $Global:OriginalTitle
    Show-Menu-Layout

    $Selection = $null
    $MenuTimeoutSeconds = 5
    $PollIntervalMs = 100
    $TicksPerSecond = [int](1000 / $PollIntervalMs)
    $MaxTicks = $MenuTimeoutSeconds * $TicksPerSecond
    $Elapsed = 0
    $LastShownSecond = -1

    while ($Elapsed -lt $MaxTicks) {
        $SecondsLeft = $MenuTimeoutSeconds - [int]($Elapsed / $TicksPerSecond)
        if ($SecondsLeft -ne $LastShownSecond) {
            Write-Host "`rSelect an option [1-7] (Defaulting to [1] in ${SecondsLeft}s): " -NoNewline
            $LastShownSecond = $SecondsLeft
        }
        if ([Console]::KeyAvailable) {
            $KeyInfo = [Console]::ReadKey($true)
            $Selection = $KeyInfo.KeyChar
            break
        }
        Start-Sleep -Milliseconds $PollIntervalMs
        $Elapsed++
    }
    Write-Host ""

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
                $TargetInput = Get-ValidNetworkInput -PromptMessage "Enter Subnet/Range (or type 'b' to go back)"
                if ($TargetInput -eq "back") { break }
                
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
                $TargetInput = Get-ValidNetworkInput -PromptMessage "Enter Discovery Target Subnet/Range (or type 'b' to go back)"
                if ($TargetInput -eq "back") { break }

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
            
            $T = Get-ValidSingleTarget -PromptMessage "Enter Target IP/Hostname"
            if ($T -ne "back") {
                $P = $null
                while ($null -eq $P) {
                    $RawPort = Read-Host "Enter Port Number (1-65535)"
                    if ($RawPort -match '^\d{1,5}$' -and [int]$RawPort -ge 1 -and [int]$RawPort -le 65535) {
                        $P = $RawPort
                    } else {
                        Write-Host "[!] Invalid port. Enter a number between 1 and 65535." -ForegroundColor Red
                    }
                }
                Invoke-BannerGrabber -Target $T -Port $P
                Read-Host "`nPress Enter to return to menu..."
            }
        }
        "4" {
            Show-Menu-Layout
            Write-Host "--------------------------------------------------------" -ForegroundColor Green
            Write-Host "Launching MTU Analyzer..." -ForegroundColor Green
            Write-Host "--------------------------------------------------------" -ForegroundColor Green
            
            $T = Get-ValidSingleTarget -PromptMessage "Enter Target IP/Hostname for MTU Sweep"
            if ($T -ne "back") {
                Invoke-MtuCalculator -Target $T
                Read-Host "`nPress Enter to return to menu..."
            }
        }
        "5" {
            Show-Menu-Layout
            Write-Host "--------------------------------------------------------" -ForegroundColor Green
            Write-Host "Launching Quick Ping..." -ForegroundColor Green
            Write-Host "--------------------------------------------------------" -ForegroundColor Green
            
            $T = Get-ValidSingleTarget -PromptMessage "Enter Target IP/Hostname for Quick Ping"
            if ($T -ne "back") {
                Invoke-QuickPing -Target $T
                Read-Host "`nDiagnostic sequence concluded. Press Enter to return to menu..."
            }
        }
        "6" {
            Show-Menu-Layout
            Write-Host "--------------------------------------------------------" -ForegroundColor Green
            Write-Host "Launching Continuous Ping..." -ForegroundColor Green
            Write-Host "--------------------------------------------------------" -ForegroundColor Green
            
            $T = Get-ValidSingleTarget -PromptMessage "Enter Target IP/Hostname for Continuous Tracking"
            if ($T -ne "back") {
                Invoke-ContinuousPing -Target $T
                Read-Host "`nPersistent tunnel stopped. Press Enter to return to menu..."
            }
        }
        "7" {
            Clear-Host
            Write-Host "[*] Tearing down session variables... Goodbye.`n" -ForegroundColor Cyan
            break MainMenuLoop
        }
        default {
            Write-Host "`n[!] '$Selection' isn't a valid option. Choose 1-7." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
}
