cls

Write-Host ""
Write-Host @"
.dP' dP"Yb.             `Yb.            db                                       
dP'    `b   'Yb             `Yb        db    db             db                     
                              Yb                                                   
 'Yb      'Yb   .dP'  dP'      Yb        'Yb    `Yb    dP' 'Yb .d888b.  `Yb.d888b  
  88       88   88    88      dPYb        88      Yb  dP    88 8'   `Yb  88'    8Y 
  88       88   Y8   .88    ,dP  Yb       88       YbdP     88 Yb.   88  88     8P 
 .8P      .8P   `Y88P'88  .dP'    `Yb.   .8P       .8P     .8P     .dP   88   ,dP  
                      88                         dP'  b          .dP'    88        
                      88                         Y.  ,P        .dP'      88        
                      Y8.                         `""'                  .8P        
"@ -ForegroundColor Red
Write-Host ""
Write-Host "                                 made by @junchrist on Discord"
Write-Host ""

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {  
    Write-Warning "This script requires Administrator privileges. Please run as Administrator."
    exit
}

function Get-OldestConnectTime {
    $oldestLogon = Get-CimInstance -ClassName Win32_LogonSession | 
        Where-Object {$_.LogonType -eq 2 -or $_.LogonType -eq 10} | 
        Sort-Object -Property StartTime | 
        Select-Object -First 1
    if ($oldestLogon) {
        return $oldestLogon.StartTime
    } else {
        return $null
    }
}

function Get-DeviceMappings {
    $DynAssembly = New-Object System.Reflection.AssemblyName('SysUtils')
    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('SysUtils', $False)
    $TypeBuilder = $ModuleBuilder.DefineType('Kernel32', 'Public, Class')
    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('QueryDosDevice', 'kernel32.dll', ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static), [Reflection.CallingConventions]::Standard, [UInt32], [Type[]]@([String], [Text.StringBuilder], [UInt32]), [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Auto)
    $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
    $SetLastError = [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
    $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor, @('kernel32.dll'), [Reflection.FieldInfo[]]@($SetLastError), @($true))
    $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
    $Kernel32 = $TypeBuilder.CreateType()
    $Max = 65536
    $StringBuilder = New-Object System.Text.StringBuilder($Max)
    $driveMappings = Get-WmiObject Win32_Volume | Where-Object { $_.DriveLetter } | ForEach-Object {
        $ReturnLength = $Kernel32::QueryDosDevice($_.DriveLetter, $StringBuilder, $Max)
        if ($ReturnLength) {
            @{
                DriveLetter = $_.DriveLetter
                DevicePath = $StringBuilder.ToString().ToLower()
            }
        }
    }
    return $driveMappings
}

function Convert-DevicePathToDriveLetter {
    param (
        [string]$DevicePath,
        $DeviceMappings
    )
    foreach ($mapping in $DeviceMappings) {
        if ($DevicePath -like ($mapping.DevicePath + "*")) {
            return $DevicePath -replace [regex]::Escape($mapping.DevicePath), $mapping.DriveLetter
        }
    }
    return $DevicePath
}

function Get-FileSignature {
    param (
        [string]$FilePath
    )
    if (Test-Path $FilePath) {
        $signature = Get-AuthenticodeSignature -FilePath $FilePath
        if ($signature.Status -eq 'Valid') {
            if ($signature.SignerCertificate.Subject -like "*Manthe Industries, LLC*") {
                return "Suspicious"
            }
            if ($signature.SignerCertificate.Subject -like "*Slinkware*") {
                return "Suspicious"
            } else {
                return "Verified"
            }
        } else {
            return "Unsigned"
        }
    } else {
        return "Deleted"
    }
}

$oldestConnectTime = Get-OldestConnectTime
$deviceMappings = Get-DeviceMappings

$ErrorActionPreference = 'SilentlyContinue'

if (!(Get-PSDrive -Name HKLM -PSProvider Registry)){
    Try{New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE}
    Catch{}
}

$bv = ("bam", "bam\State")
$Users = @()
foreach($ii in $bv){
    $Users += Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($ii)\UserSettings\" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName
}

if ($Users.Count -eq 0) {
    exit
}

$rpath = @("HKLM:\SYSTEM\CurrentControlSet\Services\bam\","HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\")

$UserTime = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -ErrorAction SilentlyContinue).TimeZoneKeyName
$UserBias = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -ErrorAction SilentlyContinue).ActiveTimeBias
$UserDay = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -ErrorAction SilentlyContinue).DaylightBias

$Bam = @()
Foreach ($Sid in $Users) {
    foreach($rp in $rpath){
        $BamItems = Get-Item -Path "$($rp)UserSettings\$Sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property
        
        Try{
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($Sid)
            $User = $objSID.Translate( [System.Security.Principal.NTAccount]) 
            $User = $User.Value
        }
        Catch{$User=""}
        
        ForEach ($Item in $BamItems){
            $Key = Get-ItemProperty -Path "$($rp)UserSettings\$Sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Item
    
            If($key.length -eq 24){
                $Hex=[System.BitConverter]::ToString($key[7..0]) -replace "-",""
                $Bias = -([convert]::ToInt32([Convert]::ToString($UserBias,2),2))
                $TimeUser = (Get-Date ([DateTime]::FromFileTimeUtc([Convert]::ToInt64($Hex, 16))).addminutes($Bias) -Format "yyyy-MM-dd HH:mm:ss") 
                
                if ([DateTime]::ParseExact($TimeUser, "yyyy-MM-dd HH:mm:ss", $null) -ge $oldestConnectTime) {
                    $f = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3)-match '\d{1}')
                    {Split-path -leaf ($item).TrimStart()} else {$item}
                    
                    $path = Convert-DevicePathToDriveLetter -DevicePath $item -DeviceMappings $deviceMappings
                    
                    $signature = Get-FileSignature -FilePath $path
                    
                    $Bam += [PSCustomObject]@{
                        'Last Execution User Time' = $TimeUser
                        Path = $path
                        'Digital Signature' = $signature
                        'File Name' = $f
                    }
                }
            }
        }
    }
}

$ErrorActionPreference = 'Continue'

$ContenidoHtml = @'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BAM Forensic Analysis | JunChrist</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0a0a0f;
            --bg-secondary: #151520;
            --bg-tertiary: #1e1e2e;
            --accent-primary: #6366f1;
            --accent-secondary: #8b5cf6;
            --text-primary: #f8fafc;
            --text-secondary: #cbd5e1;
            --text-muted: #64748b;
            --border: #2d3748;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --suspicious: #dc2626;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, var(--bg-primary) 0%, #1a1a2e 100%);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 0 20px;
        }

        .header {
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
            border-bottom: 1px solid var(--border);
            padding: 2.5rem 0;
            text-align: center;
            position: relative;
            overflow: hidden;
        }

        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(90deg, transparent, var(--accent-primary), transparent);
        }

        .logo {
            font-family: 'JetBrains Mono', monospace;
            color: var(--accent-primary);
            font-size: 0.75rem;
            line-height: 1.3;
            margin-bottom: 1.5rem;
            white-space: pre;
            opacity: 0.9;
        }

        .title {
            font-size: 2.2rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, var(--accent-primary) 0%, var(--accent-secondary) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .subtitle {
            color: var(--text-secondary);
            font-size: 1rem;
            font-weight: 400;
            opacity: 0.8;
        }

        .stats-bar {
            background: var(--bg-secondary);
            padding: 1rem 0;
            border-bottom: 1px solid var(--border);
        }

        .stats-container {
            display: flex;
            justify-content: space-around;
            flex-wrap: wrap;
            gap: 1rem;
        }

        .stat-item {
            text-align: center;
            padding: 0.5rem 1rem;
        }

        .stat-value {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--accent-primary);
            font-family: 'JetBrains Mono', monospace;
        }

        .stat-label {
            font-size: 0.8rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .controls {
            background: var(--bg-secondary);
            padding: 1.5rem 0;
            border-bottom: 1px solid var(--border);
        }

        .search-box {
            position: relative;
            max-width: 500px;
            margin: 0 auto;
        }

        .search-input {
            width: 100%;
            padding: 0.75rem 1rem 0.75rem 3rem;
            background: var(--bg-primary);
            border: 1px solid var(--border);
            border-radius: 10px;
            color: var(--text-primary);
            font-family: 'Inter', sans-serif;
            font-size: 0.9rem;
            transition: all 0.3s ease;
        }

        .search-input:focus {
            outline: none;
            border-color: var(--accent-primary);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
        }

        .search-icon {
            position: absolute;
            left: 1rem;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-muted);
            width: 16px;
            height: 16px;
        }

        .table-section {
            padding: 2rem 0;
        }

        .data-table {
            width: 100%;
            background: var(--bg-secondary);
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid var(--border);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }

        .table-header {
            background: linear-gradient(135deg, var(--bg-tertiary) 0%, #252542 100%);
            border-bottom: 1px solid var(--border);
        }

        .table-header-row {
            display: grid;
            grid-template-columns: 200px 1fr 150px 180px;
            gap: 1px;
        }

        .table-header-cell {
            padding: 1.25rem 1rem;
            font-weight: 600;
            font-size: 0.75rem;
            color: var(--accent-primary);
            text-transform: uppercase;
            letter-spacing: 0.8px;
            cursor: pointer;
            user-select: none;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .table-header-cell:hover {
            background: rgba(99, 102, 241, 0.1);
        }

        .table-header-cell.sorted::after {
            content: '↕';
            font-size: 0.7rem;
            opacity: 0.6;
        }

        .table-header-cell.asc::after {
            content: '↑';
            opacity: 1;
        }

        .table-header-cell.desc::after {
            content: '↓';
            opacity: 1;
        }

        .table-body {
            max-height: 65vh;
            overflow-y: auto;
        }

        .table-body::-webkit-scrollbar {
            width: 6px;
        }

        .table-body::-webkit-scrollbar-track {
            background: var(--bg-primary);
        }

        .table-body::-webkit-scrollbar-thumb {
            background: var(--accent-primary);
            border-radius: 3px;
        }

        .table-row {
            display: grid;
            grid-template-columns: 200px 1fr 150px 180px;
            gap: 1px;
            border-bottom: 1px solid var(--border);
            transition: all 0.3s ease;
        }

        .table-row:hover {
            background: var(--bg-tertiary);
            transform: translateX(4px);
        }

        .table-cell {
            padding: 1.25rem 1rem;
            font-size: 0.85rem;
            display: flex;
            align-items: center;
            word-break: break-word;
        }

        .timestamp {
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            font-weight: 500;
        }

        .file-path {
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            line-height: 1.4;
        }

        .file-name {
            color: var(--text-secondary);
            font-weight: 600;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
        }

        .signature {
            padding: 0.4rem 0.8rem;
            border-radius: 8px;
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border: 1px solid;
        }

        .signature-verified {
            background: rgba(16, 185, 129, 0.15);
            color: var(--success);
            border-color: var(--success);
        }

        .signature-unsigned {
            background: rgba(245, 158, 11, 0.15);
            color: var(--warning);
            border-color: var(--warning);
        }

        .signature-suspicious {
            background: rgba(220, 38, 38, 0.2);
            color: var(--suspicious);
            border-color: var(--suspicious);
        }

        .signature-deleted {
            background: rgba(100, 116, 139, 0.15);
            color: var(--text-muted);
            border-color: var(--text-muted);
        }

        .footer {
            background: var(--bg-secondary);
            border-top: 1px solid var(--border);
            padding: 2rem 0;
            margin-top: 3rem;
        }

        .footer-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }

        .footer-info {
            color: var(--text-secondary);
            font-size: 0.8rem;
        }

        .footer-links {
            display: flex;
            gap: 1.5rem;
        }

        .footer-link {
            color: var(--accent-primary);
            text-decoration: none;
            font-size: 0.8rem;
            font-weight: 600;
            transition: all 0.3s ease;
            padding: 0.5rem 1rem;
            border-radius: 6px;
        }

        .footer-link:hover {
            color: var(--text-primary);
            background: var(--accent-primary);
        }

        .no-data {
            text-align: center;
            padding: 4rem;
            color: var(--text-muted);
            font-size: 1rem;
        }

        .loading {
            text-align: center;
            padding: 2rem;
            color: var(--accent-primary);
        }

        @media (max-width: 1024px) {
            .table-header-row,
            .table-row {
                grid-template-columns: 180px 1fr 140px 160px;
            }
        }

        @media (max-width: 768px) {
            .table-header-row,
            .table-row {
                grid-template-columns: 150px 1fr 120px 140px;
            }
            
            .container {
                padding: 0 15px;
            }
            
            .table-cell {
                padding: 1rem 0.75rem;
                font-size: 0.8rem;
            }
            
            .footer-content {
                flex-direction: column;
                text-align: center;
            }
            
            .title {
                font-size: 1.8rem;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="container">
            <div class="logo">.dP' dP"Yb.             `Yb.            db                                       
dP'    `b   'Yb             `Yb        db    db             db                     
                              Yb                                                   
 'Yb      'Yb   .dP'  dP'      Yb        'Yb    `Yb    dP' 'Yb .d888b.  `Yb.d888b  
  88       88   88    88      dPYb        88      Yb  dP    88 8'   `Yb  88'    8Y 
  88       88   Y8   .88    ,dP  Yb       88       YbdP     88 Yb.   88  88     8P 
 .8P      .8P   `Y88P'88  .dP'    `Yb.   .8P       .8P     .8P     .dP   88   ,dP  
                      88                         dP'  b          .dP'    88        
                      88                         Y.  ,P        .dP'      88        
                      Y8.                         `""'                  .8P        </div>
            <h1 class="title">BAM Forensic Analysis</h1>
            <p class="subtitle">Professional Execution Timeline Analysis • Made by @junchrist on Discord</p>
        </div>
    </div>

    <div class="stats-bar">
        <div class="container">
            <div class="stats-container">
                <div class="stat-item">
                    <div class="stat-value" id="totalEntries">0</div>
                    <div class="stat-label">Total Entries</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" id="verifiedFiles">0</div>
                    <div class="stat-label">Verified</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" id="suspiciousFiles">0</div>
                    <div class="stat-label">Suspicious</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" id="unsignedFiles">0</div>
                    <div class="stat-label">Unsigned</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" id="deletedFiles">0</div>
                    <div class="stat-label">Deleted</div>
                </div>
            </div>
        </div>
    </div>

    <div class="controls">
        <div class="container">
            <div class="search-box">
                <svg class="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                    <path d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                </svg>
                <input type="text" class="search-input" id="searchInput" placeholder="Search files, paths, timestamps, or signatures...">
            </div>
        </div>
    </div>

    <div class="table-section">
        <div class="container">
            <div class="data-table">
                <div class="table-header">
                    <div class="table-header-row">
                        <div class="table-header-cell" data-sort="time">Execution Time</div>
                        <div class="table-header-cell" data-sort="path">File Path</div>
                        <div class="table-header-cell" data-sort="signature">Signature Status</div>
                        <div class="table-header-cell" data-sort="fileName">File Name</div>
                    </div>
                </div>
                <div class="table-body" id="tableBody">
                    <div class="loading">Loading forensic data...</div>
                </div>
            </div>
        </div>
    </div>

    <div class="footer">
        <div class="container">
            <div class="footer-content">
                <div class="footer-info">
                    © 2025 Forensic Analysis Tool • Made by @junchrist on Discord
                </div>
                <div class="footer-links">
                    <a href="https://github.com/junchrist" class="footer-link" target="_blank">GitHub</a>
                    <a href="https://discordapp.com/users/1357122264595693739" class="footer-link" target="_blank">Discord</a>
                </div>
            </div>
        </div>
    </div>

    <script>
        const entries = [
'@

foreach ($entry in $Bam) {
    $escapedTime = $entry.'Last Execution User Time'.Replace('"', '\"')
    $escapedPath = $entry.Path.Replace('"', '\"')
    $escapedSignature = $entry.'Digital Signature'.Replace('"', '\"')
    $escapedFileName = $entry.'File Name'.Replace('"', '\"')
    $ContenidoHtml += @"
            {
                time: `"$escapedTime`",
                path: `"$escapedPath`",
                signature: `"$escapedSignature`",
                fileName: `"$escapedFileName`"
            },
"@
}

$ContenidoHtml += @'
        ];

        let currentSort = { column: "time", direction: "desc" };
        let filteredEntries = [...entries];

        function getSignatureClass(signature) {
            if (signature === 'Verified') return 'signature-verified';
            if (signature === 'Suspicious') return 'signature-suspicious';
            if (signature === 'Unsigned') return 'signature-unsigned';
            if (signature === 'Deleted') return 'signature-deleted';
            return 'signature-unsigned';
        }

        function updateStats() {
            const total = entries.length;
            const verified = entries.filter(e => e.signature === 'Verified').length;
            const suspicious = entries.filter(e => e.signature === 'Suspicious').length;
            const unsigned = entries.filter(e => e.signature === 'Unsigned').length;
            const deleted = entries.filter(e => e.signature === 'Deleted').length;

            document.getElementById('totalEntries').textContent = total;
            document.getElementById('verifiedFiles').textContent = verified;
            document.getElementById('suspiciousFiles').textContent = suspicious;
            document.getElementById('unsignedFiles').textContent = unsigned;
            document.getElementById('deletedFiles').textContent = deleted;
        }

        function populateTable(data) {
            const tbody = document.querySelector("#tableBody");
            tbody.innerHTML = "";
            
            if (data.length === 0) {
                tbody.innerHTML = '<div class="no-data">No entries match your search criteria</div>';
                return;
            }

            data.forEach((entry, index) => {
                const row = document.createElement("div");
                row.className = "table-row";
                row.innerHTML = `
                    <div class="table-cell timestamp">${entry.time}</div>
                    <div class="table-cell file-path">${entry.path}</div>
                    <div class="table-cell">
                        <span class="signature ${getSignatureClass(entry.signature)}">${entry.signature}</span>
                    </div>
                    <div class="table-cell file-name">${entry.fileName}</div>
                `;
                tbody.appendChild(row);
            });
        }

        function applyFilters() {
            const searchTerm = document.getElementById("searchInput").value.toLowerCase();
            
            if (searchTerm) {
                filteredEntries = entries.filter((entry) =>
                    Object.values(entry).some((value) =>
                        value.toLowerCase().includes(searchTerm)
                    )
                );
            } else {
                filteredEntries = [...entries];
            }

            filteredEntries.sort((a, b) => {
                const aValue = a[currentSort.column];
                const bValue = b[currentSort.column];
                if (currentSort.direction === "asc") {
                    return aValue.localeCompare(bValue);
                } else {
                    return bValue.localeCompare(aValue);
                }
            });

            populateTable(filteredEntries);
            updateSortIndicators();
        }

        function updateSortIndicators() {
            document.querySelectorAll(".table-header-cell").forEach((th) => {
                th.classList.remove("asc", "desc", "sorted");
                if (th.dataset.sort === currentSort.column) {
                    th.classList.add("sorted", currentSort.direction);
                }
            });
        }

        document.getElementById("searchInput").addEventListener("input", applyFilters);

        document.querySelectorAll(".table-header-cell").forEach((th) => {
            th.addEventListener("click", () => {
                const column = th.dataset.sort;
                if (currentSort.column === column) {
                    currentSort.direction = currentSort.direction === "asc" ? "desc" : "asc";
                } else {
                    currentSort.column = column;
                    currentSort.direction = "asc";
                }
                applyFilters();
            });
        });

        document.addEventListener('DOMContentLoaded', function() {
            updateStats();
            applyFilters();
        });
    </script>
</body>
</html>
'@

$htmlFilePath = Join-Path $env:TEMP "BAM_Forensic_Analysis.html"
$ContenidoHtml | Out-File -FilePath $htmlFilePath -Encoding UTF8

Start-Process $htmlFilePath
