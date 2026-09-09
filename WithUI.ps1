Clear-Host

Write-Host ""
Write-Host @"
    ▄████████ ███    █▄   ▄████████    ▄█    █▄       ▄████████    ▄████████  ▄█     ▄████████     ███     
  ███    ███ ███    ███ ███    ███   ███    ███     ███    ███   ███    ███ ███    ███    ███ ▀█████████▄ 
  ███    █▀  ███    ███ ███    █▀    ███    ███     ███    ███   ███    ███ ███▌   ███    █▀     ▀███▀▀██ 
 ▄███▄▄▄     ███    ███ ███         ▄███▄▄▄▄███▄▄   ███    ███  ▄███▄▄▄▄██▀ ███▌   ███            ███   ▀ 
▀▀███▀▀▀     ███    ███ ███        ▀▀███▀▀▀▀███▀  ▀███████████ ▀▀███▀▀▀▀▀   ███▌ ▀███████████     ███     
  ███    █▄  ███    ███ ███    █▄    ███    ███     ███    ███ ▀███████████ ███           ███     ███     
  ███    ███ ███    ███ ███    ███   ███    ███     ███    ███   ███    ███ ███     ▄█    ███     ███     
  ██████████ ████████▀  ████████▀    ███    █▀      ███    █▀    ███    ███ █▀    ▄████████▀     ▄████▀   
                                                                 ███    ███                                
"@ -ForegroundColor White

Write-Host ""
Write-Host "                                 Made by @junchrist on Discord" -ForegroundColor White
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
    Write-Host "No BAM data found." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
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

if ($Bam.Count -eq 0) {
    Write-Host "No BAM entries found." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit
}

function Show-CustomGUI {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "BAM Forensic Analysis | Junchrist"
    $form.Size = New-Object System.Drawing.Size(1200, 800)
    $form.StartPosition = "CenterScreen"
    $form.BackColor = [System.Drawing.Color]::Black
    $form.ForeColor = [System.Drawing.Color]::White
    $form.FormBorderStyle = "FixedSingle"
    $form.MaximizeBox = $false
    
    $headerLabel = New-Object System.Windows.Forms.Label
    $headerLabel.Text = "BAM Forensic Analysis"
    $headerLabel.Font = New-Object System.Drawing.Font("Segoe UI", 20, [System.Drawing.FontStyle]::Bold)
    $headerLabel.ForeColor = [System.Drawing.Color]::White
    $headerLabel.Size = New-Object System.Drawing.Size(1100, 40)
    $headerLabel.Location = New-Object System.Drawing.Point(50, 20)
    $headerLabel.TextAlign = "MiddleCenter"
    $form.Controls.Add($headerLabel)
    
    $subLabel = New-Object System.Windows.Forms.Label
    $subLabel.Text = "Made by @junchrist on Discord"
    $subLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $subLabel.ForeColor = [System.Drawing.Color]::Gray
    $subLabel.Size = New-Object System.Drawing.Size(1100, 25)
    $subLabel.Location = New-Object System.Drawing.Point(50, 65)
    $subLabel.TextAlign = "MiddleCenter"
    $form.Controls.Add($subLabel)
    
    $listView = New-Object System.Windows.Forms.ListView
    $listView.Size = New-Object System.Drawing.Size(1100, 550)
    $listView.Location = New-Object System.Drawing.Point(50, 100)
    $listView.View = "Details"
    $listView.FullRowSelect = $true
    $listView.GridLines = $true
    $listView.Font = New-Object System.Drawing.Font("Consolas", 10)
    $listView.BackColor = [System.Drawing.Color]::FromArgb(10, 10, 15)
    $listView.ForeColor = [System.Drawing.Color]::White
    
    $listView.Columns.Add("Execution Time", 200)
    $listView.Columns.Add("File Path", 400)
    $listView.Columns.Add("Digital Signature", 150)
    $listView.Columns.Add("File Name", 300)
    
    $form.Controls.Add($listView)
    
    $statusBar = New-Object System.Windows.Forms.StatusStrip
    $statusBar.BackColor = [System.Drawing.Color]::FromArgb(10, 10, 15)
    $statusBar.ForeColor = [System.Drawing.Color]::White
    
    $totalCount = New-Object System.Windows.Forms.ToolStripStatusLabel
    $totalCount.Text = "Total: $($Bam.Count)"
    $totalCount.ForeColor = [System.Drawing.Color]::White
    $statusBar.Items.Add($totalCount)
    
    $verifiedCount = New-Object System.Windows.Forms.ToolStripStatusLabel
    $verifiedCount.Text = "Verified: $($Bam | Where-Object { $_.'Digital Signature' -eq 'Verified' } | Measure-Object | Select-Object -ExpandProperty Count)"
    $verifiedCount.ForeColor = [System.Drawing.Color]::Green
    $statusBar.Items.Add($verifiedCount)
    
    $suspiciousCount = New-Object System.Windows.Forms.ToolStripStatusLabel
    $suspiciousCount.Text = "Suspicious: $($Bam | Where-Object { $_.'Digital Signature' -eq 'Suspicious' } | Measure-Object | Select-Object -ExpandProperty Count)"
    $suspiciousCount.ForeColor = [System.Drawing.Color]::Red
    $statusBar.Items.Add($suspiciousCount)
    
    $unsignedCount = New-Object System.Windows.Forms.ToolStripStatusLabel
    $unsignedCount.Text = "Unsigned: $($Bam | Where-Object { $_.'Digital Signature' -eq 'Unsigned' } | Measure-Object | Select-Object -ExpandProperty Count)"
    $unsignedCount.ForeColor = [System.Drawing.Color]::Yellow
    $statusBar.Items.Add($unsignedCount)
    
    $deletedCount = New-Object System.Windows.Forms.ToolStripStatusLabel
    $deletedCount.Text = "Deleted: $($Bam | Where-Object { $_.'Digital Signature' -eq 'Deleted' } | Measure-Object | Select-Object -ExpandProperty Count)"
    $deletedCount.ForeColor = [System.Drawing.Color]::Gray
    $statusBar.Items.Add($deletedCount)
    
    $form.Controls.Add($statusBar)
    
    foreach ($entry in $Bam) {
        $item = New-Object System.Windows.Forms.ListViewItem($entry.'Last Execution User Time')
        $item.SubItems.Add($entry.Path)
        $item.SubItems.Add($entry.'Digital Signature')
        $item.SubItems.Add($entry.'File Name')
        
        if ($entry.'Digital Signature' -eq 'Verified') {
            $item.ForeColor = [System.Drawing.Color]::Green
        } elseif ($entry.'Digital Signature' -eq 'Suspicious') {
            $item.ForeColor = [System.Drawing.Color]::Red
        } elseif ($entry.'Digital Signature' -eq 'Unsigned') {
            $item.ForeColor = [System.Drawing.Color]::Yellow
        } else {
            $item.ForeColor = [System.Drawing.Color]::Gray
        }
        
        $listView.Items.Add($item)
    }
    
    $form.ShowDialog() | Out-Null
}

Show-CustomGUI
