$ErrorActionPreference = "SilentlyContinue"

Clear-Host

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

Write-Host ""
Write-Host @"
    ▄████████ ███    █▄   ▄████████    ▄█    █▄       ▄████████    ▄████████  ▄█     ▄████████     ███     
  ███    ███ ███    ███ ███    ███   ███    ███     ███    ███   ███    ███ ███    ███    ███ ▀█████████▄ 
  ███    ▀  ███    ███ ███    █▀    ███    ███     ███    ███   ███    ███ ███▌   ███    █▀     ▀███▀▀██ 
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

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )

    return $currentUser.IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator
    )
}

if (-not (Test-Admin)) {
    Write-Warning "This script requires Administrator privileges. Please run as Administrator."
    Read-Host "Press Enter to exit"
    exit
}

function Get-Signature {
    [CmdletBinding()]
    param (
        [string]$FilePath
    )

    if ([string]::IsNullOrWhiteSpace($FilePath)) {
        return "File Was Not Found"
    }

    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
        return "File Was Not Found"
    }

    try {
        $Authenticode = (
            Get-AuthenticodeSignature `
                -FilePath $FilePath `
                -ErrorAction SilentlyContinue
        ).Status
    }
    catch {
        return "Invalid Signature (UnknownError)"
    }

    switch ($Authenticode) {
        "Valid" {
            return "Valid Signature"
        }

        "NotSigned" {
            return "Invalid Signature (NotSigned)"
        }

        "HashMismatch" {
            return "Invalid Signature (HashMismatch)"
        }

        "NotTrusted" {
            return "Invalid Signature (NotTrusted)"
        }

        "UnknownError" {
            return "Invalid Signature (UnknownError)"
        }

        default {
            return "Invalid Signature (UnknownError)"
        }
    }
}

function Get-DeviceMappings {

    $DynAssembly = New-Object System.Reflection.AssemblyName('BamDeviceMapping')

    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly(
        $DynAssembly,
        [Reflection.Emit.AssemblyBuilderAccess]::Run
    )

    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule(
        'BamDeviceMapping',
        $False
    )

    $TypeBuilder = $ModuleBuilder.DefineType(
        'Kernel32',
        'Public, Class'
    )

    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod(
        'QueryDosDevice',
        'kernel32.dll',
        ([Reflection.MethodAttributes]::Public -bor
         [Reflection.MethodAttributes]::Static),
        [Reflection.CallingConventions]::Standard,
        [UInt32],
        [Type[]]@(
            [String],
            [Text.StringBuilder],
            [UInt32]
        ),
        [Runtime.InteropServices.CallingConvention]::Winapi,
        [Runtime.InteropServices.CharSet]::Auto
    )

    $DllImportConstructor =
        [Runtime.InteropServices.DllImportAttribute].GetConstructor(
            @([String])
        )

    $SetLastError =
        [Runtime.InteropServices.DllImportAttribute].GetField(
            'SetLastError'
        )

    $CustomAttribute =
        New-Object Reflection.Emit.CustomAttributeBuilder(
            $DllImportConstructor,
            @('kernel32.dll'),
            [Reflection.FieldInfo[]]@($SetLastError),
            @($true)
        )

    $PInvokeMethod.SetCustomAttribute($CustomAttribute)

    $Kernel32 = $TypeBuilder.CreateType()

    $Mappings = @()

    $Volumes = Get-CimInstance Win32_Volume |
        Where-Object {
            $_.DriveLetter
        }

    foreach ($Volume in $Volumes) {

        $StringBuilder = New-Object System.Text.StringBuilder(65536)

        $ReturnLength = $Kernel32::QueryDosDevice(
            $Volume.DriveLetter,
            $StringBuilder,
            65536
        )

        if ($ReturnLength) {

            $Mappings += [PSCustomObject]@{
                DriveLetter = $Volume.DriveLetter
                DevicePath  = $StringBuilder.ToString().ToLower()
            }
        }
    }

    return $Mappings
}

function Convert-DevicePathToDriveLetter {
    param (
        [string]$DevicePath,
        $DeviceMappings
    )

    if ([string]::IsNullOrWhiteSpace($DevicePath)) {
        return $DevicePath
    }

    foreach ($Mapping in $DeviceMappings) {

        if ($DevicePath.ToLower().StartsWith(
            $Mapping.DevicePath.ToLower()
        )) {

            return $DevicePath -replace `
                [regex]::Escape($Mapping.DevicePath),
                $Mapping.DriveLetter
        }
    }

    return $DevicePath
}

function Get-OldestConnectTime {

    $oldestLogon = Get-CimInstance `
        -ClassName Win32_LogonSession `
        -ErrorAction SilentlyContinue |
        Where-Object {
            $_.LogonType -eq 2 -or
            $_.LogonType -eq 10
        } |
        Sort-Object StartTime |
        Select-Object -First 1

    if ($oldestLogon) {
        return $oldestLogon.StartTime
    }

    return $null
}

$oldestConnectTime = Get-OldestConnectTime
$deviceMappings = Get-DeviceMappings

if (-not (Get-PSDrive -Name HKLM -PSProvider Registry)) {

    try {
        New-PSDrive `
            -Name HKLM `
            -PSProvider Registry `
            -Root HKEY_LOCAL_MACHINE |
            Out-Null
    }
    catch {
        Write-Warning "Unable to mount HKEY_LOCAL_MACHINE."
        exit
    }
}

$bv = @(
    "bam",
    "bam\State"
)

$Users = @()

foreach ($ii in $bv) {

    $Path =
        "HKLM:\SYSTEM\CurrentControlSet\Services\$ii\UserSettings"

    if (Test-Path $Path) {

        $Users += Get-ChildItem `
            -Path $Path `
            -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty PSChildName
    }
}

$Users = $Users |
    Where-Object {
        $_ -match '^S-\d-\d+-.+'
    } |
    Sort-Object -Unique

if (-not $Users -or $Users.Count -eq 0) {

    Write-Host "No BAM data found." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit
}

$rpath = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\bam\",
    "HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\"
)

$UserTime = (
    Get-ItemProperty `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation"
).TimeZoneKeyName

$UserBias = (
    Get-ItemProperty `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation"
).ActiveTimeBias

$UserDay = (
    Get-ItemProperty `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation"
).DaylightBias

$Bam = @()

foreach ($Sid in $Users) {

    try {

        $objSID = New-Object `
            System.Security.Principal.SecurityIdentifier($Sid)

        $User = $objSID.Translate(
            [System.Security.Principal.NTAccount]
        )

        $User = $User.Value
    }
    catch {

        $User = ""
    }

    foreach ($rp in $rpath) {

        $UserSettingsPath =
            "$($rp)UserSettings\$Sid"

        if (-not (Test-Path $UserSettingsPath)) {
            continue
        }

        $BamItems =
            Get-Item `
                -Path $UserSettingsPath `
                -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty Property

        foreach ($Item in $BamItems) {

            $Key =
                Get-ItemProperty `
                    -Path $UserSettingsPath `
                    -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty $Item

            if (-not $Key) {
                continue
            }

            if ($Key.Length -ne 24) {
                continue
            }

            try {

                $Hex =
                    [System.BitConverter]::ToString(
                        $Key[7..0]
                    ) -replace "-", ""

                $FileTime =
                    [Convert]::ToInt64(
                        $Hex,
                        16
                    )

                $TimeUtc =
                    [DateTime]::FromFileTimeUtc(
                        $FileTime
                    )

                $TimeUser =
                    $TimeUtc.ToLocalTime()

                if (
                    $oldestConnectTime -and
                    $TimeUser -lt $oldestConnectTime
                ) {
                    continue
                }

                $TimeLocalString =
                    $TimeUser.ToString(
                        "yyyy-MM-dd HH:mm:ss"
                    )

                $TimeUtcString =
                    $TimeUtc.ToString(
                        "yyyy-MM-dd HH:mm:ss"
                    )

                $Path =
                    Convert-DevicePathToDriveLetter `
                        -DevicePath $Item `
                        -DeviceMappings $deviceMappings

                $FileName =
                    Split-Path `
                        -Path $Path `
                        -Leaf `
                        -ErrorAction SilentlyContinue

                if ([string]::IsNullOrWhiteSpace($FileName)) {
                    $FileName = Split-Path `
                        -Path $Item `
                        -Leaf `
                        -ErrorAction SilentlyContinue
                }

                $Signature = Get-Signature `
                    -FilePath $Path

                $Bam += [PSCustomObject]@{

                    'Execution Time' =
                        $TimeLocalString

                    'Execution UTC' =
                        $TimeUtcString

                    'User Execution Time' =
                        $TimeLocalString

                    'File Path' =
                        $Path

                    'Signature Status' =
                        $Signature

                    'File Name' =
                        $FileName

                    'User' =
                        $User

                    'SID' =
                        $Sid

                    'Registry Path' =
                        $UserSettingsPath
                }
            }
            catch {
            }
        }
    }
}

$Bam = @(
    $Bam |
        Sort-Object 'Execution Time' -Descending
)

if ($Bam.Count -eq 0) {

    Write-Host "No BAM entries found." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit
}

function Show-CustomGUI {

    $Form = New-Object System.Windows.Forms.Form

    $Form.Text =
        "BAM Forensic Analysis | Junchrist"

    $Form.StartPosition =
        "CenterScreen"

    $Form.Size =
        New-Object System.Drawing.Size(1500, 900)

    $Form.MinimumSize =
        New-Object System.Drawing.Size(1100, 700)

    $Form.BackColor =
        [System.Drawing.Color]::FromArgb(
            10, 10, 15
        )

    $Form.ForeColor =
        [System.Drawing.Color]::White

    $Form.Font =
        New-Object System.Drawing.Font(
            "Segoe UI",
            9
        )

    $Form.AutoScroll = $false

    $HeaderPanel =
        New-Object System.Windows.Forms.Panel

    $HeaderPanel.Dock = "Top"
    $HeaderPanel.Height = 145
    $HeaderPanel.BackColor =
        [System.Drawing.Color]::FromArgb(
            21, 21, 32
        )

    $Form.Controls.Add($HeaderPanel)

    $TopLine =
        New-Object System.Windows.Forms.Panel

    $TopLine.Dock = "Top"
    $TopLine.Height = 3
    $TopLine.BackColor =
        [System.Drawing.Color]::FromArgb(
            99, 102, 241
        )

    $HeaderPanel.Controls.Add($TopLine)

    $Title =
        New-Object System.Windows.Forms.Label

    $Title.Text =
        "BAM FORENSIC ANALYSIS"

    $Title.Font =
        New-Object System.Drawing.Font(
            "Segoe UI",
            22,
            [System.Drawing.FontStyle]::Bold
        )

    $Title.ForeColor =
        [System.Drawing.Color]::FromArgb(
            139, 92, 246
        )

    $Title.AutoSize = $true
    $Title.Location =
        New-Object System.Drawing.Point(
            30,
            30
        )

    $HeaderPanel.Controls.Add($Title)

    $Subtitle =
        New-Object System.Windows.Forms.Label

    $Subtitle.Text =
        "Windows Background Activity Moderator execution analysis"

    $Subtitle.Font =
        New-Object System.Drawing.Font(
            "Segoe UI",
            10
        )

    $Subtitle.ForeColor =
        [System.Drawing.Color]::FromArgb(
            203, 213, 225
        )

    $Subtitle.AutoSize = $true
    $Subtitle.Location =
        New-Object System.Drawing.Point(
            32,
            75
        )

    $HeaderPanel.Controls.Add($Subtitle)

    $Author =
        New-Object System.Windows.Forms.Label

    $Author.Text =
        "Made by @junchrist on Discord"

    $Author.Font =
        New-Object System.Drawing.Font(
            "Segoe UI",
            9
        )

    $Author.ForeColor =
        [System.Drawing.Color]::FromArgb(
            100, 116, 139
        )

    $Author.AutoSize = $true
    $Author.Location =
        New-Object System.Drawing.Point(
            32,
            103
        )

    $HeaderPanel.Controls.Add($Author)

    $StatsPanel =
        New-Object System.Windows.Forms.Panel

    $StatsPanel.Dock = "Top"
    $StatsPanel.Height = 85

    $StatsPanel.BackColor =
        [System.Drawing.Color]::FromArgb(
            15, 15, 23
        )

    $Form.Controls.Add($StatsPanel)

    function Add-Stat {
        param (
            [string]$Text,
            [string]$LabelText,
            [int]$X,
            [System.Drawing.Color]$TextColor
        )

        $Value =
            New-Object System.Windows.Forms.Label

        $Value.Text = $Text

        $Value.Font =
            New-Object System.Drawing.Font(
                "Consolas",
                18,
                [System.Drawing.FontStyle]::Bold
            )

        $Value.ForeColor = $TextColor
        $Value.AutoSize = $true

        $Value.Location =
            New-Object System.Drawing.Point(
                $X,
                10
            )

        $StatsPanel.Controls.Add($Value)

        $Label =
            New-Object System.Windows.Forms.Label

        $Label.Text = $LabelText

        $Label.Font =
            New-Object System.Drawing.Font(
                "Segoe UI",
                8
            )

        $Label.ForeColor =
            [System.Drawing.Color]::FromArgb(
                100, 116, 139
            )

        $Label.AutoSize = $true

        $Label.Location =
            New-Object System.Drawing.Point(
                $X,
                42
            )

        $StatsPanel.Controls.Add($Label)
    }

    $Total =
        @($Bam).Count

    $Valid =
        @(
            $Bam |
                Where-Object {
                    $_.'Signature Status' -eq
                    "Valid Signature"
                }
        ).Count

    $NotSigned =
        @(
            $Bam |
                Where-Object {
                    $_.'Signature Status' -eq
                    "Invalid Signature (NotSigned)"
                }
        ).Count

    $Invalid =
        @(
            $Bam |
                Where-Object {
                    $_.'Signature Status' -match
                    "HashMismatch|NotTrusted"
                }
        ).Count

    $Missing =
        @(
            $Bam |
                Where-Object {
                    $_.'Signature Status' -eq
                    "File Was Not Found"
                }
        ).Count

    Add-Stat `
        -Text $Total `
        -LabelText "TOTAL ENTRIES" `
        -X 35 `
        -TextColor ([System.Drawing.Color]::FromArgb(
            139, 92, 246
        ))

    Add-Stat `
        -Text $Valid `
        -LabelText "VALID" `
        -X 190 `
        -TextColor ([System.Drawing.Color]::FromArgb(
            16, 185, 129
        ))

    Add-Stat `
        -Text $NotSigned `
        -LabelText "NOT SIGNED" `
        -X 320 `
        -TextColor ([System.Drawing.Color]::FromArgb(
            245, 158, 11
        ))

    Add-Stat `
        -Text $Invalid `
        -LabelText "INVALID" `
        -X 480 `
        -TextColor ([System.Drawing.Color]::FromArgb(
            239, 68, 68
        ))

    Add-Stat `
        -Text $Missing `
        -LabelText "FILE NOT FOUND" `
        -X 620 `
        -TextColor ([System.Drawing.Color]::FromArgb(
            100, 116, 139
        ))

    $ControlPanel =
        New-Object System.Windows.Forms.Panel

    $ControlPanel.Dock = "Top"
    $ControlPanel.Height = 70

    $ControlPanel.BackColor =
        [System.Drawing.Color]::FromArgb(
            21, 21, 32
        )

    $Form.Controls.Add($ControlPanel)

    $Search =
        New-Object System.Windows.Forms.TextBox

    $Search.Font =
        New-Object System.Drawing.Font(
            "Segoe UI",
            10
        )

    $Search.ForeColor =
        [System.Drawing.Color]::FromArgb(
            248, 250, 252
        )

    $Search.BackColor =
        [System.Drawing.Color]::FromArgb(
            10, 10, 15
        )

    $Search.BorderStyle = "FixedSingle"

    $Search.Location =
        New-Object System.Drawing.Point(
            30,
            18
        )

    $Search.Size =
        New-Object System.Drawing.Size(
            600,
            32
        )

    $Search.Text =
        "Search files, paths, timestamps, or signatures..."

    $Search.ForeColor =
        [System.Drawing.Color]::FromArgb(
            100, 116, 139
        )

    $ControlPanel.Controls.Add($Search)

    $Search.Add_GotFocus({

        if (
            $Search.Text -eq
            "Search files, paths, timestamps, or signatures..."
        ) {

            $Search.Text = ""

            $Search.ForeColor =
                [System.Drawing.Color]::White
        }
    })

    $Search.Add_LostFocus({

        if ([string]::IsNullOrWhiteSpace($Search.Text)) {

            $Search.Text =
                "Search files, paths, timestamps, or signatures..."

            $Search.ForeColor =
                [System.Drawing.Color]::FromArgb(
                    100, 116, 139
                )
        }
    })

    $TablePanel =
        New-Object System.Windows.Forms.Panel

    $TablePanel.Dock = "Fill"

    $TablePanel.Padding =
        New-Object System.Windows.Forms.Padding(
            30, 20, 30, 20
        )

    $TablePanel.BackColor =
        [System.Drawing.Color]::FromArgb(
            10, 10, 15
        )

    $Form.Controls.Add($TablePanel)

    $ListView =
        New-Object System.Windows.Forms.ListView

    $ListView.Dock = "Fill"

    $ListView.View = "Details"

    $ListView.FullRowSelect = $true

    $ListView.GridLines = $false

    $ListView.HideSelection = $false

    $ListView.MultiSelect = $false

    $ListView.OwnerDraw = $true

    $ListView.Font =
        New-Object System.Drawing.Font(
            "Consolas",
            9
        )

    $ListView.BackColor =
        [System.Drawing.Color]::FromArgb(
            21, 21, 32
        )

    $ListView.ForeColor =
        [System.Drawing.Color]::FromArgb(
            248, 250, 252
        )

    [void]$ListView.Columns.Add(
        "Execution Time",
        170
    )

    [void]$ListView.Columns.Add(
        "File Path",
        500
    )

    [void]$ListView.Columns.Add(
        "Signature Status",
        250
    )

    [void]$ListView.Columns.Add(
        "File Name",
        260
    )

    $TablePanel.Controls.Add($ListView)

    $ListView.Add_DrawColumnHeader({

        param($Sender, $Event)

        $Event.Graphics.FillRectangle(
            (New-Object System.Drawing.SolidBrush(
                [System.Drawing.Color]::FromArgb(
                    30, 30, 46
                )
            )),
            $Event.Bounds
        )

        $Event.Graphics.DrawString(
            $Event.Header.Text,
            (New-Object System.Drawing.Font(
                "Segoe UI",
                8,
                [System.Drawing.FontStyle]::Bold
            )),
            (New-Object System.Drawing.SolidBrush(
                [System.Drawing.Color]::FromArgb(
                    139, 92, 246
                )
            )),
            $Event.Bounds.X + 10,
            $Event.Bounds.Y + 10
        )
    })

    $ListView.Add_DrawItem({

        param($Sender, $Event)

        if ($Event.ItemIndex % 2 -eq 0) {

            $Event.Graphics.FillRectangle(
                (New-Object System.Drawing.SolidBrush(
                    [System.Drawing.Color]::FromArgb(
                        21, 21, 32
                    )
                )),
                $Event.Bounds
            )
        }
        else {

            $Event.Graphics.FillRectangle(
                (New-Object System.Drawing.SolidBrush(
                    [System.Drawing.Color]::FromArgb(
                        18, 18, 28
                    )
                )),
                $Event.Bounds
            )
        }

        if ($Event.Item.Selected) {

            $Event.Graphics.FillRectangle(
                (New-Object System.Drawing.SolidBrush(
                    [System.Drawing.Color]::FromArgb(
                        45, 38, 75
                    )
                )),
                $Event.Bounds
            )
        }
    })

    $ListView.Add_DrawSubItem({

        param($Sender, $Event)

        $TextColor =
            [System.Drawing.Color]::FromArgb(
                203, 213, 225
            )

        if ($Event.ColumnIndex -eq 2) {

            switch -Regex ($Event.SubItem.Text) {

                "^Valid Signature$" {
                    $TextColor =
                        [System.Drawing.Color]::FromArgb(
                            16, 185, 129
                        )
                }

                "NotSigned" {
                    $TextColor =
                        [System.Drawing.Color]::FromArgb(
                            245, 158, 11
                        )
                }

                "HashMismatch|NotTrusted" {
                    $TextColor =
                        [System.Drawing.Color]::FromArgb(
                            239, 68, 68
                        )
                }

                "UnknownError" {
                    $TextColor =
                        [System.Drawing.Color]::FromArgb(
                            245, 158, 11
                        )
                }

                "File Was Not Found" {
                    $TextColor =
                        [System.Drawing.Color]::FromArgb(
                            100, 116, 139
                        )
                }
            }
        }

        $Event.Graphics.DrawString(
            $Event.SubItem.Text,
            $ListView.Font,
            (New-Object System.Drawing.SolidBrush(
                $TextColor
            )),
            $Event.Bounds.X + 10,
            $Event.Bounds.Y + 8
        )
    })

    foreach ($Entry in $Bam) {

        $Item =
            New-Object System.Windows.Forms.ListViewItem(
                [string]$Entry.'Execution Time'
            )

        [void]$Item.SubItems.Add(
            [string]$Entry.'File Path'
        )

        [void]$Item.SubItems.Add(
            [string]$Entry.'Signature Status'
        )

        [void]$Item.SubItems.Add(
            [string]$Entry.'File Name'
        )

        $Item.Tag = $Entry

        [void]$ListView.Items.Add($Item)
    }

    $Search.Add_TextChanged({

        if (
            $Search.Text -eq
            "Search files, paths, timestamps, or signatures..."
        ) {
            return
        }

        $Query =
            $Search.Text.Trim().ToLower()

        $ListView.BeginUpdate()

        $ListView.Items.Clear()

        foreach ($Entry in $Bam) {

            $SearchText = @(
                $Entry.'Execution Time'
                $Entry.'Execution UTC'
                $Entry.'User Execution Time'
                $Entry.'File Path'
                $Entry.'Signature Status'
                $Entry.'File Name'
                $Entry.User
                $Entry.SID
            ) -join " "

            if (
                [string]::IsNullOrWhiteSpace($Query) -or
                $SearchText.ToLower().Contains($Query)
            ) {

                $Item =
                    New-Object System.Windows.Forms.ListViewItem(
                        [string]$Entry.'Execution Time'
                    )

                [void]$Item.SubItems.Add(
                    [string]$Entry.'File Path'
                )

                [void]$Item.SubItems.Add(
                    [string]$Entry.'Signature Status'
                )

                [void]$Item.SubItems.Add(
                    [string]$Entry.'File Name'
                )

                $Item.Tag = $Entry

                [void]$ListView.Items.Add($Item)
            }
        }

        $ListView.EndUpdate()
    })

    $ListView.Add_DoubleClick({

        if ($ListView.SelectedItems.Count -eq 0) {
            return
        }

        $Entry =
            $ListView.SelectedItems[0].Tag

        $Details = @"
Execution Time:
$($Entry.'Execution Time')

Execution UTC:
$($Entry.'Execution UTC')

User Execution Time:
$($Entry.'User Execution Time')

File Name:
$($Entry.'File Name')

File Path:
$($Entry.'File Path')

Signature Status:
$($Entry.'Signature Status')

User:
$($Entry.User)

SID:
$($Entry.SID)

Registry Path:
$($Entry.'Registry Path')
"@

        [System.Windows.Forms.MessageBox]::Show(
            $Details,
            "BAM Entry Details",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
    })

    $Footer =
        New-Object System.Windows.Forms.Label

    $Footer.Text =
        "BAM Forensic Analysis  •  TimeZone: $UserTime  •  Entries: $Total"

    $Footer.Dock = "Bottom"

    $Footer.Height = 28

    $Footer.TextAlign =
        [System.Drawing.ContentAlignment]::MiddleCenter

    $Footer.Font =
        New-Object System.Drawing.Font(
            "Segoe UI",
            8
        )

    $Footer.ForeColor =
        [System.Drawing.Color]::FromArgb(
            100, 116, 139
        )

    $Footer.BackColor =
        [System.Drawing.Color]::FromArgb(
            21, 21, 32
        )

    $Form.Controls.Add($Footer)

    [void]$Form.ShowDialog()
}

Show-CustomGUI
