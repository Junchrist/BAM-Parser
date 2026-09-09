cls

Write-Host ""
Write-Host @"
                        d8b                           d8,                
                        ?88                          `8P            d8P  
                         88b                                     d888888P
 d8888b?88   d8P d8888b  888888b  d888b8b    88bd88b  88b .d888b,  ?88'  
d8b_,dPd88   88 d8P' `P  88P `?8bd8P' ?88    88P'  `  88P ?8b,     88P   
88b    ?8(  d88 88b     d88   88P88b  ,88b  d88      d88    `?8b   88b   
`?888P'`?88P'?8b`?888P'd88'   88b`?88P'`88bd88'     d88' `?888P'   `?8b
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
    Write-Host "No BAM entries found." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit
}

$rpath = @("HKLM:\SYSTEM\CurrentControlSet\Services\bam\","HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\")

$UserBias = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -ErrorAction SilentlyContinue).ActiveTimeBias

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

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

$XAML = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="BAM Forensic Analysis" Height="750" Width="1300"
        WindowStartupLocation="CenterScreen"
        Background="#000000">
    <Window.Resources>
        <Style TargetType="TextBlock">
            <Setter Property="FontFamily" Value="Consolas"/>
            <Setter Property="Foreground" Value="#FFFFFF"/>
        </Style>
        <Style TargetType="TextBox">
            <Setter Property="FontFamily" Value="Consolas"/>
            <Setter Property="Foreground" Value="#FFFFFF"/>
            <Setter Property="Background" Value="#0A0A0A"/>
            <Setter Property="BorderBrush" Value="#333333"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="8"/>
            <Setter Property="CaretBrush" Value="#FFFFFF"/>
        </Style>
        <Style TargetType="ListBox">
            <Setter Property="Background" Value="#0A0A0A"/>
            <Setter Property="BorderBrush" Value="#333333"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="FontFamily" Value="Consolas"/>
            <Setter Property="Foreground" Value="#FFFFFF"/>
        </Style>
        <Style TargetType="ListBoxItem">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Foreground" Value="#FFFFFF"/>
            <Setter Property="Padding" Value="5"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#1A1A1A"/>
                </Trigger>
                <Trigger Property="IsSelected" Value="True">
                    <Setter Property="Background" Value="#2A2A2A"/>
                </Trigger>
            </Style.Triggers>
        </Style>
        <Style TargetType="Button">
            <Setter Property="FontFamily" Value="Consolas"/>
            <Setter Property="Foreground" Value="#FFFFFF"/>
            <Setter Property="Background" Value="#1A1A1A"/>
            <Setter Property="BorderBrush" Value="#333333"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="10,5"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#333333"/>
                </Trigger>
            </Style.Triggers>
        </Style>
    </Window.Resources>
    <Grid Margin="10">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <StackPanel Grid.Row="0" Margin="0,0,0,10" HorizontalAlignment="Center">
            <TextBlock FontSize="12" Foreground="#888888" TextAlignment="Center" FontFamily="Consolas" xml:space="preserve">
                        d8b                           d8,                
                        ?88                          `8P            d8P  
                         88b                                     d888888P
 d8888b?88   d8P d8888b  888888b  d888b8b    88bd88b  88b .d888b,  ?88'  
d8b_,dPd88   88 d8P' `P  88P `?8bd8P' ?88    88P'  `  88P ?8b,     88P   
88b    ?8(  d88 88b     d88   88P88b  ,88b  d88      d88    `?8b   88b   
`?888P'`?88P'?8b`?888P'd88'   88b`?88P'`88bd88'     d88' `?888P'   `?8b
            </TextBlock>
            <TextBlock FontSize="24" FontWeight="Bold" Margin="0,10,0,0">BAM Forensic Analysis</TextBlock>
            <TextBlock FontSize="14" Foreground="#888888" Margin="0,5,0,0">Made by @junchrist on Discord</TextBlock>
        </StackPanel>

        <Grid Grid.Row="1" Margin="0,0,0,10">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <TextBox Grid.Column="0" x:Name="SearchBox" Margin="0,0,10,0" />
            <Button Grid.Column="1" x:Name="ExportBtn" Content="Export CSV" Width="100"/>
        </Grid>

        <Grid Grid.Row="2" Margin="0,0,0,10">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            <Border Grid.Column="0" Background="#0A0A0A" BorderBrush="#333333" BorderThickness="1" Margin="0,0,5,0" Padding="10">
                <StackPanel HorizontalAlignment="Center">
                    <TextBlock x:Name="TotalCount" FontSize="20" FontWeight="Bold" TextAlignment="Center">0</TextBlock>
                    <TextBlock Foreground="#666666" FontSize="10" TextAlignment="Center">TOTAL</TextBlock>
                </StackPanel>
            </Border>
            <Border Grid.Column="1" Background="#0A0A0A" BorderBrush="#333333" BorderThickness="1" Margin="5,0,5,0" Padding="10">
                <StackPanel HorizontalAlignment="Center">
                    <TextBlock x:Name="VerifiedCount" FontSize="20" FontWeight="Bold" TextAlignment="Center" Foreground="#888888">0</TextBlock>
                    <TextBlock Foreground="#666666" FontSize="10" TextAlignment="Center">VERIFIED</TextBlock>
                </StackPanel>
            </Border>
            <Border Grid.Column="2" Background="#0A0A0A" BorderBrush="#333333" BorderThickness="1" Margin="5,0,5,0" Padding="10">
                <StackPanel HorizontalAlignment="Center">
                    <TextBlock x:Name="SuspiciousCount" FontSize="20" FontWeight="Bold" TextAlignment="Center" Foreground="#666666">0</TextBlock>
                    <TextBlock Foreground="#666666" FontSize="10" TextAlignment="Center">SUSPICIOUS</TextBlock>
                </StackPanel>
            </Border>
            <Border Grid.Column="3" Background="#0A0A0A" BorderBrush="#333333" BorderThickness="1" Margin="5,0,5,0" Padding="10">
                <StackPanel HorizontalAlignment="Center">
                    <TextBlock x:Name="UnsignedCount" FontSize="20" FontWeight="Bold" TextAlignment="Center" Foreground="#888888">0</TextBlock>
                    <TextBlock Foreground="#666666" FontSize="10" TextAlignment="Center">UNSIGNED</TextBlock>
                </StackPanel>
            </Border>
            <Border Grid.Column="4" Background="#0A0A0A" BorderBrush="#333333" BorderThickness="1" Margin="5,0,0,0" Padding="10">
                <StackPanel HorizontalAlignment="Center">
                    <TextBlock x:Name="DeletedCount" FontSize="20" FontWeight="Bold" TextAlignment="Center" Foreground="#666666">0</TextBlock>
                    <TextBlock Foreground="#666666" FontSize="10" TextAlignment="Center">DELETED</TextBlock>
                </StackPanel>
            </Border>
        </Grid>

        <ListBox Grid.Row="3" x:Name="DataList" Margin="0,0,0,10">
            <ListBox.ItemTemplate>
                <DataTemplate>
                    <Grid>
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="180"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="150"/>
                            <ColumnDefinition Width="180"/>
                        </Grid.ColumnDefinitions>
                        <TextBlock Grid.Column="0" Foreground="#FFFFFF" FontSize="12" Text="{Binding Time}"/>
                        <TextBlock Grid.Column="1" Foreground="#AAAAAA" FontSize="12" TextWrapping="Wrap" Text="{Binding Path}"/>
                        <Border Grid.Column="2" BorderThickness="1" CornerRadius="4" Padding="6,2" Margin="0,2" HorizontalAlignment="Left">
                            <Border.Background>
                                <SolidColorBrush Color="{Binding SigBg}"/>
                            </Border.Background>
                            <Border.BorderBrush>
                                <SolidColorBrush Color="{Binding SigBorder}"/>
                            </Border.BorderBrush>
                            <TextBlock FontSize="10" FontWeight="Bold" TextAlignment="Center" Text="{Binding Signature}">
                                <TextBlock.Foreground>
                                    <SolidColorBrush Color="{Binding SigColor}"/>
                                </TextBlock.Foreground>
                            </TextBlock>
                        </Border>
                        <TextBlock Grid.Column="3" Foreground="#CCCCCC" FontSize="12" FontWeight="Bold" Text="{Binding FileName}"/>
                    </Grid>
                </DataTemplate>
            </ListBox.ItemTemplate>
        </ListBox>

        <Border Grid.Row="4" Background="#0A0A0A" BorderBrush="#333333" BorderThickness="1" Padding="10">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <TextBlock Grid.Column="0" FontSize="12" Foreground="#888888">Made by @junchrist</TextBlock>
                <StackPanel Grid.Column="1" Orientation="Horizontal">
                    <Button x:Name="GitHubBtn" Content="GitHub" Margin="0,0,10,0" Width="80"/>
                    <Button x:Name="DiscordBtn" Content="Discord" Width="80"/>
                </StackPanel>
            </Grid>
        </Border>
    </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader ([xml]$XAML)
$Window = [Windows.Markup.XamlReader]::Load($reader)

$SearchBox = $Window.FindName("SearchBox")
$DataList = $Window.FindName("DataList")
$TotalCount = $Window.FindName("TotalCount")
$VerifiedCount = $Window.FindName("VerifiedCount")
$SuspiciousCount = $Window.FindName("SuspiciousCount")
$UnsignedCount = $Window.FindName("UnsignedCount")
$DeletedCount = $Window.FindName("DeletedCount")
$ExportBtn = $Window.FindName("ExportBtn")
$GitHubBtn = $Window.FindName("GitHubBtn")
$DiscordBtn = $Window.FindName("DiscordBtn")

if ($SearchBox) {
    $SearchBox.Text = "Search files, paths, timestamps, or signatures..."
    $SearchBox.Foreground = "#666666"
}

$allData = New-Object System.Collections.ArrayList

foreach ($entry in $Bam) {
    $sigColor = "#FFFFFFFF"
    $sigBg = "#FF1A1A1A"
    $sigBorder = "#FF333333"
    
    switch ($entry.'Digital Signature') {
        "Verified" { 
            $sigColor = "#FF888888"
            $sigBg = "#FF0A1A0A"
            $sigBorder = "#FF444444"
        }
        "Suspicious" { 
            $sigColor = "#FF666666"
            $sigBg = "#FF1A0A0A"
            $sigBorder = "#FF444444"
        }
        "Unsigned" { 
            $sigColor = "#FF888888"
            $sigBg = "#FF0A0A1A"
            $sigBorder = "#FF444444"
        }
        "Deleted" { 
            $sigColor = "#FF666666"
            $sigBg = "#FF0A0A0A"
            $sigBorder = "#FF333333"
        }
    }
    
    $obj = [PSCustomObject]@{
        Time = $entry.'Last Execution User Time'
        Path = $entry.Path
        Signature = $entry.'Digital Signature'
        FileName = $entry.'File Name'
        SigColor = $sigColor
        SigBg = $sigBg
        SigBorder = $sigBorder
    }
    [void]$allData.Add($obj)
}

function Update-List {
    $searchText = $SearchBox.Text
    if ($searchText -eq "Search files, paths, timestamps, or signatures...") {
        $searchText = ""
    }
    
    $filtered = New-Object System.Collections.ArrayList
    
    if ($searchText) {
        foreach ($item in $allData) {
            if ($item.Time -match $searchText -or 
                $item.Path -match $searchText -or 
                $item.Signature -match $searchText -or 
                $item.FileName -match $searchText) {
                [void]$filtered.Add($item)
            }
        }
    } else {
        $filtered = $allData
    }
    
    $DataList.ItemsSource = $filtered
    
    $total = 0
    $verified = 0
    $suspicious = 0
    $unsigned = 0
    $deleted = 0
    
    foreach ($item in $filtered) {
        $total++
        switch ($item.Signature) {
            "Verified" { $verified++ }
            "Suspicious" { $suspicious++ }
            "Unsigned" { $unsigned++ }
            "Deleted" { $deleted++ }
        }
    }
    
    $TotalCount.Text = $total
    $VerifiedCount.Text = $verified
    $SuspiciousCount.Text = $suspicious
    $UnsignedCount.Text = $unsigned
    $DeletedCount.Text = $deleted
}

if ($SearchBox) {
    $SearchBox.Add_GotFocus({
        if ($SearchBox.Text -eq "Search files, paths, timestamps, or signatures...") {
            $SearchBox.Text = ""
            $SearchBox.Foreground = "#FFFFFF"
        }
    })
    
    $SearchBox.Add_LostFocus({
        if ([string]::IsNullOrWhiteSpace($SearchBox.Text)) {
            $SearchBox.Text = "Search files, paths, timestamps, or signatures..."
            $SearchBox.Foreground = "#666666"
        }
    })
    
    $SearchBox.Add_TextChanged({
        Update-List
    })
}

if ($ExportBtn) {
    $ExportBtn.Add_Click({
        $saveDialog = New-Object Microsoft.Win32.SaveFileDialog
        $saveDialog.Filter = "CSV Files (*.csv)|*.csv"
        $saveDialog.DefaultExt = "csv"
        $saveDialog.FileName = "BAM_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        
        if ($saveDialog.ShowDialog() -eq $true) {
            $data = $DataList.ItemsSource
            $csv = @()
            $csv += '"Time","Path","Signature","File Name"'
            foreach ($item in $data) {
                $csv += "`"$($item.Time)`",`"$($item.Path)`",`"$($item.Signature)`",`"$($item.FileName)`""
            }
            $csv -join "`r`n" | Out-File -FilePath $saveDialog.FileName -Encoding UTF8
            [System.Windows.MessageBox]::Show("Export completed successfully!", "Success", "OK", "Information")
        }
    })
}

if ($GitHubBtn) {
    $GitHubBtn.Add_Click({
        Start-Process "https://github.com/junchrist"
    })
}

if ($DiscordBtn) {
    $DiscordBtn.Add_Click({
        Start-Process "https://discordapp.com/users/1357122264595693739"
    })
}

if ($Window) {
    $Window.Add_Loaded({
        Update-List
    })
    
    $Window.Add_KeyDown({
        if ($_.Key -eq 'Escape') {
            $Window.Close()
        }
    })
    
    $Window.ShowDialog() | Out-Null
}
