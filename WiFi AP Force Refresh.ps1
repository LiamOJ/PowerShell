$command = {
# Initial network scan
C:\WINDOWS\system32\netsh.exe wlan show networks > C:\temp\start.tmp

# get all network data
$networks = C:\WINDOWS\system32\netsh.exe wlan show networks

# Parse interfaces - may return serialised string so use in for loop
$interfaces = ($networks | select-string -Pattern "Interface Name : ") -replace "Interface Name : ",""

# iterate over interfaces, switch em off and switch em on
foreach ($interface in $interfaces) {
    C:\WINDOWS\system32\netsh.exe interface set interface name="$($interface.Trim())" admin=disabled
    C:\WINDOWS\system32\netsh.exe interface set interface name="$($interface.Trim())" admin=enabled
}

# Give them a moment to scan
Start-Sleep -Seconds 10

# Get networks detected in range and write to temp folder
C:\WINDOWS\system32\netsh.exe wlan show networks > C:\temp\1337hax0r.tmp
}

$computer = "{{CHANGE ME}}"

$encoded = [convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))

Invoke-WmiMethod win32_process -ComputerName $computer -name create -ArgumentList "powershell.exe -windowstyle hidden -e $encoded"

# TO DO
# Could use a $using:computername to write the result to the temp of the initiating computer instead of the local one
