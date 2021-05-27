$all_data_hashmap = @{}

$all_data_hashmap.add("Critical",$false)

########## Data Collection ##########

# Error handling, if error restart service
$List_of_subscriptions = C:\windows\system32\wecutil.exe es

# Check Service
$WEC_Service_Status = (Get-Service -name WECSVC).Status

$all_data_hashmap.add("Service Status", $WEC_Service_Status)

# Are the subscriptions enabled
foreach ($subscription in $List_of_subscriptions) {
    $enabled_status = [Bool](Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\Subscriptions\$subscription).enabled
    $enable_key = "Enabled/$subscription"
    $all_data_hashmap.add($enable_key,$enabled_status)
}

# Get status of EVTX files we write to
$EVTX_file_status = Get-WinEvent -ListLog WEF-* | Select -Property Logname, Isenabled, Islogfull, LastWriteTime
foreach ($evtx in $EVTX_file_status) {
    $all_data_hashmap.add("EVTX/$($evtx.LogName)",$EVTX)
}

# Get todays logs from relevant logs
$EventCollector_Logs = Get-WinEvent -FilterHashtable @{logname='Microsoft-Windows-EventCollector/Operational';starttime=(Get-Date).AddDays(-1)}

$all_data_hashmap.add("Event Collector Logs",$EventCollector_Logs)

$WinRM_Logs = Get-WinEvent -FilterHashtable @{logname='Microsoft-Windows-EventCollector/Operational';starttime=(Get-Date).AddDays(-1)}

$all_data_hashmap.add("WinRM Logs",$WinRM_Logs)

# Runtime status checks - make sure to include a time out to detect issues with wecutil.exe
foreach ($subscription in $List_of_subscriptions) {
    $runtime_active_count_active = (C:\windows\system32\wecutil.exe gr $subscription | Select-String ": Active" | Measure).Count
    $runtime_active_title = "ActiveForwarders/$subscription"
    $all_data_hashmap.add($runtime_title,$runtime_active_count_active)

    $runtime_active_count_inactive = (C:\windows\system32\wecutil.exe gr $subscription | Select-String ": Inactive" | Measure).Count
    $runtime_active_title = "InactiveForwarders/$subscription"
    $all_data_hashmap.add($runtime_title,$runtime_active_count_inactive)
}

############################################################################################

function Restart_WEC_Service() {
    # Get process ID, force kill it, then start service again.
    $service = Get-CimInstance -Query "Select * from win32_Service where name ='WECSVC'"

    $processID = Get-Process -Id $service.ProcessID

    Stop-Process -Id $processID -Force

    Get-Service -name Wecsvc | Start-Service

    $all_data_hashmap.add("Last Forced Restart",(Get-Date))

    # Ensure service is running. Mark as critial if not
    if ( (Get-Service -name Wecsvc).Status -ne "Running") {
        $all_data_hashmap.add("Critical",$true)
    }
}

########## Actions On ##########

