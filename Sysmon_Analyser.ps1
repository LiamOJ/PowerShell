$time_period = 24
$id_hash_table_for_counting = @{}

if ( -not ($all_events.length -gt 0) ) {
    $all_events = Get-WinEvent -FilterHashtable @{
    logname="microsoft-windows-sysmon/operational";
    starttime=(Get-date).addhours(-$time_period);
    };
}

# Total logs
Write-Host "[*] Number of events in the last $time_period hours is:" $all_events.Count

# List unique values
Write-Host "IDs of events seen in last 24 hours"
$event_IDs = $all_events | Sort-Object -Property ID -Unique 
$event_IDs

# Get count of each type of event
Write-Host "Get Counts"
$all_events | Group-Object -Property id | Select-Object -Property Name,Count | Format-table 

$some_events = $all_events | Where-Object { $_.id -eq 1 } | Select-Object -First 3

foreach ( $something in $some_events.Message  ) {
    foreach ( $thingy in $some_events ) {
        Write-Host "-------------------"
        $thingy
    }
}


