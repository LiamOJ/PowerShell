<# 
        -Do a sequential restart counter - if last log is Critical increment a counter field
        1 - Check complete
        2 - Service Error - Requires Restart
        3 - Service Error - Does not require a restart
        4 - Service Error - Manual Intervention Required
        5 - Restart Performed
        6 - Restart Failed 
#>

######################################## Functions and Variables ########################################
# The entire body of code is in a try block to catch if something goes wrong during the scheduled task. 

while($true) {
Write-Host "Starting Script"
try {

    $all_data_hashmap = @{}
    $evtlog = "WindowsEventCollection"
    $all_data_hashmap.add("_Critical",$false)
    $all_data_hashmap.add("_ErrorInfo","")
    $day_range_to_check_logs = 1 # grabs last N days of logs - keep small 
    $minute_range_to_check_logs = 15 # from there filter down to last N minutes of logs - depends on how often that task is run
    $eventcollector_EVID = 501 #dropped events
    $winrm_EVID = 173 #dropped connections
    $Timeout = 60 # the timeout in seconds for wecutil when checking runtime information
    $last_time_since_write = 24 # will raise issue if log file hasn't been written to in this time.
    $logname_prefix = 'WEF-' #this occur prior to the logifle name that is being written to. It cannot be left blank. 
    $EPS_time_frame = 30 # time frame we take our EPS measurements over
    $max_time_limit_multuple =  2 # max time we'll wait for jobs to complete, multiple of EPS_Time_frame


    # Name:
    # Purpose:
    # Method: 
    function Get-WECServiceStatus () {
        (Get-Service -name WECSVC).Status
    }

    # Name:
    # Purpose:
    # Method: 
    function Write-WECLog {

        param (
            [Parameter(Mandatory)]
            [Int32]$evtID,

            [Parameter(Mandatory)]
            [String]$evtlog,

            [Parameter(Mandatory)]
            [String]$source,

            [Parameter(Mandatory)]
            [String]$Message,

            [Parameter(Mandatory=$false)]
            [Array]$data,

            [Parameter(Mandatory)]
            [Int32]$type

        )

        # Check if log type exists, if not create
        if ([System.Diagnostics.EventLog]::SourceExists($source) -eq $false) {
            [System.Diagnostics.EventLog]::CreateEventSource($source, $evtlog)
        }

        # Determine type of log
        switch ($type) {
            1 {$id = New-Object System.Diagnostics.EventInstance($evtID,1)} #INFORMATION EVENT
            2 {$id = New-Object System.Diagnostics.EventInstance($evtID,1,2)} #WARNING EVENT
            3 {$id = New-Object System.Diagnostics.EventInstance($evtID,1,1)} #ERROR EVENT
        }

        # Combine data and message into an array
        [Array] $JoinedMessage = @(
            $Message
            $data | ForEach-Object { $_ }
        )

        # Create eventlog object and complete required data
        $evtObject = New-Object System.Diagnostics.EventLog;
        $evtObject.Log = $evtlog;
        $evtObject.Source = $source;

        #Perform write
        try {
            $evtObject.WriteEvent($id, $JoinedMessage)
        } catch {
            Write-Warning "Write-Event - Couldn't create new event - $($_.Exception.Message)"
        }
    }

    # Name:
    # Purpose:
    # Method: 
    function Restart_WEC_Service($force) {
        # Include errorinfo in the 666 log saying why the service was restarted. 

        # Check if status is critical, if true restart service
        if(($all_data_hashmap['_Critical']) -or $force) {

            Write-Host "Attempting to restart WECSVC service" -ForegroundColor Cyan

            Write-WECLog -evtID 5 -evtlog $evtlog -source "WEC Service: Restart Attemped" -Message "A WEC Service restart was attempted" -type 2

            # Get process ID, force kill it, then start service again.
            $service = Get-CimInstance -Query "Select * from win32_Service where name ='WECSVC'"

            $processID = (Get-Process -Id $service.ProcessID).Id

            Stop-Process -Id $processID -Force

            # Put this here as it often fails to start the process otherwise
            Start-Sleep -Seconds 5
    
            $wec = Get-Service -name Wecsvc

            # try, try, try again to start the WEC service
            try {
                $wec.Start()
            } catch {
                Get-service -name Wecsvc | Start-Service
            } finally {
                Start-Sleep -Seconds 10

                if ($wec.Status -ne "Running") {
                    Get-service -name Wecsvc | Start-Service
                }
                # Check 2 ways for if the service is running. If not, write Error log and set to critical
                if ($wec.Status -ne "Running" -or (Get-Service -name Wecsvc).Status -ne "Running") {
                    Write-WECLog -evtID 6 -evtlog $evtlog -source "Service Error: WEC Service Start Failed" -Message "The WEC Service could not be started. Manual intervention required" -type 3
                    $all_data_hashmap["_Critical"] = $true
                    $all_data_hashmap["_Errorinfo"] += "| The WEC service could not be started |"
                }
            }

            $all_data_hashmap["_Last Forced Restart"] = (Get-Date)
        
        }
    }

    ######################################## Data Collection ########################################

    # This block of code is to get the subscription names, however the following error handling
    # is to try and catch if the service and its management tool are not responding properly
    try {
        $List_of_subscriptions = C:\windows\system32\wecutil.exe es
    } catch {
        $wecutil_exit_code = $LASTEXITCODE
        $all_data_hashmap['_ErrorInfo'] += "Unable to get Subscription data from wecutil.exe"
        Restart_WEC_Service($true)
    } finally {
        # Check two ways for errors
        if (-not $? -or $LASTEXITCODE -eq 1722) { #should this not be $wecutil_exit_code?

            # If errors build event log entry, write and restart service
            $Message = "An error occured. Wecutil.exe returned error code $($LASTEXITCODE). `nIf this log occurs and is not met by a successful restart then it is likely there is an underlying issue and manual inspection of the WEC servers and WEC service is strongly suggested."
            $type = 2
            Write-WECLog -evtID 2 -source "WEC Error: Restart Required" -evtlog $evtlog -type 2 -Message $Message
            $all_data_hashmap['_ErrorInfo'] += "Unable to get Subscription data from wecutil.exe"
            Restart_WEC_Service($true)
        }
    }

    # Check Service
    $all_data_hashmap["_Service Status"] = Get-WECServiceStatus

    # Are the subscriptions enabled, check via registry. Iterates over list of all subscriptions pulled by wecutil 
    foreach ($subscription in $List_of_subscriptions) {
        $enabled_status = [Bool](Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\Subscriptions\$subscription).enabled
        $enable_key = "Subscription/$subscription/Enabled"
        $all_data_hashmap.add($enable_key,$enabled_status)
    }

    # Get status of EVTX files that we write to. If they are missing an error will occur 
    try {
        $EVTX_file_status = Get-WinEvent -ListLog WEF-* | Select -Property Logname, Isenabled, Islogfull, LastWriteTime

        foreach ($evtx in $EVTX_file_status) {
            $hours_since_last_write = [math]::Round(((Get-Date) - $evtx.LastWriteTime).TotalHours,2)
            $all_data_hashmap.add("EVTX/$($evtx.LogName)/IsEnabled",$EVTX.IsEnabled)
            $all_data_hashmap.add("EVTX/$($evtx.LogName)/HoursSinceLastWrite",$hours_since_last_write)
            $all_data_hashmap.add("EVTX/$($evtx.LogName)/IsLogFull",$EVTX.IsLogFull)
        }

        } catch {
            $all_data_hashmap['_ErrorInfo'] += "| A logfile cannot be accessed. Manual investigation required. |"
            #$all_data_hashmap["_Critical"] = $true #removed as a restart wouldn't help - keep the below error write as it happens if the logfile can't be accessed
            Write-WECLog -evtID 3 -evtlog $evtlog -source "WEC Error: No Restart Required" -Message "A logfile cannot be accessed. Manual investigation required" -type 3
        } 

    # Get 24 hours of logs from WinRM and EventCollector log sources. If none, return is $false. If some, filter for key EVIDs and store count.
    try {
        $EventCollector_Logs = Get-WinEvent -FilterHashtable @{logname='Microsoft-Windows-EventCollector/Operational';starttime=(Get-Date).AddDays( -$day_range_to_check_logs )} -ErrorAction Stop
        $EventCollector_Logs = ($EventCollector_Logs | ? {$_.ID -eq $eventcollector_EVID -and $_.TimeCreated -ge $((Get-Date).AddMinutes(-$minute_range_to_check_logs))} | measure).Count
    } catch {
        $EventCollector_Logs = $false
    }

    $all_data_hashmap.add("Logs_EventCollector_EVID_501",$EventCollector_Logs)

    try {
        $WinRM_Logs = Get-WinEvent -FilterHashtable @{logname='Microsoft-Windows-WinRM/Operational';starttime=(Get-Date).AddDays( -$day_range_to_check_logs )} -ErrorAction Stop
        $WinRM_Logs = ($WinRM_Logs | ? {$_.ID -eq $winrm_EVID -and $_.TimeCreated -ge $((Get-Date).AddMinutes(-$minute_range_to_check_logs))} | measure).Count
    } catch {
        $WinRM_Logs = $false
    }

    $all_data_hashmap.add("Logs_WinRM_EVID_173",$WinRM_Logs)

    # Runtime status checks - make sure to include a time out to detect issues with wecutil.exe
    foreach ($subscription in $List_of_subscriptions) {

        # This block of code is largely a wrapper around wecutil, looking for timeouts that occur when the service is running slowly
        # It will create a time limited job that will get the active forwarders, if it times out it will restart the service
        # It will attempt this process 3 times, writing error information twice. 

        $retry = $false
        $retry_limit = 2

        do {
            $job_active  = Start-Job -ScriptBlock {(C:\windows\system32\wecutil.exe gr $using:subscription | Select-String ": Active" | Measure).Count}
            
            if (Wait-Job $job_active -Timeout $timeout) { 
                # Comes here if there is no time out - does not mean the result is good (> 0 forwarders) this is checked further below

                # Get the job, if successful it will be an integer
                $runtime_active_count_active = Receive-Job $job_active 

                # Remove job
                Remove-Job -Job $job_active
                $retry = $false
                
            } else {
                # Comes here if there is a timeout - set this to false so that an issue is raised. 
                $all_data_hashmap['_ErrorInfo'] += "| Timeout occured while trying to use Wecutil.exe. The service will be restarted. Typically this is all that is required to resolve the issue. The task will attempt to get the wecutil data $($retry_limit) more times before exiting |"
                Restart_WEC_Service($true)
                Start-Sleep -Seconds 5
                $retry = $true 
                $runtime_active_count_active = $false
            }

            $retry_limit--
            
        } while ( $retry -eq $true -and $retry_limit -gt 0)


        $runtime_active_title = "Subscription/$subscription/ActiveForwarders"
        $all_data_hashmap.add($runtime_active_title,$runtime_active_count_active)
    }

    # Check processor is actually actively working with process
    # There is some debate about how this should be done, it may be necessary to make changes 
    # https://stackoverflow.com/questions/11523150/how-do-you-monitor-the-cpu-utilization-of-a-process-using-powershell
    $iteration_limit = 5
    $percentprocessortime = 0
    for ($counter = 0; $counter -lt $iteration_limit; $counter++ ) {
        $percentprocessortime += (Get-CimInstance -Query "select * from Win32_PerfFormattedData_PerfProc_Process where IDprocess = '$((Get-CimInstance -Query "Select * from win32_Service where name ='WECSVC'").ProcessID)'").PercentProcessorTime
        Start-Sleep -Seconds 1
    }

    # Take average and add to hashtable
    $percentprocessortime /= $iteration_limit

    $all_data_hashmap.add("PercentProcessorTime",$percentprocessortime)

    # Get Events Per Second for each Subscription. 
    # Remove old jobs 
    Get-job | Remove-Job

    # EPS Collector
    foreach ($sub in $List_of_subscriptions) {
    
        $job_name = $sub   
    
        Start-Job -Name $job_name -ScriptBlock {

            # There needs to be error handling here for if there's no counters - possibly consider generating an error log if there isn't with remediation advice

            $events_lost_start = (Get-Counter -Counter "\Event Tracing for Windows Session(wef-$($using:sub))\Events Lost").CounterSamples.CookedValue

            $EPS = (Get-Counter -Counter "\Event Tracing for Windows Session(wef-$($using:sub))\Events Logged Per sec" -SampleInterval $using:EPS_time_frame).CounterSamples.CookedValue

            $events_lost_end = (Get-Counter -Counter "\Event Tracing for Windows Session(wef-$($using:sub))\Events Lost").CounterSamples.CookedValue

            $events_lost_difference = ($events_lost_end - $events_lost_start) / $using:EPS_time_frame

            $EPS += $events_lost_difference

            return $EPS

        } > $null

    }

    # give jobs time to complete
    $job_count = (Get-job -State Completed | measure).count

    $maximum_job_wait_time = $EPS_time_frame * $max_time_limit_multuple

    $stopwatch_EPS_jobs = [Diagnostics.Stopwatch]::StartNew()

    $stopwatch_EPS_jobs.Start()

    while ($job_count -lt $List_of_subscriptions.Count) {

        # Stop if time limit exceeded - currently setting to 2 times the EPS_Time_Frame
        if ($stopwatch_EPS_jobs.Elapsed.TotalSeconds -gt $maximum_job_wait_time) {
            # May wish to write error log here that did not wait for job to finish
            break
        }

        # Update job count
        $job_count = (Get-job -State Completed | measure).count

    }

    $stopwatch_EPS_jobs.Stop()

    # Collect data
    foreach ($sub in $List_of_subscriptions) {
    
        $EPS_to_add = [math]::Round((Receive-Job -name $sub),0)

        $all_data_hashmap.add("Subscription/$sub/_EventsPerSecond",$EPS_to_add)
    
        # Clear jobs 
        Get-job -Name $sub | Remove-Job
    }


    ######################################## Actions On ########################################

    # Logic is to check for a POSITIVE match on an UNDESIRABLE status. If TRUE then CRITICAL.

    # Check if service is enabled. Should be FALSE
    $service_status_bool = [Bool]$all_data_hashmap.'_Service Status' -ne "Running" 

    # Check if log files are full - should be FALSE
    $logfile_full_bool = [Bool](($all_data_hashmap.GetEnumerator() | where {$_.Name -like "*/IsLogFull*"}).Value).Contains($true)

    # Check if log files are enabled - should be FALSE
    $logfile_enabled_bool = [Bool](($all_data_hashmap.GetEnumerator() | where {$_.Name -like "*/IsEnabled*"}).Value).Contains($false)

    # Check there are > 0 ActiveForwarders (might be worth checking it's a % of active computers from AD here?) 
    # Should be FALSE
    $subscription_0_forwarders_bool = $false
    
    ForEach ($sub_name in $List_of_subscriptions) {
        # ensure the subscription is active, as an inactive one will have 0 anyway
        if ($all_data_hashmap["Subscription/$sub_name/Enabled"] -and $all_data_hashmap["Subscription/$sub_name/ActiveForwarders"] -eq $false) {
            $subscription_0_forwarders_bool = $true
        }
    }

    # Processor Time average at 0 - should be FALSE
    $percentprocessortime_bool = [Bool]($percentprocessortime -eq 0)

    # LastWriteTime of file is within last 24 hours
    $checktime = (Get-Date).AddHours(-24)

    # iterates over lastwritestimes checking is longer than 12 hours and ago and currently an enabled subscription.  
    # Should be FALSE    
    ForEach ($sub_name in $List_of_subscriptions) {
        # ensure the subscription is active, as an inactive one will have 0 anyway
        if ($all_data_hashmap["Subscription/$sub_name/Enabled"] -and $all_data_hashmap["EVTX/WEF-$sub_name/HoursSinceLastWrite"] -gt $last_time_since_write ) {
            $lastwritetime_bool = $true
        }
    }

    #################### WRITE ERROR LOGS ####################
    # Check if specific error logs have been found and if so set to Critical and write errorinfo
    if ( $EventCollector_Logs ) {
        $all_data_hashmap['_ErrorInfo'] += "| Events are being lost. Manual investigation required. |"
        $all_data_hashmap["_Critical"] = $true
        Write-WECLog -evtID 2 -evtlog $evtlog -source "WEC Error: Restart Required" -Message "Events have been lost in the last $minute_range_to_check_logs minutes. A restart of the WEC service will be attemped, however this may not correct the issue." -type 2
    }

    if ( $WinRM_Logs ) {
        $all_data_hashmap['_ErrorInfo'] += "| WinRM connections are being dropped. Manual investigation required. |"
        $all_data_hashmap["_Critical"] = $true
        Write-WECLog -evtID 2 -evtlog $evtlog -source "WEC Error: Restart Required" -Message "WinRM connections have been dropped in the last $minute_range_to_check_logs minutes. A restart of the WEC service will be attemped, however this may not correct the issue." -type 2
    }

    # Error if service is not enabled in the first place
    if ( $service_status_bool ) {
        $all_data_hashmap['_ErrorInfo'] += "| The service is not in a 'Running' state |"
        $all_data_hashmap["_Critical"] = $true
        Write-WECLog -evtID 2 -evtlog $evtlog -source "WEC Error: Restart Required" -Message "The WECSVC is not in a running state. A restart will be attempted" -type 3
        # Might be we want to change this to just change the service back on?
    }

    # Carry out action and fill ErrorInfo param
    if ( $logfile_full_bool) {
        $all_data_hashmap['_ErrorInfo'] += "| A logfile is full |"
        #$all_data_hashmap["_Critical"] = $true #disabled this as restarting the service will not resolve the issue
        Write-WECLog -evtID 4 -evtlog $evtlog -source "WEC Error: Manual Intervention Required" -Message "A logfile is full. This must be manually corrected. No service restart has been attempted." -type 3
        # Should write an ERROR or WARNING log here indicating the issue 
    }

    if ( $logfile_enabled_bool ) {
        $all_data_hashmap['_ErrorInfo'] += "| A logfile is disabled |"
        #$all_data_hashmap["_Critical"] = $true  #disabled this as restarting the service will not resolve the issue
        Write-WECLog -evtID 4 -evtlog $evtlog -source "WEC Error: Manual Intervention Required" -Message "A logfile is disabled. This must be manually corrected. No service restart has been attempted." -type 3
        # Should write an ERROR or WARNING log here indicating the issue 
    }

    if ( $subscription_0_forwarders_bool ) {
        $all_data_hashmap['_ErrorInfo'] += "| An enabled subscription has no active forwarders |"
        $all_data_hashmap["_Critical"] = $true
        Write-WECLog -evtID 2 -evtlog $evtlog -source "WEC Error: Restart Required" -Message "An enabled subscription has been found to have no active forwarders. It is assumed that there is an issue with the service and a restart will be attempted. It is also possible there is an issue with the SDDL, ACLs or GPO. If a restart does not correct the issue manual investigation is required." -type 2
    }

    if ( $percentprocessortime_bool ) {
        $all_data_hashmap['_ErrorInfo'] += "| The scvhost.exe process appears inactive |"
        $all_data_hashmap["_Critical"] = $true
        Write-WECLog -evtID 2 -evtlog $evtlog -source "WEC Error: Restart Required" -Message "The svchost executing the Windows event collection service does not appear to be doing anything. If this is the case it is likely events are not being written to disk." -type 2
    }

    if ( $lastwritetime_bool ) {
        $all_data_hashmap['_ErrorInfo'] += "| A lastwritetime for a logfile is greater than 24 hours ago |"
        #$all_data_hashmap["_Critical"] = $true
        # Doesn't actually fix this, and its debatable if its even an issue
        # Write this to new log type 3
        Write-WECLog -evtID 3 -evtlog $evtlog -source "WEC Error: No Restart Required" -Message "A logfile has not been written to in more than 24 hours. This may occur is very few events are being sent to the WEC server" -type 2
    }


    ######################################## Write Status Log ########################################
    #Define event log params
    $evtID = 1
    $Message = "WECSVC Check complete" + "`n$($all_data_hashmap._ErrorInfo)"
    $source = "WEC Check Complete"

    # Convert hashtable into array to be written to event log. 
    $data = @($all_data_hashmap.GetEnumerator() | % { "$($_.Name)=$($_.Value)" }) | Sort

    Write-WECLog -evtID $evtID -evtlog $evtlog -source $source -Message $Message -data $data -type 1


    ######################################## Attempt service restart ########################################
    # In the event the Critical status has been set to true this will restart the service 

    Restart_WEC_Service

    } catch {
        Write-Host "The WECSVC scheduled task encountered an unknown error and ended: $($_.Exception.Message)"
        Write-WECLog -evtID 4 -evtlog $evtlog -source "WECSVC Scheduled Task Error" -Message "The WEC service scheduled task encountered an unknown error and had to end. Manual investigation required. "  -data $($_.Exception.Message) -type 3
}

Write-Host "Finished script. Sleeping"
Start-Sleep -Seconds 600

}                 
