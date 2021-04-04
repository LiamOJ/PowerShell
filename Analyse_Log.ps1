function Analyse-Log {

    <#
        .SYNOPSIS
            Analyse the specified log. Originally intended to aid customisation of Sysmon configuration. 
            Logs currently known to work: Sysmon/Operational and Security 
            Current issues: errors with System (summary works, nothing else) and Powershell/Operational (4104 script blocks aren't working)
        .DESCRIPTION
            Essentially a syntactically simple wrapper for Wevtutil.
            Queries a local or remote event log, parsing the event data into searchable fields. 
            It provides the some of the functionality of Xpaths but without the complex syntax. 


        .PARAMETER TimePeriod
            Measured in hours. This has a default is 1 hour. 
            E.g. Analyse-Log -TimePeriod 12 -LogName Security

        .PARAMETER ComputerName
            The name of the computers you wish to query. The default is the current system. 
            E.g Analyse-Log -ComputerName LT12345 -Summary

        .PARAMETER QueryID
            The Event ID number you wish to query 
            E.g. Analyse-Log -QueryID 1

        .PARAMETER Summary
            Provides a brief summary of totals.
            E.g. Analyse-Log -TimePeriod 24 -Summary

        .PARAMETER SummaryDepth
            The log results are provided top first, by the number specified by this variable. Default is 10.
            E.g. Analyse-Log -QueryID 15 -SummaryDepth 5

        .PARAMETER LogName
            The log you wish to query. The default is Microsoft-Windows-Sysmon/Operational.
            E.g. Anaylse-Log -Logname Security -Summary

        .PARAMETER Field
            The name of the log line you wish to query.
            E.g. Analyse-Log -TimePeriod 24 -QueryId 1 -Field ParentImage

        .PARAMETER Value
            The specified value of the field you wish to search for. Must be used after Field
            E.g. Analyse-Log -TimePeriod 12 -QueryID 1 -Field Image -Value C:\Windows\System32\cmd.exe

        .PARAMETER FieldList
            Gives a list of all available fields for the Event ID specified by -QueryID
            E.g. -QueryID 1 -FieldList

        .PARAMETER Display
            This switch must be set if you wish to print out the full log. The default depth of 3 is used if it is not set.
            E.g. Analyse-Log -TimePeriod 5 -QueryID 1 -Field Image -Value "*firefox.exe" -Display

        .PARAMETER SubField
            For when you have selected logs matching a Field and Value pair but you do not want the full output
            E.g Analyse-Log -TimePeriod 5 -QueryID 1 -Field Image -Value "*firefox.exe" -SubField ParentImage,CommandLine -SummaryDepth 4 
               
        .PARAMETER Path
            Takes the log from the specified path rather than the local or a remote system.
            E.g. Analyse-Log -Path C:\Temp\logs.evtx -TimePeriod 12 -QueryID 1 -Field Image -Value C:\Windows\System32\cmd.exe 

        .PARAMETER DisplayDepth
            Limits the printed out logs to the specified number. The Default is 3. 
            E.g. Analyse-Log -TimePeriod 5 -QueryID 1 -Field Image -Value "*firefox.exe" -Display -DisplayDepth 4
        

        .INPUTS
            None
        .OUTPUTS
            Tables of summarised data via Format-Table, or pased log output. 

                                      
        .EXAMPLE
        This will get a summary of the default logs (Sysmon) for the last 5 hours from the default computer (current machine) and output. 

        PS C:\Users\User\Documents> Analyse-Log -TimePeriod 5 -Summary
        [*] Fetching logs ...
        [*] Logs fetched. Now analysing...
        [*] Number of events in the last 5 hours is: 970
        [*] IDs of events seen in last 5 hours

        Get Counts
        Id Message                                                                                                                            
        -- -------                                                                                                                            
         1 Process Create:...                                                                                                                 
         3 Network connection detected:...                                                                                                    
         4 Sysmon service state changed:...                                                                                                   
         5 Process terminated:...                                                                                                             
         6 Driver loaded:...                                                                                                                  
        11 File created:...                                                                                                                   
        12 Registry object added or deleted:...                                                                                               
        13 Registry value set:...                                                                                                             
        15 File stream created:...                                                                                                            


        Name Count Percent
        ---- ----- -------
        1      446 45.98% 
        11     356 36.70% 
        13     129 13.30% 
        3       11 1.13%  
        6       11 1.13%  
        5        7 0.72%  
        12       5 0.52%  
        15       4 0.41%  
        4        1 0.10%  
        
        .EXAMPLE
        You can list the Field names for any event that is within the captured logs

        PS C:\Users\User\Documents> Analyse-Log -TimePeriod 5 -QueryID 1 -FieldList
        [*] Fetching logs ...
        [*] Logs fetched. Now analysing...
        The state of the current PowerShell instance is not valid for this operation.
        At line:0 char:0

        Field Names for Event ID 1
        Time
        ParentCommandLine
        Description
        CommandLine
        CurrentDirectory
        User
        Hashes
        Image
        UtcTime
        ProcessGuid
        Company
        IntegrityLevel
        EventID
        FileVersion
        Process Create
        RuleName
        Product
        LogonId
        ProcessId
        LogonGuid
        TerminalSessionId
        ParentProcessGuid
        ParentProcessId
        ParentImage

        .EXAMPLE
        From this point you may wish to drill down, here we can see a specific event ID selected, with the output limited to the top 5 results and showing only the Image field. 

        Multiple Field parameters may be specified  (or none at all for a full output)

        PS C:\WINDOWS\system32> Analyse-Log -TimePeriod 1 -QueryID 1 -SummaryDepth 5 -Field Image
        Image
        Summary for 
         Event ID:1 
         Field: Image

        Count Name                                                                                               
        ----- ----                                                                                               
            5 C:\Windows\System32\cmd.exe                                                                        
            4 C:\Windows\System32\sc.exe                                                                         
            3 C:\Windows\System32\icacls.exe                                                                     
            3 C:\Windows\System32\wbem\WmiPrvSE.exe                                                              
            2 C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe   

        .EXAMPLE
        You may then drill down further by looking for summaries of all other fields matching a specified Event ID and Field. In this case only 1 Field parameter should be specified. 

        PS C:\Users\User\Documents> Analyse-Log -TimePeriod 5 -QueryID 1 -Field Image -Value "*svchost.exe"
        [*] Fetching logs ...
        [*] Logs fetched. Now analysing...
        Summary for 
         Event ID:1 
         Field: Time

        Count Name               
        ----- ----               
            1 01/03/2021 12:29:00
            1 01/03/2021 08:20:32
            1 01/03/2021 08:20:32
            1 01/03/2021 08:20:32
            1 01/03/2021 08:20:32
            1 01/03/2021 08:20:33
            1 01/03/2021 08:20:33
            1 01/03/2021 08:20:33
            1 01/03/2021 08:20:33
            1 01/03/2021 08:20:33


        Summary for 
         Event ID:1 
         Field: ParentCommandLine

        Count Name                            
        ----- ----                            
          111 C:\WINDOWS\system32\services.exe


        Summary for 
         Event ID:1 
         Field: Description

        Count Name                             
        ----- ----                             
          111 Host Process for Windows Services

          (output truncated ... )

        .EXAMPLE
        Here we can specify which SubFields we want displayed and to what depth (decided by the First N entries). 

        PS C:\Users\User\Documents> Analyse-Log -TimePeriod 5 -QueryID 1 -Field Image -Value "*firefox.exe" -SubField ParentImage,CommandLine -SummaryDepth 3
        [*] Fetching logs ...
        [*] Logs fetched. Now analysing...
        Summary for 
            Event ID:1 
            Field: ParentImage

        Count Name                                        
        ----- ----                                        
            17 C:\Program Files\Mozilla Firefox\firefox.exe
            2 C:\Program Files\Mozilla Firefox\updater.exe
            1 C:\Windows\explorer.exe                     


        Summary for 
            Event ID:1 
            Field: CommandLine

        Count Name                                                                                                                                            
        ----- ----                                                                                                                                            
            6 "C:\Program Files\Mozilla Firefox\firefox.exe"                                                                                                  
            1 "C:\Program Files\Mozilla Firefox\firefox.exe" -contentproc --channel="16876.90.1950749878\1884807123" -childID 13 -isForBrowser -prefsHandle   
                7896 -prefMapHandle 6968 -prefsLen 14547 -prefMapSize 244344 -parentBuildID 20210222142601 -appdir "C:\Program Files\Mozilla Firefox\browser" - 
                16876 "\\.\pipe\gecko-crash-server-pipe.16876" 3184 tab                                                                                         
            1 "C:\Program Files\Mozilla Firefox\firefox.exe" -contentproc --channel="16876.83.1359252187\986738803" -childID 12 -isForBrowser -prefsHandle    
                3468 -prefMapHandle 5280 -prefsLen 14547 -prefMapSize 244344 -parentBuildID 20210222142601 -appdir "C:\Program Files\Mozilla Firefox\browser" - 
                16876 "\\.\pipe\gecko-crash-server-pipe.16876" 6372 tab  


        .EXAMPLE
        If you wish to display the full log/s matching a specific query you can do so in the following way

        PS C:\Users\User\Documents> Analyse-Log -TimePeriod 5 -QueryID 1 -Field Image -Value "*firefox.exe" -Display -DisplayDepth 4
        [*] Fetching logs ...
        [*] Logs fetched. Now analysing...
        Summary for 
         Event ID:1 
         Field: Time

        Name                           Value                                                                            
        ----                           -----                                                                            
        Time                           01/03/2021 13:25:52                                                              
        ParentCommandLine              "C:\Program Files\Mozilla Firefox\firefox.exe"                                   
        Description                    Firefox                                                                          
        CommandLine                    "C:\Program Files\Mozilla Firefox\firefox.exe" -contentproc --channel="16876.9...
        CurrentDirectory               C:\Program Files\Mozilla Firefox\                                                
        User                           SCOTLAND\U447692                                                                 
        Hashes                         MD5=21754E43574EA7411AED6B3EA639F22D,SHA256=FDA4D66274A0D99C33B19A3FE565EB9225...
        Image                          C:\Program Files\Mozilla Firefox\firefox.exe                                     
        UtcTime                        2021-03-01 13:25:52.600                                                          
        ProcessGuid                    {bb437cb3-eb60-603c-0000-001019c81b0a}                                           
        Company                        Mozilla Corporation                                                              
        IntegrityLevel                 Low                                                                              
        EventID                        1                                                                                
        FileVersion                    86.0                                                                             
        Process Create                                                                                                  
        RuleName                                                                                                        
        Product                        Firefox                                                                          
        LogonId                        0x2EE27E                                                                         
        ProcessId                      17392                                                                            
        LogonGuid                      {bb437cb3-a410-603c-0000-00207ee22e00}                                           
        TerminalSessionId              1                                                                                
        ParentProcessGuid              {bb437cb3-a508-603c-0000-0010819fd100}                                           
        ParentProcessId                16876                                                                            
        ParentImage                    C:\Program Files\Mozilla Firefox\firefox.exe                                     
        -----------------------------------------
        Time                           01/03/2021 12:33:17                                                              
        ParentCommandLine              "C:\Program Files\Mozilla Firefox\firefox.exe"                                   
        Description                    Firefox                                                                          

        output truncated...

        .EXAMPLE
        To increase speed it is suggested you save remote logs using the -Save switch. This is demonstrated here. 

        PS C:\WINDOWS\system32> Analyse-Log -TimePeriod 4 -ComputerName LT12345 -Save
        [*] Fetching logs ...
        [*] Logs fetched. Now analysing...
        [!] There's no error handling here - beware dragons
        This will save to C:\Temp. Please specify a filename: Someones_logs
        [*] Phew, that seemed to work. :D

        .EXAMPLE
        To load a JSON file, such as that saved by the Save switch, you may do the following. This is the suggested way when working with remote logs. 
        
        PS C:\WINDOWS\system32> Analyse-Log -TimePeriod 12 -Load C:\temp\sysmon_logs.json -QueryID 1 -Field Image
        [*] Fetching logs ...
        [*] Logs fetched. Now analysing...
        Summary for 
         Event ID:1 
         Field: Image

        Count Name                                        
        ----- ----                                        
          108 C:\Windows\System32\svchost.exe             
          107 C:\Windows\System32\wevtutil.exe            
           28 C:\Windows\System32\PING.EXE                
           27 C:\Program Files\Mozilla Firefox\firefox.exe
           19 C:\Windows\System32\taskhostw.exe           
           10 C:\Windows\SysWOW64\cmd.exe                 
           10 C:\Windows\System32\dsregcmd.exe            
           10 C:\Windows\System32\cmd.exe                 
            8 C:\Windows\System32\msiexec.exe             
            7 C:\Windows\System32\gpupdate.exe  


#>

    [CmdletBinding()]
    Param (

        [Parameter(Mandatory = $false, Position = 0)]
        [Float] $TimePeriod = 24,

        [Parameter(Mandatory = $false, Position = 0)]
        [String] $ComputerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false, Position = 0)]
        [Array] $QueryID,

        [Parameter(Mandatory = $false, Position = 0)]
        [Switch] $Summary,

        [Parameter(Mandatory = $false, Position = 0)]
        [Int32] $SummaryDepth = 10,

        [Parameter(Mandatory = $false, Position = 0)]
        [String] $Logname = "microsoft-windows-sysmon/operational",

        [Parameter(Mandatory = $false, Position = 0)]
        [Array] $Field,

        [Parameter(Mandatory = $false, Position = 0)]
        [String] $Value,

        [Parameter(Mandatory = $false, Position = 0)]
        [Switch] $FieldList,

        [Parameter(Mandatory = $false, Position = 0)]
        [Switch] $Display,

        [Parameter(Mandatory = $false, Position = 0)]
        [switch]$Save,

        [Parameter(Mandatory = $false, Position = 0)]
        [System.IO.FileInfo]$Load,

        [Parameter(Mandatory = $false, Position = 0)]
        [Array] $SubField,

        [Parameter(Mandatory = $false, Position = 0)]
        [System.IO.FileInfo]$Path,

        [Parameter(Mandatory = $false, Position = 0)]
        [String] $RefreshData,

        [Parameter(Mandatory = $false, Position = 0)]
        [Int32] $DisplayDepth = 3,

        [Parameter(Mandatory = $false, Position = 0)]
        [switch]$Interactive

        )

    $all_events = $null
    $Array_List = $null
    $keys = $null
    # Local Variable, not intended for changing
    # Used to calculate time for XPath 
    [Int32]$Xpath_Time = (86400000/24)*$TimePeriod
    $XPath = "*[System[TimeCreated[timediff(@SystemTime) <= $Xpath_Time]]]"
    [System.Collections.ArrayList]$Array_List = @()
    $Hashmah = @{}
    $default_Save_path = "C:\Temp\" + (Get-Date).ToString("dd-MM-yyyy") + "_Logs_" + $TimePeriod + "hours.json"
    #[System.Collections.ArrayList]$specified_events = @()

    # Title: Delim Control
    # Purpose: Handles spacing/parsing issues, bespoke to each log
    # Method: provides the delimiter and padding to the hash table in the Log Parser function. 
    switch($Logname) {
        Microsoft-Windows-Sysmon/Operational {
            $delim = ":"
            $spacing = 1 
        }
        Security {
            $delim = ":"
            $spacing = 1
        }
        Microsoft-Windows-Powershell/Operational {
            $delim = "="
            $spacing = 1            
        }
        "Windows Powershell" {
            $delim = "="
            $spacing = 1
        }
        Default {
            $delim = ":"
            $spacing = 2
        }
    }
   
    # Title: Log Collector
    # Purpose: Does the actual job of pulling the logs from the local or remote system
    # Method: Currently employs Get-WinEvent with time handled via XPaths. 
    # Issues: Will also need to test if requested time is larger than current time
    if ( $all_events.length -eq 0 -or $refreshdata ) {
        Write-Host "[*] Fetching logs ..."
        try {
            if ( $Path ) {
                $all_events = wevtutil.exe qe $Path /lf:$true /f:text /rd:true /q:$Xpath
            } elseif ( $Load ) { 
                $Array_List = Get-Content $Load | ConvertFrom-Json
            } else {
                $all_events = wevtutil.exe /r:$ComputerName qe $logname /f:text /rd:true /q:$Xpath
            }
        } catch {
            Write-Host "No matching logs found"
            Return
        }
    }

    # Title: Log parser
    # Purpose: Parses all event objects into something searchable. 
    # Method: Breaks up each log entry into key:values pairs in a hashmap and stores them all in an arraylist
    if ( -not ($load) ) {
        Write-Host "[*] Logs fetched. Now parsing..."
        For ($counter = 1 ; $counter -le $all_events.Length ; $counter++ ) {
        
            # Skip is the entry is null - this may create an issue with the event separation ?

            if ($all_events[$counter] -eq $null) {continue}

            $line_to_be_split = $all_events[$counter] 

            # Test if line has the delimiter in it - continue to next if it doesn't
            if ( $line_to_be_split.IndexOf($delim) -eq -1 ) { 
                # "Windows Powershell" logs use both : AND = delims, there would need to be a flag set to not 
                # test for either in a line here (probably in the if condition e.g -OR $WinPS_flag is true
                Continue 
            }


            # You reach a newline and the next line is a new event
            # So add the current hash map to the array list, clear it and move on
            if ($line_to_be_split -Match "^Event\[" ) {
                $Array_List.Add($hashmah) > $null
                $Hashmah = @{}
                continue
            }    

            # Adds key:value pair to hash map - this will also capture keys with empty values
            # TODO Add test to 
            $hashmah_key = $($all_events[$counter].Split($delim)[0].Trim())
            $hashmah_value = $($all_events[$counter].Substring($all_events[$counter].IndexOf($delim)+$spacing).Trim())
            $hashmah[$hashmah_key] = $hashmah_value

        }
    }

    # Title: Log Saver
    # Purpose: Saves the variable $Array_List into a json file
    # Method: Uses built in feature, with a suggested default location 
    if ( $save ) {
        Write-Host "[!] There's no error handling here - beware dragons" 

        $incomplete_path = Read-Host "This will save to C:\temp. Specify a filename"

        $full_path = "C:\Temp\" + $incomplete_path + ".json"

        $Array_List | ConvertTo-Json -Depth 4 | Out-File $full_path

        if ( Test-Path $full_path ) {
            Write-Host "[*] Phew, that seemed to work. :D"
        }
    }

    # Title: Summary Generator
    # Purpose: To generate a brief summary of the log, getting all occuring event IDs and totals
    # Method: 
    function Generate_Summary {
        if ( $Summary -and -not $QueryID  ) {
            Write-Host "Processing Summary"
           # Total logs
            Write-Host "[*] Number of events in the last $($TimePeriod) hours is:" $Array_List.Count

            # List unique values
            Write-Host "[*] IDs of events seen in last $($TimePeriod) hours"
            $print_event_IDs = $Array_List."Event ID" | Group-Object | Select -Property Count,Name,@{Name = 'Percent'; Expression = {($_.Count/$Array_List.Count).tostring("P") }} | Sort -Property count -Descending

            # Merge data with event IDs with the task. Pretty slow way of doing this. Refactor at some point. 
            $collection = @()

            foreach ($line in $print_event_IDs) {
            $collection += [pscustomobject] @{
                    EventID   = $line.Name
                    EventName = ($Array_List | where "Event ID" -eq $line.Name | select -first 1).Task
                    EventCount = $line.Count
                    EventPercent = $line.Percent
                }
            }

            $collection | Format-Table -AutoSize
        }
    }
    Generate_Summary
    
    # Title: Key parser
    # Purpose: To stop needing to repeatedly pull keys out we'll do it once and store 
    # Method: use pipeline to pull unique IDs. Iterate over, pulling keys from first match and adding to hashmap based on event ID. 
    $hashmap_of_event_keys_by_event_id = @{}
    $all_event_ids = $Array_List."Event ID" | Sort -Unique

    if ( $load ) {
        foreach ( $each_unique_id in $all_event_ids ){
           $keys_to_be_added = foreach ($property in ($Array_List | where {$_."Event ID" -eq 1} | select -first 1 | Get-Member)) { if ($property.MemberType -eq "NoteProperty") { $property.Name } }
           $hashmap_of_event_keys_by_event_id.add([int32]$each_unique_id, $keys_to_be_added)
           #$hashmap_of_event_keys_by_event_id[$each_unique_id]
        }
    } else {
        foreach ( $each_unique_id in $all_event_ids ){
           $keys_to_be_added = ($Array_List | where {$_."Event ID" -eq $each_unique_id} | select -first 1).keys 
           $hashmap_of_event_keys_by_event_id.add([int32]$each_unique_id, $keys_to_be_added)
           #$hashmap_of_event_keys_by_event_id[$each_unique_id]
        }
    }

    # Title: List all field names
    # Purpose: Provides the user with a list of fields for a given event
    # Method: selects 1 matching event and loops over the hashmap keys. Cannot generate fields if event did not occur in time frame.
    function Generate_FieldList { 
        if ( $QueryID -and $FieldList ) {
            foreach ($ID_Queried in $QueryID) {
                Write-Host "Field Names for Event ID $($ID_Queried)"
                $hashmap_of_event_keys_by_event_id[$ID_Queried]
            }
        }
    }
    Generate_FieldList

    
    # Experimental interactive mode
    Do {
    
        # Title: Query Based Analysis - By Key (Field)
        # Purpose: Does the actual breakdow
        # Method: iterates over QueryID array, getting field names (or  using supplied ones) and displays the data based on that by iterating over the array list for matching keys.  
        if ( ($field -or $QueryID -ne "") -and -not $FieldList) {
            Write-Host "[*] Logs parsed. Now analysing..."
            foreach ($ID_Queried in $QueryID) {

                #$ID_Queried = [Int32]$ID_Queried
                $keys = $hashmap_of_event_keys_by_event_id[$ID_Queried]

                # This provides the more drilled down functionality of Value and SubField (sub functionality of QueryID)
                if ( $field -and $value ) { 

                    # If SubField specified use those fields
                    if ( $SubField ) { $keys = $SubField }

                    foreach ($key in $keys) {

                        Write-Host "Summary for `n Event ID:$ID_Queried `n Field: $key"

                        $specified_events = $Array_List | where "event id" -eq $ID_Queried | where $($field) -like $value

                        # This does the printing, and also handles subfield printing. 
                        if ( $Display ) {
                            $events_to_display = $specified_events | Select-Object -first $DisplayDepth

                            foreach ($display_item in $events_to_display ) {
                                if ( $SubField ) {
                                    foreach ( $subfield_to_print in $SubField ) {
                                        $display_item.$subfield_to_print
                                        Write-Host "-----------------------------------------"
                                    }
                                } else {
                                    $display_item
                                    Write-Host "-----------------------------------------"
                                }
                            }
                        
                        } else {                                                              
                            $output_table = ($specified_events).$key | Group-Object
        
                            $output_table | Sort-Object -Property Count -Descending | Select count,name -First $SummaryDepth | Format-table -wrap
                        } 
                        if ( $display ) { Return }
                    } # end of iteration over keys/subfields
                }
            
                # This provides the basic functionality of QueryID and Field
                # This test was always coming back false, not sure why changed to true
                if (  $ID_Queried -and $value -eq "" ){
                    # If fields specified, use those fields rather than keys
                    if ( $field ) { $keys = $field }

                    foreach ($key in $keys) {

                        Write-Host "Summary for `n Event ID:$ID_Queried `n Field: $key"
                                                       

                        $specified_events = $Array_List | where {$_."event id" -eq $ID_Queried}

                        if ( $display ) {
                            $events_to_display = $specified_events | Select-Object -first $DisplayDepth

                            foreach ($display_item in $events_to_display ) {
                                $display_item | Format-Table -AutoSize
                                Write-Host "-----------------------------------------"                           
                            }
                          return # put here to exit loop after printing. Not a great way to handle it but w/e
                        } else {
                            $output_table = ($specified_events).$key | Group-Object

                            $output_table | Sort-Object -Property Count -Descending | Select count,name -First $SummaryDepth | Format-table -wrap 
                        }
                    }
                }
            }# end query foreach
        }#end if
        
        if ( $Interactive ) {
            $value = $null
            $field = $null
            $QueryID = $null
            $FieldList = $null
            $Summary = $null
            Write-Host "Analyse-Log Interactive Mode - This mode will keep the data loaded into memory. 
            Limitations:
            You cannot enter more than one QueryID, Field or Value.
            Do not place values in `"quotations`"
            Cannot generate Summary
            If a variable is Off/On enter any value to use" -Fore cyan

            $inputs = Read-Host "Exit to leave. Return to continue"
            if ( $inputs -eq "exit" ) {
                return
            }
            [Int32]$QueryID = Read-Host "QueryID"
            [String]$Field = Read-Host "Field"
            [String]$Value = Read-Host "Value"
            [String]$Summary = Read-Host "Summary"
            [Int32]$SummaryDepth = Read-Host "SummaryDepth"
            if ( -NOT($SummaryDepth) ) { $SummaryDepth = 10 }

            
            Generate_FieldList
            Generate_Summary
        } 


    } While ( $Interactive ) # end of while loop interactive mode 
    #Return $Array_List
}#end of script


    <#
    TO DOs
    - Expand Interactive mode with more variables 
    - Add local export functionality
    - Add a 'Reverse' switch that changes it from First n to Last n
    - Add a suppress feature that excludes certain criteria
    - A 'Basic Analysis' switch that gets the 3 busiest events and for each of those gets the 3 busiest fields (exl some noise)

    Known Issues:
    - PowerShell event 4104 Scripting block is a mess
    - It's slow af
    - Can't look at a value lower than 1 hour. 


    #>
