function Analyse-Log {

    <#
        .SYNOPSIS
            Analyse the specified log. Originally intended to aid customisation of Sysmon configuration. 
            Logs currently known to work: Sysmon/Operational and Security 
            Current issues: errors with System (summary works, nothing else) and Powershell/Operational (4104 script blocks aren't working)
        .DESCRIPTION
            Essentially a syntactically simple wrapper for Get-WinEvent.
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

        PS C:\Users\Z447692\Documents> Analyse-Log -TimePeriod 5 -Summary
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

        PS C:\Users\Z447692\Documents> Analyse-Log -TimePeriod 5 -QueryID 1 -FieldList
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

        PS C:\Users\Z447692\Documents> Analyse-Log -TimePeriod 5 -QueryID 1 -Field Image -Value "*svchost.exe"
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

        PS C:\Users\Z447692\Documents> Analyse-Log -TimePeriod 5 -QueryID 1 -Field Image -Value "*firefox.exe" -SubField ParentImage,CommandLine -SummaryDepth 3
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

        PS C:\Users\Z447692\Documents> Analyse-Log -TimePeriod 5 -QueryID 1 -Field Image -Value "*firefox.exe" -Display -DisplayDepth 4
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
#>

    [CmdletBinding()]
    Param (

        [Parameter(Mandatory = $false, Position = 0)]
        [int32] $TimePeriod = 1,

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
        [Array] $SubField,

        [Parameter(Mandatory = $false, Position = 0)]
        [String] $Path,

        [Parameter(Mandatory = $false, Position = 0)]
        [Switch] $RefreshData,

        [Parameter(Mandatory = $false, Position = 0)]
        [Int32] $DisplayDepth = 3

        )

    # Local Variable, not intended for changing
    # Used to calculate time for XPath 
    $Xpath_Time = (86400000/24)*$TimePeriod
    $XPath = "*[System[TimeCreated[timediff(@SystemTime) <= $Xpath_Time]]]"
    [System.Collections.ArrayList]$Array_List = @()
 
    # Title: Delim Control
    # Purpose: Handles spacing/parsing issues, bespoke to each log
    # Method: provides the delimiter and padding to the hash table in the Log Parser function. 
    switch($Logname) {
        Microsoft-Windows-Sysmon/Operational {
            $delim = ":"
            $spacing = 2 
        }
        Security {
            $delim = ":"
            $spacing = 2
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
    if ( $True ) {
        Write-Host "[*] Fetching logs ..."
        try {
            if ( $Path ) {
                $all_events = Get-WinEvent -Path $Path -ErrorAction Stop
            } else {
                $all_events = Get-WinEvent -ComputerName $computername -LogName $logname -FilterXPath $Xpath -ErrorAction Stop
            }
        } catch {
            Write-Host "No matching logs found"
            Return
        }

        Write-Host "[*] Logs fetched. Now analysing..."
    }


    # Title: Log parser
    # Purpose: Parses all event objects into something searchable. 
    # Method: Breaks up each log entry into key:values pairs in a hashmap and stores them all in an arraylist
    Foreach ($event in $all_events) {

        # Occasional errors: FullyQualifiedErrorId : InvokeMethodOnNull
	    $array_message = $event.Message.split("`n")
	
	    $Hashmah = @{}

        # Add event data into table
        $hashmah["EventID"] = $event.Id
        $hashmah["Time"] = $event.TimeCreated
    
	    foreach ($line in $array_message) {  
        
            # To remove lines without a Key : Value relationship (not exactly fool proof)
            if ( $line.IndexOf($delim) -eq -1 ) { Continue }

            # Spacing and delim are used for neatly parsing key:value relationships in log data strings
            # The values change a little depending on which log we're lookng at, the switch at the top controls it
            # Trim in value might break things that aren't strings?
            $hashmah[$($line.substring(0,$line.IndexOf($delim))).Trim()] = $($line.Substring($line.IndexOf($delim)+$spacing)).Trim() 
        
        }

        # The '> null' redirects the printed output to null rather than STDOUT
        $Array_List.Add($hashmah) > $null
    }


    # Title: Summary Generator
    # Purpose: To generate a brief summary of the log, getting all occuring event IDs and totals
    # Method: 
    if ( $Summary -and -not $QueryID  ) {
    
       # Total logs
        Write-Host "[*] Number of events in the last $($TimePeriod) hours is:" $all_events.Count

        # List unique values
        Write-Host "[*] IDs of events seen in last $($TimePeriod) hours"
        $event_IDs = $all_events | Sort-Object -Property ID -Unique | Select-Object ID,Message
        $event_IDs

        # Get count of each type of event
        Write-Host "Get Counts"
        $all_events | Group-Object -Property id | Select-Object -Property Name,Count,@{Name = 'Percent'; Expression = {($_.Count/$all_events.Count).tostring("P") }} | 
        Sort-Object -Property Count -Descending | Format-table
    
    }

    # Title: List all field names
    # Purpose: Provides the user with a list of fields for a given event
    # Method: selects 1 matching event and loops over the hashmap keys. Cannot generate fields if event did not occur in time frame. 
    if ( $QueryID -and $FieldList ) {
        foreach ($ID_Queried in $QueryID) {
            $keys = foreach ($field_name in $($Array_List | where eventid -eq $ID_Queried | select -first 1) ) { $field_name.Keys }

            Write-Host "Field Names for Event ID $($ID_Queried)"
            $keys
        }
    }


    # Title: Query Based Analysis - By Key (Field)
    # Purpose: Does the actual breakdow
    # Method: iterates over QueryID array, getting field names (or  using supplied ones) and displays the data based on that by iterating over the array list for matching keys.  
    if ( ($field -or $QueryID) -and -not $FieldList) {
        foreach ($ID_Queried in $QueryID) {

            $ID_Queried = [Int32]$ID_Queried
            $keys = foreach ($field_name in $($Array_List | where eventid -eq $ID_Queried | select -first 1) ) { $field_name.Keys }

            # This provides the more drilled down functionality of Value and SubField (sub functionality of QueryID)
            if ( $field -and $value -ne "" ) { 

                # If SubField specified use those fields
                if ( $SubField ) { $keys = $SubField }

                foreach ($key in $keys) {

                    Write-Host "Summary for `n Event ID:$ID_Queried `n Field: $key"

                    $specified_events = $Array_List | where eventid -eq $ID_Queried | where $($field) -like $value

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
            if ( $ID_Queried -and $value -eq ""){
                
                # If fields specified, use those fields rather than keys
                if ( $field ) { $keys = $field }

                foreach ($key in $keys) {

                    Write-Host "Summary for `n Event ID:$ID_Queried `n Field: $key"

                    $specified_events = $Array_List | where {$_.eventid -eq $ID_Queried}

                    if ( $display ) {
                        $events_to_display = $specified_events | Select-Object -first $DisplayDepth

                        foreach ($display_item in $events_to_display ) {
                            $display_item
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

} #end of script
    <#
    TO DOs
    - List fields for specific logs e.g. -QueryID 1 -FieldList should produce Image, ParentImage, etc
    - Next thing would be to search by a field inside an event ID and pull all the matching events out
        e.g. ID is 1 and image is C:\Windows\System32\cmd.exe would show all matching events
    - Log refresh feature - to blank out $all_events (only seems to be an issue when you want to lengthen the time?)
    - As above, add test condition to make sure the time period of the current logs >= asked for logs 
    - DONE Wrap the query based analysis in a for loop that iterates over the specified query ID
    - Add a 'Reverse' switch that changes it from First n to Last n
    - Add handling for Powershell/Operational 4104 (Script block logging) so it separates the script block into its own key:value pair. 
    - DONE: Add Path parameter
    - Add Print with limit 


    #Fields to consider removing from keys: time, UTCTime, ProcessGUID, Description, fileversion, processid
    # Consider filtering them by default but have a switch for 'full data'

    #>


# For debugging purposes, allows me to manipulate the data without calling the cmdlet
$external_array_list = $Array_List