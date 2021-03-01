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
        .PARAMETER ComputerName
            The name of the computers you wish to query. The default is the current system. 
        .PARAMETER QueryID
            The Event ID number you wish to query e.g. 1 - Process Creation. 
        .PARAMETER LogName
            The log you wish to query. The default is Microsoft-Windows-Sysmon/Operational.
        .PARAMETER Summary
            Provides a brief summary of totals.
        .PARAMETER SummaryDepth
            The log results are provided top first, by the number specified by this variable. Default is 10.
        .PARAMETER Field
            The name of the log line you wish to query.
            E.g. -Field ParentProcessName.
        .PARAMETER Value
            The specified value of the field you wish to search for. Must be used after Field
            E.g. -Field Image -Value C:\Windows\System32\cmd.exe
        .PARAMETER FieldList
            

        .INPUTS
            None
        .OUTPUTS
            Tables of summarised data via Format-Table, or pased log output. 

        .EXAMPLE
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
        [Switch] $Display

        )

    # Local Variable, not intended for changing
    # Used to calculate time for XPath 
    $id_hash_table_for_counting = @{}
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
    if ( -not ($all_events.length -gt 0) ) {
        Write-Host "[*] Fetching logs ..."
        try {
            $all_events = Get-WinEvent -ComputerName $computername -LogName $logname -FilterXPath $Xpath -ErrorAction Stop
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
            #$($line.substring(0,$line.IndexOf($delim))).Trim() #DEBUGGING
            #$($line.Substring($line.IndexOf($delim)+$spacing)) #DEBUGGING

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
        Write-Host "[*] Number of events in the last $time_period hours is:" $all_events.Count

        # List unique values
        Write-Host "[*] IDs of events seen in last $($TimePeriod) hours"
        $event_IDs = $all_events | Sort-Object -Property ID -Unique | Select-Object ID,Message
        $event_IDs

        # Get count of each type of event
        Write-Host "Get Counts"
        $all_events | Group-Object -Property id | Select-Object -Property Name,Count | 
        Sort-Object -Property Count -Descending | Format-table
    
    }

    # Title: List all field names
    if ( $QueryID -and $FieldList ) {
        foreach ($ID_Queried in $QueryID) {
            $keys = foreach ($field_name in $($Array_List | where eventid -eq $ID_Queried | select -first 1) ) { $field_name.Keys }

            Write-Host "Field Names for Event ID $($ID_Queried)"
            $keys
        }
    }

    #Fields to consider removing from keys: time, UTCTime, ProcessGUID, Description, fileversion, processid
    # Consider filtering them by default but have a switch for 'full data'

    # Title: Query Based Analysis - By Key (Field)
    # Purpose: Does the actual breakdow
    # Method: iterates over QueryID array, getting field names (or  using supplied ones) and displays the data based on that by iterating over the array list for matching keys.  
    if ( ($field -or $QueryID) -and -not $FieldList) {

        foreach ($ID_Queried in $QueryID) {
            $ID_Queried = [Int32]$ID_Queried
            $keys = foreach ($field_name in $($Array_List | where eventid -eq $ID_Queried | select -first 1) ) { $field_name.Keys }


            if ( $field -and $value -ne "" ) {  
                foreach ($key in $keys) {
                    #Display group by for each key value - specify SummaryDepth


                    Write-Host "Summary for `n Event ID:$ID_Queried `n Field: $key"
                    #                                                                     Problem is here?
                    $output_table = ($Array_List | where {$_.eventid -eq $ID_Queried -and $($_.$field) -like $value } ).$key | Group-Object
        
                    $output_table | Sort-Object -Property Count -Descending | Select count,name -First $SummaryDepth | Format-table -wrap 
                }
            }
            
            if ( $field -and $value -eq "" ){
                $keys = $field
                foreach ($key in $keys) {
                    #Display group by for each key value - specify SummaryDepth


                    Write-Host "Summary for `n Event ID:$ID_Queried `n Field: $key"
                    $output_table = ($Array_List | where {$_.eventid -eq $ID_Queried} ).$key | Group-Object

        
                    $output_table | Sort-Object -Property Count -Descending | Select count,name -First $SummaryDepth | Format-table -wrap 
                }
            }
        }
    }

    # Title: Query Based Analysis - By Value
    # Purpose: To allow for querying a specific value
    # Method: ...

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

    #>
}

# For debugging purposes, allows me to manipulate the data without calling the cmdlet
$external_array_list = $Array_List
