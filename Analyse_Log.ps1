#Measure-Command -Expression {
$TimePeriod = Read-Host "Enter number of hours"
$Xpath_Time = (86400000/24)*$TimePeriod
$XPath = "*[System[TimeCreated[timediff(@SystemTime) <= $Xpath_Time]]]"

$object_of_all_events = wevtutil /r:$env:COMPUTERNAME qe Microsoft-Windows-Sysmon/Operational /q:$XPath /rd:true

[System.Collections.ArrayList]$Array_List_of_xml_events = @()

# Title: Log parser
# Purpose: Parses all event objects into an easily searchable hash table
# Method: Breaks up each log entry into key:values pairs in a hashmap and stores them all in an arraylist
foreach ($event in $all_events) { 
    
    # =================
    # Convert Wevtutil XML string to Powershell XML object and error handling thereof
    try {
        # Convert event into XML event
        $xml_event = [XML]$event
    } catch {
        # For some reason occasionally events are split in two, this should stitch them back together
        # When it encounters the first error it saves it and moves on
        # The next error is stitched to the end of that one and the holder cleared
        if ( -NOT ($first_half_of_corrupted_event) ) {
            $first_half_of_corrupted_event = $event
            continue
        } else {
            $XML_event = [XML]($first_half_of_corrupted_event + $event)
            $first_half_of_corrupted_event = $null
        }
    }

    # Declare new hashtable to be used - it has to be done in the loop
    $hash_table_of_individual_event = @{}

    # =================
    # System Section
    # The System bit is a little nested and not everything is useful, so we'll pull out specifics
    $system_data_holder = $xml_event.Event.System

    $hash_table_of_individual_event.add('EventID',$system_data_holder.EventID)
    $hash_table_of_individual_event.add('ThreadID',$system_data_holder.Execution.ThreadID)
    $hash_table_of_individual_event.add('UserID',$system_data_holder.Security.UserID)
    $hash_table_of_individual_event.add('Level',$system_data_holder.Level)
    $hash_table_of_individual_event.add('Computer',$system_data_holder.Computer)
    $hash_table_of_individual_event.add('Time',$system_data_holder.TimeCreated.SystemTime)
    $hash_table_of_individual_event.add('EventRecordID',$system_data_holder.EventRecordID)


    # ==================
    # Event Data Section
    # The event data is, arguably, all useful and not nested. 
    $eventdata = $xml_event.Event.EventData.Data

    foreach ($event_data_row in $Eventdata) {
        $hash_table_of_individual_event.add($event_data_row.Name, $event_data_row.'#text')
    }
   
    # =================
    # Add finished hashtable to array list
    $Array_List.Add($hash_table_of_individual_event) > $null       
}

#} #end of measure command function


# To Dos

# For the compare-object script comapre A to B-Z, but group and keep top 3  with predefined levels of difference descriptions
# E.g. if only 5% difference then (very similar to N number of other events) if 50%-75% then somewhat similar, less than 50% not very similar
# etc. Could be an extra feature for checking if there's some sort of repeating events, but you'd probs need something like eventid as a key 
# to help contextualise it to the user
 
