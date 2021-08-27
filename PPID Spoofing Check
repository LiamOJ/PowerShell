# arraylist to hold relationships
[System.Collections.ArrayList]$arraylist_spoofed_ppid_processes = @()

# Pull straight from ETL file
$etl_events = Get-WinEvent -Path C:\WINDOWS\system32\test_trace.etl -Oldest

# Just pull out the event ID we want
$etl_events = $etl_events|?{$_.id -eq 1}

# iterate over length of events, looking for a mismatch between PPIDs
$(0..$($etl_events.Length-1)) | `
    % {if(($etl_events[$_] | `
    select -expandProperty Properties).Value[3] -ne ($etl_events[$_] | `
    select -Property ProcessID).PRocessid) {
        $actual_parent = ($etl_events[$_] | select -Property ProcessID).ProcessID
        $faux_parent = ($etl_events[$_] | select -ExpandProperty properties)[3].Value
        $child_process_id = ($etl_events[$_] | select -ExpandProperty properties)[0].Value
        $child_process_name = ($etl_events[$_] | select -ExpandProperty properties)[10].Value 
        $timestamp = ($etl_events[$_] | select -ExpandProperty properties)[12].Value

        # child process ID & timestamp
        #$identifer = [string]$child_process_id + "/" + [string]$timestamp

        # Make and build hashtable of data
        $hashtable_single_ppid_mismatch_instance = @{}

        $hashtable_single_ppid_mismatch_instance.add("Real Parent",$actual_parent)
        $hashtable_single_ppid_mismatch_instance.add("Spoofed Parent",$faux_parent)
        $hashtable_single_ppid_mismatch_instance.add("Child Process ID",$child_process_id)
        $hashtable_single_ppid_mismatch_instance.add("Child Process Name",$child_process_name)
        $hashtable_single_ppid_mismatch_instance.add("Timestamp",$identifer)


        # add to arraylist
        $arraylist_spoofed_ppid_processes.add($hashtable_single_ppid_mismatch_instance) > $null
        }
    }

# TODO
# Might need to reimplement this in wevtutil for speeds sakw - doesn't seem to have the required data
# Logman as a remote computer switch (-s)
# Code will need to be broken up into parts
