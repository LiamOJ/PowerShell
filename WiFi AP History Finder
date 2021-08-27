# Connection mode allows you to see if the machine has used this AP before
# Authentication and Encryption can tell us if it's an open (and likely public) WiFi AP

# Variables
$computer = '{{CHANGE ME}}'
$connections_over_time_arraylist = [System.Collections.ArrayList]::new() 

# Get successful WiFi connections
$wifi_connections = .\wevtutil.exe qe Microsoft-Windows-WLAN-AutoConfig/Operational /rd:true "/q:*[System[EventID=8001]]" /r:$computer

foreach ($connection in $wifi_connections) {
    $time_of_connection = ([xml]$connection).Event.System.TimeCreated.SystemTime
    $SSID_of_connection = ([xml]$connection).Event.EventData.Data.'#text'[4]
    $connection_mode = ([xml]$connection).Event.EventData.Data.'#text'[2]
    $encryption = ([xml]$connection).Event.EventData.Data.'#text'[8]
    $authentication = ([xml]$connection).Event.EventData.Data.'#text'[7]

    $collection = [pscustomobject] @{
        ConnectionTime = $time_of_connection
        AP_SSID = $SSID_of_connection
        Connection_Mode = $connection_mode
        Authentication = $authentication
        Encryption = $encryption
    }

    $connections_over_time_arraylist.add($collection) > $null

}

$connections_over_time_arraylist | Out-GridView
