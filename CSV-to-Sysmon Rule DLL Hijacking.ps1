# This script will convert the DLL side loading data from here:
# https://github.com/wietze/windows-dll-hijacking/blob/master/dll_hijacking_candidates.csv
# into Sysmon rules
# uses Image rather than original file name, which could be one potential improvement

$csv = import-csv C:\temp\dll_hijacking_candidates.csv

# get important autoelevated ones
$autoelevated = $csv | ?{$_.'Auto-elevated' -eq "TRUE"}

$template = @"
<Rule name="auto_name" groupRelation="and">
		<Image condition="end with">\exe_name</Image>
		<ImageLoaded condition="contains any">dll_list</ImageLoaded>
		<Signature condition="is not">Microsoft Windows</Signature>
</Rule>		
"@

$executables = $csv | select executable -Unique

$arraylist = [System.Collections.ArrayList]::new()

$hash = @{} 

# build out 
foreach ($exe in $executables) {
    $dlls = [System.Collections.ArrayList]::new()

    # build empty hashmap of exe::arraylist_of_dlls
    $hash.add($($exe.Executable),$dlls)

}

# populate
foreach ($line in $csv) {
    $hash[$line.Executable].add($line.DLL) > $null
}


# translate into the format for the template
foreach ($instance in $hash.GetEnumerator()) {
    # copy over template for editing 
    $template_copy = $template -replace "exe_name",$instance.Name

    # turn arraylist of DLLs into string with semi-colons
    $dll_list = [String]($instance.Value) -replace " ",";"

    $template_copy = $template_copy -replace "dll_list",$dll_list

    #auto populate a name into the rule - useful if it proves too noisy 
    $template_copy = $template_copy -replace "auto_name","$($instance.name) DLL Side Loading"

    $arraylist.add($template_copy) > $null
}
