$alph = "abcdefghijklmnopqrstuvwxyz"

$reverse = $false

if ($reverse) {
    $alph = $alph.ToCharArray()
    [array]::Reverse($alph)
    $alph = [string]$alph -replace " ",""
}

$string = "TLEQIL ZVL RCO-1970U"

$dict = @{}

1..25 | % {
    for ($counter = 0; $counter -lt $string.Length; $counter++) {
        if ($string[$counter] -eq " ") { $dict[$_] += " "; continue }
        $dict[$_] += $alph[($alph.ToUpper()).IndexOf($string[$counter]) - $_]
    }
}

$dict 

