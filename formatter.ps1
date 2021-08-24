$file_array = [System.Collections.ArrayList]::new()   
$file_array.add("C:\Temp\report.csv") > $null
$file_array.add("C:\Temp\Spreadsheet 2.csv") > $null
$file_array.add("C:\Temp\Spreadsheet 3.csv") > $null
$file_array.add("C:\Temp\Spreadsheet 4.csv") > $null
$file_array.add("C:\Temp\other_export.csv") > $null

# Title: CSV Formatter
# Purpose: Formats and converts CSV files into XLSX 
# Method: iterates over CSVs in array list, deleting blanks, colours top row with content 
foreach ($filelocation in $file_array) {

    # Remove empty files
    if (-NOT (Get-Content $filelocation) ) {
        Remove-Item $filelocation
        if ($?) {Write-Host "$($filelocation) removed"}
        # Could call the email sending here with the blank
        continue
    }
    
    $objExcel = New-Object -comobject Excel.Application

    $objExcel.Visible = $true

    $WorkBooks = $objExcel.Workbooks.Open(${filelocation})

    $worksheet = $workbooks.Worksheets.Item(1)

    for ( $cell_column_num = 1 ; $cell_column_num -le 20 ; $cell_column_num++) {

        $retry = $true 
        $retry_limit = 10

        do {
            try {
                $cell_contents = $worksheet.Cells.Item(1,$cell_column_num).text
                $retry = $false
            } catch {
                Start-Sleep -Seconds 0.5
                $cell_contents = $worksheet.Cells.Item(1,$cell_column_num).text
                $retry = $false
            }
            $retry_limit--
        } while ( $retry -eq $true -and $retry_limit -gt 0)

        if ($cell_contents) {
        
            while ( -NOT ($worksheet.Cells.Item(1,$cell_column_num).Interior.ColorIndex -eq 45) ) {
                Start-Sleep -Seconds 0.5
           
                $worksheet.Cells.Item(1,$cell_column_num).Interior.ColorIndex = 45 
               
            }

        }

    }

    $worksheet.UsedRange.Columns.Autofit() > $null

    $file_path_for_saving = Join-Path -Path (Get-item $filelocation).DirectoryName -ChildPath (Get-item $filelocation).Basename

    $worksheet.SaveAs($file_path_for_saving, 61) #save as XLSX format - https://docs.microsoft.com/en-us/office/vba/api/excel.workbook.saveas

}
