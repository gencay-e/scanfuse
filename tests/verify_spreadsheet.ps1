param([string]$CsvPath, [int]$ExpectedRows)
$ErrorActionPreference = 'Stop'
$excel = $null
$book = $null
try {
    $excel = New-Object -ComObject Excel.Application
    $excel.Visible = $false
    $excel.DisplayAlerts = $false
    $excel.AutomationSecurity = 3
    $book = $excel.Workbooks.Add()
    $sheet = $book.Worksheets.Item(1)
    $escapedPath = $CsvPath.Replace('"', '""')
    $formula = 'Csv.Document(File.Contents("' + $escapedPath + '"),[Delimiter=",", Encoding=65001, QuoteStyle=QuoteStyle.Csv])'
    $book.Queries.Add('SafeCsv', $formula) | Out-Null
    $connection = 'OLEDB;Provider=Microsoft.Mashup.OleDb.1;Data Source=$Workbook$;Location=SafeCsv;Extended Properties=""'
    $table = $sheet.ListObjects.Add(0, $connection, $null, 0, $sheet.Range('A1'))
    $table.QueryTable.CommandType = 2
    $table.QueryTable.CommandText = 'SELECT * FROM [SafeCsv]'
    $table.QueryTable.Refresh($false) | Out-Null
    if ($sheet.UsedRange.Rows.Count -ne ($ExpectedRows + 2)) { throw "CSV row count changed during import: $($sheet.UsedRange.Rows.Count)" }
    foreach ($cell in $sheet.UsedRange.Cells) {
        if ($cell.HasFormula) { throw 'Imported CSV cell contains a formula' }
    }
    $expected = @(Import-Csv -LiteralPath $CsvPath -Encoding utf8)
    for ($index = 0; $index -lt $ExpectedRows; $index++) {
        $actual = [string]$sheet.Cells.Item($index + 3, 1).Value2
        if ($actual -cne [string]$expected[$index].Title) { throw "CSV title changed during import at row $index" }
    }
    Write-Output 'PASS: Excel imported all rows without formulas'
} finally {
    if ($null -ne $book) { $book.Close($false) }
    if ($null -ne $excel) { $excel.Quit(); [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($excel) }
}
