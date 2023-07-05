Write-Host 
("   _______    ________                    __    __             
  / ____/ |  / / ____/  ____ __________ _/ /_  / /_  ___  ___
 / /    | | / / __/    / __ `/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
/ /___  | |/ / /___   / /_/ / /  / /_/ / /_/ / /_/ /  __/ /    
\____/  |___/_____/   \__, /_/   \__,_/_.___/_.___/\___/_/     
                     /____/                                    
")

Write-Host ("Grab useful CVE information from multiple sources.")
Write-Host ("---------------------------------------------------------------")
                                              

$CVEs = Read-Host -Prompt "Enter one or more CVE IDs separated by a comma (e.g. CVE-2023-27997,CVE-2022-41040)"
$CVEArray = $CVEs -split ',\s*'

foreach ($CVE in $CVEArray) {
    $apiUrl = "https://cve.circl.lu/api/cve/$CVE"
    $jsonResponse = Invoke-RestMethod -Uri $apiUrl
    
    $id = $jsonResponse.id
    $references = $jsonResponse.references
    $summary = $jsonResponse.summary
    $vulnerableProducts = $jsonResponse.vulnerable_product
    
    $url = "https://nvd.nist.gov/vuln/detail/$CVE"
    $response = Invoke-RestMethod -Uri $url
    
    $exploitString = "This CVE is in CISA's Known Exploited Vulnerabilities Catalog"
    
    $regex = '(?<=class="label label-(\w+)">)(.*?)(?=<\/a>)'
    $matches = [regex]::Match($response, $regex)
    
    $cvssScore = "N/A"
    if ($matches.Success) {
        $cvssScore = $matches.Groups[2].Value
        $severityLevel = $matches.Groups[1].Value
    }
    
    Write-Host ("ID: {0,-20} CVSS Score: {1}" -f $id, $cvssScore) -ForegroundColor Magenta
    
    Write-Host ("References:") -ForegroundColor Green
    foreach ($ref in $references) {
        Write-Host $ref -ForegroundColor Blue
    }
    
    Write-Host ("Summary:") -ForegroundColor Green
    Write-Host $summary -ForegroundColor Yellow
    
    Write-Host "Vulnerable Products:" -ForegroundColor Green
    $sortedProducts = $vulnerableProducts | Sort-Object
    foreach ($product in $sortedProducts) {
        $cleanProduct = $product -replace '^cpe:2\.3:[a-z]:'
        Write-Host $cleanProduct -ForegroundColor Yellow
    }
    
    if ($response.Contains($exploitString)) {
        Write-Host ("Exploit: ") -NoNewline -ForegroundColor Green
        Write-Host "Yes, this CVE is in CISA's Known Exploited Vulnerabilities Catalog." -ForegroundColor Red
        Write-Host ("URLs: ") -ForegroundColor Green
        Write-Host https://nvd.nist.gov/vuln/detail/$CVE -ForegroundColor Blue
        Write-Host https://github.com/nomi-sec/PoC-in-GitHub -ForegroundColor Blue
    } else {
        Write-Host ("Exploit: ") -NoNewline -ForegroundColor Green
        Write-Host "No, this CVE is not in CISA's Known Exploited Vulnerabilities Catalog." -ForegroundColor Yellow
    }
    
    Write-Host "---------------------"
}
