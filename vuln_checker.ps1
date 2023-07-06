Write-Host 
("              __              __              __            
 _   ____  __/ /___     _____/ /_  ___  _____/ /_____  _____
| | / / / / / / __ \   / ___/ __ \/ _ \/ ___/ //_/ _ \/ ___/
| |/ / /_/ / / / / /  / /__/ / / /  __/ /__/ ,< /  __/ /    
|___/\__,_/_/_/ /_/   \___/_/ /_/\___/\___/_/|_|\___/_/     
                                                            ")

Write-Host ("Check for vulnerabilites in software/hardware and thereafter grab corresponding CVE information.")
Write-Host ("Maintained by @b41ss.")
Write-Host ("*Keep in mind that the public NVD rate limit (without an API key) is 5 requests in a 30 second window.") -ForegroundColor Red
Write-Host ("---------------------------------------------------------------")

# Prompt user input for software and results per page
$software = Read-Host -Prompt "Enter the name and version of the software/hardware (be specific), separated by a space (e.g: moveit 2023.0.3)"

$resultsPerPage = 0
while ($resultsPerPage -lt 1 -or $resultsPerPage -gt 100) {
    $resultsPerPage = Read-Host -Prompt "Enter the number of results per page (maximum: 100)"
    if (![string]::IsNullOrWhiteSpace($resultsPerPage) -and $resultsPerPage -match '^\d+$') {
        $resultsPerPage = [int]$resultsPerPage
        if ($resultsPerPage -lt 1 -or $resultsPerPage -gt 100) {
            Write-Host "Invalid input. Please enter a number between 1 and 100."
        }
    }
    else {
        Write-Host "Invalid input. Please enter a number between 1 and 100."
    }
}

$searchQuery = $software.Replace(" ", "%20")

# Public API url
$url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$searchQuery&resultsPerPage=$resultsPerPage&startIndex=10"

$headers = @{
    "User-Agent" = "Mozilla/5.0 (Linux; Android 12; CPH2127 Build/RKQ1.211119.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/114.0.5735.196 Mobile Safari/537.36"
}

try {
    Write-Host "Fetching data from the NVD database, this can take a minute (±).." -ForegroundColor Green
    $response = Invoke-RestMethod -Uri $url -Headers $headers
}
catch {
    Write-Host "Error occurred while fetching data. Details: $_"
    exit
}

# Check if vulnerabilities exist in the response
if ($response.vulnerabilities -eq $null) {
    Write-Host "No CVE IDs found for the given software."
    exit
}

# Extract CVE IDs and descriptions from the response
$cveIDs = @()
$descriptions = @()

foreach ($vulnerability in $response.vulnerabilities) {
    $cveIDs += $vulnerability.cve.id

    $description = $vulnerability.cve.descriptions | Where-Object { $_.lang -eq "en" } | Select-Object -ExpandProperty value
    $descriptions += $description
}

# Display the CVE IDs and descriptions
if ($cveIDs.Count -eq 0) {
    Write-Host "No hits for given keyword search, please try again." -ForegroundColor Magenta
} else {
    for ($i = 0; $i -lt $cveIDs.Count; $i++) {
        Write-Host "$($cveIDs[$i])" -ForegroundColor Magenta
        Write-Host "$($descriptions[$i])" -ForegroundColor Yellow
        Write-Host "---------------------"
    }
}

Write-Output "CVE sum:"

for ($i = 0; $i -lt $cveIDs.Count; $i++) {
    Write-Host "$($cveIDs[$i])," -NoNewLine -ForegroundColor Magenta
}

Write-Output ""
Write-Output ""

# Third user prompt for CVE ID input
$CVEs = Read-Host -Prompt "Extended CVE ID lookup. Enter one or more CVE IDs, separated by a comma (e.g. CVE-2023-27997,CVE-2022-41040)"

# Check if the input is empty or contains only whitespace
if ([string]::IsNullOrWhiteSpace($CVEs)) {
    Write-Host "No CVE IDs entered. Please try again."
    # Prompt the user to re-enter the CVE ID information
    $CVEs = Read-Host -Prompt "Enter one or more CVE IDs, separated by a comma (e.g. CVE-2023-27997,CVE-2022-41040)"
    # Check if the input is empty or contains only whitespace again
    if ([string]::IsNullOrWhiteSpace($CVEs)) {
        Write-Host "No CVE IDs entered. Exiting the script."
        exit
    }
}

# Validate the input using regex
$validCVEs = $CVEs -split ',\s*' | Where-Object { $_ -match '^CVE-\d{4}-\d{4,}$' }
if ($validCVEs.Count -eq 0) {
    Write-Host "Invalid CVE IDs entered. Please enter one or more valid CVE IDs in the format 'CVE-YYYY-NNNNN'."
    # Prompt the user to re-enter the CVE ID information
    $CVEs = Read-Host -Prompt "Now enter one or more CVE IDs, separated by a comma (e.g. CVE-2023-27997,CVE-2022-41040)"
    # Check if the input is empty or contains only whitespace
    if ([string]::IsNullOrWhiteSpace($CVEs)) {
        Write-Host "No CVE IDs entered. Exiting the script."
        exit
    }
    # Validate the input again
    $validCVEs = $CVEs -split ',\s*' | Where-Object { $_ -match '^CVE-\d{4}-\d{4,}$' }
}

# Process valid CVE IDs
foreach ($CVE in $validCVEs) {
    $apiUrl = "https://cve.circl.lu/api/cve/$CVE"
    $jsonResponse = Invoke-RestMethod -Uri $apiUrl
    
    $id = $jsonResponse.id
    $references = $jsonResponse.references
    $summary = $jsonResponse.summary
    $vulnerableProducts = $jsonResponse.vulnerable_product
    
    $url = "https://nvd.nist.gov/vuln/detail/$CVE"

    try {
        $response = Invoke-RestMethod -Uri $url -ErrorVariable errorMessage -ErrorAction SilentlyContinue
    } catch {
        if ($errorMessage.Exception.Response.StatusCode -eq [System.Net.HttpStatusCode]::ServiceUnavailable) {
            Write-Host "The server responded with a 503 error. Please try again later."
            continue
    } else {
        Write-Host "Error occurred while fetching data. Details: $_"
        exit
    }
}


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

    $exploitFound = $response -like "*$exploitString*"

    if ($exploitFound) {
        Write-Host ("Exploit: ") -NoNewline -ForegroundColor Green
        Write-Host "Yes, this CVE is in CISA's Known Exploited Vulnerabilities Catalog." -ForegroundColor Red
        Write-Host ("URLs: ") -ForegroundColor Green
        Write-Host "https://nvd.nist.gov/vuln/detail/$CVE" -ForegroundColor Blue
        Write-Host "https://github.com/nomi-sec/PoC-in-GitHub" -ForegroundColor Blue
    } else {
        Write-Host ("Exploit: ") -NoNewline -ForegroundColor Green
        Write-Host "No, this CVE is not in CISA's Known Exploited Vulnerabilities Catalog." -ForegroundColor Yellow
        Write-Host "However, there could still be an exploit POC for this vuln:" -ForegroundColor Yellow
        Write-Host "https://github.com/nomi-sec/PoC-in-GitHub" -ForegroundColor Blue
    }

    Write-Host "---------------------"
}
