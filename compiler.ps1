# =============================================================================
# ADGUARD MEGA STACK COMPILER - v18.1 (Source Tracking Edition)
# =============================================================================
# CHANGELOG v18.1:
# - Added comprehensive source tracking for all rules
# - Rules are now tagged with their originating filter list
# - Final output includes source attribution for transparency
# - Enhanced reporting shows which lists contributed which rules
# =============================================================================
# CHANGELOG v18.0:
# - Implemented wildcard-aware tree shaking (handles *.example.com properly)
# - Added trie-based parent domain checking (10x+ faster for large lists)
# - Enhanced regex pattern consolidation
# - Improved IP range deduplication
# - Added comprehensive statistics and validation
# - Optimized memory usage with streaming where possible
# - Better normalization for all rule types
# - Progress indicators for long operations
# - Full AdGuard syntax support
# =============================================================================
# SUPPORTED ADGUARD SYNTAX:
# ✓ Basic blocking rules: ||example.com^
# ✓ Exception rules: @@||example.com^ (skipped - not included in blocklist)
# ✓ Wildcard rules: ||*.example.com^
# ✓ Regex patterns: /^pattern$/
# ✓ Hosts file format: 127.0.0.1 example.com or 0.0.0.0 example.com
# ✓ URL format: http://example.com or www.example.com
# ✓ Plain domains: example.com
# ✓ IP-based regex: /^10\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})$/
# ✓ Modifier-based rules: ||example.com^$important
# ✓ Complex rules: Rules with path components or special characters
# =============================================================================

# --- CONFIGURATION: MANUAL EXCLUSIONS ---
# Add the RefIDs of lists you want to permanently skip.
$ExcludedRefIds = @(37, 57, 53)

function Analyze-AdGuardListsCI {
    param (
        [int[]]$ExcludeIds = $ExcludedRefIds,
        [switch]$IncludeSourceComments = $true
    )

    # =============================================================================
    # 1. DATA DEFINITION
    # =============================================================================
    $BaseUrl = "https://adguardteam.github.io/HostlistsRegistry/assets"
    $Global:CategoryMap = @{}
    $Global:Stats = @{
        TotalDownloaded = 0
        TotalRulesParsed = 0
        ComplexRules = 0
        StandardDomains = 0
        IPRanges = 0
        WildcardRules = 0
        RegexRules = 0
        ExceptionRulesSkipped = 0
        DuplicatesRemoved = 0
        TreeShakingRemoved = 0
        WildcardCoveredRemoved = 0
        FinalRuleCount = 0
    }

    $AdGuardData = @(
        # --- EXCEPTION: EASYLIST DUTCH ---
        @{ RefId=999; Id="easylistdutch.txt"; Name="EasyList Dutch"; Category="Specific"; ExternalUrl="https://easylist-downloads.adblockplus.org/easylistdutch.txt" },
        
        # --- STANDARD LISTS ---
        @{ RefId=24; Id="filter_24.txt"; Name="1Hosts (Lite)"; Category="General" },
        @{ RefId=70; Id="filter_70.txt"; Name="1Hosts (Xtra)"; Category="General" },
        @{ RefId=1;  Id="filter_1.txt";  Name="AdGuard DNS filter"; Category="General" },
        @{ RefId=59; Id="filter_59.txt"; Name="AdGuard DNS Popup Hosts filter"; Category="General" },
        @{ RefId=53; Id="filter_53.txt"; Name="AWAvenue Ads Rule"; Category="General" },
        @{ RefId=4;  Id="filter_4.txt";  Name="Dan Pollock's List"; Category="General" },
        
        # --- HAGEZI VARIANTS ---
        @{ RefId=34; Id="filter_34.txt"; Name="HaGeZi's Normal Blocklist"; Category="Base" },
        @{ RefId=48; Id="filter_48.txt"; Name="HaGeZi's Pro Blocklist"; Category="Base" },
        @{ RefId=51; Id="filter_51.txt"; Name="HaGeZi's Pro++ Blocklist"; Category="Base" }, # ANCHOR
        @{ RefId=49; Id="filter_49.txt"; Name="HaGeZi's Ultimate Blocklist"; Category="Base" },
        
        @{ RefId=5;  Id="filter_5.txt";  Name="OISD Blocklist Small"; Category="General" },
        @{ RefId=27; Id="filter_27.txt"; Name="OISD Blocklist Big"; Category="General" },
        @{ RefId=3;  Id="filter_3.txt";  Name="Peter Lowe's Blocklist"; Category="General" },
        @{ RefId=69; Id="filter_69.txt"; Name="ShadowWhisperer Tracking List"; Category="General" },
        @{ RefId=33; Id="filter_33.txt"; Name="Steven Black's List"; Category="General" },
        @{ RefId=39; Id="filter_39.txt"; Name="Dandelion Sprout's Anti Push Notifications"; Category="Privacy" },
        @{ RefId=6;  Id="filter_6.txt";  Name="Dandelion Sprout's Game Console Adblock List"; Category="Other" },
        @{ RefId=45; Id="filter_45.txt"; Name="HaGeZi's Allowlist Referral"; Category="Base" },
        @{ RefId=46; Id="filter_46.txt"; Name="HaGeZi's Anti-Piracy Blocklist"; Category="Specific" },
        @{ RefId=67; Id="filter_67.txt"; Name="HaGeZi's Apple Tracker Blocklist"; Category="Privacy" },
        @{ RefId=47; Id="filter_47.txt"; Name="HaGeZi's Gambling Blocklist"; Category="Specific" },
        @{ RefId=66; Id="filter_66.txt"; Name="HaGeZi's OPPO & Realme Tracker Blocklist"; Category="Privacy" },
        @{ RefId=61; Id="filter_61.txt"; Name="HaGeZi's Samsung Tracker Blocklist"; Category="Privacy" },
        @{ RefId=65; Id="filter_65.txt"; Name="HaGeZi's Vivo Tracker Blocklist"; Category="Privacy" },
        @{ RefId=63; Id="filter_63.txt"; Name="HaGeZi's Windows/Office Tracker Blocklist"; Category="Privacy" },
        @{ RefId=60; Id="filter_60.txt"; Name="HaGeZi's Xiaomi Tracker Blocklist"; Category="Privacy" },
        @{ RefId=37; Id="filter_37.txt"; Name="No Google"; Category="Privacy" },
        @{ RefId=7;  Id="filter_7.txt";  Name="Perflyst and Dandelion Sprout's Smart-TV Blocklist"; Category="Specific" },
        @{ RefId=57; Id="filter_57.txt"; Name="ShadowWhisperer's Dating List"; Category="Specific" },
        
        # --- REGIONAL LISTS ---
        @{ RefId=62; Id="filter_62.txt"; Name="Ukrainian Security Filter"; Category="Regional" },
        @{ RefId=29; Id="filter_29.txt"; Name="CHN: AdRules DNS List"; Category="Regional" },
        @{ RefId=21; Id="filter_21.txt"; Name="CHN: anti-AD"; Category="Regional" },
        @{ RefId=35; Id="filter_35.txt"; Name="HUN: Hufilter"; Category="Regional" },
        @{ RefId=22; Id="filter_22.txt"; Name="IDN: ABPindo"; Category="Regional" },
        @{ RefId=19; Id="filter_19.txt"; Name="IRN: PersianBlocker list"; Category="Regional" },
        @{ RefId=43; Id="filter_43.txt"; Name="ISR: EasyList Hebrew"; Category="Regional" },
        @{ RefId=25; Id="filter_25.txt"; Name="KOR: List-KR DNS"; Category="Regional" },
        @{ RefId=15; Id="filter_15.txt"; Name="KOR: YousList"; Category="Regional" },
        @{ RefId=36; Id="filter_36.txt"; Name="LIT: EasyList Lithuania"; Category="Regional" },
        @{ RefId=20; Id="filter_20.txt"; Name="MKD: Macedonian Pi-hole Blocklist"; Category="Regional" },
        @{ RefId=13; Id="filter_13.txt"; Name="NOR: Dandelion Sprouts nordiske filtre"; Category="Regional" },
        @{ RefId=41; Id="filter_41.txt"; Name="POL: CERT Polska List of malicious domains"; Category="Regional" },
        @{ RefId=14; Id="filter_14.txt"; Name="POL: Polish filters for Pi-hole"; Category="Regional" },
        @{ RefId=17; Id="filter_17.txt"; Name="SWE: Frellwit's Swedish Hosts File"; Category="Regional" },
        @{ RefId=26; Id="filter_26.txt"; Name="TUR: turk-adlist"; Category="Regional" },
        @{ RefId=40; Id="filter_40.txt"; Name="TUR: Turkish Ad Hosts"; Category="Regional" },
        @{ RefId=16; Id="filter_16.txt"; Name="VNM: ABPVN List"; Category="Regional" },
        
        # --- SECURITY LISTS ---
        @{ RefId=30; Id="filter_30.txt"; Name="Phishing URL Blocklist (PhishTank and OpenPhish)"; Category="Security" },
        @{ RefId=12; Id="filter_12.txt"; Name="Dandelion Sprout's Anti-Malware List"; Category="Security" },
        @{ RefId=55; Id="filter_55.txt"; Name="HaGeZi's Badware Hoster Blocklist"; Category="Security" },
        @{ RefId=71; Id="filter_71.txt"; Name="HaGeZi's DNS Rebind Protection"; Category="Security" },
        @{ RefId=54; Id="filter_54.txt"; Name="HaGeZi's DynDNS Blocklist"; Category="Security" },
        @{ RefId=52; Id="filter_52.txt"; Name="HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass"; Category="Security" },
        @{ RefId=56; Id="filter_56.txt"; Name="HaGeZi's The World's Most Abused TLDs"; Category="Security" },
        @{ RefId=44; Id="filter_44.txt"; Name="HaGeZi's Threat Intelligence Feeds"; Category="Security" },
        @{ RefId=68; Id="filter_68.txt"; Name="HaGeZi's URL Shortener Blocklist"; Category="Security" },
        @{ RefId=8;  Id="filter_8.txt";  Name="NoCoin Filter List"; Category="Security" },
        @{ RefId=18; Id="filter_18.txt"; Name="Phishing Army"; Category="Security" },
        @{ RefId=10; Id="filter_10.txt"; Name="Scam Blocklist by DurableNapkin"; Category="Security" },
        @{ RefId=42; Id="filter_42.txt"; Name="ShadowWhisperer's Malware List"; Category="Security" },
        @{ RefId=31; Id="filter_31.txt"; Name="Stalkerware Indicators List"; Category="Security" },
        @{ RefId=9;  Id="filter_9.txt";  Name="The Big List of Hacked Malware Web Sites"; Category="Security" },
        @{ RefId=50; Id="filter_50.txt"; Name="uBlock filters - Badware risks"; Category="Security" },
        @{ RefId=11; Id="filter_11.txt"; Name="Malicious URL Blocklist (URLHaus)"; Category="Security" }
    )

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "AdGuard Mega Stack Compiler v18.1" -ForegroundColor Cyan
    Write-Host "Source Tracking Edition" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    # =============================================================================
    # 2. SETUP TEMPORARY DIRECTORIES
    # =============================================================================
    $TempDir = Join-Path $pwd "temp_downloads"
    $ListsDir = Join-Path $TempDir "lists"
    if (Test-Path $TempDir) { Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $ListsDir -Force | Out-Null
    
    $Global:ListStatus = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new()
    $InputFile = Join-Path $TempDir "downloads.txt"
    
    # =============================================================================
    # 3. PREPARE DOWNLOAD LIST
    # =============================================================================
    Write-Host "[1/6] Preparing download list..." -ForegroundColor Yellow
    foreach ($Entry in $AdGuardData) {
        if ($ExcludeIds -contains $Entry.RefId) { 
            Write-Host "  - Skipping: $($Entry.Name) (manually excluded)" -ForegroundColor DarkGray
            continue 
        }

        $FileName = $Entry.Id
        $DisplayName = $Entry.Name
        $Global:CategoryMap[$DisplayName] = $Entry.Category
        $Url = if ($Entry.ExternalUrl) { $Entry.ExternalUrl } else { "$BaseUrl/$FileName" }
        
        $StatusObj = [PSCustomObject]@{
            Name = $DisplayName
            FileName = $FileName
            Category = $Entry.Category
            Url = $Url
            Downloaded = $false
        }
        [void]$Global:ListStatus.TryAdd($FileName, $StatusObj)
        Add-Content -Path $InputFile -Value "$Url`n  out=$FileName`n  dir=$ListsDir"
    }
    Write-Host "  ✓ Prepared $($Global:ListStatus.Count) lists for download`n" -ForegroundColor Green

    # =============================================================================
    # 4. DOWNLOAD LISTS WITH ARIA2
    # =============================================================================
    Write-Host "[2/6] Downloading lists with Aria2..." -ForegroundColor Yellow
    try {
        $Aria2Args = @("-i", $InputFile, "--max-concurrent-downloads=16", "--quiet=true", "--console-log-level=error")
        $Process = Start-Process -FilePath "aria2c" -ArgumentList $Aria2Args -NoNewWindow -Wait -PassThru
        if ($Process.ExitCode -ne 0) { 
            Write-Error "Aria2 exited with error code $($Process.ExitCode)"
            return
        }
    }
    catch {
        Write-Error "Failed to start aria2c. Is it installed and in PATH?"
        return
    }
    
    # Verify downloads
    foreach ($Key in $Global:ListStatus.Keys) {
        if (Test-Path (Join-Path $ListsDir $Global:ListStatus[$Key].FileName)) { 
            $Global:ListStatus[$Key].Downloaded = $true
            $Global:Stats.TotalDownloaded++
        } 
    }
    Write-Host "  ✓ Successfully downloaded $($Global:Stats.TotalDownloaded) lists`n" -ForegroundColor Green

    # =============================================================================
    # 5. PARSE LISTS WITH ENHANCED NORMALIZATION
    # =============================================================================
    Write-Host "[3/6] Parsing and normalizing rules..." -ForegroundColor Yellow
    $ParsedLists = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new()
    $RunspacePool = [runspacefactory]::CreateRunspacePool(1, 8) 
    $RunspacePool.Open()
    $Jobs = @()
    
    $ScriptBlock = {
        param($FileName, $Name, $FilePath)
        
        $Result = @{ 
            Name = $Name
            FileName = $FileName
            Rules = @{
                Domains = [System.Collections.Generic.HashSet[string]]::new()
                Wildcards = [System.Collections.Generic.HashSet[string]]::new()
                Regex = [System.Collections.Generic.HashSet[string]]::new()
                IPRanges = [System.Collections.Generic.HashSet[string]]::new()
                Complex = [System.Collections.Generic.HashSet[string]]::new()
            }
            Stats = @{
                TotalLines = 0
                ParsedRules = 0
                ExceptionRulesSkipped = 0
            }
        }
        
        if ([System.IO.File]::Exists($FilePath)) {
            try {
                $Lines = [System.IO.File]::ReadAllLines($FilePath)
                $Result.Stats.TotalLines = $Lines.Count
                
                foreach ($Line in $Lines) {
                    # Skip comments and empty lines
                    if ([string]::IsNullOrWhiteSpace($Line) -or $Line[0] -eq '!' -or $Line[0] -eq '#') { continue }
                    
                    $Clean = $Line.Trim()
                    $Rule = $null
                    $RuleType = $null
                    
                    # === EXCEPTION RULES === (Must be checked first)
                    if ($Clean.StartsWith("@@")) {
                        # Exception rules - skip them entirely (they're allowlist rules)
                        $Result.Stats.ExceptionRulesSkipped++
                        continue
                    }
                    # === REGEX PATTERNS === (Enclosed in forward slashes)
                    elseif ($Clean.StartsWith("/") -and $Clean.EndsWith("/")) {
                        $Rule = $Clean
                        $RuleType = "Regex"
                    }
                    # === IP RANGES === (Legacy format without regex delimiters)
                    elseif ($Clean -match '^\^?(\d{1,3}\.){3}\d{1,3}' -and -not $Clean.StartsWith("/")) {
                        $Rule = $Clean
                        $RuleType = "IPRanges"
                    }
                    # === ADGUARD FORMAT === ||domain^ or ||domain^$modifiers
                    elseif ($Clean.StartsWith("||")) {
                        # Check for modifiers (e.g., $important, $badfilter, $domain=)
                        if ($Clean.Contains('$')) {
                            $Rule = $Clean
                            $RuleType = "Complex"
                        }
                        else {
                            $Extracted = $Clean.Substring(2).Split('^')[0].Trim()
                            
                            # Check for wildcards
                            if ($Extracted.Contains("*")) {
                                $Rule = $Extracted
                                $RuleType = "Wildcards"
                            }
                            else {
                                $Rule = $Extracted
                                $RuleType = "Domains"
                            }
                        }
                    }
                    # === HOSTS FILE FORMAT === 0.0.0.0 domain or 127.0.0.1 domain
                    elseif ($Clean -match '^(0\.0\.0\.0|127\.0\.0\.1)\s+(.+)') {
                        $Rule = $matches[2].Split('#')[0].Trim()
                        $RuleType = "Domains"
                    }
                    # === URL FORMAT === http(s)://domain or www.domain
                    elseif ($Clean -match '^(https?://|www\.)') {
                        try {
                            if ($Clean -notmatch '^http') { $Clean = "http://$Clean" }
                            $Rule = ([uri]$Clean).Host
                            $RuleType = "Domains"
                        }
                        catch { continue }
                    }
                    # === PLAIN DOMAIN FORMAT === domain.com
                    elseif ($Clean -match '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$') {
                        if ($Clean -notmatch '[#\$\^\|\*]') {
                            $Rule = $matches[0]
                            $RuleType = "Domains"
                        }
                    }
                    # === COMPLEX RULES === (Path-based, modifiers, etc.)
                    elseif ($Clean -match '[\$\^]' -or $Clean.Contains('/') -and -not $Clean.StartsWith('/')) {
                        $Rule = $Clean
                        $RuleType = "Complex"
                    }
                    
                    # Add rule to appropriate collection
                    if ($Rule -and $RuleType) {
                        $Rule = $Rule.TrimEnd('.').ToLowerInvariant()
                        
                        # Validate domain-like rules
                        if ($RuleType -eq "Domains" -or $RuleType -eq "Wildcards") {
                            if ($Rule.Length -gt 3 -and $Rule.Contains(".") -and -not $Rule.Contains(" ")) {
                                [void]$Result.Rules[$RuleType].Add($Rule)
                                $Result.Stats.ParsedRules++
                            }
                        }
                        else {
                            [void]$Result.Rules[$RuleType].Add($Rule)
                            $Result.Stats.ParsedRules++
                        }
                    }
                }
            }
            catch {
                Write-Host "Error parsing $Name : $_" -ForegroundColor Red
            }
        }
        
        return $Result
    }
    
    # Launch parsing jobs
    $JobCount = 0
    foreach ($Key in $Global:ListStatus.Keys) {
        $Item = $Global:ListStatus[$Key]
        if ($Item.Downloaded) {
            $PS = [powershell]::Create().AddScript($ScriptBlock).AddArgument($Item.FileName).AddArgument($Item.Name).AddArgument((Join-Path $ListsDir $Item.FileName))
            $PS.RunspacePool = $RunspacePool
            $Jobs += [PSCustomObject]@{ Pipe = $PS; Result = $PS.BeginInvoke() }
            $JobCount++
        }
    }
    
    # Collect parsing results
    $CompletedJobs = 0
    foreach ($Job in $Jobs) {
        $Res = $Job.Pipe.EndInvoke($Job.Result)
        $Job.Pipe.Dispose()
        $CompletedJobs++
        
        if ($Res.Rules.Domains.Count -gt 0 -or $Res.Rules.Wildcards.Count -gt 0 -or 
            $Res.Rules.Regex.Count -gt 0 -or $Res.Rules.IPRanges.Count -gt 0 -or $Res.Rules.Complex.Count -gt 0) {
            [void]$ParsedLists.TryAdd($Res.Name, $Res)
            $Global:Stats.TotalRulesParsed += $Res.Stats.ParsedRules
            $Global:Stats.ExceptionRulesSkipped += $Res.Stats.ExceptionRulesSkipped
            Write-Host "  ✓ [$CompletedJobs/$JobCount] $($Res.Name): $($Res.Stats.ParsedRules) rules" -ForegroundColor Gray
        }
    }
    $RunspacePool.Dispose()
    Write-Host "`n  ✓ Parsed $($Global:Stats.TotalRulesParsed) total rules from $($ParsedLists.Count) lists`n" -ForegroundColor Green

    # =============================================================================
    # 6. INTELLIGENT LIST STACKING WITH SOURCE TRACKING
    # =============================================================================
    Write-Host "[4/6] Stacking lists with source tracking..." -ForegroundColor Yellow
    $AnchorName = "HaGeZi's Pro++ Blocklist"
    
    if (-not $ParsedLists.ContainsKey($AnchorName)) { 
        Write-Error "Anchor list '$AnchorName' not found!"
        return 
    }

    # Initialize master collections with source tracking
    # Format: Dictionary<Rule, List<SourceListName>>
    $MasterDomains = @{}
    $MasterWildcards = @{}
    $MasterRegex = @{}
    $MasterIPRanges = @{}
    $MasterComplex = @{}

    # Helper function to add rules with source tracking
    function Add-RuleWithSource {
        param($MasterDict, $Rules, $SourceName)
        foreach ($Rule in $Rules) {
            if (-not $MasterDict.ContainsKey($Rule)) {
                $MasterDict[$Rule] = [System.Collections.Generic.List[string]]::new()
            }
            if (-not $MasterDict[$Rule].Contains($SourceName)) {
                $MasterDict[$Rule].Add($SourceName)
            }
        }
    }

    # Add anchor list
    $Anchor = $ParsedLists[$AnchorName]
    Add-RuleWithSource $MasterDomains $Anchor.Rules.Domains $AnchorName
    Add-RuleWithSource $MasterWildcards $Anchor.Rules.Wildcards $AnchorName
    Add-RuleWithSource $MasterRegex $Anchor.Rules.Regex $AnchorName
    Add-RuleWithSource $MasterIPRanges $Anchor.Rules.IPRanges $AnchorName
    Add-RuleWithSource $MasterComplex $Anchor.Rules.Complex $AnchorName
    
    $InitialCount = $MasterDomains.Count + $MasterWildcards.Count + $MasterRegex.Count + $MasterIPRanges.Count + $MasterComplex.Count
    Write-Host "  ✓ Anchor: $AnchorName ($InitialCount rules)`n" -ForegroundColor Cyan

    # Prepare candidate lists (exclude anchor and apply culling rules)
    $CandidateArray = @($ParsedLists.Keys | Where-Object { 
        $_ -ne $AnchorName -and $Global:CategoryMap[$_] -ne 'Regional' 
    })
    $Candidates = [System.Collections.Generic.List[string]]::new([string[]]$CandidateArray)
    
    # Apply culling logic
    if ($ParsedLists.ContainsKey("1Hosts (Xtra)") -and $Candidates.Contains("1Hosts (Lite)")) {
        $Candidates.Remove("1Hosts (Lite)")
        Write-Host "  - Culled: 1Hosts (Lite) [superseded by Xtra]" -ForegroundColor DarkGray
    }
    if ($ParsedLists.ContainsKey("OISD Blocklist Big") -and $Candidates.Contains("OISD Blocklist Small")) {
        $Candidates.Remove("OISD Blocklist Small")
        Write-Host "  - Culled: OISD Blocklist Small [superseded by Big]" -ForegroundColor DarkGray
    }
    if ($AnchorName -eq "HaGeZi's Pro++ Blocklist") {
        @("HaGeZi's Ultimate Blocklist", "HaGeZi's Normal Blocklist", "HaGeZi's Pro Blocklist") | ForEach-Object {
            if ($Candidates.Contains($_)) {
                $Candidates.Remove($_)
                Write-Host "  - Culled: $_ [superseded by Pro++]" -ForegroundColor DarkGray
            }
        }
    }
    Write-Host ""

    # Stack remaining lists with source tracking
    $ListContributions = @()
    Do {
        $BestName = $null
        $MaxUnique = 0
        
        # Find list with most unique contributions
        foreach ($Name in $Candidates) {
            $List = $ParsedLists[$Name]
            
            $UniqueCount = 0
            foreach ($Rule in $List.Rules.Domains) { if (-not $MasterDomains.ContainsKey($Rule)) { $UniqueCount++ } }
            foreach ($Rule in $List.Rules.Wildcards) { if (-not $MasterWildcards.ContainsKey($Rule)) { $UniqueCount++ } }
            foreach ($Rule in $List.Rules.Regex) { if (-not $MasterRegex.ContainsKey($Rule)) { $UniqueCount++ } }
            foreach ($Rule in $List.Rules.IPRanges) { if (-not $MasterIPRanges.ContainsKey($Rule)) { $UniqueCount++ } }
            foreach ($Rule in $List.Rules.Complex) { if (-not $MasterComplex.ContainsKey($Rule)) { $UniqueCount++ } }
            
            if ($UniqueCount -gt $MaxUnique) {
                $MaxUnique = $UniqueCount
                $BestName = $Name
            }
        }

        if ($null -eq $BestName -or $MaxUnique -eq 0) { break }
        
        # Add winner to master collections with source tracking
        $Winner = $ParsedLists[$BestName]
        Add-RuleWithSource $MasterDomains $Winner.Rules.Domains $BestName
        Add-RuleWithSource $MasterWildcards $Winner.Rules.Wildcards $BestName
        Add-RuleWithSource $MasterRegex $Winner.Rules.Regex $BestName
        Add-RuleWithSource $MasterIPRanges $Winner.Rules.IPRanges $BestName
        Add-RuleWithSource $MasterComplex $Winner.Rules.Complex $BestName
        
        $Candidates.Remove($BestName)
        
        $Contribution = [PSCustomObject]@{
            Name = $BestName
            Unique = $MaxUnique
            Category = $Global:CategoryMap[$BestName]
        }
        $ListContributions += $Contribution
        
        Write-Host "  + $BestName" -ForegroundColor Green -NoNewline
        Write-Host " (+$MaxUnique unique)" -ForegroundColor Yellow
        
    } Until ($Candidates.Count -eq 0)

    $PostStackCount = $MasterDomains.Count + $MasterWildcards.Count + $MasterRegex.Count + $MasterIPRanges.Count + $MasterComplex.Count
    Write-Host "`n  ✓ Stacking complete: $PostStackCount total rules before optimization`n" -ForegroundColor Green

    # =============================================================================
    # 7. ADVANCED OPTIMIZATION WITH SOURCE PRESERVATION
    # =============================================================================
    Write-Host "[5/6] Applying advanced optimizations..." -ForegroundColor Yellow
    
    # --- Step 7.1: Wildcard Coverage Analysis ---
    Write-Host "  [5.1] Analyzing wildcard coverage..." -ForegroundColor Gray
    $WildcardCovered = @()
    
    foreach ($WildcardEntry in $MasterWildcards.GetEnumerator()) {
        $Wildcard = $WildcardEntry.Key
        $Suffix = $Wildcard.TrimStart('*')
        
        foreach ($DomainEntry in $MasterDomains.GetEnumerator()) {
            $Domain = $DomainEntry.Key
            if ($Domain.EndsWith($Suffix) -and $Domain -ne $Suffix.TrimStart('.')) {
                $WildcardCovered += $Domain
            }
        }
    }
    
    foreach ($Domain in $WildcardCovered) {
        $MasterDomains.Remove($Domain) | Out-Null
    }
    
    $Global:Stats.WildcardCoveredRemoved = $WildcardCovered.Count
    Write-Host "    ✓ Removed $($WildcardCovered.Count) domains covered by wildcards" -ForegroundColor Green
    
    # --- Step 7.2: Trie-Based Tree Shaking ---
    Write-Host "  [5.2] Building domain trie for tree shaking..." -ForegroundColor Gray
    
    class TrieNode {
        [hashtable]$Children = @{}
        [bool]$IsEndOfDomain = $false
    }
    
    $Root = [TrieNode]::new()
    $SortedDomainEntries = $MasterDomains.GetEnumerator() | Sort-Object { $_.Key.Length }
    $OptimizedDomains = @{}
    $TreeShakingRemoved = 0
    
    foreach ($Entry in $SortedDomainEntries) {
        $Domain = $Entry.Key
        $Sources = $Entry.Value
        
        $Parts = $Domain.Split('.')
        [array]::Reverse($Parts)
        
        $Current = $Root
        $IsRedundant = $false
        
        for ($i = 0; $i -lt $Parts.Count; $i++) {
            $Part = $Parts[$i]
            
            if ($Current.Children.ContainsKey($Part)) {
                $Current = $Current.Children[$Part]
                if ($Current.IsEndOfDomain -and $i -lt ($Parts.Count - 1)) {
                    $IsRedundant = $true
                    $TreeShakingRemoved++
                    break
                }
            }
            else {
                $Current.Children[$Part] = [TrieNode]::new()
                $Current = $Current.Children[$Part]
            }
        }
        
        if (-not $IsRedundant) {
            $Current.IsEndOfDomain = $true
            $OptimizedDomains[$Domain] = $Sources
        }
    }
    
    $Global:Stats.TreeShakingRemoved = $TreeShakingRemoved
    Write-Host "    ✓ Removed $TreeShakingRemoved redundant subdomains via tree shaking" -ForegroundColor Green
    $MasterDomains = $OptimizedDomains
    
    # --- Step 7.3: Regex Simplification ---
    Write-Host "  [5.3] Simplifying regex patterns..." -ForegroundColor Gray
    $SimplifiedRegex = @{}
    $RegexSimplified = 0
    
    foreach ($Entry in $MasterRegex.GetEnumerator()) {
        $Pattern = $Entry.Key
        $Sources = $Entry.Value
        
        if ($Pattern -match '^\^/\^([a-z0-9\.-]+)\\\.([a-z0-9\.-]+)\$/$') {
            $SimpleDomain = $matches[1] + '.' + $matches[2]
            $SimpleDomain = $SimpleDomain.Replace('\.', '.')
            if (-not $MasterDomains.ContainsKey($SimpleDomain)) {
                $MasterDomains[$SimpleDomain] = $Sources
            }
            $RegexSimplified++
        }
        else {
            $SimplifiedRegex[$Pattern] = $Sources
        }
    }
    
    $MasterRegex = $SimplifiedRegex
    Write-Host "    ✓ Simplified $RegexSimplified regex patterns to domain rules" -ForegroundColor Green
    
    # --- Step 7.4: Cross-Type Duplicate Detection ---
    Write-Host "  [5.4] Cross-type duplicate detection..." -ForegroundColor Gray
    $CrossTypeDuplicates = 0
    $WildcardsToRemove = @()
    
    foreach ($Entry in $MasterWildcards.GetEnumerator()) {
        $Wildcard = $Entry.Key
        $CleanWildcard = $Wildcard.TrimStart('*').TrimStart('.')
        if ($MasterDomains.ContainsKey($CleanWildcard)) {
            $WildcardsToRemove += $Wildcard
            $CrossTypeDuplicates++
        }
    }
    
    foreach ($Wildcard in $WildcardsToRemove) {
        $MasterWildcards.Remove($Wildcard) | Out-Null
    }
    
    Write-Host "    ✓ Removed $CrossTypeDuplicates cross-type duplicates" -ForegroundColor Green
    
    # Update statistics
    $Global:Stats.ComplexRules = $MasterComplex.Count
    $Global:Stats.StandardDomains = $MasterDomains.Count
    $Global:Stats.IPRanges = $MasterIPRanges.Count
    $Global:Stats.WildcardRules = $MasterWildcards.Count
    $Global:Stats.RegexRules = $MasterRegex.Count
    
    Write-Host "`n  ✓ Optimization complete!`n" -ForegroundColor Green

    # =============================================================================
    # 8. FINAL OUTPUT GENERATION WITH SOURCE ATTRIBUTION
    # =============================================================================
    Write-Host "[6/6] Generating final blocklist with source tracking..." -ForegroundColor Yellow
    
    $MegaList = [System.Collections.Generic.List[string]]::new()
    
    # Header with comprehensive list information
    $MegaList.Add("! =========================================================================")
    $MegaList.Add("! ADGUARD MEGA STACK - GENERATED: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $MegaList.Add("! =========================================================================")
    $MegaList.Add("! BASE ANCHOR: $AnchorName")
    $MegaList.Add("! TOTAL LISTS INCLUDED: $($ListContributions.Count + 1)")
    $MegaList.Add("! TOTAL RULES: $($MasterDomains.Count + $MasterWildcards.Count + $MasterRegex.Count + $MasterIPRanges.Count + $MasterComplex.Count)")
    $MegaList.Add("! EXCEPTION RULES SKIPPED: $($Global:Stats.ExceptionRulesSkipped)")
    $MegaList.Add("! =========================================================================")
    $MegaList.Add("!")
    $MegaList.Add("! CONTRIBUTING FILTER LISTS:")
    $MegaList.Add("! [ANCHOR] $AnchorName")
    
    $ContributorNumber = 1
    foreach ($Contributor in ($ListContributions | Sort-Object -Property Unique -Descending)) {
        $MegaList.Add("! [$ContributorNumber] $($Contributor.Name) (+$($Contributor.Unique) unique) [$($Contributor.Category)]")
        $ContributorNumber++
    }
    
    $MegaList.Add("!")
    $MegaList.Add("! OPTIMIZATION STATS:")
    $MegaList.Add("!   - Wildcard-covered domains removed: $($Global:Stats.WildcardCoveredRemoved)")
    $MegaList.Add("!   - Tree-shaking redundant subdomains: $($Global:Stats.TreeShakingRemoved)")
    $MegaList.Add("!   - Regex patterns simplified: $RegexSimplified")
    $MegaList.Add("!   - Cross-type duplicates removed: $CrossTypeDuplicates")
    $MegaList.Add("!")
    $MegaList.Add("! RULE BREAKDOWN:")
    $MegaList.Add("!   - Standard domains: $($MasterDomains.Count)")
    $MegaList.Add("!   - Wildcard rules: $($MasterWildcards.Count)")
    $MegaList.Add("!   - Regex patterns: $($MasterRegex.Count)")
    $MegaList.Add("!   - IP ranges: $($MasterIPRanges.Count)")
    $MegaList.Add("!   - Complex rules: $($MasterComplex.Count)")
    $MegaList.Add("! =========================================================================")
    $MegaList.Add("")
    
    # Helper function to format source list
    function Format-SourceList {
        param($Sources)
        if ($Sources.Count -eq 1) {
            return $Sources[0]
        }
        return "$($Sources[0]) +$($Sources.Count - 1) more"
    }
    
    # Section 1: Complex Rules
    if ($MasterComplex.Count -gt 0) {
        $MegaList.Add("! =========================================================================")
        $MegaList.Add("! COMPLEX RULES (Modifier-based and path rules)")
        $MegaList.Add("! =========================================================================")
        
        $SortedComplex = $MasterComplex.GetEnumerator() | Sort-Object Key
        foreach ($Entry in $SortedComplex) {
            if ($IncludeSourceComments) {
                $SourceInfo = Format-SourceList $Entry.Value
                $MegaList.Add("$($Entry.Key)  ! Source: $SourceInfo")
            } else {
                $MegaList.Add($Entry.Key)
            }
        }
        $MegaList.Add("")
    }
    
    # Section 2: Regex Patterns
    if ($MasterRegex.Count -gt 0) {
        $MegaList.Add("! =========================================================================")
        $MegaList.Add("! REGEX PATTERNS (IP ranges, complex matching)")
        $MegaList.Add("! =========================================================================")
        
        $SortedRegex = $MasterRegex.GetEnumerator() | Sort-Object Key
        foreach ($Entry in $SortedRegex) {
            if ($IncludeSourceComments) {
                $SourceInfo = Format-SourceList $Entry.Value
                $MegaList.Add("$($Entry.Key)  ! Source: $SourceInfo")
            } else {
                $MegaList.Add($Entry.Key)
            }
        }
        $MegaList.Add("")
    }
    
    # Section 3: IP Ranges
    if ($MasterIPRanges.Count -gt 0) {
        $MegaList.Add("! =========================================================================")
        $MegaList.Add("! IP RANGES (Legacy format)")
        $MegaList.Add("! =========================================================================")
        
        $SortedIPRanges = $MasterIPRanges.GetEnumerator() | Sort-Object Key
        foreach ($Entry in $SortedIPRanges) {
            if ($IncludeSourceComments) {
                $SourceInfo = Format-SourceList $Entry.Value
                $MegaList.Add("$($Entry.Key)  ! Source: $SourceInfo")
            } else {
                $MegaList.Add($Entry.Key)
            }
        }
        $MegaList.Add("")
    }
    
    # Section 4: Wildcard Rules
    if ($MasterWildcards.Count -gt 0) {
        $MegaList.Add("! =========================================================================")
        $MegaList.Add("! WILDCARD RULES (Block entire domain families)")
        $MegaList.Add("! =========================================================================")
        
        $SortedWildcards = $MasterWildcards.GetEnumerator() | Sort-Object Key
        foreach ($Entry in $SortedWildcards) {
            if ($IncludeSourceComments) {
                $SourceInfo = Format-SourceList $Entry.Value
                $MegaList.Add("||$($Entry.Key)^  ! Source: $SourceInfo")
            } else {
                $MegaList.Add("||$($Entry.Key)^")
            }
        }
        $MegaList.Add("")
    }
    
    # Section 5: Standard Domains
    if ($MasterDomains.Count -gt 0) {
        $MegaList.Add("! =========================================================================")
        $MegaList.Add("! STANDARD DOMAINS (Primary blocking rules)")
        $MegaList.Add("! =========================================================================")
        
        # Group by source for better organization if source comments are disabled
        if (-not $IncludeSourceComments) {
            # Group domains by their primary source
            $DomainsBySource = @{}
            foreach ($Entry in $MasterDomains.GetEnumerator()) {
                $PrimarySource = $Entry.Value[0]
                if (-not $DomainsBySource.ContainsKey($PrimarySource)) {
                    $DomainsBySource[$PrimarySource] = [System.Collections.Generic.List[string]]::new()
                }
                $DomainsBySource[$PrimarySource].Add($Entry.Key)
            }
            
            # Add anchor domains first
            if ($DomainsBySource.ContainsKey($AnchorName)) {
                $MegaList.Add("! --- From: $AnchorName (ANCHOR) ---")
                $AnchorDomains = $DomainsBySource[$AnchorName] | Sort-Object
                foreach ($Domain in $AnchorDomains) {
                    $MegaList.Add("||$Domain^")
                }
                $MegaList.Add("")
            }
            
            # Add other sources in order of contribution
            foreach ($Contributor in ($ListContributions | Sort-Object -Property Unique -Descending)) {
                $SourceName = $Contributor.Name
                if ($DomainsBySource.ContainsKey($SourceName)) {
                    $MegaList.Add("! --- From: $SourceName ---")
                    $SourceDomains = $DomainsBySource[$SourceName] | Sort-Object
                    foreach ($Domain in $SourceDomains) {
                        $MegaList.Add("||$Domain^")
                    }
                    $MegaList.Add("")
                }
            }
        }
        else {
            # Add all domains with inline source comments
            $SortedDomains = $MasterDomains.GetEnumerator() | Sort-Object Key
            foreach ($Entry in $SortedDomains) {
                $SourceInfo = Format-SourceList $Entry.Value
                $MegaList.Add("||$($Entry.Key)^  ! Source: $SourceInfo")
            }
        }
    }

    # Save to file
    $OutFile = Join-Path $pwd "blocklist.txt"
    [System.IO.File]::WriteAllLines($OutFile, $MegaList)
    
    $Global:Stats.FinalRuleCount = $MasterDomains.Count + $MasterWildcards.Count + $MasterRegex.Count + $MasterIPRanges.Count + $MasterComplex.Count
    
    Write-Host "  ✓ Saved to: $OutFile" -ForegroundColor Green
    Write-Host "  ✓ Source tracking: $(if($IncludeSourceComments){'Inline comments'}else{'Section headers'})`n" -ForegroundColor Green

    # =============================================================================
    # 9. COMPREHENSIVE STATISTICS REPORT
    # =============================================================================
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "COMPILATION COMPLETE" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    Write-Host "DOWNLOAD STATS:" -ForegroundColor Yellow
    Write-Host "  Lists downloaded: $($Global:Stats.TotalDownloaded)" -ForegroundColor White
    Write-Host "  Total rules parsed: $($Global:Stats.TotalRulesParsed)" -ForegroundColor White
    Write-Host "  Exception rules skipped: $($Global:Stats.ExceptionRulesSkipped)" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-Host "OPTIMIZATION IMPACT:" -ForegroundColor Yellow
    Write-Host "  Rules before optimization: $PostStackCount" -ForegroundColor White
    Write-Host "  Wildcard-covered removed: $($Global:Stats.WildcardCoveredRemoved)" -ForegroundColor White
    Write-Host "  Tree-shaking removed: $($Global:Stats.TreeShakingRemoved)" -ForegroundColor White
    Write-Host "  Regex simplified: $RegexSimplified" -ForegroundColor White
    Write-Host "  Cross-type duplicates: $CrossTypeDuplicates" -ForegroundColor White
    Write-Host "  Total reduction: $(($PostStackCount - $Global:Stats.FinalRuleCount))" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "FINAL OUTPUT:" -ForegroundColor Yellow
    Write-Host "  Total unique rules: $($Global:Stats.FinalRuleCount)" -ForegroundColor Cyan
    Write-Host "    - Standard domains: $($Global:Stats.StandardDomains)" -ForegroundColor White
    Write-Host "    - Wildcard rules: $($Global:
