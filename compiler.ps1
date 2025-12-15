# =============================================================================
# ADGUARD MEGA STACK COMPILER - v21.0 (Source-Aware Diff & Full Stats)
# =============================================================================
# CHANGELOG v21.0:
# - NEW: Source-Aware Diffing (Tracks exactly which list added/removed a rule)
# - REF: Restored full detailed headers, optimization stats, and contributor logs
# - REF: Full rebuild strategy maintained to prevent "Zombie Rule" false positives
# =============================================================================

# --- CONFIGURATION: MANUAL EXCLUSIONS ---
$ExcludedRefIds = @(37, 57, 53, 46)

function Analyze-AdGuardListsCI {
    param (
        [int[]]$ExcludeIds = $ExcludedRefIds
    )

    # =============================================================================
    # 0. LOAD PREVIOUS STATE (Source-Aware)
    # =============================================================================
    $ExistingBlocklistPath = Join-Path $pwd "blocklist.txt"
    # Map: Rule -> SourceName
    $PreviousRulesMap = @{}
    $DiffMode = $false

    if (Test-Path $ExistingBlocklistPath) {
        Write-Host "[0/7] Loading existing blocklist for smart comparison..." -ForegroundColor Yellow
        try {
            $CurrentReadSource = "Unknown"
            # Read lines, skipping empty ones
            $Lines = [System.IO.File]::ReadAllLines($ExistingBlocklistPath)
            
            foreach ($Line in $Lines) {
                if ([string]::IsNullOrWhiteSpace($Line)) { continue }
                
                # Detect Source Header: "! [Source Name] - X rules"
                if ($Line -match '^! \[(.+?)\] - \d+ rules') {
                    $CurrentReadSource = $matches[1]
                    continue
                }
                
                # Skip other comments/metadata
                if ($Line.StartsWith('!')) { continue }
                
                # Store Rule + Source
                $CleanRule = $Line.Trim()
                if (-not $PreviousRulesMap.ContainsKey($CleanRule)) {
                    $PreviousRulesMap[$CleanRule] = $CurrentReadSource
                }
            }
            $PrevCount = $PreviousRulesMap.Count
            Write-Host "  [OK] Indexed $PrevCount rules from previous build." -ForegroundColor Green
            $DiffMode = $true
        }
        catch {
            Write-Host "  [!] Error reading existing file. Diff skipped. $_" -ForegroundColor Red
        }
    } else {
        Write-Host "[0/7] No existing blocklist found. First run?" -ForegroundColor DarkGray
    }
    Write-Host ""

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
        TreeShakingRemoved = 0
        WildcardCoveredRemoved = 0
        RegexSimplified = 0
        CrossTypeDuplicates = 0
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

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "AdGuard Mega Stack Compiler v21.0" -ForegroundColor Cyan
    Write-Host "Source-Aware Diff Edition" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
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
    Write-Host "[1/7] Preparing download list..." -ForegroundColor Yellow
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
    $PreparedCount = $Global:ListStatus.Count
    Write-Host "  [OK] Prepared $PreparedCount lists for download" -ForegroundColor Green
    Write-Host ""

    # =============================================================================
    # 4. DOWNLOAD LISTS WITH ARIA2
    # =============================================================================
    Write-Host "[2/7] Downloading lists with Aria2..." -ForegroundColor Yellow
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
    $DownloadedCount = $Global:Stats.TotalDownloaded
    Write-Host "  [OK] Successfully downloaded $DownloadedCount lists" -ForegroundColor Green
    Write-Host ""

    # =============================================================================
    # 5. PARSE LISTS WITH ENHANCED NORMALIZATION
    # =============================================================================
    Write-Host "[3/7] Parsing and normalizing rules..." -ForegroundColor Yellow
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
                    if ([string]::IsNullOrWhiteSpace($Line) -or $Line[0] -eq '!' -or $Line[0] -eq '#') { continue }
                    
                    $Clean = $Line.Trim()
                    $Rule = $null
                    $RuleType = $null
                    
                    # Skip exception rules
                    if ($Clean.StartsWith("@@")) {
                        $Result.Stats.ExceptionRulesSkipped++
                        continue
                    }
                    # Regex patterns
                    elseif ($Clean.StartsWith("/") -and $Clean.EndsWith("/")) {
                        $Rule = $Clean
                        $RuleType = "Regex"
                    }
                    # IP ranges (legacy format)
                    elseif ($Clean -match '^\^?(\d{1,3}\.){3}\d{1,3}' -and -not $Clean.StartsWith("/")) {
                        $Rule = $Clean
                        $RuleType = "IPRanges"
                    }
                    # AdGuard format ||domain^
                    elseif ($Clean.StartsWith("||")) {
                        if ($Clean.Contains('$')) {
                            $Rule = $Clean
                            $RuleType = "Complex"
                        }
                        else {
                            $Extracted = $Clean.Substring(2).Split('^')[0].Trim()
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
                    # Hosts file format
                    elseif ($Clean -match '^(0\.0\.0\.0|127\.0\.0\.1)\s+(.+)') {
                        $Rule = $matches[2].Split('#')[0].Trim()
                        $RuleType = "Domains"
                    }
                    # URL format
                    elseif ($Clean -match '^(https?://|www\.)') {
                        try {
                            if ($Clean -notmatch '^http') { $Clean = "http://$Clean" }
                            $Rule = ([uri]$Clean).Host
                            $RuleType = "Domains"
                        }
                        catch { continue }
                    }
                    # Plain domain format
                    elseif ($Clean -match '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$') {
                        if ($Clean -notmatch '[#\$\^\|\*]') {
                            $Rule = $matches[0]
                            $RuleType = "Domains"
                        }
                    }
                    # Complex rules
                    elseif ($Clean -match '[\$\^]' -or ($Clean.Contains('/') -and -not $Clean.StartsWith('/'))) {
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
            
            $ProgressPercent = [math]::Round(($CompletedJobs / $JobCount) * 100)
            $ParsedRuleCount = $Res.Stats.ParsedRules
            Write-Host "  [OK] [$ProgressPercent%] $($Res.Name): $ParsedRuleCount rules" -ForegroundColor Gray
        }
    }
    $RunspacePool.Dispose()
    $TotalParsed = $Global:Stats.TotalRulesParsed
    $ListCount = $ParsedLists.Count
    Write-Host ""
    Write-Host "  [OK] Parsed $TotalParsed rules from $ListCount lists" -ForegroundColor Green
    Write-Host ""

    # =============================================================================
    # 6. INTELLIGENT LIST STACKING
    # =============================================================================
    Write-Host "[4/7] Stacking lists (tracking primary source)..." -ForegroundColor Yellow
    $AnchorName = "HaGeZi's Pro++ Blocklist"
    
    if (-not $ParsedLists.ContainsKey($AnchorName)) { 
        Write-Error "Anchor list '$AnchorName' not found!"
        return 
    }

    $MasterDomains = @{}
    $MasterWildcards = @{}
    $MasterRegex = @{}
    $MasterIPRanges = @{}
    $MasterComplex = @{}

    function Add-RulePrimarySource {
        param($MasterDict, $Rules, $SourceName)
        $NewRules = 0
        foreach ($Rule in $Rules) {
            if (-not $MasterDict.ContainsKey($Rule)) {
                $MasterDict[$Rule] = $SourceName
                $NewRules++
            }
        }
        return $NewRules
    }

    # Add anchor list
    $Anchor = $ParsedLists[$AnchorName]
    Add-RulePrimarySource $MasterDomains $Anchor.Rules.Domains $AnchorName | Out-Null
    Add-RulePrimarySource $MasterWildcards $Anchor.Rules.Wildcards $AnchorName | Out-Null
    Add-RulePrimarySource $MasterRegex $Anchor.Rules.Regex $AnchorName | Out-Null
    Add-RulePrimarySource $MasterIPRanges $Anchor.Rules.IPRanges $AnchorName | Out-Null
    Add-RulePrimarySource $MasterComplex $Anchor.Rules.Complex $AnchorName | Out-Null
    
    $InitialCount = $MasterDomains.Count + $MasterWildcards.Count + $MasterRegex.Count + $MasterIPRanges.Count + $MasterComplex.Count
    Write-Host "  [OK] Anchor: $AnchorName" -ForegroundColor Cyan -NoNewline
    Write-Host " ($InitialCount rules)" -ForegroundColor Cyan
    Write-Host ""

    # Prepare candidate lists
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

    # Stack remaining lists
    $ListContributions = @()
    Do {
        $BestName = $null
        $MaxUnique = 0
        
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
        
        # Add winner
        $Winner = $ParsedLists[$BestName]
        $TotalAdded = 0
        $TotalAdded += Add-RulePrimarySource $MasterDomains $Winner.Rules.Domains $BestName
        $TotalAdded += Add-RulePrimarySource $MasterWildcards $Winner.Rules.Wildcards $BestName
        $TotalAdded += Add-RulePrimarySource $MasterRegex $Winner.Rules.Regex $BestName
        $TotalAdded += Add-RulePrimarySource $MasterIPRanges $Winner.Rules.IPRanges $BestName
        $TotalAdded += Add-RulePrimarySource $MasterComplex $Winner.Rules.Complex $BestName
        
        $Candidates.Remove($BestName)
        
        $ListContributions += [PSCustomObject]@{
            Name = $BestName
            Unique = $TotalAdded
            Category = $Global:CategoryMap[$BestName]
        }
        
        Write-Host "  + $BestName" -ForegroundColor Green -NoNewline
        Write-Host " (+$TotalAdded)" -ForegroundColor Yellow
        
    } Until ($Candidates.Count -eq 0)

    $PostStackCount = $MasterDomains.Count + $MasterWildcards.Count + $MasterRegex.Count + $MasterIPRanges.Count + $MasterComplex.Count
    Write-Host ""
    Write-Host "  [OK] Stacking complete: $PostStackCount rules before optimization" -ForegroundColor Green
    Write-Host ""

    # =============================================================================
    # 7. OPTIMIZATION
    # =============================================================================
    Write-Host "[5/7] Applying optimizations..." -ForegroundColor Yellow
    
    # 7.1 Wildcard Coverage
    $WildcardCovered = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($WildcardEntry in $MasterWildcards.GetEnumerator()) {
        $Suffix = $WildcardEntry.Key.TrimStart('*')
        foreach ($Domain in $MasterDomains.Keys) {
            if ($Domain.EndsWith($Suffix) -and $Domain -ne $Suffix.TrimStart('.')) {
                [void]$WildcardCovered.Add($Domain)
            }
        }
    }
    foreach ($Domain in $WildcardCovered) { [void]$MasterDomains.Remove($Domain) }
    $Global:Stats.WildcardCoveredRemoved = $WildcardCovered.Count
    Write-Host "  [OK] Removed $($WildcardCovered.Count) covered by wildcards" -ForegroundColor Green
    
    # 7.2 Tree Shaking
    class TrieNode { [hashtable]$Children = @{}; [bool]$IsEndOfDomain = $false }
    $Root = [TrieNode]::new()
    $SortedDomains = $MasterDomains.GetEnumerator() | Sort-Object { $_.Key.Length }
    $OptimizedDomains = @{}
    
    foreach ($Entry in $SortedDomains) {
        $Parts = $Entry.Key.Split('.')
        [array]::Reverse($Parts)
        $Current = $Root
        $IsRedundant = $false
        
        for ($i = 0; $i -lt $Parts.Count; $i++) {
            $Part = $Parts[$i]
            if ($Current.Children.ContainsKey($Part)) {
                $Current = $Current.Children[$Part]
                if ($Current.IsEndOfDomain -and $i -lt ($Parts.Count - 1)) {
                    $IsRedundant = $true
                    $Global:Stats.TreeShakingRemoved++
                    break
                }
            } else {
                $Current.Children[$Part] = [TrieNode]::new()
                $Current = $Current.Children[$Part]
            }
        }
        if (-not $IsRedundant) {
            $Current.IsEndOfDomain = $true
            $OptimizedDomains[$Entry.Key] = $Entry.Value
        }
    }
    $MasterDomains = $OptimizedDomains
    Write-Host "  [OK] Tree shaking removed $($Global:Stats.TreeShakingRemoved) redundant subdomains" -ForegroundColor Green

    # 7.3 Regex Simplification
    $SimplifiedRegex = @{}
    foreach ($Entry in $MasterRegex.GetEnumerator()) {
        if ($Entry.Key -match '^\^/\^([a-z0-9\.-]+)\\\.([a-z0-9\.-]+)\$/$') {
            $Simple = ($matches[1] + '.' + $matches[2]).Replace('\.', '.')
            if (-not $MasterDomains.ContainsKey($Simple)) {
                $MasterDomains[$Simple] = $Entry.Value
                $Global:Stats.RegexSimplified++
            }
        } else { $SimplifiedRegex[$Entry.Key] = $Entry.Value }
    }
    $MasterRegex = $SimplifiedRegex
    Write-Host "  [OK] Simplified $($Global:Stats.RegexSimplified) regex patterns" -ForegroundColor Green
    
    # 7.4 Cross-Type Dupes
    $WildcardsToRemove = [System.Collections.Generic.List[string]]::new()
    foreach ($Entry in $MasterWildcards.GetEnumerator()) {
        if ($MasterDomains.ContainsKey($Entry.Key.TrimStart('*').TrimStart('.'))) {
            $WildcardsToRemove.Add($Entry.Key)
            $Global:Stats.CrossTypeDuplicates++
        }
    }
    foreach ($W in $WildcardsToRemove) { [void]$MasterWildcards.Remove($W) }
    Write-Host "  [OK] Removed $($Global:Stats.CrossTypeDuplicates) cross-type duplicates" -ForegroundColor Green
    Write-Host ""

    # =============================================================================
    # 8. GENERATE SOURCE-AWARE DIFF REPORT
    # =============================================================================
    Write-Host "[6/7] Generating SOURCE-AWARE diff report..." -ForegroundColor Yellow
    $DiffFile = Join-Path $pwd "diffs.txt"
    $DiffOutput = [System.Collections.Generic.List[string]]::new()
    
    # Update Stats for final output
    $Global:Stats.ComplexRules = $MasterComplex.Count
    $Global:Stats.StandardDomains = $MasterDomains.Count
    $Global:Stats.IPRanges = $MasterIPRanges.Count
    $Global:Stats.WildcardRules = $MasterWildcards.Count
    $Global:Stats.RegexRules = $MasterRegex.Count
    $Global:Stats.FinalRuleCount = $MasterDomains.Count + $MasterWildcards.Count + $MasterRegex.Count + $MasterIPRanges.Count + $MasterComplex.Count

    if ($DiffMode) {
        # Construct Current Map for comparison: Rule -> Source
        $NewRulesMap = @{}
        
        # Format rules exactly as they appear in the file for accurate string comparison
        $MasterDomains.GetEnumerator() | ForEach-Object { $NewRulesMap["||$($_.Key)^"] = $_.Value }
        $MasterWildcards.GetEnumerator() | ForEach-Object { $NewRulesMap["||$($_.Key)^"] = $_.Value }
        $MasterRegex.GetEnumerator() | ForEach-Object { $NewRulesMap[$_.Key] = $_.Value }
        $MasterIPRanges.GetEnumerator() | ForEach-Object { $NewRulesMap[$_.Key] = $_.Value }
        $MasterComplex.GetEnumerator() | ForEach-Object { $NewRulesMap[$_.Key] = $_.Value }

        $Added = 0
        $Removed = 0
        $Transferred = 0

        $DiffOutput.Add("! =========================================================================")
        $DiffOutput.Add("! DIFF REPORT: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
        $DiffOutput.Add("! =========================================================================")
        $DiffOutput.Add("")
        
        $DiffOutput.Add("! --- REMOVED RULES ---")
        foreach ($Key in $PreviousRulesMap.Keys) {
            if (-not $NewRulesMap.ContainsKey($Key)) {
                $OldSource = $PreviousRulesMap[$Key]
                $DiffOutput.Add("- $Key [Was: $OldSource]")
                $Removed++
            }
        }
        
        $DiffOutput.Add("")
        $DiffOutput.Add("! --- ADDED RULES ---")
        foreach ($Key in $NewRulesMap.Keys) {
            if (-not $PreviousRulesMap.ContainsKey($Key)) {
                $NewSource = $NewRulesMap[$Key]
                $DiffOutput.Add("+ $Key [Source: $NewSource]")
                $Added++
            }
            elseif ($PreviousRulesMap[$Key] -ne $NewRulesMap[$Key]) {
                # Ownership transfer (same rule, new primary source)
                $Old = $PreviousRulesMap[$Key]
                $New = $NewRulesMap[$Key]
                $DiffOutput.Add("~ $Key [Moved: $Old -> $New]")
                $Transferred++
            }
        }
        
        Write-Host "  [DIFF] Added: $Added | Removed: $Removed | Moved: $Transferred" -ForegroundColor Cyan
        [System.IO.File]::WriteAllLines($DiffFile, $DiffOutput)
        Write-Host "  [OK] Saved Source-Aware diffs to: $DiffFile" -ForegroundColor Green

    } else {
        Set-Content -Path $DiffFile -Value "! No previous blocklist found to compare against."
        Write-Host "  [!] Skipped diff generation (no previous file)" -ForegroundColor DarkGray
    }
    Write-Host ""

    # =============================================================================
    # 9. FINAL OUTPUT (FULL STATS RESTORED)
    # =============================================================================
    Write-Host "[7/7] Generating final blocklist..." -ForegroundColor Yellow
    
    $MegaList = [System.Collections.Generic.List[string]]::new()
    
    # Header
    $MegaList.Add("! =========================================================================")
    $MegaList.Add("! ADGUARD MEGA STACK - GENERATED: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $MegaList.Add("! =========================================================================")
    $MegaList.Add("! BASE ANCHOR: $AnchorName")
    $ContribCount = $ListContributions.Count + 1
    $MegaList.Add("! TOTAL LISTS: $ContribCount")
    $TotalRulesCount = $Global:Stats.FinalRuleCount
    $MegaList.Add("! TOTAL RULES: $TotalRulesCount")
    $ExceptionsSkipped = $Global:Stats.ExceptionRulesSkipped
    $MegaList.Add("! EXCEPTION RULES SKIPPED: $ExceptionsSkipped")
    $MegaList.Add("! =========================================================================")
    $MegaList.Add("!")
    $MegaList.Add("! CONTRIBUTING LISTS:")
    $MegaList.Add("! [ANCHOR] $AnchorName")
    
    $Num = 1
    foreach ($Contributor in ($ListContributions | Sort-Object -Property Unique -Descending)) {
        $ContribName = $Contributor.Name
        $ContribUnique = $Contributor.Unique
        $ContribCat = $Contributor.Category
        $MegaList.Add("! [$Num] $ContribName (+$ContribUnique) [$ContribCat]")
        $Num++
    }
    
    $MegaList.Add("!")
    $MegaList.Add("! OPTIMIZATIONS APPLIED:")
    $OptWildcard = $Global:Stats.WildcardCoveredRemoved
    $MegaList.Add("!    Wildcard coverage: -$OptWildcard")
    $OptTree = $Global:Stats.TreeShakingRemoved
    $MegaList.Add("!    Tree shaking: -$OptTree")
    $OptRegex = $Global:Stats.RegexSimplified
    $MegaList.Add("!    Regex simplified: -$OptRegex")
    $OptCross = $Global:Stats.CrossTypeDuplicates
    $MegaList.Add("!    Cross-type dupes: -$OptCross")
    $MegaList.Add("!")
    $MegaList.Add("! RULE TYPES:")
    $DomainCount = $MasterDomains.Count
    $MegaList.Add("!    Domains: $DomainCount")
    $WildcardCount = $MasterWildcards.Count
    $MegaList.Add("!    Wildcards: $WildcardCount")
    $RegexCount = $MasterRegex.Count
    $MegaList.Add("!    Regex: $RegexCount")
    $IPCount = $MasterIPRanges.Count
    $MegaList.Add("!    IP Ranges: $IPCount")
    $ComplexCount = $MasterComplex.Count
    $MegaList.Add("!    Complex: $ComplexCount")
    $MegaList.Add("! =========================================================================")
    $MegaList.Add("")
    
    # Helper to add rules grouped by source
    function Add-RulesBySource {
        param($MasterDict, $RulePrefix = "", $RuleSuffix = "")
        
        # Group by source
        $BySource = @{}
        foreach ($Entry in $MasterDict.GetEnumerator()) {
            $Source = $Entry.Value
            if (-not $BySource.ContainsKey($Source)) {
                $BySource[$Source] = [System.Collections.Generic.List[string]]::new()
            }
            $BySource[$Source].Add($Entry.Key)
        }
        
        # Sort sources by contribution
        $SourceOrder = @($AnchorName) + ($ListContributions | Sort-Object -Property Unique -Descending | Select-Object -ExpandProperty Name)
        
        foreach ($Source in $SourceOrder) {
            if ($BySource.ContainsKey($Source)) {
                $Rules = $BySource[$Source] | Sort-Object
                $RuleCount = $Rules.Count
                $MegaList.Add("! [$Source] - $RuleCount rules")
                foreach ($Rule in $Rules) {
                    $MegaList.Add("$RulePrefix$Rule$RuleSuffix")
                }
                $MegaList.Add("")
            }
        }
    }
    
    # Complex Rules
    if ($MasterComplex.Count -gt 0) {
        $MegaList.Add("! =========================================================================")
        $MegaList.Add("! COMPLEX RULES")
        $MegaList.Add("! =========================================================================")
        Add-RulesBySource $MasterComplex
    }
    
    # Regex
    if ($MasterRegex.Count -gt 0) {
        $MegaList.Add("! =========================================================================")
        $MegaList.Add("! REGEX PATTERNS")
        $MegaList.Add("! =========================================================================")
        Add-RulesBySource $MasterRegex
    }
    
    # IP Ranges
    if ($MasterIPRanges.Count -gt 0) {
        $MegaList.Add("! =========================================================================")
        $MegaList.Add("! IP RANGES")
        $MegaList.Add("! =========================================================================")
        Add-RulesBySource $MasterIPRanges
    }
    
    # Wildcards
    if ($MasterWildcards.Count -gt 0) {
        $MegaList.Add("! =========================================================================")
        $MegaList.Add("! WILDCARD RULES")
        $MegaList.Add("! =========================================================================")
        Add-RulesBySource $MasterWildcards "||" "^"
    }
    
    # Domains
    if ($MasterDomains.Count -gt 0) {
        $MegaList.Add("! =========================================================================")
        $MegaList.Add("! STANDARD DOMAINS")
        $MegaList.Add("! =========================================================================")
        Add-RulesBySource $MasterDomains "||" "^"
    }

    # Save
    $OutFile = Join-Path $pwd "blocklist.txt"
    [System.IO.File]::WriteAllLines($OutFile, $MegaList)
    
    Write-Host "  [OK] Saved to: $OutFile" -ForegroundColor Green
    Write-Host ""

    # =============================================================================
    # 10. STATISTICS REPORT
    # =============================================================================
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "COMPILATION COMPLETE" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "DOWNLOAD:" -ForegroundColor Yellow
    $StatsDownloaded = $Global:Stats.TotalDownloaded
    Write-Host "  Lists: $StatsDownloaded" -ForegroundColor White
    $StatsParsed = $Global:Stats.TotalRulesParsed
    Write-Host "  Rules parsed: $StatsParsed" -ForegroundColor White
    $StatsExceptions = $Global:Stats.ExceptionRulesSkipped
    Write-Host "  Exceptions skipped: $StatsExceptions" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-Host "OPTIMIZATION:" -ForegroundColor Yellow
    Write-Host "  Before: $PostStackCount rules" -ForegroundColor White
    $StatsWildcardRemoved = $Global:Stats.WildcardCoveredRemoved
    Write-Host "  Wildcard coverage: -$StatsWildcardRemoved" -ForegroundColor White
    $StatsTreeRemoved = $Global:Stats.TreeShakingRemoved
    Write-Host "  Tree shaking: -$StatsTreeRemoved" -ForegroundColor White
    $StatsRegexSimp = $Global:Stats.RegexSimplified
    Write-Host "  Regex simplified: -$StatsRegexSimp" -ForegroundColor White
    $StatsCrossType = $Global:Stats.CrossTypeDuplicates
    Write-Host "  Cross-type dupes: -$StatsCrossType" -ForegroundColor White
    $TotalReduction = $PostStackCount - $Global:Stats.FinalRuleCount
    Write-Host "  Total reduction: $TotalReduction" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "FINAL OUTPUT:" -ForegroundColor Yellow
    $StatsFinalCount = $Global:Stats.FinalRuleCount
    Write-Host "  Total rules: $StatsFinalCount" -ForegroundColor Cyan
    $StatsDomains = $Global:Stats.StandardDomains
    Write-Host "    Domains: $StatsDomains" -ForegroundColor White
    $StatsWildcards = $Global:Stats.WildcardRules
    Write-Host "    Wildcards: $StatsWildcards" -ForegroundColor White
    $StatsRegex = $Global:Stats.RegexRules
    Write-Host "    Regex: $StatsRegex" -ForegroundColor White
    $StatsIPRanges = $Global:Stats.IPRanges
    Write-Host "    IP Ranges: $StatsIPRanges" -ForegroundColor White
    $StatsComplex = $Global:Stats.ComplexRules
    Write-Host "    Complex: $StatsComplex" -ForegroundColor White
    Write-Host ""
    
    Write-Host "TOP CONTRIBUTORS:" -ForegroundColor Yellow
    $ListContributions | Sort-Object -Property Unique -Descending | Select-Object -First 10 | ForEach-Object {
        $TopName = $_.Name
        $TopUnique = $_.Unique
        $TopCategory = $_.Category
        Write-Host "  $TopName : +$TopUnique [$TopCategory]" -ForegroundColor White
    }
    Write-Host ""
    
    $ReductionPercent = [math]::Round((($PostStackCount - $Global:Stats.FinalRuleCount) / $PostStackCount) * 100, 2)
    Write-Host "EFFICIENCY: $ReductionPercent% size reduction" -ForegroundColor Green
    Write-Host ""
    
    # Cleanup
    if (Test-Path $TempDir) { Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue }
    
    Write-Host "[OK] Done! Check blocklist.txt and diffs.txt" -ForegroundColor Green
    Write-Host ""
}

# =============================================================================
# EXECUTE
# =============================================================================
Analyze-AdGuardListsCI
