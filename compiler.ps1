# --- CONFIGURATION: MANUAL EXCLUSIONS ---
# Add the RefIDs of lists you want to permanently skip.
# (e.g. 34 = HaGeZi Normal, 24 = 1Hosts Lite)
$ExcludedRefIds = @(
    # Add IDs here, e.g.: 24, 34
)

function Analyze-AdGuardListsCI {
    param (
        [int[]]$ExcludeIds = $ExcludedRefIds
    )

    # 1. DATA DEFINITION
    $BaseUrl = "https://adguardteam.github.io/HostlistsRegistry/assets"
    $Global:CategoryMap = @{}

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
        @{ RefId=50; Id="filter_50.txt"; Name="uBlock₀ filters – Badware risks"; Category="Security" },
        @{ RefId=11; Id="filter_11.txt"; Name="Malicious URL Blocklist (URLHaus)"; Category="Security" }
    )

    Write-Host "Running CI Compiler (Polyglot v12.0)" -ForegroundColor Cyan
    
    # Setup temp dirs (Uses local workspace in GitHub Actions)
    $TempDir = Join-Path $pwd "temp_downloads"
    $ListsDir = Join-Path $TempDir "lists"
    if (Test-Path $TempDir) { Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $ListsDir -Force | Out-Null
    
    $Global:ListStatus = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new()
    $InputFile = Join-Path $TempDir "downloads.txt"
    
    # --- PREPARE ---
    foreach ($Entry in $AdGuardData) {
        if ($ExcludeIds -contains $Entry.RefId) { continue }

        $FileName = $Entry.Id
        $DisplayName = $Entry.Name
        $Global:CategoryMap[$DisplayName] = $Entry.Category
        $Url = if ($Entry.ExternalUrl) { $Entry.ExternalUrl } else { "$BaseUrl/$FileName" }
        
        $StatusObj = [PSCustomObject]@{
            Name = $DisplayName; FileName = $FileName; Category = $Entry.Category; Url = $Url; Downloaded = $false
        }
        [void]$Global:ListStatus.TryAdd($FileName, $StatusObj)
        Add-Content -Path $InputFile -Value "$Url`n  out=$FileName`n  dir=$ListsDir"
    }

    # --- DOWNLOAD (Uses system aria2c) ---
    Write-Host "Starting Aria2 Download..."
    $Aria2Args = @("-i", $InputFile, "--max-concurrent-downloads=16", "--quiet=true")
    Start-Process -FilePath "aria2c" -ArgumentList $Aria2Args -NoNewWindow -Wait
    
    foreach ($Key in $Global:ListStatus.Keys) {
        if (Test-Path (Join-Path $ListsDir $Global:ListStatus[$Key].FileName)) { $Global:ListStatus[$Key].Downloaded = $true } 
    }

    # --- PARSE ---
    Write-Host "Parsing Lists..."
    $ParsedLists = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new()
    # Note: GitHub runners have 2-4 cores usually, 10 threads is fine for IO
    $RunspacePool = [runspacefactory]::CreateRunspacePool(1, 10) 
    $RunspacePool.Open()
    $Jobs = @()
    
    $ScriptBlock = {
        param($FileName, $Name, $FilePath)
        $Result = @{ Name = $Name; FileName = $FileName; Domains = $null }
        if ([System.IO.File]::Exists($FilePath)) {
            try {
                $Lines = [System.IO.File]::ReadAllLines($FilePath)
                $DomainSet = [System.Collections.Generic.HashSet[string]]::new()
                foreach ($Line in $Lines) {
                    if ([string]::IsNullOrWhiteSpace($Line) -or $Line[0] -eq '!' -or $Line[0] -eq '#') { continue }
                    $Clean = $Line.Trim(); $Rule = $null; $IsExplicit = $false
                    
                    if ($Clean.StartsWith("/") -and $Clean.EndsWith("/")) { $Rule = $Clean; $IsExplicit = $true }
                    elseif ($Clean.StartsWith("||")) { $Rule = $Clean.Substring(2).Split('^$')[0]; $IsExplicit = $true }
                    elseif ($Clean -match '^(https?://|www\.)') { 
                         try { if($Clean -notmatch '^http') { $Clean="http://$Clean"}; $Rule = ([uri]$Clean).Host } catch {} 
                    }
                    elseif ($Clean -match '^(0\.0\.0\.0|127\.0\.0\.1)\s+(.+)') { $Rule = $matches[2].Split('#')[0].Trim() }
                    elseif ($Clean -match '([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]') {
                         if ($Clean -notmatch '[#\$\^]') { $Rule = $matches[0] }
                    }
                    
                    if ($Rule) {
                        $Rule = $Rule.TrimEnd('.')
                        if ($IsExplicit -or ($Rule.Length -gt 3 -and $Rule.Contains(".") -and -not $Rule.Contains("*") -and -not $Rule.Contains(" "))) {
                            [void]$DomainSet.Add($Rule.ToLowerInvariant())
                        }
                    }
                }
                if ($DomainSet.Count -gt 0) { $Result.Domains = $DomainSet }
            } catch {}
        }
        return $Result
    }
    
    foreach ($Key in $Global:ListStatus.Keys) {
        $Item = $Global:ListStatus[$Key]
        if ($Item.Downloaded) {
            $PS = [powershell]::Create().AddScript($ScriptBlock).AddArgument($Item.FileName).AddArgument($Item.Name).AddArgument((Join-Path $ListsDir $Item.FileName))
            $PS.RunspacePool = $RunspacePool
            $Jobs += [PSCustomObject]@{ Pipe = $PS; Result = $PS.BeginInvoke() }
        }
    }
    
    foreach ($Job in $Jobs) {
        $Res = $Job.Pipe.EndInvoke($Job.Result)
        $Job.Pipe.Dispose()
        if ($Res.Domains) { [void]$ParsedLists.TryAdd($Res.Name, $Res.Domains) }
    }
    $RunspacePool.Dispose()

    # --- STACKING ---
    Write-Host "Stacking Lists..."
    $AnchorName = "HaGeZi's Pro++ Blocklist"
    if (-not $ParsedLists.ContainsKey($AnchorName)) { Write-Error "Anchor missing"; return }

    $MegaList = [System.Collections.Generic.List[string]]::new()
    $MegaList.Add("! ADGUARD MEGA STACK - GENERATED: $(Get-Date)")
    $MegaList.Add("! BASE: $AnchorName")
    
    $AccumulatedSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$ParsedLists[$AnchorName])
    $MegaList.Add("! --- SOURCE: $AnchorName ---"); $MegaList.AddRange($AccumulatedSet)

    $Candidates = [System.Collections.Generic.List[string]]::new(@($ParsedLists.Keys | Where { $_ -ne $AnchorName -and $Global:CategoryMap[$_] -ne 'Regional' }))
    
    # Culls
    if ($ParsedLists.ContainsKey("1Hosts (Xtra)") -and $Candidates.Contains("1Hosts (Lite)")) { $Candidates.Remove("1Hosts (Lite)") }
    if ($ParsedLists.ContainsKey("OISD Blocklist Big") -and $Candidates.Contains("OISD Blocklist Small")) { $Candidates.Remove("OISD Blocklist Small") }
    if ($AnchorName -eq "HaGeZi's Pro++ Blocklist") {
        $Candidates.Remove("HaGeZi's Ultimate Blocklist"); $Candidates.Remove("HaGeZi's Normal Blocklist"); $Candidates.Remove("HaGeZi's Pro Blocklist")
    }

    Do {
        $BestName = $null; $MaxUnique = 0
        foreach ($Name in $Candidates) {
            $TestSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$ParsedLists[$Name])
            $TestSet.ExceptWith($AccumulatedSet)
            if ($TestSet.Count -gt $MaxUnique) { $MaxUnique = $TestSet.Count; $BestName = $Name }
        }

        if ($null -eq $BestName -or $MaxUnique -eq 0) { break }
        
        $WinnerSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$ParsedLists[$BestName])
        $WinnerSet.ExceptWith($AccumulatedSet)
        
        $MegaList.Add(""); $MegaList.Add("! --- SOURCE: $BestName (+$($WinnerSet.Count)) ---")
        $MegaList.AddRange($WinnerSet)
        
        $AccumulatedSet.UnionWith($WinnerSet)
        $Candidates.Remove($BestName)
        Write-Host "Added $BestName (+$MaxUnique)"
    } Until ($Candidates.Count -eq 0)

    # --- SAVE ---
    # Save to current workspace root as 'blocklist.txt'
    $OutFile = Join-Path $pwd "blocklist.txt"
    [System.IO.File]::WriteAllLines($OutFile, $MegaList)
    Write-Host "Done! Saved to $OutFile"
}

Analyze-AdGuardListsCI 
