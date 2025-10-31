function Show-ProgramDetails {
    param (
        [psobject]$program
    )
    Write-Host "`n--- Program Details ---" -ForegroundColor Blue
    Write-Host "Name: $($program.Name)"
    Write-Host "Category: $($program.Category -join ', ')"
    Write-Host "Source: $($program.Source -join ', ')"
    Write-Host "Description: $($program.Description)"
    Write-Host "Documentation: $($program.Documentation)"
}

function Get-ProgramList {
    param (
        [psobject[]]$list
    )
    Write-Host "Listing all the programs..." -ForegroundColor Blue
    Write-Host "---------------------------" -ForegroundColor Blue
    Write-Host "Name                                            Category"
    Write-Host "----                                            --------"
    foreach ($program in $list) {
        if ($null -ne $program.Name -and $null -ne $program.Category) {
            Write-Output ("{0,-47} {1}" -f $program.Name, ($program.Category -join ', '))
        }
    }
}

function Get-CategoryWithCounts {
    param (
        [psobject[]]$list
    )
    $categoryCounts = @{}
    foreach ($item in $list) {
        foreach ($category in $item.Category) {
            if ($categoryCounts.ContainsKey($category)) {
                $categoryCounts[$category]++
            }
            else {
                $categoryCounts[$category] = 1
            }
        }
    }
    Write-Host "Category                      Count" -ForegroundColor Blue
    Write-Host "--------                      -----" -ForegroundColor Blue
    $categoryCounts.GetEnumerator() | Sort-Object Name | ForEach-Object {
        Write-Output ("{0,-30} {1}" -f $_.Name, $_.Value)
    }
}

function Get-ProgramsByCategory {
    param (
        [psobject[]]$list,
        [string]$category
    )
    Write-Host "Name                            Category" -ForegroundColor Blue
    Write-Host "----                            --------" -ForegroundColor Blue
    foreach ($program in $list) {
        if ($null -ne $program.Name -and $null -ne $program.Category) {
            if ($program.Category -contains $category) {
                Write-Output ("{0,-31} {1}" -f $program.Name, ($program.Category -join ', '))
            }
        }
    }
}

function Get-ProgramByName {
    param (
        [psobject[]]$list,
        [string]$name
    )
    try {
        foreach ($program in $list) {
            if ($program.Name -ieq $name) {
                # returns the object. All output will be handled by the calling function.
                return $program
            }
        }
        return $null
    }
    catch {
        Write-Error "An error occurred while processing the program list."
        Write-Error $_.Exception.Message
        return $null
    }
}

# Starts a Microsoft developer environment
function Invoke-VisualStudioEnvironment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("x86", "x64")]
        [string]$Arch = "x64"
    )

    # Path to the discovery tool
    $vswherePath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"

    if (-not (Test-Path $vswherePath)) {
        Write-Error "Error: vswhere.exe not found. Ensure Visual Studio Build Tools 2022 is installed."
        return $false
    }

    # Locate the installation directory containing vcvarsall.bat
    Write-Host "Searching for Visual Studio 2022 Build Tools (Target Arch: $Arch)..." -ForegroundColor Yellow

    $VSInstallPath = & $vswherePath -latest -products * -prerelease -property installationPath -format value | Select-Object -First 1

    if ([string]::IsNullOrWhiteSpace($VSInstallPath)) {
        Write-Error "Error: Could not locate Visual Studio installation path. Ensure the C++ tools are installed."
        return $false
    }

    # Construct the full path to the environment setup script
    $vcvarsall = Join-Path $VSInstallPath "VC\Auxiliary\Build\vcvarsall.bat"

    if (-not (Test-Path $vcvarsall)) {
        Write-Error "Error: vcvarsall.bat not found at '$vcvarsall'. Ensure the 'Desktop development with C++' workload is installed."
        return $false
    }

    # Execute the batch file within the current session using the call operator ('.')
    Write-Host "Initializing C++ environment by executing: '$vcvarsall' $Arch" -ForegroundColor Cyan

    try {
        . "$vcvarsall" $Arch
        Write-Host "Environment setup complete (Verified by successful installation)." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to execute vcvarsall.bat. Check permissions or internal vcvarsall errors."
        return $false
    }

    # Final Confirmation.
    Write-Host "Environment is configured. The compiler is available to subsequent commands." -ForegroundColor Green
    return $true
}

# ----------------------------------------------------------------------------------
# --- Environment / Pre-requisite Checks ---
# ----------------------------------------------------------------------------------

# Check if NPM is installed
function Invoke-NpmCheck {
    $NodePackageId = "OpenJS.NodeJS"
    Write-Host "--- Checking for Node.js and NPM installation ---" -ForegroundColor Cyan

    # Check if node is installed
    try {
        # Check if node.exe is accessible
        $NodePath = Get-Command node.exe -ErrorAction Stop | Select-Object -ExpandProperty Path
        Write-Host "Node.js (and NPM) found at: $NodePath" -ForegroundColor Green
        return
    }
    catch {
        Write-Host "Node.js executable not found in PATH. Checking winget list..." -ForegroundColor Yellow
    }

    # Check if node is listed by winget
    $InstalledNode = winget list --id $NodePackageId | Select-String $NodePackageId
    if ($InstalledNode) {
        Write-Host "Node.js package found listed by winget, but not accessible via PATH. Installation assumed complete." -ForegroundColor Green
        return
    }

    Write-Host "Node.js is not installed. Initiating installation via winget..." -ForegroundColor Yellow

    # Install Node.js
    try {
        $Command = "winget install -e --id $NodePackageId --silent --accept-package-agreements --accept-source-agreements --disable-interactivity"

        Write-Host "Executing command: $Command" -ForegroundColor DarkGray
        $Result = Invoke-Expression $Command

        # Check the output for success
        if ($Result -match "Successfully installed" -or $LASTEXITCODE -eq 0) {
            Write-Host "Successfully installed Node.js (and NPM)." -ForegroundColor Green
            Write-Host "NOTE: You may need to restart your PowerShell session for 'node' and 'npm' commands to be available in the PATH." -ForegroundColor Yellow
        }
        else {
            Write-Host "Node.js installation failed. Check winget error output." -ForegroundColor Red
            Write-Host $Result -ForegroundColor Red
        }
    }
    catch {
        Write-Host "An error occurred during winget installation:" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
}

# Check if git is installed
function Invoke-GitCheck {
    $GitPackageId = "Git.Git"

    Write-Host "--- Checking for Git installations ---" -ForegroundColor Cyan

    # Check if git is already  in the PATH
    try {
        $GitPath = Get-Command git.exe -ErrorAction Stop | Select-Object -ExpandProperty Path
        Write-Host "Git found at: $GitPath" -ForegroundColor Green
        return
    }
    catch {
        Write-Host "Git executable not found in PATH. Checking winget list..." -ForegroundColor Yellow
    }

    # Check if Git is listed by winget
    $InstalledGit = winget list --id $GitPackageId | Select-String $GitPackageId
    if ($InstalledGit) {
        Write-Host "Git package found listed by winget, but not accessible via PATH. Installation assumed complete." -ForegroundColor Green
        return
    }

    Write-Host "Git is not installed. Initiating installation via winget..." -ForegroundColor Yellow

    # Install Git using winget
    try {
        $Command = "winget install -e --id $GitPackageId --silent --accept-package-agreements --accept-source-agreements --disable-interactivity"
        Write-Host "Executing command: $Command" -ForegroundColor DarkGray
        $Result = Invoke-Expression $Command

        # Check the output for success
        if ($Result -match "Successfully installed" -or $LASTEXITCODE -eq 0) {
            Write-Host "Successfully installed Git." -ForegroundColor Green
            Write-Host "NOTE: You may need to restart your PowerShell session for 'git' command to be available in the PATH." -ForegroundColor Yellow
        }
        else {
            Write-Host "Git installation failed. Check winget error output." -ForegroundColor Red
            Write-Host $Result -ForegroundColor Red
        }
    }
    catch {
        Write-Host "An error occurred during winget installation:" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
}

# Check if uv is installed
function Invoke-UvCheck {
    $UvPackageId = "astral-sh.uv"
    Write-Host "--- Checking for uv package manager installation ---" -ForegroundColor Cyan

    # Check if uv is already in the PATH
    try {
        # Check if uv.exe is accessible
        $UvPath = Get-Command uv.exe -ErrorAction Stop | Select-Object -ExpandProperty Path
        Write-Host "uv found at: $UvPath" -ForegroundColor Green
        return
    }
    catch {
        Write-Host "uv executable not found in PATH. Checking winget list..." -ForegroundColor Yellow
    }

    # Check if uv listed by winget
    $InstalledUv = winget list --id $UvPackageId | Select-String $UvPackageId
    if ($InstalledUv) {
        Write-Host "uv package found listed by winget, but not accessible via PATH. Installation assumed complete." -ForegroundColor Green
        return
    }

    Write-Host "uv is not installed. Initiating installation via winget..." -ForegroundColor Yellow

    try {
        $Command = "winget install -e --id $UvPackageId --silent --accept-package-agreements --accept-source-agreements --disable-interactivity"
        Write-Host "Executing command: $Command" -ForegroundColor DarkGray
        $Result = Invoke-Expression $Command

        # Check the output for success
        if ($Result -match "Successfully installed" -or $LASTEXITCODE -eq 0) {
            Write-Host "Successfully installed uv." -ForegroundColor Green
            Write-Host "NOTE: You may need to restart your PowerShell session for 'uv' command to be available in the PATH." -ForegroundColor Yellow
        }
        else {
            Write-Host "uv installation failed. Check winget error output." -ForegroundColor Red
            Write-Host $Result -ForegroundColor Red
        }
    }
    catch {
        Write-Host "An error occurred during winget installation:" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
}

# Check if Visual Studio Build tools are installed
function Invoke-VisualCppCheck {
    [CmdletBinding()]
    param()
    $BuildToolsId = "Microsoft.VisualStudio.2022.BuildTools"
    $VCToolsWorkload = "Microsoft.VisualStudio.Workload.VCTools"

    Write-Host "--- Checking for existing Visual C++ Build Tools ($BuildToolsId) ---" -ForegroundColor Cyan

    # Use winget list to check for the package ID and suppress errors if not found
    $InstallCheck = winget list --id $BuildToolsId --exact 2>$null

    # Check if the output contains the package ID
    $IsInstalled = $InstallCheck -match $BuildToolsId

    if ($IsInstalled) {
        Write-Host "Microsoft Visual Studio 2022 Build Tools found." -ForegroundColor Green
        return
    }

    Write-Host "Visual C++ Build Tools not found. Starting silent installation..." -ForegroundColor Red

    $OverrideArgs = "--quiet --add $VCToolsWorkload --includeRecommended"

    Write-Host "Executing command to install VCTools (this may take several minutes)..." -ForegroundColor DarkCyan

    # Execute the command using Start-Process to handle the process and wait for completion
    try {
        Start-Process -FilePath "winget" -ArgumentList "install", "--id", $BuildToolsId, "--exact", "--source", "winget", "--override", "`"$OverrideArgs`"" -Wait -NoNewWindow -ErrorAction Stop
        Write-Host "Installation complete! Please restart your terminal/PowerShell session." -ForegroundColor Green
    }
    catch {
        Write-Error "Installation failed."
        Write-Error "Make sure PowerShell is running as Administrator and winget is functional."
        Write-Error "Error details: $($_.Exception.Message)"
        return
    }
}

# Test internet connection
function Test-Internet {
    try {
        if (Test-Connection -ComputerName "google.com" -Count 1 -Quiet) {
            Write-Host "[✓] Connected to the internet." -ForegroundColor Green
            return $true
        }
        else {
            Write-Host "[✗] Internet seems disconnected."  -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Host "An error occurred while testing the connection." -ForegroundColor Red
        return $false
    }
}

# Check Firewall status
function Test-Firewall {
    try {
        $service = Get-Service -Name "MpsSvc" -ErrorAction Stop
        if ($service.Status -eq "Running") {
            Write-Host "[✗] Windows Firewall is running." -ForegroundColor Red
            return $true
        }
        else {
            Write-Host "[✓] Windows Firewall is not running." -ForegroundColor Green
            return $false
        }
    }
    catch {
        Write-Host "An error occurred while checking the Windows Firewall service." -ForegroundColor Red
        Write-Host "Error Details: $_" -ForegroundColor Red
        return $false
    }
}

# Test if the Windows Defender Antivirus service is running.
function Test-Defender {
    try {

        $service = Get-Service -Name "WinDefend" -ErrorAction Stop
        if ($service.Status -eq "Running") {
            Write-Host "[✗] Windows Defender is running." -ForegroundColor Red
            return $true
        }
        else {
            Write-Host "[✓] Windows Defender is not running." -ForegroundColor Green
            return $false
        }
    }
    catch {
        Write-Host "An error occurred while checking the Windows Defender service." -ForegroundColor Red
        Write-Host "Error Details: $_" -ForegroundColor Red
        return $false
    }
}

# Check if a folder exists. Create otherwise
function Invoke-FolderCheck {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Folder
    )

    if (-not (Test-Path -Path $Folder -PathType Container)) {
        Write-Host "Directory '$Folder' does not exist. Creating..."
        try {
            $newFolder = New-Item -Path $Folder -ItemType Directory -Force
            Write-Host "Directory: $($newFolder.FullName) created successfully..."
        }
        catch {
            Write-Error "Failed to create directory '$Folder'. Error: $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "Directory '$Folder' already exists. Proceeding..."
    }
}

# ----------------------------------------------------------------------------------
# --- Installation Helper Functions ---
# ----------------------------------------------------------------------------------

# Adds the installed package to path
function Invoke-FixUvPath {
    [CmdletBinding()]
    param()

    $UvBinPath = Join-Path $env:USERPROFILE ".local\bin"

    # Check if the path is already in the User scope
    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")

    if ($UserPath -like "*$UvBinPath*") {
        Write-Host "UV path is already permanently set for the user. Restart PowerShell to refresh the PATH if needed." -ForegroundColor DarkYellow
        return
    }

    # Add the path permanently
    try {
        [Environment]::SetEnvironmentVariable("Path", "$UvBinPath;$UserPath", "User")
        Write-Host "Successfully added '$UvBinPath' to the User's PATH environment variable." -ForegroundColor Green
        Write-Host "IMPORTANT: Close and reopen all PowerShell/Command Prompt windows for the change to take effect globally." -ForegroundColor Red

        # Set for the current session as well
        $env:PATH = "$UvBinPath;$env:PATH"
        Write-Host "Path set for current session. You can now run the tool immediately." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to set permanent PATH. Run this command as administrator or set manually: $UvBinPath"
    }
}

# Install using program using uv pip install
function Invoke-PipInstall {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackageName
    )

    $command = "uv tool install $PackageName"
    Write-Host "Executing command: $command" -ForegroundColor White

    # Conditional C++ Environment Setup
    if ($PackageName -ieq "angr") {
        Invoke-VisualCppCheck
        Write-Host "`nAttempting conditional C++ Build Environment setup for compilation..." -ForegroundColor Yellow
        $SetupSuccess = Invoke-VisualStudioEnvironment
        if (-not $SetupSuccess) {
            Write-Error "C++ environment setup failed. Aborting installation of $PackageName."
            return
        }
    }

    # Execute the installation command
    Invoke-Expression $command

    # Fix the PATH if the installation was successful
    if ($LASTEXITCODE -eq 0) {
        Write-Host "`nInstallation of $PackageName successful. Now running Invoke-FixUvPath to ensure the executable is accessible." -ForegroundColor Green
        Invoke-FixUvPath
    }
}


# Install package using NPM
function Invoke-npmInstall {
    param (
        [string]$packageName
    )
    $command = "npm install -g $($packageName)"
    Write-Host "Executing command: $command"
    Invoke-Expression $command
}

# Install a program from external source
function Invoke-installFromExternalSource {
    param (
        [psobject]$program
    )
    Write-Host "Refreshing winget package source..."
    $updateProcess = Start-Process -FilePath "winget" -ArgumentList "source update" -PassThru -Wait
    if ($updateProcess.ExitCode -ne 0) {
        Write-Host "WARNING: Failed to update winget source. Proceeding with potentially stale cache." -ForegroundColor Yellow
    }
    
    # Define a hash table to map Package names to the actual manifest filenames.
    $ManifestFileMap = @{
        "Apktool"           = "Apktool.yml"
        "AutoIt-Ripper"     = "AutoItRipper.yml"
        "BinDiff"           = "BinDiff.yml"
        "BlobRunner"        = "BlobRunner.yml"
        "Bytecode Viewer"   = "Bytecode_viewer.yml"
        "Capa"              = "Capa.yml"
        "CodeTrack"         = "CodeTrack.yml"
        "CryptoTester"      = "CryptoTester.yml"
        "dex2jar"           = "Dex2jar.yml"
        "Diaphora"          = "Diaphora.yml"
        "dll_to_exe"        = "dll_to_exe.yml"
        "Exeinfope"         = "Exeinfo_ASL.yml"
        "Explorer Suite"    = "Explorer_Suite.yml"
        "fakenet-ng"        = "Fakenet-NG.yml"
        "GarbageMan"        = "GarbageMan.yml"
        "Ghidra"            = "Ghidra.yml"
        "GoReSym"           = "GoReSym.yml"
        "gostringungarbler" = "Gostringungarbler.yml"
        "Hollows_Hunter"    = "Hollows_hunter.yml"
        "jd-gui"            = "JD-GUI.yml"
        "pe-sieve"          = "PE-sieve.yml"
        "pe-unmapper"       = "pe-unmapper.yml"
        "pestudio"          = "PEstudio.yml"
        "ProcDOT"           = "ProcDOT.yml"
        "Recaf"             = "Recaf.yml"
        "sclauncher"        = "Sclauncher.yml"
        "UniExtract2"       = "UniExtract2.yml"
        "VB Decompiler"     = "VB_Decompiler_lite.yml"
        "XPEviewer"         = "XPEviewer.yml"
        "Test"              = "Test.yml"  
    }

    $programName = $program.Name
    $fileName = ""
    if ($ManifestFileMap.ContainsKey($programName)) {
        $fileName = $ManifestFileMap[$programName]
    }
    else {
        $fileName = "$programName.yml"
    }

    $filePath = Join-Path -Path ".\other" -ChildPath $fileName
    if (-not (Test-Path $filePath)) {
        Write-Host "Error: Manifest file not found at '$filePath'. Please check the file map or the 'other' directory." -ForegroundColor Red
        return
    }
    
    $InstallPath = "C:\WRAP\$($programName)"
    Write-Host "Manifest found ($filePath). Executing installation..." -ForegroundColor Yellow

    # --- Read Manifest Content to determine Installer Type ---
    $manifestContent = Get-Content $filePath | Out-String
    
    # Extract InstallerType
    $InstallerTypeMatch = $manifestContent | Select-String -Pattern 'InstallerType:\s*(.*)' | Select-Object -First 1
    $installerType = if ($InstallerTypeMatch) {
        $InstallerTypeMatch.Matches.Groups[1].Value.Trim().ToLower()
    }
    else {
        "unknown"
    }
    
    # Extract InstallerUrl (for manual portable handling)
    $InstallerUrl = ($manifestContent | Select-String -Pattern 'InstallerUrl:\s*(.*)').Matches.Groups[1].Value.Trim()
    
    # Types that require manual download/extraction because winget fails --location
    $portableTypes = @('zip', 'portable', 'pwa') 
    $isPortable = $installerType -in $portableTypes
    
    # Standard installer types that work with winget --location
    $standardTypes = @('msi', 'exe', 'inno', 'nullsoft', 'burn', 'wix') 

    try {
        # --- Standard installation (Using winget for MSI/EXE installers) ---
        if ($installerType -in $standardTypes) { 
            $arguments = @(
                "install", 
                "--manifest", $filePath,
                "--location", $InstallPath 
            )
            
            Write-Host "Standard installer ($installerType) detected. Using winget to enforce path: $InstallPath" -ForegroundColor Yellow
            Write-Host "--- Starting winget Installation (Manual interaction may be required) ---" -ForegroundColor Cyan
            
            $command = "winget"
            & $command @arguments
            $exitCode = $LASTEXITCODE
            
            Write-Host "--- Installation Finished ---" -ForegroundColor Cyan
        }
        # --- Portable Installation (If winget fails) ---
        elseif ($isPortable) {
            Write-Host "Portable package detected ($installerType). Bypassing 'winget' to manually enforce path: $InstallPath" -ForegroundColor Magenta
            
            if (-not $InstallerUrl) {
                Write-Host "Error: Could not find InstallerUrl in manifest for $($programName). Cannot proceed with manual installation." -ForegroundColor Red
                return
            }

            # Setup paths and directories
            $TempDir = Join-Path -Path $env:TEMP -ChildPath "winget-temp-$([Guid]::NewGuid().Guid)"
            if (-not (Test-Path $TempDir)) { New-Item -Path $TempDir -ItemType Directory | Out-Null }
            if (-not (Test-Path $InstallPath)) { New-Item -Path $InstallPath -ItemType Directory | Out-Null }
            
            # Determine the file name and download path
            $FileExtension = [System.IO.Path]::GetExtension($InstallerUrl)
            $BaseFileName = [System.IO.Path]::GetFileName($InstallerUrl)
            $DownloadPath = Join-Path -Path $TempDir -ChildPath $BaseFileName
            
            Write-Host "Downloading $InstallerUrl..."
            Write-Host "--- Starting Download using Invoke-WebRequest ---" -ForegroundColor Cyan
            Invoke-WebRequest -Uri $InstallerUrl -OutFile $DownloadPath -ErrorAction Stop
            Write-Host "Download complete. File saved to: $DownloadPath"
            
            # Process based on file extension (Ensuring all are covered with clean logic)
            if ($FileExtension -match '\.zip$' -or $FileExtension -match '\.7z$' -or $FileExtension -match '\.rar$') {
                Write-Host "File is a ZIP/archive. Extracting to $InstallPath..."
                if ($FileExtension -match '\.zip$') {
                    Expand-Archive -Path $DownloadPath -DestinationPath $InstallPath -Force
                }
                else {
                    Write-Host "WARNING: Non-ZIP archive detected ($FileExtension). You may need 7z for extraction." -ForegroundColor Yellow
                    Copy-Item -Path $DownloadPath -DestinationPath $InstallPath -Force # Copying archive itself
                }
                Write-Host "Successfully handled archive contents to $InstallPath." -ForegroundColor Green
            }
            elseif ($FileExtension -match '\.jar$' -or $FileExtension -match '\.dat$' -or $FileExtension -match '\.bin$' -or $FileExtension -notmatch '\.') {
                # For direct files (JAR, data files, or files with no extension, like pe-sieve64.exe)
                Write-Host "File is a direct portable file ($FileExtension). Copying to $InstallPath..."
                Copy-Item -Path $DownloadPath -DestinationPath $InstallPath -Force
                Write-Host "Successfully copied $BaseFileName to $InstallPath." -ForegroundColor Green
            }
            else {
                # Fallback for any other portable type
                Write-Host "Copying downloaded portable file to $InstallPath..." -ForegroundColor Yellow
                Copy-Item -Path $DownloadPath -DestinationPath $InstallPath -Force
            }

            # Cleanup
            Remove-Item -Path $TempDir -Recurse -Force
    
            Write-Host "Installation for $($programName) completed successfully to $InstallPath." -ForegroundColor Green
            $exitCode = 0 
            
        }
        else {
            # For unsupported installer types
            Write-Host "Error: Installer type '$installerType' is neither a supported portable type nor a standard winget-compatible installer. Skipping installation." -ForegroundColor Red
            return
        }

        # Final exit code check (Only runs if installation was attempted)
        if ($exitCode -eq 0) {
            Write-Host "Installation for $($programName) completed successfully." -ForegroundColor Green
            
            # --- Add to Path ---
            Write-Host "Attempting to add '$InstallPath' to the System PATH..." -ForegroundColor Cyan

            # Get the current system PATH 
            $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")

            $pathExists = $currentPath.Split(';') | Where-Object { $_ -ceq $InstallPath }
            
            if ($pathExists) {
                Write-Host "Path entry '$InstallPath' already exists in the System PATH. Skipping addition." -ForegroundColor Yellow
            }
            else {
                $newPath = "$currentPath;$InstallPath"
                [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
                Write-Host "Successfully added '$InstallPath' to the System PATH." -ForegroundColor Green
                Write-Host "NOTE: You may need to restart your terminal or shell for the PATH change to take effect." -ForegroundColor Yellow
            }
            
        }
        else {
            Write-Host "Installation for $($programName) FAILED with installer exit code $($exitCode)." -ForegroundColor Red
            Write-Host "NOTE: Check the winget output above for specific errors." -ForegroundColor Red
        }
    }
    catch {
        Write-Host "An unexpected PowerShell error occurred for $($programName)." -ForegroundColor Red
        Write-Host "Error details: $($_.Exception.Message)" -ForegroundColor Red
    }
}


# Installs IDA plugins
function Install-idaPlugins {
    param(
        [string]$Location
    )
    Write-Host "Installing IDA plugins into $Location"

    # # Install IDA Capa plugin
    # Invoke-Expression "git clone https://github.com/mandiant/capa.git"

    # # Install IDA comida plugin
    # Invoke-Expression "git clone https://github.com/airbus-cert/comida.git"

    # # Install IDA Dereferencing plugin
    # Invoke-Expression "git clone https://github.com/danigargu/deREferencing.git"

    # # Install IDA Diaphora plugin
    # Invoke-Expression "git clone https://github.com/joxeankoret/diaphora.git"

    # # Install IDA Flare plugin
    # Invoke-Expression "git clone https://github.com/mandiant/flare-ida.git"

    # # Install IDA IFL plugin
    # Invoke-Expression "git clone https://github.com/hasherezade/ida_ifl.git"

    # # Install IDA xray plugin
    # Invoke-Expression "git clone https://github.com/patois/xray.git"

    # # Install IDA xrefer plugin
    # Invoke-Expression "git clone https://github.com/mandiant/xrefer.git"

    # Copy-Item -Path "C:\THisDOesntExistss" -Destination "$Location" -Recurse
}

# Install x64dbg plugins
function Install-x64dbgPlugins {
    Write-Host "Installing x64dbg plugins into $Location"
    # Install x64dbg ScyllaHide plugin
    # Invoke-Expression "git clone https://github.com/x64dbg/ScyllaHide.git"

    # # Install x64dbg TitanHide plugin
    # Invoke-Expression "git clone https://github.com/mrexodia/TitanHide.git"

    # # Install x64dbg DbgChild plugin
    # Invoke-Expression "git clone https://github.com/therealdreg/DbgChild.git"

}

# Install program using Winget
function Invoke-WingetInstall {
    param (
        [string[]]$Source,
        [string]$programName
    )

    $ID = $Source[1]
    $command = "winget install -e $ID --location 'C:\WRAP\$programName' --silent --accept-package-agreements --accept-source-agreements --disable-interactivity"
    Write-Host "Executing command: $command"
    # Invoke-Expression $command

    Write-Host "Source - $Source"  # FT
    Write-Host "Progam name - $programName" # FT
    Write-Host $Source[1]
    $location = "C:\WRAP\$programName"

    if ($ID -ieq "Hex-Rays.IDA.Free") {
        Write-Host "Installing IDA plugins..."
        Install-idaPlugins -Location $location
    }

    if ($ID -ieq "x64dbg.x64dbg") {
        Write-Host "Installing x64dbg plugins..."
        Install-idaPlugins -Location $location
    }
}

# Main installer function
function Install-Program {
    param (
        [psobject]$program
    )
    if ($program.Source.Count -gt 0) {
        $installer = $program.Source[0]
        Write-Host "Installing $($program.Name)..." -ForegroundColor Yellow
        switch ($installer) {
            "winget" {
                # Passing $program.Source[1] explicitly since Invoke-WingetInstall expects it
                Invoke-WingetInstall -Source @($program.Source[0], $program.Source[1]) -programName $program.Name
            }
            "pip" {
                Invoke-PipInstall -packageName $program.Source[1]
            }
            "npm" {
                Invoke-npmInstall -packageName $program.Source[1]
            }
            "other" {
                Invoke-installFromExternalSource -program $program
            }
            Default {
                Write-Host "Installer type '$installer' not recognized. Cannot install $($program.Name)." -ForegroundColor Yellow
            }
        }
        Write-Host "Press any key to continue..." -ForegroundColor White
        [System.Console]::ReadKey($true) | Out-Null
    }
}

# ----------------------------------------------------------------------------------
# --- Menu and Main Functions ---
# ----------------------------------------------------------------------------------

# Display the Select Menu
function Show-SelectableMenu {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Options,
        [int]$InitialIndex = 0
    )

    if (-not $host.UI.RawUI) {
        throw "This function requires an interactive console environment."
    }

    $selectedIndex = $InitialIndex
    $maxIndex = $Options.Length - 1
    $key = $null

    # Use [System.Console] for cursor control
    $console = [System.Console]

    while ($key -notlike "Enter") {

        # Cursor Control for Redraw
        if ($null -ne $key) {
            $currentTop = $console::CursorTop
            $startTop = $currentTop - ($maxIndex + 1)
            $console::SetCursorPosition(0, $startTop)
            $bufferWidth = $host.UI.RawUI.BufferSize.Width
            for ($i = 0; $i -le $maxIndex; $i++) {
                Write-Host (" " * $bufferWidth)
            }

            # Reset cursor
            $console::SetCursorPosition(0, $startTop)
        }

        # Redraw Menu
        for ($i = 0; $i -le $maxIndex; $i++) {
            if ($i -eq $selectedIndex) {
                Write-Host ">> $($Options[$i])" -ForegroundColor Green
            }
            else {
                Write-Host "   $($Options[$i])" -ForegroundColor White
            }
        }

        # Key Reading Logic
        $keyInfo = [System.Console]::ReadKey($true)
        $key = $keyInfo.Key.ToString()

        switch ($key) {
            "UpArrow" {
                $selectedIndex = if ($selectedIndex -eq 0) { $maxIndex } else { $selectedIndex - 1 }
            }
            "DownArrow" {
                $selectedIndex = if ($selectedIndex -eq $maxIndex) { 0 } else { $selectedIndex + 1 }
            }
            "Enter" {
                break
            }
        }
    }

    return $selectedIndex + 1
}

# Run find functions
function Invoke-FindFunctions {
    param (
        [psobject[]]$list
    )

    # Menu items
    $searchMenuItems = @(
        "1. Find a program.",
        "2. Find programs by category.",
        "3. List all programs.",
        "4. List categories.",
        "5. List installed programs."
    )
    Clear-Host
    Write-Host "--- Search Options ---" -ForegroundColor Yellow

    # Call the selectable menu function; get the selected option
    $selectionIndex = Show-SelectableMenu -Options $searchMenuItems
    $searchOpt = "$selectionIndex" # Convert to string for switching

    switch ($searchOpt) {
        "1" {
            $programName = Read-Host -Prompt "Search for"
            $foundProgram = Get-ProgramByName -list $list -name $programName
            if ($null -ne $foundProgram) {
                Show-ProgramDetails -program $foundProgram
            }
            else {
                Write-Host "Program '$programName' not found." -ForegroundColor Yellow
            }

            Start-Sleep -Seconds 1
        }
        "2" {
            $inputCategory = Read-Host -Prompt "Enter the category"
            Get-ProgramsByCategory -list $list -category $inputCategory
            Start-Sleep -Seconds 1
        }
        "3" {
            Get-ProgramList($list)
            Start-Sleep -Seconds 1
        }
        "4" {
            Get-CategoryWithCounts($list)
            Start-Sleep -Seconds 1
        }
        "5" {
            Write-Host "Listing installed programs..."
            Start-Sleep -Seconds 1
        }
        Default {
            Write-Host "Invalid option." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
    Write-Host "Press any key to continue..." -ForegroundColor White
    [System.Console]::ReadKey($true) | Out-Null
}

# Install everything; TODO
function Install-Everything {
    param (
        [psobject[]]$list
    )
    Write-Host "Wow, you are really doing this. This could take ages..." -ForegroundColor DarkYellow
    foreach ($program in $list) {
        Write-Host "Installing $name..."
    }
    Write-Host "Press any key to continue..." -ForegroundColor White
    [System.Console]::ReadKey($true) | Out-Null
}

function Get-Installed {
    param (
        [psobject[]]$list
    )

}

function Init {
    # Check if the Root folder exists. Create otherwise.
    Invoke-FolderCheck "C:\WRAP"

    # Check if Execution Policy is unrestricted.
    $ScopeToCheck = "CurrentUser"
    Write-Host "Checking PowerShell Execution Policy for scope: $($ScopeToCheck)..." -ForegroundColor Yellow
    try {
        $currentPolicy = Get-ExecutionPolicy -Scope $ScopeToCheck
        if ($currentPolicy -ne "Unrestricted") {
            Write-Host "[WARNING!] - The execution policy for '$ScopeToCheck' is set to '$currentPolicy'. This is NOT Unrestricted." -ForegroundColor Red
            Write-Host "To change it, run: Set-ExecutionPolicy Unrestricted -Scope $ScopeToCheck (use caution, as this lowers security)." -ForegroundColor Yellow
            return
        }
        Write-Host "[✓] The execution policy for '$ScopeToCheck' is currently set to '$currentPolicy'." -ForegroundColor Green
    }
    catch {
        Write-Error "An error occurred while trying to retrieve the execution policy: $($_.Exception.Message)"
    }
    $internetStatus = Test-Internet
    if (!$internetStatus) {
        Write-Host "Internet connection is required." -ForegroundColor Red
        Write-Host "Exiting..." -ForegroundColor Red
        Start-Sleep -Seconds 1
        exit
    }
    $firewallStatus = Test-Firewall
    $defenderStatus = Test-Defender
    if ($firewallStatus) {
        Write-Host "[WARNING!] - You may need to disable Windows Firewall." -ForegroundColor Yellow
    }
    if ($defenderStatus) {
        Write-Host "[WARNING!] - You may need to disable Windows Defender." -ForegroundColor Yellow
    }

    Invoke-GitCheck
    Invoke-NpmCheck
    Invoke-UvCheck
    Write-Host "Press any key to continue..." -ForegroundColor White
    [System.Console]::ReadKey($true) | Out-Null
}


# ----------- Main Script Body (Execution) -------------

$Data = Get-Content -Path ".\list.json" -Raw
$list = $Data | ConvertFrom-Json

Init

$menuItems = @(
    "1. Install Program by Name",
    "2. Find",
    "3. Install Everything",
    "4. Exit"
)

$opt = ""
do {
    Clear-Host
    # Call select menu function
    $selectionIndex = Show-SelectableMenu -Options $menuItems
    $opt = "$selectionIndex" # Cast the integer result back to string

    switch ($opt) {
        "1" {
            $programName = Read-Host -Prompt "Enter application name"
            $foundProgram = Get-ProgramByName -list $list -name $programName
            if ($foundProgram) {
                Show-ProgramDetails -program $foundProgram
                Install-Program -program $foundProgram
            }
        }
        "2" {
            Invoke-FindFunctions -list $list
        }
        "3" {
            Install-Everything -list $list
        }
        "4" {
            Write-Host "Exiting..." -ForegroundColor Yellow
            return
        }
        Default {
            Write-Host "Invalid Option." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
} while ($opt -ne "4")
