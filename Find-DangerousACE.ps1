[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$d,    # Domain Name

    [Parameter(Mandatory = $true)]
    [string]$dc,   # Domain Controller IP/Hostname

    [Parameter(Mandatory = $true)]
    [string]$u,    # Username

    [Parameter(Mandatory = $true)]
    [string]$p,    # Password

    [Parameter(Mandatory = $false)]
    [ValidateSet('users', 'computers', 'all')]
    [string]$o = 'all', # Object type to scan

    [Parameter(Mandatory = $true)]
    [string[]]$t   # Controlled Trustee names or SIDs (Array)
)

# --- Resolve Object Filter ---
switch ($o) {
    'users'     { $filter = "(objectClass=user)" }
    'computers' { $filter = "(objectClass=computer)" }
    'all'       { $filter = "(|(objectClass=user)(objectClass=computer))" }
}

# --- Establish LDAP Connections ---
Write-Host "[*] Querying rootDSE for Base DN..."
try {
    $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dc/RootDSE", "$u@$d", $p)
    $baseDN = $rootDSE.Properties["defaultNamingContext"].Value
    if (-not $baseDN) { throw "Base DN empty" }
} catch {
    Write-Error "[-] Error: Failed to retrieve Base DN dynamically. Check credentials/connectivity."
    exit 1
}

Write-Host "[+ Dynamic Base DN Found: $baseDN"
Write-Host "[*] Starting RBCD scan (Type: $o) against DC: $dc"
# Create a clean regex pattern out of the trustee array elements
$trusteePattern = ($t | ForEach-Object { [regex]::Escape($_) }) -join '|'
Write-Host "[*] Scanning for objects that our controlled trustees [ $($t -join ', ') ] have dangerous permissions over..."
Write-Host ("-" * 80)

# Setup directory search engine
$ldapRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dc/$baseDN", "$u@$d", $p)
$searcher = New-Object System.DirectoryServices.DirectorySearcher($ldapRoot)
$searcher.Filter = $filter
$searcher.SizeLimit = 0
$searcher.PageSize = 250
$null = $searcher.PropertiesToLoad.Add("distinguishedname")

# Run search query
$targets = $searcher.FindAll()

# --- Audit Object DACLs ---
# GUID matching the ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity attribute
$rbcdSchemaGuid = "3f78c3e5-95f1-11d2-bbd5-00c04f79e83a"

foreach ($target in $targets) {
    $dn = $target.Properties["distinguishedname"][0]
    Write-Host "[*] Processing target DN: $dn"

    # Fetch ACL rules natively via Active Directory Security descriptors
    try {
        $targetEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dc/$dn", "$u@$d", $p)
        $acl = $targetEntry.ObjectSecurity
        $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])
    } catch {
        # Catch environments handling SID values only
        try {
            $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
        } catch {
            continue
        }
    }

    $matchedTrusteRules = @()

    foreach ($rule in $rules) {
        $identity = $rule.IdentityReference.Value
        
        # Check if the trustee matches our tracking pattern
        if ($identity -match $trusteePattern) {
            $hasControl = $false

            # Check for generic rights/FullControl equivalents
            if (($rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericAll -or
                ($rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericChild) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericChild) {
                $hasControl = $true
            }
            # Fixed Syntax Error: Changed 'elif' to 'elseif'
            elseif (($rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -eq [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) {
                if ($rule.ObjectType.ToString() -eq $rbcdSchemaGuid -or $rule.ObjectType.ToString() -eq "00000000-0000-0000-0000-000000000000" -or -not $rule.ObjectType) {
                    $hasControl = $true
                }
            }

            if ($hasControl) {
                $matchedTrusteRules += $identity
            }
        }
    }

    # Deduplicate and output findings per object
    $matchedTrusteRules | Select-Object -Unique | ForEach-Object {
        Write-Host "[+] Found a dangerous ACE for the trustee: $_" -ForegroundColor Green
        Write-Host "    [+] You have control over: $dn" -ForegroundColor Green
        Write-Host ""
    }
}
