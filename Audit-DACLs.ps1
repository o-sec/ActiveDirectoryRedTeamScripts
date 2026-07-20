[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage = "Domain name is required.")]
    [string]$Domain,

    [Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage = "Domain Controller IP or Hostname is required.")]
    [string]$DomainController,

    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "Default", HelpMessage = "Target Distinguished Name (DN) is required.")]
    [string]$TargetDN,

    [Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage = "List of controlled principals to check.")]
    [string[]]$ControlledPrincipals,

    [Parameter(Mandatory = $true, ParameterSetName = "Help")]
    [Alias("h")]
    [switch]$Help
)

begin {
    # Custom interactive help menu
    if ($PSCmdlet.ParameterSetName -eq "Help" -or $Help) {
        Write-Host "`n--------------------------------------------------------------------------" -ForegroundColor Cyan
        Write-Host "  Active Directory DACL Auditor (PowerShell Edition)" -ForegroundColor White
        Write-Host "--------------------------------------------------------------------------" -ForegroundColor Cyan
        Write-Host "Usage:" -ForegroundColor Yellow
        Write-Host "  Standard execution:" -ForegroundColor White
        Write-Host "    .\Audit-DACLs.ps1 -Domain 'domain.local' -DomainController '10.10.10.10' -TargetDN 'CN=Target...' -ControlledPrincipals 'lowuser', 'Domain Users'" -ForegroundColor Gray
        Write-Host "`n  Pipeline execution (Multiple TargetDNs from text file/output):" -ForegroundColor White
        Write-Host "    Get-Content .\DNs.txt | .\Audit-DACLs.ps1 -Domain 'domain.local' -DomainController '10.10.10.10' -ControlledPrincipals 'Domain Users', 'lowuser'" -ForegroundColor Gray
        Write-Host "`nParameters:" -ForegroundColor Yellow
        Write-Host "  -Domain              Target AD domain FQDN (e.g., corp.local)" -ForegroundColor White
        Write-Host "  -DomainController    IP address or hostname of the Domain Controller" -ForegroundColor White
        Write-Host "  -TargetDN            Distinguished Name (DN) of the AD object to audit" -ForegroundColor White
        Write-Host "  -ControlledPrincipals  Array of SamAccountNames, SIDs, or display names to map" -ForegroundColor White
        Write-Host "  -Help, -h            Show this help message" -ForegroundColor White
        Write-Host "--------------------------------------------------------------------------" -ForegroundColor Cyan
        exit
    }

    # 1. Base Active Directory Rights (Bitmask checks)
    $DangerousBaseRights = @(
        "GenericAll",        # Full control over the object
        "WriteDacl",          # Ability to modify permissions (grant self GenericAll)
        "WriteOwner",         # Ability to take ownership of the object
        "GenericWrite",       # Includes WriteProperty and Self (Write)
        "WriteProperty",      # Ability to modify object attributes (e.g., scriptPath, servicePrincipalName)
        "ExtendedRight",      # Required for specific tasks like Reset Password or ForceChangePassword
        "CreateChild",        # Dangerous if target is an OU (e.g., creating a malicious computer/user object)
        "DeleteChild",        # Can bypass protections by dropping structural objects
        "Delete",             # Direct object deletion capabilities
        "Self"                # Self-membership write actions
    )

    # 2. Specific Extended Rights GUIDs / Known Names
    # These map to "ExtendedRight" but represent the actual dangerous actions
    $DangerousExtendedRights = @{
        "ab721a52-1e2f-11d0-9819-00aa0040529b" = "Domain-Administer-Server"
        "00299570-246d-11d0-a768-00aa006e0529" = "User-Force-Change-Password"
        "c7407360-20bf-11d0-a768-00aa006e0529" = "Domain-Password"
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes"
        "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Synchronize"
        "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Manage-Topology"
        "e12b56b6-0a95-11d1-adbb-00c04fd8d5cd" = "Change-Schema-Master"
        "d58d5f36-0a98-11d1-adbb-00c04fd8d5cd" = "Change-Rid-Master"
        "1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd" = "Allocate-Rids"
        "bae50096-4752-11d1-9052-00c04fc2d4cf" = "Change-PDC"
        "014bf69c-7b3b-11d1-85f6-08002be74fab" = "Change-Domain-Master"
        "edacfd8f-ffb3-11d1-b41d-00a0c968f939" = "Apply-Group-Policy"
        "0e10c968-78fb-11d2-90d4-00c04f79dc55" = "Certificate-Enrollment"
        "72e39547-7b18-11d1-adef-00c04fd8d5cd" = "Validated-DNS-Host-Name"
        "cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd" = "Change-Infrastructure-Master"
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes-All"
        "ba33815a-4f93-4c76-87f3-57574bff8109" = "Migrate-SID-History"
        "1131f6ae-9c07-11d1-f79f-00c04fc2dcd2" = "Read-Only-Replication-Secret-Synchronization"
        "89e95b76-444d-4c62-991a-0facbeda640c" = "DS-Replication-Get-Changes-In-Filtered-Set"
        "7c0e2a7c-a419-48e4-a995-10180aad54dd" = "Manage-Optional-Features"
        "80863791-dbe9-4eb8-837e-7f0ab55d9ac7" = "Validated-MS-DS-Additional-DNS-Host-Name"
        "a05b8cc2-17bc-4802-a710-e7c15ab866a2" = "Certificate-AutoEnrollment"
        "4125c71f-7fac-4ff0-bcb7-f09a41325286" = "DS-Set-Owner"
        "084c93a2-620d-4879-a836-f0ae47de0e89" = "DS-Read-Partition-Secrets"
        "94825a8d-b171-4116-8146-1e34d8f54401" = "DS-Write-Partition-Secrets"
        "9b026da6-0d3c-465c-8bee-5199d7165cba" = "DS-Validated-Write-Computer"
        "ab721a54-1e2f-11d0-9819-00aa0040529b" = "Send-As"
        "ab721a56-1e2f-11d0-9819-00aa0040529b" = "Receive-As"
        "f3a64788-5306-11d1-a9c5-0000f80367c1" = "Validated-SPN"
        "68b1d179-0d15-4d4f-ab71-46152e79a7bc" = "Allowed-To-Authenticate"
    }

    # 3. Critical Properties / Attributes GUIDs
    # Maps specific high-impact attribute modifications when WriteProperty is restricted
    $DangerousProperties = @{
        "bf9679c0-0de6-11d0-a285-00aa003049e2" = "member (Group Membership Modification)"
        "f3a647c6-011e-11d1-a93b-00a0c90f57b7" = "servicePrincipalName (Kerberoasting/Delegation)"
        "a05b03d2-8790-11d1-9243-00c04f79dec0" = "msDS-AllowedToDelegateTo (Constrained Delegation)"
        "3b9087b3-0d56-44b2-8412-2ca447bcc21f" = "msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)"
        "5f202011-e3a1-11d1-90c8-00c04fd91a17" = "scriptPath (Logon Script Modification)"
        "f3a647c9-011e-11d1-a93b-00a0c90f57b7" = "userAccountControl (Malicious Delegation/Pre-Auth Flags)"
        "3e0abfd0-126a-11d0-a0c2-00aa006c33ed" = "gPCFileSysPath (GPO Underlying File Paths Modification)"
        "f3a647cc-011e-11d1-a93b-00a0c90f57b7" = "gPLink (GPO Link Overlay Execution)"
        "46a9b11d-23e7-44bc-a1a9-21b78d21097a" = "ms-MCS-AdmPwd (Legacy LAPS Password Read)"
        "adc338f0-3134-4bc6-a0f5-3c120d0f2849" = "ms-LAPS-Password (Modern LAPS Password Read)"
    }

    Write-Verbose "Database containing expanded dangerous rights initialized successfully."
}

process {
    # Output heading style: [(yellow)*(white)] - processing <target DN>
    Write-Host -NoNewline -ForegroundColor White "["
    Write-Host -NoNewline -ForegroundColor Yellow "*"
    Write-Host -ForegroundColor White "] - processing $TargetDN"

    try {
        # Secure construction of the native LDAP query via ADSI
        $LdapPath = "LDAP://$DomainController/$TargetDN"
        $ADObject = [ADSI]$LdapPath

        # Enforce structural validation to confirm the object exists
        if ($null -eq $ADObject.path -or $ADObject.name -eq $null) {
            throw "Target object not found or unavailable."
        }

        # Query the security descriptor and retrieve standard NT Account format rules
        $ObjectSecurity = $ADObject.ObjectSecurity
        $AccessRules = $ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])

        foreach ($Rule in $AccessRules) {
            $Identity = $Rule.IdentityReference.Value
            
            # Match identity references cleanly against predefined targets
            foreach ($Principal in $ControlledPrincipals) {
                if ($Identity -match [regex]::Escape($Principal)) {
                    
                    # Inspect rule definitions for matching base dangerous flags
                    foreach ($Right in $DangerousBaseRights) {
                        if ($Rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]$Right) {
                            
                            $SpecificDetail = ""
                            $IsDangerous = $true
                            $ObjectGuidStr = $Rule.ObjectType.ToString()

                            # Fine-grained validation for Extended Rights
                            if ($Right -eq "ExtendedRight" -and $ObjectGuidStr -ne "00000000-0000-0000-0000-000000000000") {
                                if ($DangerousExtendedRights.ContainsKey($ObjectGuidStr)) {
                                    $SpecificDetail = " -> $($DangerousExtendedRights[$ObjectGuidStr])"
                                } else {
                                    $IsDangerous = $false # Filter non-critical extended rights
                                }
                            }

                            # Fine-grained validation for WriteProperty
                            if ($Right -eq "WriteProperty" -and $ObjectGuidStr -ne "00000000-0000-0000-0000-000000000000") {
                                if ($DangerousProperties.ContainsKey($ObjectGuidStr)) {
                                    $SpecificDetail = " -> Attribute: $($DangerousProperties[$ObjectGuidStr])"
                                }
                                # Note: If ObjectType is empty, it implies generic WriteProperty to ALL attributes, which is inherently dangerous.
                            }

                            # Render clean console matches
                            if ($IsDangerous) {
                                # Updated output style: [+] - <controlled principal> -> <dangerous rights>
                                Write-Host -NoNewline -ForegroundColor White "["
                                Write-Host -NoNewline -ForegroundColor Green "+"
                                Write-Host -NoNewline -ForegroundColor White "] - "
                                Write-Host -NoNewline -ForegroundColor Yellow "$Identity "
                                Write-Host -NoNewline -ForegroundColor White "-> "
                                Write-Host -ForegroundColor Green "$Right$SpecificDetail ($($Rule.AccessControlType))"
                            }
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-Host -ForegroundColor Red "    [-] Error processing object: $_"
    }
}

end {
    Write-Verbose "Audit complete."
}
