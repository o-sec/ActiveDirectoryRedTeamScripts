<#
.SYNOPSIS
    Audits Active Directory object DACLs for specific dangerous permissions held by controlled principals.
.DESCRIPTION
    This script connects to a specified Domain Controller and retrieves the discretionary access control list (DACL)
    of a target object. It checks if any provided controlled principals possess critical or dangerous rights 
    (e.g., GenericAll, WriteDacl, WriteOwner, DCSync, or RBCD modifications) over that object.
.PARAMETER Domain
    The target domain name (e.g., corp.local).
.PARAMETER DomainController
    The IP address or hostname of the Domain Controller to query.
.PARAMETER TargetDN
    The Distinguished Name of the target object to inspect. Accepts pipeline input.
.PARAMETER ControlledPrincipals
    An array of SamAccountNames, SIDs, or Display Names representing the principals you control or want to check.
.EXAMPLE
    Get-Content .\targets.txt | .\Find-DangerousACE.ps1 -Domain "INLANEFREIGHT.LOCAL" -DomainController "10.129.202.146" -ControlledPrincipals "lowuser", "Domain Users"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Domain name is required.")]
    [string]$Domain,

    [Parameter(Mandatory = $true, HelpMessage = "Domain Controller IP or Hostname is required.")]
    [string]$DomainController,

    [Parameter(Mandatory = $true, ValueFromPipeline = $true, HelpMessage = "Target Distinguished Name (DN) is required.")]
    [string]$TargetDN,

    [Parameter(Mandatory = $true, HelpMessage = "List of controlled principals to check.")]
    [string[]]$ControlledPrincipals
)

begin {
    # 1. Base Active Directory Rights (Bitmask checks)
    $DangerousBaseRights = @(
        "GenericAll",        # Full control over the object
        "WriteDacl",          # Ability to modify permissions (grant self GenericAll)
        "WriteOwner",         # Ability to take ownership of the object
        "GenericWrite",       # Includes WriteProperty and Self (Write)
        "WriteProperty",      # Ability to modify object attributes (e.g., scriptPath, servicePrincipalName)
        "ExtendedRight",      # Required for specific tasks like Reset Password or ForceChangePassword
        "CreateChild",        # Dangerous if target is an OU (e.g., creating a malicious computer/user object)
        "Self"                # Self-membership write actions
    )

    # 2. Specific Extended Rights GUIDs / Known Names
    # These often map to "ExtendedRight" but represent the actual dangerous actions
    $DangerousExtendedRights = @{
        "002a969f-2652-11d1-bf8d-0000f8757935" = "DS-Replication-Get-Changes (DCSync part 1)"
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes-All (DCSync part 2)"
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes-In-Filtered-Set"
        "00000000-0000-0000-0000-000000000000" = "All Extended Rights"
        "002a96a0-2652-11d1-bf8d-0000f8757935" = "User-Force-Change-Password"
    }

    # 3. Critical Properties / Attributes GUIDs
    # Maps specific high-impact attribute modifications when WriteProperty is restricted
    $DangerousProperties = @{
        "bf9679c0-0de6-11d0-a285-00aa003049e2" = "member (Group Membership Modification)"
        "f3a647c6-011e-11d1-a93b-00a0c90f57b7" = "servicePrincipalName (Kerberoasting/Delegation)"
        "a05b03d2-8790-11d1-9243-00c04f79dec0" = "msDS-AllowedToDelegateTo (Constrained Delegation)"
        "3b9087b3-0d56-44b2-8412-2ca447bcc21f" = "msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)"
        "5f202011-e3a1-11d1-90c8-00c04fd91a17" = "scriptPath (Logon Script Modification)"
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
