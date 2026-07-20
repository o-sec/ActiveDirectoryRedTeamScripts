#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -eo pipefail

# --- Configuration & Knowledge Base ---

DANGERO_LIST=(
    "GenericAll"
    "GenericWrite"
    "WriteOwner"
    "WriteDACL"
    "WriteProperty"
    "WriteProperties"
    "Self"
    "CreateChild"
    "DeleteChild"
    "Delete"
    "DeleteTree"
    "AllExtendedRights"
    "Domain-Administer-Server"
    "User-Force-Change-Password"
    "Domain-Password"
    "DS-Replication-Get-Changes"
    "DS-Replication-Synchronize"
    "DS-Replication-Manage-Topology"
    "Change-Schema-Master"
    "Change-Rid-Master"
    "Allocate-Rids"
    "Change-PDC"
    "Change-Domain-Master"
    "Apply-Group-Policy"
    "Certificate-Enrollment"
    "Validated-DNS-Host-Name"
    "Change-Infrastructure-Master"
    "DS-Replication-Get-Changes-All"
    "Migrate-SID-History"
    "Read-Only-Replication-Secret-Synchronization"
    "DS-Replication-Get-Changes-In-Filtered-Set"
    "Manage-Optional-Features"
    "Validated-MS-DS-Additional-DNS-Host-Name"
    "Certificate-AutoEnrollment"
    "DS-Set-Owner"
    "DS-Read-Partition-Secrets"
    "DS-Write-Partition-Secrets"
    "DS-Validated-Write-Computer"
    "Send-As"
    "Receive-As"
    "Validated-SPN"
    "Allowed-To-Authenticate"
)

# --- Helper Functions ---

usage() {
    cat << EOF
Usage: 
  Standard execution:
    $(basename "$0") -d <domain/user:pass> -dc <dc_ip> -t <target_DN> -p <principal_or_SID>

  Piped execution (Multiple DNs from output):
    cat dns.txt | $(basename "$0") -d <domain/user:pass> -dc <dc_ip> -p <principal_or_SID>

Options:
  -d,  --domain      Domain credentials in Impacket format (e.g., "domain.local/username:password")
  -dc, --dc-ip       IP address or hostname of the Domain Controller
  -t,  --target      Target Distinguished Name (DN) to query
  -p,  --principal   Controlled principal name or SID to audit (Can use multiple flags)
  -h,  --help        Show this help message
EOF
    exit 1
}

# --- Parsing Logic ---

parse_and_audit_dacledit() {
    local target_dn="$1"
    local raw_output="$2"
    
    local ace_type=""
    local access_mask=""
    local object_type=""
    local trustee=""

    evaluate_ace_block() {
        if [[ -z "$trustee" ]]; then return; fi
        
        local trustee_lower
        trustee_lower=$(echo "$trustee" | tr '[:upper:]' '[:lower:]')
        local matched=0
        
        for p in "${CONTROLLED_PRINCIPALS[@]}"; do
            local p_lower
            p_lower=$(echo "$p" | tr '[:upper:]' '[:lower:]')
            if [[ "$trustee_lower" == *"$p_lower"* ]]; then
                matched=1
                break
            fi
        done

        if [ "$matched" -eq 1 ]; then
            local found_permissions=()
            
            for right_name in "${DANGERO_LIST[@]}"; do
                if [[ "$access_mask" == *"$right_name"* || "$object_type" == *"$right_name"* ]]; then
                    found_permissions+=("$right_name")
                fi
            done
            
            if [ ${#found_permissions[@]} -gt 0 ]; then
                local joined_perms
                joined_perms=$(IFS=', '; echo "${found_permissions[*]}")
                
                echo "      ACE Type:      $ace_type"
                echo "      Permissions:   $joined_perms"
                echo "      Trustee:       $trustee"
                echo "      --------------------------------------------------------------------"
            fi
        fi
    }

    while IFS= read -r line || [[ -n "$line" ]]; do
        line=$(echo "$line" | sed -E 's/^\[\*\]//; s/^[[:space:]]+//; s/[[:space:]]+$//')

        case "$line" in
            ACE\[*\]*)
                evaluate_ace_block
                
                ace_type=""
                access_mask=""
                object_type=""
                trustee=""
                ;;
            "ACE Type"[:\ ]*|*"ACE Type"[:\ ]*)
                ace_type=$(echo "$line" | cut -d':' -f2- | sed 's/^[[:space:]]*//')
                ;;
            "Access mask"[:\ ]*|*"Access mask"[:\ ]*)
                access_mask=$(echo "$line" | cut -d':' -f2- | sed 's/^[[:space:]]*//')
                ;;
            "Object type (GUID)"[:\ ]*|*"Object type (GUID)"[:\ ]*)
                object_type=$(echo "$line" | cut -d':' -f2- | sed 's/^[[:space:]]*//')
                ;;
            "Trustee (SID)"[:\ ]*|*"Trustee (SID)"[:\ ]*)
                trustee=$(echo "$line" | cut -d':' -f2- | sed 's/^[[:space:]]*//')
                ;;
        esac
    done <<< "$raw_output"

    evaluate_ace_block
}

execute_dacledit_query() {
    local target_dn="$1"
    local raw_out
    
    # Notify the user that processing is underway for this target
    echo "[*] Processing : $target_dn" 

    if ! raw_out=$(impacket-dacledit -target-dn "$target_dn" -dc-ip "$DC_IP" "$DOMAIN_CREDS" -action read 2>&1); then
        echo "[!] Error running impacket-dacledit on target: $target_dn" >&2
        echo "$raw_out" | grep -Ei "error|failed|exception" >&2
        return
    fi

    parse_and_audit_dacledit "$target_dn" "$raw_out"
}

# --- Argument Processing ---

DOMAIN_CREDS=""
DC_IP=""
TARGET_DN=""
CONTROLLED_PRINCIPALS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--domain)      DOMAIN_CREDS="$2"; shift 2 ;;
        -dc|--dc-ip)      DC_IP="$2"; shift 2 ;;
        -t|--target)      TARGET_DN="$2"; shift 2 ;;
        -p|--principal)   CONTROLLED_PRINCIPALS+=("$2"); shift 2 ;;
        -h|--help)        usage ;;
        *)                echo "Error: Unknown argument $1" >&2; usage ;;
    esac
done

# --- Operational Validation ---

if [[ -z "$DOMAIN_CREDS" || -z "$DC_IP" ]]; then
    echo "Error: Missing connection parameters (-d and -dc)." >&2
    usage
fi

if [[ ${#CONTROLLED_PRINCIPALS[@]} -eq 0 ]]; then
    echo "Error: Provide at least one controlled security principal via -p." >&2
    usage
fi

# --- Engine Execution Path ---
OLD_IFS=$IFS
echo ""
echo "              Active Directory DACL Auditor"
echo "      [ Automated Wrapper Utility for impacket-dacledit ]"
echo ""
echo "[i] - DC Server:  $DC_IP"
echo "[i] - Controlled Principal(s) : $(IFS=',  '; echo "${CONTROLLED_PRINCIPALS[*]}")"
echo ""
echo ""
IFS=$OLD_IFS
if [ -p /dev/stdin ]; then
    if [[ -n "$TARGET_DN" ]]; then
        echo "[*] Warning: Pipe detected. Ignoring explicit target parameter (-t)." >&2
    fi
    while IFS= read -r piped_dn || [[ -n "$piped_dn" ]]; do
        piped_dn=$(echo "$piped_dn" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
        if [[ -n "$piped_dn" ]]; then
            execute_dacledit_query "$piped_dn"
        fi
    done
elif [[ -n "$TARGET_DN" ]]; then
    execute_dacledit_query "$TARGET_DN"
else
    echo "Error: Provide a target DN (-t) or pipe targets to stdin." >&2
    usage
fi

echo ""
echo "[*] Audit completed."
exit 0
