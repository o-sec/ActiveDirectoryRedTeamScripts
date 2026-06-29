#!/bin/bash


usage() {
    echo "Usage: $0 -d <domain> -dc <dc_ip> -u <username> -p <password> [-o users|computers|all] -t <trustee1> [-t <trustee2> ...]"
    echo ""
    echo "Options:"
    echo "  -d     Domain Name (e.g., INLANEFREIGHT.LOCAL)"
    echo "  -dc    Domain Controller IP or Hostname"
    echo "  -u     Username to authenticate with"
    echo "  -p     Password to authenticate with"
    echo "  -o     Object type to scan: users, computers, or all (Default: all)"
    echo "  -t     Controlled trustee name or SID (Can be specified multiple times)"
    echo "  -h     Display this help menu"
    exit 1
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d)
            DOMAIN="$2"
            shift 2
            ;;
        -dc)
            DC="$2"
            shift 2
            ;;
        -u)
            USER="$2"
            shift 2
            ;;
        -p)
            PASS="$2"
            shift 2
            ;;
        -o)
            TYPE="$2"
            shift 2
            ;;
        -t)
            CONTROLLED_TRUSTEES+=("$2")
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "[-] Error: Unknown argument $1"
            usage
            ;;
    esac
done

# Validate required parameters
if [ -z "$DOMAIN" ] || [ -z "$DC" ] || [ -z "$USER" ] || [ -z "$PASS" ] || [ ${#CONTROLLED_TRUSTEES[@]} -eq 0 ]; then
    echo "[-] Error: Missing required arguments."
    usage
fi

case "$TYPE" in
    users)     FILTER="(objectClass=user)" ;;
    computers) FILTER="(objectClass=computer)" ;;
    all)       FILTER="(|(objectClass=user)(objectClass=computer))" ;;
    *) echo "[!] Invalid type option: $TYPE"; usage ;;
esac

# Join the controlled trustees array into a pipe-separated regex pattern for awk
TRUSTEE_REGEX=$(printf "%s|" "${CONTROLLED_TRUSTEES[@]}")
TRUSTEE_REGEX="${TRUSTEE_REGEX%|}" # Strip trailing pipe

echo "[*] Querying rootDSE for Base DN..."
# Query rootDSE dynamically using credentials to extract defaultNamingContext
BASE=$(ldapsearch -LLL -x \
    -H ldap://$DC \
    -D "${USER}@${DOMAIN}" \
    -w "$PASS" \
    -b "" \
    -s base \
    defaultNamingContext | awk -F': ' '/^defaultNamingContext:/ {print $2}')

if [ -z "$BASE" ]; then
    echo "[-] Error: Failed to retrieve Base DN dynamically."
    exit 1
fi

echo "[+] Base DN Found: $BASE"
echo "[*] Starting the scan (Type: $TYPE) against DC: $DC"
echo "[*] Scanning for objects that our controlled trustees have dangerous permissions over..."
echo "--------------------------------------------------------------------------------"
echo ""

ldapsearch -LLL -x \
    -H ldap://$DC \
    -o ldif-wrap=no \
    -D "${USER}@${DOMAIN}" \
    -w "$PASS" \
    -b "$BASE" \
    "$FILTER" \
    distinguishedName |
awk -F': ' '/^distinguishedName:/ {print $2}' |
while read -r DN; do

    # Verbosity check tracker line added here
    echo "[*] Processing target DN: $DN"

    impacket-dacledit "${DOMAIN}/${USER}:${PASS}" \
        -target-dn "$DN" \
        -action read 2>/dev/null |
    awk -v pattern="$TRUSTEE_REGEX" -v target_dn="$DN" '
    BEGIN { IGNORECASE = 1; match_found = 0; mask = ""; obj = ""; trustee_line = "" }

    function evaluate_block() {
        if (match_found && (mask ~ /FullControl|GenericAll|0xf01ff/ || ((mask ~ /WriteProperty|0x20|0x30/) && (obj ~ /ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity|3f78c3e5/ || obj == "")))) {
            print "MATCH|" trustee_line
            return 1
        }
        return 0
    }

    # When a new ACE block starts, evaluate the previous one
    /^\[\*\]\s+ACE\[[0-9]+\]/ {
        if (evaluate_block()) exit 0
        match_found = 0; mask = ""; obj = ""; trustee_line = ""
    }

    # Capture fields within the current ACE block
    /Access mask/         { sub(/^.*:\s*/, ""); mask = $0 }
    /Object type \(GUID\)/ { sub(/^.*:\s*/, ""); obj = $0 }
    /Trustee \(SID\)/     { 
        if ($0 ~ pattern) {
            match_found = 1
            sub(/^.*:\s*/, "")
            trustee_line = $0
        }
    }

    # Check the final block if the stream ends
    END {
        if (evaluate_block()) exit 0
        exit 1
    }
    ' | while IFS='|' read -r status details; do
        if [ "$status" = "MATCH" ]; then
            echo "[+] Found a dangerous ACE for the trustee: $details"
            echo "    [+] You have control over: $DN"
            echo ""
        fi
    done

done
