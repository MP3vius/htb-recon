#!/bin/bash

### VARIABLES

NEW_LINE="\n"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

### FUNCTIONS

# sudo password check
check_sudo_password() {
  while true; do
    sudo -k
    read -s -p "Enter your sudo password: " SUDO_PASSWD
    echo

    echo "$SUDO_PASSWD" | sudo -S -v &>/dev/null
    if [ $? -eq 0 ]; then
        break
    else
        echo -e "${RED}[-] Incorrect sudo password. Please try again.${NC}"
    fi
  done
}

# output var check
check_output_path() {
  while [[ -z "$OUTPUT_PATH" || ! "$OUTPUT_PATH" =~ ^/ ]]; do
    echo -e $NEW_LINE
    echo -e "Enter the directory path where you want to save output."
    echo -e "(Example: /home/kali/htb/boxes/dog)"
    echo -e "-------------------------------------------------------"
    read -p "Path: " OUTPUT_PATH
    if [[ ! "$OUTPUT_PATH" =~ ^/ ]]; then
      echo -e "${RED}[-] Invalid path. It must start with '/'.${NC}"
      OUTPUT_PATH=""
    fi
  done
  echo -e $NEW_LINE
  sleep 0.5
}

# IP var check
check_ip_address() {
  while true; do
    read -p "Enter the IP address | example: 10.10.10.10 (or press Enter to skip): " IP_ADDRESS
    if [[ -z "$IP_ADDRESS" ]]; then
      # Allow skipping
      break
    elif [[ "$IP_ADDRESS" =~ ^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}$ ]]; then
      break
    else
      echo -e "${RED}[-] Invalid IP address format. Please enter a valid IP like 192.168.1.1, or press Enter to skip.${NC}"
      IP_ADDRESS=""
    fi
  done
  sleep 0.5
}

# Domain var check
check_domain() {
  while true; do
    read -p "Enter the domain | example: dog.htb (or press Enter to skip): " DOMAIN
    if [[ -z "$DOMAIN" ]]; then
      # Allow skipping
      break
    elif [[ "$DOMAIN" =~ ^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$ ]]; then
      break
    else
      echo -e "${RED}[-] Invalid domain. Only letters, numbers, hyphens, and dots are allowed. Must end in a valid TLD.${NC}"
      DOMAIN=""
    fi
  done
  sleep 0.5
}

# appending to hosts file
append_to_hosts() {
echo -e "${SUDO_PASSWD}" | sudo -S -p "" bash -c "echo '${IP_ADDRESS} ${DOMAIN}' >> /etc/hosts"
}

# installation check
install_check() {
if ! command -v $1 &>/dev/null
then
	echo -e $NEW_LINE
	echo -e "${RED}[-] $1 is not installed. Please install it to continue.${NC}"
	exit 0
fi
}

# quick nmap scan
quick_nmap() {
install_check nmap
check_output_path
mkdir -p "$OUTPUT_PATH/nmap"

echo -e "${BLUE}[*] Running nmap scan on $IP_ADDRESS...${NC}"
sleep 0.5
nmap -p- "${IP_ADDRESS}" -T5 -oA "${OUTPUT_PATH}/nmap/quickscan"

if [ $? -eq 0 ]
then
	echo -e "${GREEN}[+] Scan completed successfully.${NC}"
	sleep 0.5
	echo -e "${BLUE}[*] Output saved to: $OUTPUT_PATH/nmap/quickscan.${NC}"
	sleep 0.5
else
	echo -e "${RED}[-] nmap scan failed!${NC}"
	sleep 0.5
fi
}

# quick rustscan
quick_rustscan() {
install_check rustscan
check_output_path
mkdir -p "$OUTPUT_PATH/nmap"

echo -e "${BLUE}[*] Running rustscan on $IP_ADDRESS...${NC}"
echo -e $NEW_LINE
sleep 0.5
rustscan -a "${IP_ADDRESS}" --range 1-65535 --ulimit 5000 --greppable > "${OUTPUT_PATH}/nmap/quickscan.txt"

if [ $? -eq 0 ]
then
	echo -e "${YELLOW}--------------------"
	echo -e "Output of quickscan:"
	echo -e "--------------------${NC}"
	echo -e $NEW_LINE
	echo -e ${YELLOW}
        cat "$OUTPUT_PATH/nmap/quickscan.txt"
	echo -e ${NC}
	echo -e $NEW_LINE
	echo -e "${GREEN}[+] Scan completed successfully.${NC}"
	sleep 0.5
	echo -e "${BLUE}[*] Output saved to: $OUTPUT_PATH/nmap/quickscan.${NC}"
	sleep 0.5
else
	echo -e "${RED}[-] rustscan failed!${NC}"
	sleep 0.5
fi
}

# thorough nmap scan
deep_nmap() {

    	if [[ -z "$IP_ADDRESS" ]]; then
    check_ip_address
    	fi

    	if [[ -z "$DOMAIN" ]]; then
    check_domain
    	fi

check_output_path
    echo -e $NEW_LINE
    echo -e "${BLUE}[*] Filtering ports from quick scan output if available...${NC}"
    sleep 0.5

    if [ -f "$OUTPUT_PATH/nmap/quickscan.gnmap" ]; then
        echo -e "${BLUE}[*] Extracting open ports from quickscan.gnmap (Nmap format)${NC}"
        awk -F'[ /]' '/Ports:/{for(i=1;i<=NF;i++) if ($i ~ /^[0-9]+$/ && $(i+1)=="open" && $(i+2)=="tcp") print $i}' "$OUTPUT_PATH/nmap/quickscan.gnmap" | sort -n | uniq > "$OUTPUT_PATH/nmap/ports.txt"
	sleep 0.5

    elif [ -f "$OUTPUT_PATH/nmap/quickscan.txt" ]; then
        echo -e "${BLUE}[*] Extracting open ports from quickscan.txt (RustScan format)${NC}"
	grep -oP '\[\K[0-9,]+' "$OUTPUT_PATH/nmap/quickscan.txt" | tr ',' '\n' | sort -n | uniq > "$OUTPUT_PATH/nmap/ports.txt"
	sleep 0.5

    else
        echo -e "${BLUE}[*] Quick scan output not found, running full port scan instead.${NC}"
	sleep 0.5
	echo -e "${BLUE}[*] This can take a little longer...${NC}"
	sleep 0.5
        nmap -p- -sV -sC -T5 "${IP_ADDRESS}" -oA "${OUTPUT_PATH}/nmap/deepscan"
        if [ ! -f "$OUTPUT_PATH/nmap/deepscan.gnmap" ]; then
            echo "${RED}[-] Thorough scan failed! Exiting...${NC}"
	    sleep 0.5
            exit 1
        fi
        return
    fi

    echo -e "${BLUE}[*] Running thorough nmap scan on the extracted ports...${NC}"
    sleep 0.5
    PORTS=$(paste -sd, "$OUTPUT_PATH/nmap/ports.txt")
    nmap -sV -sC -T5 -p"${PORTS}" "${IP_ADDRESS}" -oA "${OUTPUT_PATH}/nmap/deepscan"

    if [ ! -f "$OUTPUT_PATH/nmap/deepscan.gnmap" ]; then
        echo -e "${RED}[-] Thorough scan failed! Exiting...${NC}"
        sleep 0.5
	exit 1
    else
        echo -e "${GREEN}[+] Scan completed successfully.${NC}"
	sleep 0.5
        echo -e "${BLUE}[*] Output saved to: $OUTPUT_PATH/nmap/deepscan.${NC}"
        sleep 0.5
    fi
}

# directory fuzzing
dir_fuzz() {
    install_check ffuf
    check_output_path

    	if [[ -z "$DOMAIN" ]]; then
    check_domain
    	fi

    echo -e $NEW_LINE
    echo -e "${BLUE}[*] Starting directory fuzzing...${NC}"

    mkdir -p "$OUTPUT_PATH/dir"

    while true; do
    echo -e "Please specify the port to use for directory fuzzing."
    echo -e "-----------------------------------------------------"
    read -p "Enter port: " DIR_PORT
    if [[ "$DIR_PORT" =~ ^[0-9]+$ ]]; then
        break
    else
        echo -e "${RED}[-] Invalid port. Please enter digits only.${NC}"
    fi
	done

    echo -e $NEW_LINE 
    echo -e "Please specify what wordlist to use for directory fuzzing."
    echo -e "(e.g., /usr/share/seclists/Discovery/Web-Content/common.txt)"
    echo -e "------------------------------------------------------------"
    read -p "Enter path to wordlist: " DIR_LIST

    if [ ! -f "$DIR_LIST" ]; then
        echo -e "${RED}[-] Wordlist $DIR_LIST not found! Exiting...${NC}"
	sleep 0.5
        return
    fi

    echo -e "${BLUE}[*] Running ffuf on http://$DOMAIN:$DIR_PORT using wordlist $DIR_LIST.${NC}"
    sleep 0.5
    ffuf -w "${DIR_LIST}":FUZZ -u "http://${DOMAIN}:${DIR_PORT}/FUZZ" -o "${OUTPUT_PATH}/dir/results.txt" | tee -a "${OUTPUT_PATH}/dir/results.txt"

    echo -e "${GREEN}[+] Directory fuzzing completed. Results saved to: $OUTPUT_PATH/dir/results.txt.${NC}"
    sleep 0.5
}

# subdomain fuzzing
sub_fuzz() {
    install_check ffuf
    check_output_path

    	if [[ -z "$DOMAIN" ]]; then
    check_domain
    	fi

    echo -e $NEW_LINE
    echo -e "${BLUE}[*] Starting subdomain fuzzing...${NC}"

    mkdir -p "$OUTPUT_PATH/sub"

    echo -e $NEW_LINE
    while true; do
    echo -e "Please specify the port to use for subdomain fuzzing."
    echo -e "-----------------------------------------------------"
    read -p "Enter port: " SUB_PORT
    if [[ "$SUB_PORT" =~ ^[0-9]+$ ]]; then
        break
    else
        echo -e "${RED}[-] Invalid port. Please enter digits only.${NC}"
    fi
	done

    echo -e $NEW_LINE
    echo -e "Please specify what wordlist to use for subdomain fuzzing."
    echo -e "(e.g., /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt)"
    echo -e "-------------------------------------------------------------------------"
    read -p "Enter path to wordlist: " SUB_LIST

    if [ ! -f "$SUB_LIST" ]; then
        echo -e "${RED}[-] Wordlist $SUB_LIST not found! Exiting...${NC}"
	sleep 0.5
        return
    fi
    echo -e "${BLUE}[*] Running ffuf on http://$DOMAIN:$SUB_PORT using wordlist $SUB_LIST.${NC}"
    sleep 0.5
    echo -e "${YELLOW}[!] Please note once scan runs you can press ENTER for an interactive shell to set size filter with \"fs [value]\"${NC}" 
    sleep 2.5
    ffuf -w "${SUB_LIST}":FUZZ -u "http://${DOMAIN}:${SUB_PORT}/" -H "Host: FUZZ.${DOMAIN}" -o "${OUTPUT_PATH}/sub/results.txt" | tee -a "${OUTPUT_PATH}/sub/results.txt"

    echo -e "${GREEN}[+] Subdomain fuzzing completed. Results saved to: $OUTPUT_PATH/sub/results.txt.${NC}"
    sleep 0.5

    echo -e "${BLUE}[*] Adding found subdomain(s) to /etc/hosts file...${NC}"
    sleep 0.5
    # Parse JSON output to extract valid subdomains
    FOUND_SUBS=$(jq -r '.results[].host' "$OUTPUT_PATH/sub/results.txt" | cut -d'.' -f1)

    # Append each found subdomain to /etc/hosts
    if [ -z "$FOUND_SUBS" ]; then
    	echo -e "${RED}[-] No subdomains found to add to /etc/hosts${NC}"
    else
    	for SUB in $FOUND_SUBS; do
        	FQDN="$SUB.$DOMAIN"
        	if ! grep -q "$FQDN" /etc/hosts; then
            	echo -e "${SUDO_PASSWD}" | sudo -S -p "" bash -c "echo '${IP_ADDRESS} ${FQDN}' >> /etc/hosts"
            	echo -e "${GREEN}[+] Added subdomains(s) to /etc/hosts${NC}"
            	sleep 0.5
        	fi
    	done
    fi
}

# DNS zone transfer check
dns_check() {
    install_check dig

    	if [[ -z "$IP_ADDRESS" ]]; then
    check_ip_address
    	fi

    	if [[ -z "$DOMAIN" ]]; then
    check_domain
    	fi

    check_output_path
    echo -e $NEW_LINE
    echo -e "${BLUE}[*] Starting zone transfer check...${NC}"
    sleep 0.5
    mkdir -p "$OUTPUT_PATH/dns"

    dig axfr "${DOMAIN}" @"${IP_ADDRESS}" > "${OUTPUT_PATH}/dns/results.txt"

    if [ -f "$OUTPUT_PATH/dns/results.txt" ]; then
    	cat "$OUTPUT_PATH/dns/results.txt"
        echo -e "${GREEN}[+] Output saved to: $OUTPUT_PATH/dns/results.txt.${NC}"
	sleep 0.5
    else
    	echo -e "${RED}[-] Zone transfer failed! Please try again.${NC}"
	sleep 0.5
    fi
}

# FTP anonymous login check
ftp_check() {
    install_check ftp
    install_check lftp

    	if [[ -z "$IP_ADDRESS" ]]; then
    check_ip_address
    	fi

    check_output_path
    echo -e $NEW_LINE
    echo -e "${BLUE}[*] Starting FTP anonymous login check...${NC}"
    sleep 0.5
    mkdir -p "$OUTPUT_PATH/ftp"

    echo -e "${BLUE}[*] Attempting anonymous login on $IP_ADDRESS...${NC}"
    sleep 0.5

    echo -e "open $IP_ADDRESS\nuser anonymous anonymous\nbye" | ftp -inv > "$OUTPUT_PATH/ftp/ftp_listing.txt" 2>/dev/null

    if grep -qi "230" "$OUTPUT_PATH/ftp/ftp_listing.txt"; then
        echo -e "${GREEN}[+] Anonymous login allowed.${NC}"
	sleep 0.5
        echo -e "${BLUE}[*] Attempting recursive download of all files...${NC}"
	sleep 0.5
        lftp -c "open -u anonymous,anonymous ftp://$IP_ADDRESS; mirror -e / $OUTPUT_PATH/ftp/downloads"

        echo -e "${GREEN}[+] Download attempt finished. Check $OUTPUT_PATH/ftp/downloads for any retrieved content.${NC}"
        sleep 0.5
    else
        echo -e "${RED}[-] Anonymous login not allowed on $IP_ADDRESS.${NC}"
        sleep 0.5
    fi
}

# enum4linux
smb_enum() {
    install_check enum4linux

    	if [[ -z "$IP_ADDRESS" ]]; then
    check_ip_address
    	fi

    check_output_path
    echo -e $NEW_LINE
    echo -e "${BLUE}[*] Starting enum4linux...${NC}"
    sleep 0.5
    echo -e "${BLUE}[*] This will take a minute.${NC}"
    sleep 0.5

    mkdir -p "$OUTPUT_PATH/smb/enum4linux"

    enum4linux "${IP_ADDRESS}" > "${OUTPUT_PATH}/smb/enum4linux/results.txt" 2>/dev/null

    if [ -f "$OUTPUT_PATH/smb/enum4linux/results.txt" ]; then
    	echo -e "${GREEN}[+] Output saved to: $OUTPUT_PATH/smb/enum4linux/results.txt.${NC}"
    	sleep 0.5
	cat "$OUTPUT_PATH/smb/enum4linux/results.txt"
	sleep 0.5
    else
    	echo -e $NEW_LINE
    	echo -e "${RED}[-] Scan failed. Please try again.${NC}"
    	sleep 0.5
    fi
}

# SMB null auth and recursive download
smb_null() {
    install_check smbclient
    install_check smbget

    	if [[ -z "$IP_ADDRESS" ]]; then
    check_ip_address
    	fi

    check_output_path
    echo -e "$NEW_LINE"
    echo -e "${BLUE}[*] Starting SMB null authentication check using smbclient and smbget...${NC}"
    sleep 0.5

    mkdir -p "$OUTPUT_PATH/smb/downloads"

    echo -e "${BLUE}[*] Listing SMB shares on $IP_ADDRESS...${NC}"
    smbclient -L "//${IP_ADDRESS}" -N 2>/dev/null | grep -P "^\s+[a-zA-Z0-9_\$-]+" | awk '{print $1}' > "${OUTPUT_PATH}/smb/shares.txt"
    sleep 0.5

    # Remove headers and separators from the output
    sed -i '/^Sharename/d;/^---------/d;/^$/d' "$OUTPUT_PATH/smb/shares.txt"

    if [ ! -s "$OUTPUT_PATH/smb/shares.txt" ]; then
        echo -e "${RED}[-] No valid shares found on $IP_ADDRESS. Exiting...${NC}"
        sleep 0.5
        return
    fi

    while IFS= read -r SHARE_NAME; do
        echo -e "${BLUE}[*] Processing share '$SHARE_NAME'...${NC}"
        sleep 0.5

        # Skip system and administrative shares
        if [[ "$SHARE_NAME" =~ ^(print\$|IPC\$|ADMIN\$|.*\$$) ]]; then
            echo -e "${BLUE}[*] Skipping system share '$SHARE_NAME'.${NC}"
            sleep 0.5
            continue
        fi

        SHARE_DOWNLOAD_DIR="$OUTPUT_PATH/smb/downloads/$SHARE_NAME"
        mkdir -p "$SHARE_DOWNLOAD_DIR"

        echo -e "${BLUE}[*] Attempting recursive download from smb://$IP_ADDRESS/$SHARE_NAME...${NC}"
        sleep 0.5
        # Change into the share's download directory so smbget downloads files there
        pushd "$SHARE_DOWNLOAD_DIR" > /dev/null

        smbget --recursive --user="" --no-pass "smb://${IP_ADDRESS}/${SHARE_NAME}"

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[+] Download from '$SHARE_NAME' completed successfully.${NC}"
            sleep 0.5
        else
            echo -e "${RED}[-] Download from '$SHARE_NAME' failed or is empty.${NC}"
            sleep 0.5
        fi

        popd > /dev/null

    done < "$OUTPUT_PATH/smb/shares.txt"

    echo -e "${BLUE}[*] SMB NULL session download complete.${NC}"
    sleep 0.5
    echo -e "${BLUE}[*] Files saved in '$SHARE_DOWNLOAD_DIR'.${NC}"
    sleep 0.5
}

# SMB check (enum4linux + null auth & recursive download)
smb_check() {
    echo -e "Available options:"
    echo -e "\t1) enum4linux"
    echo -e "\t2) null auth & recursive download"
    echo -e $NEW_LINE
    echo -e "\t3) Exit."

    read -p "Select one of the options: " smb_opt

    case $smb_opt in
        "1") smb_enum ;;
        "2") smb_null ;;
        "3") exit 0 ;;
        *) echo "Invalid option, please select 1, 2, or 3." ;;
    esac
}

# NFS check and mounting
nfs_check() {
    install_check showmount
    install_check mount

    	if [[ -z "$IP_ADDRESS" ]]; then
    check_ip_address
    	fi

    check_output_path
    echo -e "$NEW_LINE"
    echo -e "${BLUE}[*] Starting NFS share check against $IP_ADDRESS...${NC}"
    sleep 0.5
    echo -e "${BLUE}[*] Querying available NFS exports from $IP_ADDRESS...${NC}"
    sleep 0.5

    # Retrieve the list of NFS exports; skip the header line.
    exports=$(showmount -e "$IP_ADDRESS" 2>/dev/null | tail -n +2)
    if [ -z "$exports" ]; then
        echo -e "${RED}[-] No NFS shares available on $IP_ADDRESS. Exiting...${NC}"
        sleep 0.5
        return
    fi

    echo -e "${BLUE}[*] Found the following NFS shares on $IP_ADDRESS:${NC}"
    sleep 0.5
    echo -e "${YELLOW}'$exports'${NC}"
    sleep 0.5
    echo

    # Loop through each export; the share path is the first column.
    while IFS= read -r line; do
        NFS_SHARE=$(echo "$line" | awk '{print $1}')
        # Clean up the share name for a local mount point (remove leading slash)
        nfs_share_name=$(basename "$NFS_SHARE")
        MOUNT_POINT="/mnt/$nfs_share_name"

        echo -e "---------------------------------------------"
        echo -e "${BLUE}[*] Attempting to mount NFS share '$NFS_SHARE' from $IP_ADDRESS to $MOUNT_POINT...${NC}"

        # Create the mount point directory if it doesn't exist.
        sudo mkdir -p "$MOUNT_POINT"

        # Attempt to mount the NFS share.
        sudo mount -t nfs "$IP_ADDRESS:$NFS_SHARE" "$MOUNT_POINT"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[+] Mount successful: '$NFS_SHARE' is mounted at $MOUNT_POINT.${NC}"
            sleep 0.5
            echo -e "${YELLOW}[!] To unmount, run: sudo umount $MOUNT_POINT.${NC}"
            sleep 0.5
        else
            echo -e "${RED}[-] ERROR: Failed to mount NFS share '$NFS_SHARE'.${NC}"
            sleep 0.5
        fi
    done <<< "$exports"

    echo -e "${BLUE}[*] NFS check complete.${NC}"
    sleep 0.5
}

### PROMPT FOR SUDO PASSWORD

check_sudo_password

### ASCII + INFO

printf $NEW_LINE
printf " _     _   _                                      \n"
printf "| |__ | |_| |__         ___ _ __  _   _ _ __ ___  \n"
printf "| '_ \| __| '_ \ _____ / _ \ '_ \| | | | '_ \` _ \ \n"
printf "| | | | |_| |_) |_____|  __/ | | | |_| | | | | | |\n"
printf "|_| |_|\__|_.__/       \___|_| |_|\__,_|_| |_| |_| \n"

echo -e $NEW_LINE
echo -e "------------------------------------------------"
echo -e "by MP3vius - \"https://github.com/MP3vius\" - 2025"
echo -e "------------------------------------------------"
printf "$NEW_LINE%.0s" {1..10}

sleep 0.25

### START

echo -e "Welcome to this HTB initial recon script"
echo -e "Let's add the IP and domain name to your hosts file"
echo -e $NEW_LINE
echo -e "${YELLOW}[!] OR PRESS ENTER TO SKIP, BUT MAKE SURE TO MANUALLY ADD TO HOST FILE.${NC}"
echo -e "-----------------------------------------------------------------------"

check_ip_address

check_domain

# Only run append_to_hosts if both inputs were provided
if [[ -n "$IP_ADDRESS" && -n "$DOMAIN" ]]; then
    append_to_hosts
    if [ $? -ne 0 ]; then
        echo -e $NEW_LINE
        echo -e "${RED}[-] Failed to add $IP_ADDRESS and $DOMAIN to the hosts file!${NC}"
        sleep 0.5
        echo -e "${RED}[-] Please try again... maybe you misspelled the sudo password?${NC}"
        sleep 0.5
        echo -e $NEW_LINE
        exit 1
    else
        echo -e $NEW_LINE
        echo -e "${GREEN}[+] $IP_ADDRESS $DOMAIN successfully added to hosts file!${NC}"
        sleep 0.5
	echo -e $NEW_LINE
    fi
else
    echo -e "${YELLOW}[!] Skipping hosts file update — make sure it's already configured.${NC}"
fi

sleep 0.5

### PORT SCANNING

echo -e "What port scan tool would you like to use?"
echo -e "------------------------------------------"
echo -e "\t1) nmap"
echo -e "\t2) rustscan"
echo -e $NEW_LINE
echo -e "\t3) continue without port scan"

read -p "Select tool: " tool

case $tool in
	"1") quick_nmap ;;
	"2") quick_rustscan ;;
	"3") sleep 0.5 && echo -e $NEW_LINE && echo -e "${BLUE}[*] continue...${NC}" && echo -e $NEW_LINE ;;
esac

### RECON MENU

echo -e $NEW_LINE
echo -e "+-+-+-+-+-+ +-+-+-+-+"
echo -e "|R|E|C|O|N| |M|E|N|U|"
echo -e "+-+-+-+-+-+ +-+-+-+-+"
echo -e $NEW_LINE

while true
do
	echo -e $NEW_LINE
	echo -e "What would you like to do next?"
	echo -e "-------------------------------"
	echo -e "\t1) deeper port scanning"
	echo -e "\t2) directory fuzzing"
	echo -e "\t3) subdomain fuzzing"
	echo -e "\t4) DNS zone transfer check"
	echo -e "\t5) FTP check"
	echo -e "\t6) SMB check"
	echo -e "\t7) NFS check"
	echo -e $NEW_LINE
	echo -e "\t8) Exit.\n"

	read -p "Select option: " opt

	case $opt in
	"1") deep_nmap ;;
	"2") dir_fuzz ;;
	"3") sub_fuzz ;;
	"4") dns_check ;;
	"5") ftp_check ;;
	"6") smb_check ;;
	"7") nfs_check ;;
	"8") echo -e $NEW_LINE && echo -e "${YELLOW}Thanks for using this script, good luck!" && break ;;
	esac
done
