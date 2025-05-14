# HTB Recon Script

## Version 1.0.1

A modular, interactive Bash automation tool for efficient initial reconnaissance of Hack The Box (HTB) machines. It supports both quick and deep scanning, directory and subdomain fuzzing, DNS zone transfer checks, FTP/Samba enumeration with anonymous access checks, and recursive file downloads.

## ⚙️ Requirements

Make sure the following tools are installed on your Kali Linux system:

- `nmap`
- `rustscan`
- `ffuf`
- `jq`
- `dig`
- `ftp`
- `lftp`
- `enum4linux`
- `smbclient`
- `smbget`
- `showmount`
- `mount`

Install missing tools via apt or cargo:

```bash
sudo apt update
sudo apt install nmap ffuf jq dnsutils ftp lftp enum4linux smbclient smbget nfs-common -y
cargo install rustscan
```

## 🔧 Features

- Quick Scans: Fast full-port discovery using Nmap or Rustscan.

- Deep Scans: Thorough Nmap service enumeration based on quickscan output.

- Directory Fuzzing: Fuzz web directories using FFUF.

- Subdomain Fuzzing: Bruteforce virtual host subdomains and auto-add to /etc/hosts.

- DNS Zone Transfer: AXFR query support using dig.

- FTP Enumeration: Anonymous login checks and auto-download via lftp.

- SMB Enumeration: Basic share listing and user/group info via enum4linux.

- SMB Enumeration: Null session share access and recursive download with smbclient and smbget.

- NFS Enumeration: Checking for mountable shares and auto mounting for the user.

## 🚀 Usage

```bash
chmod +x htb-recon.sh
./htb-recon.sh
```
When prompted, provide:

- Target IP address

- Domain (e.g., example.htb)

- Output directory path

- Wordlists for fuzzing (directory/subdomain)

- Port numbers where needed

- The script creates structured output directories for each module (quickscan, deepscan, ftp, smb, dir, sub, dns) inside the path you provide.

## 📝 Notes

- Uses sudo for modifying /etc/hosts. Your password will be prompted if required.

- Automatically filters ports from quick scans for focused deep scans.

- Validates tool presence before executing each module.

- Interactive and modular — ideal for CTF and HTB workflows.

## 📂 Output Structure

```bash
/home/kali/htb/boxes/obscure/
├── nmap/
│   ├── quickscan.txt
│   ├── ports.txt
│   ├── deepscan.gnmap
│   ├── deepscan.nmap
│   └── deepscan.xml
├── dir/
│   └── results.txt
├── sub/
│   └── results.txt
├── ftp/
│   ├── ftp_listing.txt
│   └── downloads/
├── smb/
│   ├── shares.txt
│   ├── enum4linux/
│   │   └── results.txt
│   └── downloads/
└── dns/
    └── results.txt
```

Happy hunting 🕵
