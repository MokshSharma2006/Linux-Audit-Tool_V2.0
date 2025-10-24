#!/bin/bash

#Linux Audit Tool
# Version: 2.0
# Author: Moksh Sharma

echo " _     _                         _             _ _ _      _____           _"
echo "| |   (_)_ __  _   ___  __      / \  _   _  __| (_) |_   |_   _|__   ___ | |"
echo "| |   | | '_ \| | | \ \/ /____ / _ \| | | |/ _\` | | __|____| |/ _ \ / _ \| |"
echo "| |___| | | | | |_| |>  <_____/ ___ \ |_| | (_| | | ||_____| | (_) | (_) | |"
echo "|_____|_|_| |_|\__,_/_/\_\   /_/   \_\__,_|\__,_|_|\__|    |_|\___/ \___/|_|"

echo ""
echo ""
                           
echo "================================================================"
echo "            L I N U X   A U D I T                               "
echo "================================================================"
echo " Version : 2.0"
echo " Author  : Moksh Sharma"
echo " Project : Linux-Audit-Tool"
echo " GitHub  : https://github.com/MokshSharma2006"
echo "================================================================"


# Output file
OUTPUT_FILE="Linux_security_audit_$(date +%Y%m%d_%H%M%S).txt"
TEMP_FILE="/tmp/security_audit_temp.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Global variables
SCRIPT_START_TIME=$(date +%s)
AUDIT_SECTIONS=()

# Banner
banner() {
    echo -e "${CYAN}"
    echo "  ╔═══════════════════════════════════════════════════════════╗"
    echo "  ║                LINUX SECURITY AUDIT TOOL                  ║"
    echo "  ║                    Enhanced Version                       ║"
    echo "  ╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${YELLOW}Date: $(date)${NC}"
    echo -e "${YELLOW}Hostname: $(hostname)${NC}"
    echo -e "${BLUE}=========================================${NC}"
    echo ""
}

# Initialize output file with header
initialize_output() {
    cat > "$OUTPUT_FILE" << EOF
╔══════════════════════════════════════════════════════════════════════════════╗
║                          LINUX SECURITY AUDIT REPORT                         ║
╚══════════════════════════════════════════════════════════════════════════════╝

Generated on: $(date)
Hostname: $(hostname)
Kernel Version: $(uname -r)
Distribution: $(lsb_release -d 2>/dev/null | cut -f2- || echo "Unknown")
IP Address: $(hostname -I 2>/dev/null | awk '{print $1}' || echo "Unknown")
User: $(whoami)
Working Directory: $(pwd)

╔══════════════════════════════════════════════════════════════════════════════╗
║                                TABLE OF CONTENTS                             ║
╚══════════════════════════════════════════════════════════════════════════════╝

1. SYSTEM SECURITY AUDIT
   - User Account Analysis
   - SSH Configuration Review
   - File System Permissions
   - Kernel and System Configuration
   - Logging and Auditing
   - Package Management
   - Scheduled Tasks (Cron Jobs)
   - Security Modules (SELinux/AppArmor)

2. NETWORK SECURITY AUDIT
   - Network Interface Analysis
   - Firewall Configuration
   - Active Network Connections
   - DNS Configuration
   - Routing Information
   - Network Statistics

3. PORT SCANNING ANALYSIS
   - Open Port Detection
   - Service Identification
   - Listening Services
   - UDP Port Analysis

4. SECURITY SUMMARY & RECOMMENDATIONS

══════════════════════════════════════════════════════════════════════════════

EOF
}

# Function to check if command exists
check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}[-] Error: $1 is not installed${NC}"
        return 1
    fi
    return 0
}

# Function to check and append results with better formatting
check_append() {
    local section_num=$1
    local title=$2
    local command=$3
    local description=$4
    
    echo -e "${YELLOW}[*] $section_num - Checking: $title${NC}"
    
    cat >> "$OUTPUT_FILE" << EOF

┌─────────────────────────────────────────────────────────────────────────────┐
│ $section_num - $title                                                       │
└─────────────────────────────────────────────────────────────────────────────┘
Description: $description
Timestamp: $(date)

EOF
    
    # Execute command and capture both stdout and stderr
    if eval "$command" >> "$OUTPUT_FILE" 2>&1; then
        echo "Status: SUCCESS" >> "$OUTPUT_FILE"
    else
        echo "Status: FAILED or INCOMPLETE" >> "$OUTPUT_FILE"
    fi
    
    echo "" >> "$OUTPUT_FILE"
    echo "─────────────────────────────────────────────────────────────────────────────" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
}

# System Security Audit Functions
system_security_audit() {
    echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                           1. SYSTEM SECURITY AUDIT                          ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}\n"
    
    echo "╔══════════════════════════════════════════════════════════════════════════════╗" >> "$OUTPUT_FILE"
    echo "║                           1. SYSTEM SECURITY AUDIT                           ║" >> "$OUTPUT_FILE"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝" >> "$OUTPUT_FILE"

    # User Account Checks
    check_append "1.1" "User Accounts" "cat /etc/passwd" "Complete list of all user accounts in the system"
    check_append "1.2" "Password Hashes" "sudo cat /etc/shadow 2>/dev/null || echo 'Access denied - requires root privileges'" "Password hashes and account status"
    check_append "1.3" "Empty Password Accounts" "sudo awk -F: '(\$2 == \"\") {print \$1 \" - CRITICAL: Empty Password!\"}' /etc/shadow 2>/dev/null || echo 'Requires root privileges'" "Accounts with empty passwords (SECURITY RISK)"
    check_append "1.4" "UID 0 Accounts" "awk -F: '(\$3 == 0) {print \$1 \" - UID 0 (root equivalent)\"}' /etc/passwd" "Accounts with UID 0 (root privileges)"
    check_append "1.5" "Last Logins" "lastlog | head -20" "Recent login information for users"
    check_append "1.6" "Failed Login Attempts" "sudo lastb 2>/dev/null | head -20 || echo 'No failed login records or access denied'" "Recent failed login attempts"
    check_append "1.7" "Password Aging Policy" "sudo chage -l root 2>/dev/null && echo && sudo grep -E '^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE' /etc/login.defs || echo 'Access denied or file not found'" "Password aging configuration"

    # SSH Configuration
    check_append "1.8" "SSH Configuration" "sudo cat /etc/ssh/sshd_config 2>/dev/null | grep -v '^#' | grep -v '^$' || echo 'SSH config not accessible'" "SSH server configuration (non-default settings)"
    check_append "1.9" "SSH Root Login Status" "sudo grep -i 'PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null || echo 'SSH config not accessible'" "SSH root login permission status"
    check_append "1.10" "SSH Protocol Version" "sudo grep -i 'Protocol' /etc/ssh/sshd_config 2>/dev/null || echo 'Protocol not explicitly set (likely SSH-2)'" "SSH protocol version configuration"

    # File System and Permissions
    check_append "1.11" "World Writable Files" "sudo find / -xdev -type f -perm -0002 -exec ls -l {} + 2>/dev/null | head -20 || echo 'No world writable files found or access denied'" "World writable files (SECURITY RISK)"
    check_append "1.12" "SUID/SGID Files" "sudo find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f -exec ls -l {} + 2>/dev/null | head -20" "SUID/SGID files that can execute with elevated privileges"
    check_append "1.13" "Unowned Files" "sudo find / -xdev \\( -nouser -o -nogroup \\) -exec ls -l {} + 2>/dev/null | head -10 || echo 'No unowned files found'" "Files with no owner or group"
    check_append "1.14" "Critical Directory Permissions" "ls -ld /tmp /var /etc /root 2>/dev/null" "Permissions on critical system directories"
    check_append "1.15" "Critical File Permissions" "ls -l /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/ssh/sshd_config 2>/dev/null" "Permissions on critical system files"

    # Kernel and System Configuration
    check_append "1.16" "Core Dump Configuration" "sudo sysctl fs.suid_dumpable kernel.core_pattern 2>/dev/null || echo 'Access denied'" "Core dump security settings"
    check_append "1.17" "ASLR Status" "cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo 'Not accessible'" "Address Space Layout Randomization status"
    check_append "1.18" "Kernel Security Parameters" "sudo sysctl net.ipv4.ip_forward net.ipv4.conf.all.send_redirects net.ipv4.conf.all.accept_redirects kernel.dmesg_restrict 2>/dev/null || echo 'Some parameters not accessible'" "Key kernel security parameters"

    # Logging and Auditing
    check_append "1.19" "Audit Daemon Status" "sudo systemctl status auditd 2>/dev/null || echo 'Auditd not available or accessible'" "Audit daemon status and configuration"
    check_append "1.20" "Audit Rules" "sudo auditctl -l 2>/dev/null || echo 'No audit rules or access denied'" "Current audit rules configuration"
    check_append "1.21" "System Log Files" "sudo ls -la /var/log/ 2>/dev/null | head -15" "System log files and their permissions"
    check_append "1.22" "Recent Authentication Logs" "sudo tail -20 /var/log/auth.log 2>/dev/null || sudo tail -20 /var/log/secure 2>/dev/null || echo 'Auth logs not accessible'" "Recent authentication attempts"

    # Package and Update Information
    check_append "1.23" "Installed Packages Count" "(dpkg -l 2>/dev/null | wc -l) || (rpm -qa 2>/dev/null | wc -l) || echo 'Package manager not detected'" "Total number of installed packages"
    check_append "1.24" "Security Updates Available" "sudo apt list --upgradable 2>/dev/null | grep -i security | head -10 || sudo yum list updates 2>/dev/null | grep -i security | head -10 || echo 'No security updates found or package manager not detected'" "Available security updates"

    # Cron Jobs
    check_append "1.25" "System Cron Jobs" "sudo ls -la /etc/cron* /var/spool/cron* 2>/dev/null || echo 'Cron directories not accessible'" "System cron job directories"
    check_append "1.26" "Active Cron Jobs" "sudo cat /etc/crontab 2>/dev/null && for user in \$(cut -f1 -d: /etc/passwd); do echo \"--- Cron for \$user ---\"; sudo crontab -u \$user -l 2>/dev/null || echo \"No crontab for \$user\"; done" "Contents of active cron jobs"

    # SELinux/AppArmor
    check_append "1.27" "SELinux Status" "sudo sestatus 2>/dev/null || echo 'SELinux not installed or not accessible'" "SELinux security status"
    check_append "1.28" "AppArmor Status" "sudo aa-status 2>/dev/null || echo 'AppArmor not installed or not accessible'" "AppArmor security status"
}

# Network Security Audit Functions
network_security_audit() {
    echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                          2. NETWORK SECURITY AUDIT                          ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}\n"
    
    echo "╔══════════════════════════════════════════════════════════════════════════════╗" >> "$OUTPUT_FILE"
    echo "║                          2. NETWORK SECURITY AUDIT                           ║" >> "$OUTPUT_FILE"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝" >> "$OUTPUT_FILE"

    # Network Interfaces
    check_append "2.1" "Network Interfaces" "ip -br addr show && echo && ip link show" "Network interface configuration and status"
    check_append "2.2" "Active Network Interfaces" "ip -br addr show | grep -v 'DOWN'" "Currently active network interfaces"

    # Network Services and Ports
    check_append "2.3" "Listening TCP Services" "sudo ss -tulnp 2>/dev/null | grep LISTEN || netstat -tulnp 2>/dev/null | grep LISTEN || echo 'No tools available for port scanning'" "TCP services listening on network ports"
    check_append "2.4" "Listening UDP Services" "sudo ss -ulnp 2>/dev/null || netstat -ulnp 2>/dev/null || echo 'No tools available for UDP port scanning'" "UDP services listening on network ports"
    check_append "2.5" "All Network Connections" "sudo ss -atnp 2>/dev/null || netstat -atnp 2>/dev/null || echo 'Network connection tools not available'" "All active network connections"

    # Firewall Configuration
    check_append "2.6" "IPTables Firewall Rules" "sudo iptables -L -n -v --line-numbers 2>/dev/null || echo 'IPTables not accessible'" "Current IPTables firewall configuration"
    check_append "2.7" "UFW Firewall Status" "sudo ufw status verbose 2>/dev/null || echo 'UFW not installed or accessible'" "Uncomplicated Firewall (UFW) status"
    check_append "2.8" "Firewalld Status" "sudo firewall-cmd --state 2>/dev/null && sudo firewall-cmd --get-active-zones 2>/dev/null || echo 'Firewalld not available'" "Firewalld configuration and zones"

    # Network Configuration
    check_append "2.9" "DNS Configuration" "cat /etc/resolv.conf 2>/dev/null && echo && cat /etc/hosts | head -10" "DNS resolver and hosts file configuration"
    check_append "2.10" "Network Routing Table" "ip route show && echo && route -n 2>/dev/null" "System routing table information"
    check_append "2.11" "ARP Table" "ip neigh show || arp -a 2>/dev/null || echo 'ARP tools not available'" "ARP table entries"

    # Network Statistics and Performance
    check_append "2.12" "Network Interface Statistics" "ip -s link" "Network interface traffic statistics"
    check_append "2.13" "Network Protocol Statistics" "netstat -s 2>/dev/null | head -50 || ss -s 2>/dev/null || echo 'Network statistics not available'" "Network protocol statistics summary"
}

# Port Scanning Analysis Functions
port_scanning_audit() {
    echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                         3. PORT SCANNING ANALYSIS                           ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}\n"
    
    echo "╔══════════════════════════════════════════════════════════════════════════════╗" >> "$OUTPUT_FILE"
    echo "║                         3. PORT SCANNING ANALYSIS                            ║" >> "$OUTPUT_FILE"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝" >> "$OUTPUT_FILE"

    # Port Scanning
    if check_command "nmap"; then
        check_append "3.1" "Quick Port Scan (Top 1000)" "nmap -sS --top-ports 1000 localhost 2>/dev/null || nmap --top-ports 1000 localhost 2>/dev/null" "Quick scan of most common ports using nmap"
        check_append "3.2" "Service Version Detection" "nmap -sV -sC --top-ports 100 localhost 2>/dev/null || echo 'Service detection requires elevated privileges'" "Service version and default script scanning"
        check_append "3.3" "UDP Port Scan" "sudo nmap -sU --top-ports 100 localhost 2>/dev/null || echo 'UDP scan requires root privileges'" "UDP port scanning (top 100 ports)"
    else
        check_append "3.1" "Fallback Port Scan" "
            echo 'NMAP not available - using fallback method'
            common_ports=(21 22 23 25 53 80 110 135 139 143 443 445 993 995 1433 1723 3306 3389 5900 8080)
            for port in \"\${common_ports[@]}\"; do
                if timeout 2 bash -c \"echo >/dev/tcp/localhost/\$port\" 2>/dev/null; then
                    echo \"Port \$port: OPEN\"
                fi
            done
        " "Fallback port scanning using bash TCP connections"
    fi

    # Currently listening services
    check_append "3.4" "Currently Listening Services" "sudo netstat -tlnp 2>/dev/null | grep LISTEN || sudo ss -tlnp 2>/dev/null | grep LISTEN || echo 'Unable to determine listening services'" "Services currently listening for connections"
    
    # Process and port correlation
    check_append "3.5" "Process-Port Mapping" "sudo lsof -i -P -n 2>/dev/null | grep LISTEN || echo 'lsof not available or requires privileges'" "Mapping of processes to listening ports"
}

# Security Summary and Recommendations
generate_security_summary() {
    echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                      4. SECURITY SUMMARY & RECOMMENDATIONS                     ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}\n"
    
    cat >> "$OUTPUT_FILE" << EOF
╔══════════════════════════════════════════════════════════════════════════════╗
║                      4. SECURITY SUMMARY & RECOMMENDATIONS                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

CRITICAL SECURITY FINDINGS:
══════════════════════════

EOF

    # Extract potential security issues
    echo -e "${YELLOW}[*] Analyzing audit results for security issues...${NC}"
    
    # Look for critical findings in the audit file
    echo "Searching for potential security issues:" >> "$OUTPUT_FILE"
    grep -i -E 'empty password|permitrootlogin yes|world writable|suid.*root|uid 0.*:|password.*no|disabled.*audit|critical|error' "$OUTPUT_FILE" | grep -v "Description:" | head -20 >> "$OUTPUT_FILE" 2>/dev/null
    
    cat >> "$OUTPUT_FILE" << EOF

SECURITY RECOMMENDATIONS:
═══════════════════════════

1. USER ACCOUNT SECURITY:
   - Ensure all accounts have strong passwords
   - Remove or disable unused accounts
   - Implement account lockout policies
   - Monitor failed login attempts

2. SSH SECURITY:
   - Disable root SSH login (PermitRootLogin no)
   - Use SSH key authentication
   - Change default SSH port
   - Implement fail2ban for brute force protection

3. FILE SYSTEM SECURITY:
   - Review world-writable files
   - Audit SUID/SGID files
   - Secure critical file permissions
   - Regular filesystem integrity checks

4. NETWORK SECURITY:
   - Close unnecessary ports
   - Configure proper firewall rules
   - Monitor network connections
   - Implement network segmentation

5. SYSTEM MONITORING:
   - Enable linux logging
   - Configure log rotation
   - Implement file integrity monitoring
   - Set up security alerting

6. UPDATE MANAGEMENT:
   - Keep system updated with security patches
   - Configure automatic security updates
   - Monitor security advisories
   - Test updates in staging environment

AUDIT COMPLETION SUMMARY:
═══════════════════════════
Audit completed on: $(date)
Total scan duration: $(($(date +%s) - SCRIPT_START_TIME)) seconds
Output file: $OUTPUT_FILE
System examined: $(hostname) ($(uname -r))

NOTE: This audit provides a linux security assessment. Regular audits
      are recommended to maintain security posture. Review all findings and
      implement appropriate security measures based on your environment.

╔══════════════════════════════════════════════════════════════════════════════╗
║                              END OF REPORT                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
}

# Progress indicator
show_progress() {
    local current=$1
    local total=$2
    local description=$3
    local percent=$((current * 100 / total))
    local completed=$((percent / 5))
    local remaining=$((20 - completed))
    
    printf "\r${CYAN}Progress: ["
    printf "%*s" $completed | tr ' ' '█'
    printf "%*s" $remaining | tr ' ' '░'
    printf "] %d%% - %s${NC}" $percent "$description"
    
    if [ $current -eq $total ]; then
        echo ""
    fi
}

# Main execution function
main() {
    local total_sections=4
    local current_section=0
    
    # Check for root privileges
    if [[ $EUID -eq 0 ]]; then
        echo -e "${GREEN}[+] Running with root privileges - full audit available${NC}"
    else
        echo -e "${YELLOW}[!] Running without root privileges - some checks will be limited${NC}"
        echo -e "${YELLOW}[!] For linux audit, consider running with sudo${NC}"
    fi
    
    echo -e "${BLUE}[*] Initializing Linux security audit...${NC}"
    initialize_output
    
    # System Security Audit
    current_section=$((current_section + 1))
    show_progress $current_section $total_sections "System Security Audit"
    system_security_audit
    
    # Network Security Audit  
    current_section=$((current_section + 1))
    show_progress $current_section $total_sections "Network Security Audit"
    network_security_audit
    
    # Port Scanning Analysis
    current_section=$((current_section + 1))
    show_progress $current_section $total_sections "Port Scanning Analysis"
    port_scanning_audit
    
    # Security Summary
    current_section=$((current_section + 1))
    show_progress $current_section $total_sections "Generating Security Summary"
    generate_security_summary
    
    echo -e "\n${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    AUDIT COMPLETED SUCCESSFULLY                ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo -e "${GREEN}[+] Linux security audit completed!${NC}"
    echo -e "${GREEN}[+] Results saved to: ${YELLOW}$OUTPUT_FILE${NC}"
    echo -e "${GREEN}[+] Total audit time: ${YELLOW}$(($(date +%s) - SCRIPT_START_TIME)) seconds${NC}"
    
    # Display file size and summary
    if [ -f "$OUTPUT_FILE" ]; then
        local file_size=$(du -h "$OUTPUT_FILE" | cut -f1)
        echo -e "${GREEN}[+] Report size: ${YELLOW}$file_size${NC}"
        echo -e "${CYAN}[*] Review the complete report for detailed security analysis${NC}"
    fi
}

# Help function
show_help() {
    echo -e "${CYAN} Linux Security Audit Tool${NC}"
    echo ""
    echo -e "${YELLOW}Usage: $0 [OPTIONS]${NC}"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -v, --verbose  Run with verbose output"
    echo "  -q, --quiet    Run quietly (minimal console output)"
    echo ""
    echo "Features:"
    echo "  • System Security Assessment"
    echo "  • Network Configuration Analysis"
    echo "  • Port Scanning and Service Detection"
    echo "  • Linux Security Reporting"
    echo ""
    echo "Output:"
    echo "  All results are automatically saved to a timestamped file:"
    echo "  linux_security_audit_YYYYMMDD_HHMMSS.txt"
    echo ""
    echo "Requirements:"
    echo "  • Linux system (any distribution)"
    echo "  • Bash shell"
    echo "  • Root privileges recommended for complete audit"
}

# Parse command line arguments
case "${1:-}" in
    -h|--help)
        banner
        show_help
        exit 0
        ;;
    -v|--verbose)
        banner
        echo -e "${GREEN}[+] Running in verbose mode${NC}"
        main
        ;;
    -q|--quiet)
        main > /dev/null 2>&1
        echo "Audit completed. Results saved to: $OUTPUT_FILE"
        ;;
    *)
        banner
        main
        ;;
esac

exit 0