# Linux-Audit-Tool_V2.0

# 🛡️ Linux Security Audit Tool

A comprehensive Bash-based Linux Security Auditing Tool designed to analyze system security, network configuration, firewall rules, running services, and open ports, and generate a detailed security report in a single execution.

This project is ideal for students, system administrators, cybersecurity learners, and Linux enthusiasts who want an automated way to assess Linux security posture.

# 📌 Features
## 🔐 System Security Audit

User account and password policy analysis

Empty password and UID 0 account detection

SSH configuration and root login checks

File system permission analysis

World-writable, SUID & SGID file detection

Kernel security parameters (ASLR, core dumps, sysctl)

Logging and auditing status (auditd)

Cron job inspection

SELinux & AppArmor status

## 🌐 Network Security Audit

Network interface and IP configuration

Active connections (TCP & UDP)

Firewall status (iptables, UFW, firewalld)

DNS and routing table analysis

ARP table inspection

Network statistics and traffic summary

## 🔍 Port Scanning & Service Analysis

Nmap-based port scanning (TCP & UDP)

Service and version detection

Process-to-port mapping

Fallback scanning if nmap is unavailable

## 📄 Reporting

Automatically generates a timestamped audit report

Clearly formatted sections with timestamps

Security findings and recommendations summary

Progress indicator and colored terminal output

## 🧰 Requirements

Linux OS (Debian, Ubuntu, RHEL, CentOS, Arch, etc.)

Bash shell

Recommended tools:

sudo

ip, ss, netstat

lsof

nmap (optional but recommended)

auditd (for audit checks)

⚠️ Root privileges are strongly recommended for full audit coverage.

## 🚀 Installation

Clone the repository:

git clone https://github.com/MokshSharma2006/Linux-Audit-Tool.git
cd Linux-Audit-Tool


Make the script executable:

chmod +x linux_audit.sh

## ▶️ Usage
Run normally
./linux_audit.sh

Run with root privileges (recommended)
sudo ./linux_audit.sh

Show help menu
./linux_audit.sh --help

Verbose mode
./linux_audit.sh --verbose

Quiet mode
./linux_audit.sh --quiet

## 📂 Output

Audit reports are saved automatically with timestamps:

Linux_security_audit_YYYYMMDD_HHMMSS.txt


The report includes:

System details

Audit sections

Detected security risks

Security recommendations

Audit duration and summary

## 📊 Sample Audit Sections
1. SYSTEM SECURITY AUDIT
2. NETWORK SECURITY AUDIT
3. PORT SCANNING ANALYSIS
4. SECURITY SUMMARY & RECOMMENDATIONS

## ⚠️ Limitations

Some checks require root access

Nmap-based scans may be limited without sudo

Script is designed for local host auditing only

Large filesystems may increase execution time

## 🎯 Use Cases

Linux security assessment

Academic and cybersecurity projects

System hardening verification

Pre-deployment security checks

Learning Linux internals and auditing concepts

## 👨‍💻 Author

Moksh Sharma
Version: 2.0

🔗 GitHub: https://github.com/MokshSharma2006

## 📜 License

This project is licensed under the MIT License.
You are free to use, modify, and distribute it with proper attribution.

## ⭐ Future Enhancements (Planned)

CVE vulnerability lookup

HTML/PDF report export

Email alerts for critical findings

Remote host auditing

Docker & container security checks

## ⭐ Support

If you find this project helpful:

⭐ Star the repository

🐛 Report issues

🔧 Submit pull requests
