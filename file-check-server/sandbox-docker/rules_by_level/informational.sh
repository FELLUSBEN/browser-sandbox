#!/bin/bash

grep -E '\btype\s?=\s?PATH\b' /var/log/audit/audit.log | grep -Ff <( grep -E '\bname\s?=\s?(/sys/class/dmi/id/bios_version|/sys/class/dmi/id/product_name|/sys/class/dmi/id/chassis_vendor|/proc/scsi/scsi|/proc/ide/hd0/model|/proc/version|/etc/.*version|/etc/.*release|/etc/issue)' /var/log/audit/audit.log )
grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -Ff <( grep -E '\b(shutdown|reboot|halt|poweroff)' /var/log/audit/audit.log ; grep -Ff <( grep -E '\b(init|telinit)' /var/log/audit/audit.log ) | grep -Ff <( grep -E '\b(0|6)' /var/log/audit/audit.log ) )
grep -E '\bImage\s?=\s?.*/file\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?(.){200,}\b' ; grep -E '\bImage\s?=\s?.*/ls\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*-R.*\b' ; grep -E '\bImage\s?=\s?.*/find\b' /var/log/syslog ; grep -E '\bImage\s?=\s?.*/tree\b' /var/log/syslog
grep -E '\bImage\s?=\s?(.*/rm|.*/shred|.*/unlink)' /var/log/syslog
grep -E '\bImage\s?=\s?(.*/ps|.*/top)' /var/log/syslog
grep -E '\bImage\s?=\s?(.*/uname|.*/hostname|.*/uptime|.*/lspci|.*/dmidecode|.*/lscpu|.*/lsmod)' /var/log/syslog
grep -E '\bImage\s?=\s?(.*/firewall-cmd|.*/ufw|.*/iptables|.*/netstat|.*/ss|.*/ip|.*/ifconfig|.*/systemd-resolve|.*/route)' /var/log/syslog ; grep -E '\bCommandLine\s?=\s?.*/etc/resolv\.conf.*\b' /var/log/syslog
