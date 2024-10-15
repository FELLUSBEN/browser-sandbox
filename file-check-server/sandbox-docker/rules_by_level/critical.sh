#!/bin/bash
grep -E '\ba1\s?=\s?--cpu-priority.*\b' /var/log/audit/audit.log ; grep -E '\ba2\s?=\s?--cpu-priority.*\b' /var/log/audit/audit.log ; grep -E '\ba3\s?=\s?--cpu-priority.*\b' /var/log/audit/audit.log ; grep -E '\ba4\s?=\s?--cpu-priority.*\b' /var/log/audit/audit.log ; grep -E '\ba5\s?=\s?--cpu-priority.*\b' /var/log/audit/audit.log ; grep -E '\ba6\s?=\s?--cpu-priority.*\b' /var/log/audit/audit.log ; grep -E '\ba7\s?=\s?--cpu-priority.*\b' /var/log/audit/audit.log
grep -E '\btype\s?=\s?SYSCALL\b' /var/log/audit/audit.log | grep -E '\bsyscall\s?=\s?execve\b' | grep -E '\bkey\s?=\s?detect_execve_www\b'
grep -E '\bUSER\s?=\s?(#-.*|#.*4294967295)' /var/log/auth.log
grep -E '\bImage\s?=\s?.*/bin/bash\b' /var/log/syslog | grep -v -Ff <( grep -E '\bDestinationIp\s?=\s?(127\.0\.0\.1|0\.0\.0\.0)' /var/log/syslog )
