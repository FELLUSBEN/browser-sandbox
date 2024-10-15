#!/bin/bash

grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?arecord\b' | grep -E '\ba1\s?=\s?-vv\b' | grep -E '\ba2\s?=\s?-fdat\b'
grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?getcap\b' | grep -E '\ba1\s?=\s?-r\b' | grep -E '\ba2\s?=\s?/\b'
grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?xclip\b' | grep -Ff <( grep -E '\ba1\s?=\s?(-selection|-sel)' /var/log/audit/audit.log ) | grep -Ff <( grep -E '\ba2\s?=\s?(clipboard|clip)' /var/log/audit/audit.log ) | grep -E '\ba3\s?=\s?-o\b'
grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?xclip\b' | grep -Ff <( grep -E '\ba1\s?=\s?(-selection|-sel)' /var/log/audit/audit.log ) | grep -Ff <( grep -E '\ba2\s?=\s?(clipboard|clip)' /var/log/audit/audit.log ) | grep -E '\ba3\s?=\s?-t\b' | grep -E '\ba4\s?=\s?image/.*\b' | grep -E '\ba5\s?=\s?-o\b'
grep -E '\btype\s?=\s?execve\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?zip\b' ; grep -E '\btype\s?=\s?execve\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?gzip\b' | grep -E '\ba1\s?=\s?-k\b' ; grep -E '\btype\s?=\s?execve\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?tar\b' | grep -E '\ba1\s?=\s?.*-c.*\b'
grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?.*dd.*\b' | grep -Ff <( grep -E '\ba1\s?=\s?(.*if=/dev/null.*|.*if=/dev/zero.*)' /var/log/audit/audit.log )
grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -Ff <( grep -E '\ba0\s?=\s?(.*chmod.*|.*chown.*)' /var/log/audit/audit.log )
grep -E '\btype\s?=\s?PATH\b' /var/log/audit/audit.log | grep -E '\bname\s?=\s?.*/\..*\b' | grep -v -Ff <( grep -E '\bname\s?=\s?(.*/\.cache/.*|.*/\.config/.*|.*/\.pyenv/.*|.*/\.rustup/toolchains.*)' /var/log/audit/audit.log )
grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -Ff <( grep -E '\ba0\s?=\s?(mkdir|touch|vim|nano|vi)' /var/log/audit/audit.log ) | grep -Ff <( grep -E '\ba1\s?=\s?.*/\..*\b' /var/log/audit/audit.log ; grep -E '\ba1\s?=\s?\..*\b' /var/log/audit/audit.log ; grep -E '\ba2\s?=\s?.*/\..*\b' /var/log/audit/audit.log ; grep -E '\ba2\s?=\s?\..*\b' /var/log/audit/audit.log )
grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?cat\b' | grep -Ff <( grep -E '\ba1\s?=\s?(.*\.jpg|.*\.png)' /var/log/audit/audit.log ) | grep -E '\ba2\s?=\s?.*\.zip\b'
grep -E '\btype\s?=\s?SYSCALL\b' /var/log/audit/audit.log | grep -Ff <( grep -E '\bexe\s?=\s?(.*/telnet|.*/nmap|.*/netcat|.*/nc|.*/ncat|.*/nc\.openbsd)' /var/log/audit/audit.log ) | grep -E '\bkey\s?=\s?network_connect_4\b'
grep -E '\btype\s?=\s?execve\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?tcpdump\b' | grep -E '\ba1\s?=\s?-c\b' | grep -E '\ba3\s?=\s?.*-i.*\b' ; grep -E '\btype\s?=\s?execve\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?tshark\b' | grep -E '\ba1\s?=\s?-c\b' | grep -E '\ba3\s?=\s?-i\b'
grep -E '\btype\s?=\s?PATH\b' /var/log/audit/audit.log | grep -Ff <( grep -E '\bname\s?=\s?(/etc/pam\.d/common-password|/etc/security/pwquality\.conf|/etc/pam\.d/system-auth|/etc/login\.defs)' /var/log/audit/audit.log ) ; grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?chage\b' | grep -Ff <( grep -E '\ba1\s?=\s?(--list|-l)' /var/log/audit/audit.log ) ; grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?passwd\b' | grep -Ff <( grep -E '\ba1\s?=\s?(-S|--status)' /var/log/audit/audit.log )
grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?.*systemctl.*\b' | grep -Ff <( grep -E '\ba1\s?=\s?(.*daemon-reload.*|.*start.*)' /var/log/audit/audit.log )
grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?import\b' | grep -Ff <( grep -E '\ba1\s?=\s?-window\b' /var/log/audit/audit.log | grep -E '\ba2\s?=\s?root\b' | grep -Ff <( grep -E '\ba3\s?=\s?(.*\.png|.*\.jpg|.*\.jpeg)' /var/log/audit/audit.log ) ; grep -E '\ba1\s?=\s?(.*\.png|.*\.jpg|.*\.jpeg)' /var/log/audit/audit.log )
grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?xwd\b' | grep -Ff <( grep -E '\ba1\s?=\s?-root\b' /var/log/audit/audit.log | grep -E '\ba2\s?=\s?-out\b' | grep -E '\ba3\s?=\s?.*\.xwd\b' ; grep -E '\ba1\s?=\s?-out\b' /var/log/audit/audit.log | grep -E '\ba2\s?=\s?.*\.xwd\b' )
grep -E '\btype\s?=\s?SYSCALL\b' /var/log/audit/audit.log | grep -E '\bcomm\s?=\s?split\b'
grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?steghide\b' | grep -E '\ba1\s?=\s?embed\b' | grep -Ff <( grep -E '\ba2\s?=\s?(-cf|-ef)' /var/log/audit/audit.log ) | grep -Ff <( grep -E '\ba4\s?=\s?(-cf|-ef)' /var/log/audit/audit.log )
grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?steghide\b' | grep -E '\ba1\s?=\s?extract\b' | grep -E '\ba2\s?=\s?-sf\b' | grep -Ff <( grep -E '\ba3\s?=\s?(.*\.jpg|.*\.png)' /var/log/audit/audit.log )
grep -E '\btype\s?=\s?PATH\b' /var/log/audit/audit.log | grep -Ff <( grep -E '\bname\s?=\s?(/etc/lsb-release|/etc/redhat-release|/etc/issue)' /var/log/audit/audit.log ) ; grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -Ff <( grep -E '\ba0\s?=\s?(uname|uptime|lsmod|hostname|env)' /var/log/audit/audit.log ) ; grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?grep\b' | grep -Ff <( grep -E '\ba1\s?=\s?(.*vbox.*|.*vm.*|.*xen.*|.*virtio.*|.*hv.*)' /var/log/audit/audit.log ) ; grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?kmod\b' | grep -E '\ba1\s?=\s?list\b'
grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?unzip\b' | grep -Ff <( grep -E '\ba1\s?=\s?(.*\.jpg|.*\.png)' /var/log/audit/audit.log )
grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -Ff <( grep -E '\ba0\s?=\s?(users|w|who)' /var/log/audit/audit.log )
grep -Ff <( grep -E '\b(scp |rsync |sftp )' /var/log/syslog ) | grep -Ff <( grep -E '\b(@|:)' /var/log/syslog )
grep '\becho ".*" > .* && chmod \+x .*\b' /var/log/syslog | grep '\bmv .* ".* "\b'
grep -E '\bTargetFilename\s?=\s?.*/etc/profile\.d/.*\b' /var/log/syslog | grep -Ff <( grep -E '\bTargetFilename\s?=\s?(.*\.csh|.*\.sh)' /var/log/syslog )
grep -E '\bImage\s?=\s?(.*/at|.*/atd)' /var/log/syslog
grep -E '\bImage\s?=\s?.*/base64\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*-d.*\b'
grep -E '\bImage\s?=\s?.*/bash\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.* -i .*\b'
grep -E '\bImage\s?=\s?.*xclip.*\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*-sel.*\b' | grep -E '\bCommandLine\s?=\s?.*clip.*\b' | grep -E '\bCommandLine\s?=\s?.*-o.*\b'
grep -E '\bImage\s?=\s?.*/crontab\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.* -l.*\b'
grep -E '\bImage\s?=\s?.*/curl\b' /var/log/syslog
grep -Ff <( grep -E '\bImage\s?=\s?(/bin/dd|/usr/bin/dd)' /var/log/syslog ) | grep -E '\bCommandLine\s?=\s?.*of=.*\b' | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.*if=/dev/zero.*|.*if=/dev/null.*)' /var/log/syslog )
grep -E '\bImage\s?=\s?.*/doas\b' /var/log/syslog
grep -E '\bImage\s?=\s?.*/grep\b' /var/log/syslog | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.*aarch64|.*arm|.*i386|.*i686|.*mips|.*x86_64)' /var/log/syslog )
grep -E '\bImage\s?=\s?(.*/update-ca-certificates|.*/update-ca-trust)' /var/log/syslog
grep -E '\bImage\s?=\s?(.*/kill|.*/pkill|.*/killall)' /var/log/syslog
grep -E '\bImage\s?=\s?.*/lastlog\b' /var/log/syslog ; grep -E '\bCommandLine\s?=\s?.*''x:0:''.*\b' /var/log/syslog ; grep -Ff <( grep -E '\bImage\s?=\s?(.*/cat|.*/head|.*/tail|.*/more)' /var/log/syslog ) | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.*/etc/passwd.*|.*/etc/shadow.*|.*/etc/sudoers.*)' /var/log/syslog ) ; grep -E '\bImage\s?=\s?.*/id\b' /var/log/syslog ; grep -E '\bImage\s?=\s?.*/lsof\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*-u.*\b'
grep -E '\bImage\s?=\s?.*/groups\b' /var/log/syslog ; grep -Ff <( grep -E '\bImage\s?=\s?(.*/cat|.*/head|.*/tail|.*/more)' /var/log/syslog ) | grep -E '\bCommandLine\s?=\s?.*/etc/group.*\b'
grep -E '\bImage\s?=\s?.*/mkfifo\b' /var/log/syslog
grep -E '\bCommandLine\s?=\s?(.*http_proxy=.*|.*https_proxy=.*)' /var/log/syslog
grep -E '\bParentImage\s?=\s?.*/TeamViewer_Service\b' /var/log/syslog | grep -E '\bImage\s?=\s?.*/TeamViewer_Desktop\b' | grep -E '\bCommandLine\s?=\s?.*/TeamViewer_Desktop --IPCport 5939 --Module 1\b'
grep -E '\bImage\s?=\s?.*/arp\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*-a.*\b' ; grep -E '\bImage\s?=\s?.*/ping\b' /var/log/syslog | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.* 10\..*|.* 192\.168\..*|.* 172\.16\..*|.* 172\.17\..*|.* 172\.18\..*|.* 172\.19\..*|.* 172\.20\..*|.* 172\.21\..*|.* 172\.22\..*|.* 172\.23\..*|.* 172\.24\..*|.* 172\.25\..*|.* 172\.26\..*|.* 172\.27\..*|.* 172\.28\..*|.* 172\.29\..*|.* 172\.30\..*|.* 172\.31\..*|.* 127\..*|.* 169\.254\..*)' /var/log/syslog )
grep -E '\bImage\s?=\s?.*/yum\b' /var/log/syslog | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.*erase.*|.*remove.*)' /var/log/syslog ) ; grep -Ff <( grep -E '\bImage\s?=\s?(.*/apt|.*/apt-get)' /var/log/syslog ) | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.*remove.*|.*purge.*)' /var/log/syslog ) ; grep -E '\bImage\s?=\s?.*/dpkg\b' /var/log/syslog | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.*--remove .*|.* -r .*)' /var/log/syslog ) ; grep -E '\bImage\s?=\s?.*/rpm\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.* -e .*\b'
grep -Ff <( grep -E '\bImage\s?=\s?(.*/grep|.*/egrep)' /var/log/syslog ) | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.*nessusd.*|.*td-agent.*|.*packetbeat.*|.*filebeat.*|.*auditbeat.*|.*osqueryd.*|.*cbagentd.*|.*falcond.*)' /var/log/syslog )
grep -E '\bCommandLine\s?=\s?.*chown root.*\b' /var/log/syslog | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.* chmod u\+s.*|.* chmod g\+s.*)' /var/log/syslog )
grep -Ff <( grep -E '\bImage\s?=\s?(.*awk|.*/cat|.*grep|.*/head|.*/less|.*/more|.*/nl|.*/tail)' /var/log/syslog ) | grep -Ff <( grep -E '\bCommandLine\s?=\s?.*/proc/2/.*\b' /var/log/syslog ; grep -E '\bCommandLine\s?=\s?.*/proc/.*\b' /var/log/syslog | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.*/cgroup|.*/sched)' /var/log/syslog ) )
grep -Ff <( grep -E '\bImage\s?=\s?(.*/cat|.*/dir|.*/find|.*/ls|.*/stat|.*/test|.*grep)' /var/log/syslog ) | grep -E '\bCommandLine\s?=\s?.*\.dockerenv\b'
grep -E '\bImage\s?=\s?.*/ls\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.* -.*i.*\b' | grep -E '\bCommandLine\s?=\s?.* -.*d.*\b' | grep -E '\bCommandLine\s?=\s?.* /\b'
grep -Ff <( grep -E '\bImage\s?=\s?(.*/nc|.*/ncat|.*/netcat|.*/socat)' /var/log/syslog ) | grep -v -Ff <( grep -E '\bCommandLine\s?=\s?(.* --listen .*|.* -l .*)' /var/log/syslog ) ; grep -E '\bImage\s?=\s?(.*/autorecon|.*/hping|.*/hping2|.*/hping3|.*/naabu|.*/nmap|.*/nping|.*/telnet|.*/zenmap)' /var/log/syslog
grep -Ff <( grep -E '\bImage\s?=\s?(.*/who|.*/w|.*/last|.*/lsof|.*/netstat)' /var/log/syslog ) | grep -v -Ff <( grep -E '\bParentCommandLine\s?=\s?.*/usr/bin/landscape-sysinfo.*\b' /var/log/syslog | grep -E '\bImage\s?=\s?.*/who\b' )