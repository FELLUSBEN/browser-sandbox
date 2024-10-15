#!/bin/bash

grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?.*iptables\b' | grep -E '\ba1\s?=\s?-t\b' | grep -E '\ba2\s?=\s?nat\b' | grep -Ff <( grep -E '\b(--to-ports 42|--to-ports 43)' /var/log/audit/audit.log )
grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep '\btouch\b' | grep -Ff <( grep -E '\b(-t|-acmr|-d|-r)' /var/log/audit/audit.log )
grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?.*chattr.*\b' | grep -E '\ba1\s?=\s?.*-i.*\b'
grep -E '\btype\s?=\s?SYSCALL\b' /var/log/audit/audit.log | grep -E '\bexe\s?=\s?.*/useradd\b' ; grep -E '\btype\s?=\s?ADD_USER\b' /var/log/audit/audit.log
grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?wget\b' | grep -E '\ba1\s?=\s?--post-file=.*\b'
grep -E '\btype\s?=\s?execve\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?cp\b' | grep -E '\ba1\s?=\s?/bin/sh\b' | grep -E '\ba2\s?=\s?.*/crond\b'
grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?iptables\b' | grep -E '\ba1\s?=\s?.*DROP.*\b' ; grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?firewall-cmd\b' | grep -E '\ba1\s?=\s?.*remove.*\b' ; grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?ufw\b' | grep -E '\ba1\s?=\s?.*delete.*\b'
grep -E '\bkey\s?=\s?susp_activity\b' /var/log/audit/audit.log
grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?chmod\b' | grep -E '\ba1\s?=\s?777\b' ; grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?chmod\b' | grep -E '\ba1\s?=\s?u\+s\b' ; grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?cp\b' | grep -E '\ba1\s?=\s?/bin/ksh\b' ; grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -E '\ba0\s?=\s?cp\b' | grep -E '\ba1\s?=\s?/bin/sh\b'
grep -E '\btype\s?=\s?SYSCALL\b' /var/log/audit/audit.log | grep -Ff <( grep -E '\bexe\s?=\s?(/tmp/.*|/var/www/.*|/home/.*/public_html/.*|/usr/local/apache2/.*|/usr/local/httpd/.*|/var/apache/.*|/srv/www/.*|/home/httpd/html/.*|/srv/http/.*|/usr/share/nginx/html/.*|/var/lib/pgsql/data/.*|/usr/local/mysql/data/.*|/var/lib/mysql/.*|/var/vsftpd/.*|/etc/bind/.*|/var/named/.*)' /var/log/audit/audit.log )
grep -E '\btype\s?=\s?EXECVE\b' /var/log/audit/audit.log | grep -Ff <( grep -E '\b(\.bash_history|\.zsh_history|\.zhistory|\.history|\.sh_history|fish_history)' /var/log/audit/audit.log )
grep -E '\btype\s?=\s?PATH\b' /var/log/audit/audit.log | grep -E '\bnametype\s?=\s?CREATE\b' | grep -Ff <( grep -E '\bname\s?=\s?(/usr/lib/systemd/system/.*|/etc/systemd/system/.*)' /var/log/audit/audit.log ; grep -E '\bname\s?=\s?.*/\.config/systemd/user/.*\b' /var/log/audit/audit.log )
grep -E '\b(entered promiscuous mode|Deactivating service|Oversized packet received from|imuxsock begins to drop messages)' /var/log/syslog
grep -E '\b(cat </dev/tcp/|exec 3<>/dev/tcp/|echo >/dev/tcp/|bash -i >& /dev/tcp/|sh -i >& /dev/udp/|0<&196;exec 196<>/dev/tcp/|exec 5<>/dev/tcp/|\(sh\)0>/dev/tcp/|bash -c ''bash -i >& /dev/tcp/|echo -e ''#!/bin/bash\\nbash -i >& /dev/tcp/)' /var/log/syslog
grep '\bREPLACE\b' /var/log/syslog
grep '\berror: buffer_get_ret: trying to get more bytes 1907 than in buffer 308 \[preauth\]\b' /var/log/auth.log
grep -E '\b(unexpected internal error|unknown or unsupported key type|invalid certificate signing key|invalid elliptic curve value|incorrect signature|error in libcrypto|unexpected bytes remain after decoding|fatal: buffer_get_string: bad string|Local: crc32 compensation attack|bad client public DH value|Corrupted MAC on input)' /var/log/auth.log
grep -E '\b(stopping iptables|stopping ip6tables|stopping firewalld|stopping cbdaemon|stopping falcon-sensor)' /var/log/syslog
grep -E '\b(Connection refused: too many sessions for this address\.|Connection refused: tcp_wrappers denial\.|Bad HTTP verb\.|port and pasv both active|pasv and port both active|Transfer done \(but failed to open directory\)\.|Could not set file modification time\.|bug: pid active in ptrace_sandbox_free|PTRACE_SETOPTIONS failure|weird status:|couldn''t handle sandbox event|syscall .* out of bounds|syscall not permitted:|syscall validate failed:|Input line too long\.|poor buffer accounting in str_netfd_alloc|vsf_sysutil_read_loop)' /var/log/vsftpd.log
grep -E '\bTargetFilename\s?=\s?.*/etc/doas\.conf\b' /var/log/syslog
grep -E '\bTargetFilename\s?=\s?(/etc/cron\.d/.*|/etc/cron\.daily/.*|/etc/cron\.hourly/.*|/etc/cron\.monthly/.*|/etc/cron\.weekly/.*|/var/spool/cron/crontabs/.*)' /var/log/syslog ; grep -E '\bTargetFilename\s?=\s?(.*/etc/cron\.allow.*|.*/etc/cron\.deny.*|.*/etc/crontab.*)' /var/log/syslog
grep -E '\bTargetFilename\s?=\s?/etc/sudoers\.d/.*\b' /var/log/syslog
grep -E '\bImage\s?=\s?.*/wget\b' /var/log/syslog | grep -Ff <( grep -E '\bTargetFilename\s?=\s?(/tmp/.*|/var/tmp/.*)' /var/log/syslog )
grep -Ff <( grep -E '\bImage\s?=\s?(.*/apt|.*/apt-get)' /var/log/syslog ) | grep -E '\bCommandLine\s?=\s?.*APT::Update::Pre-Invoke::=.*\b'
grep -E '\bCommandLine\s?=\s?.*base64 .*\b' /var/log/syslog | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.*\| bash .*|.*\| sh .*|.*\|bash .*|.*\|sh .*)' /var/log/syslog ; grep -E '\bCommandLine\s?=\s?(.* \|sh|.*\| bash|.*\| sh|.*\|bash)' /var/log/syslog )
grep -E '\bCommandLine\s?=\s?(.*IyEvYmluL2Jhc2.*|.*IyEvYmluL2Rhc2.*|.*IyEvYmluL3pza.*|.*IyEvYmluL2Zpc2.*|.*IyEvYmluL3No.*)' /var/log/syslog
grep -E '\bImage\s?=\s?.*bpftrace\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*--unsafe.*\b'
grep -E '\bCommandLine\s?=\s?.*echo 1 >.*\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*/sys/kernel/debug/tracing/events/kprobes/.*\b' | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.*/myprobe/enable.*|.*/myretprobe/enable.*)' /var/log/syslog )
grep -Ff <( grep -E '\bImage\s?=\s?(.*/cat|.*grep|.*/head|.*/tail|.*/more)' /var/log/syslog ) | grep -E '\bCommandLine\s?=\s?.* /etc/sudoers.*\b'
grep -E '\bImage\s?=\s?.*/chattr\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.* -i .*\b'
grep -Ff <( grep -E '\bImage\s?=\s?(.*/rm|.*/shred|.*/unlink)' /var/log/syslog ) | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.*/var/log.*|.*/var/spool/mail.*)' /var/log/syslog )
grep -E '\bImage\s?=\s?.*crontab\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.* -r.*\b'
grep -E '\bImage\s?=\s?.*/dd\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*of=.*\b' | grep -E '\bCommandLine\s?=\s?.*/proc/.*\b' | grep -E '\bCommandLine\s?=\s?.*/mem.*\b'
grep -E '\bCommandLine\s?=\s?.*-ufw-init.*\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*force-stop.*\b' ; grep -E '\bCommandLine\s?=\s?.*ufw.*\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*disable.*\b'
grep -E '\bImage\s?=\s?.*/esxcli\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*network.*\b' | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.* get.*|.* list.*)' /var/log/syslog )
grep -E '\bImage\s?=\s?.*/esxcli\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*storage.*\b' | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.* get.*|.* list.*)' /var/log/syslog )
grep -E '\bImage\s?=\s?.*/esxcli\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*system.*\b' | grep -E '\bCommandLine\s?=\s?.*syslog.*\b' | grep -E '\bCommandLine\s?=\s?.*config.*\b' | grep -E '\bCommandLine\s?=\s?.* set.*\b'
grep -E '\bImage\s?=\s?.*/esxcli\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*system.*\b' | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.* get.*|.* list.*)' /var/log/syslog )
grep -E '\bImage\s?=\s?.*/esxcli\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*system .*\b' | grep -E '\bCommandLine\s?=\s?.*account .*\b' | grep -E '\bCommandLine\s?=\s?.*add .*\b'
grep -E '\bImage\s?=\s?.*/esxcli\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*vm process.*\b' | grep -E '\bCommandLine\s?=\s?.* list\b'
grep -E '\bImage\s?=\s?.*/esxcli\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*vm process.*\b' | grep -E '\bCommandLine\s?=\s?.*kill.*\b'
grep -E '\bImage\s?=\s?.*/esxcli\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*vsan.*\b' | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.* get.*|.* list.*)' /var/log/syslog )
grep -E '\bImage\s?=\s?.*/groupdel\b' /var/log/syslog
grep -Ff <( grep -Ff <( grep -E '\bImage\s?=\s?(.*/apt|.*/apt-get)' /var/log/syslog ) | grep -E '\bCommandLine\s?=\s?.*install.*\b' ; grep -E '\bImage\s?=\s?.*/yum\b' /var/log/syslog | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.*localinstall.*|.*install.*)' /var/log/syslog ) ; grep -E '\bImage\s?=\s?.*/rpm\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*-i.*\b' ; grep -E '\bImage\s?=\s?.*/dpkg\b' /var/log/syslog | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.*--install.*|.*-i.*)' /var/log/syslog ) ) | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.*nmap.*|.* nc.*|.*netcat.*|.*wireshark.*|.*tshark.*|.*openconnect.*|.*proxychains.*)' /var/log/syslog )
grep -Ff <( grep -E '\bImage\s?=\s?(.*/iptables|.*/xtables-legacy-multi|.*/iptables-legacy-multi|.*/ip6tables|.*/ip6tables-legacy-multi)' /var/log/syslog ) | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.*-F.*|.*-Z.*|.*-X.*)' /var/log/syslog ) | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.*ufw-logging-deny.*|.*ufw-logging-allow.*|.*ufw6-logging-deny.*|.*ufw6-logging-allow.*)' /var/log/syslog )
grep -E '\bImage\s?=\s?.*/mkfifo\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.* /tmp/.*\b'
grep -E '\bImage\s?=\s?.*/mount\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*hidepid=2.*\b' | grep -E '\bCommandLine\s?=\s?.* -o .*\b'
grep -E '\bImage\s?=\s?.*/nohup\b' /var/log/syslog
grep -E '\bCommandLine\s?=\s?-(W|R)\s?(\s|"|'')([0-9a-fA-F]{2}\s?){2,20}(\s|"|'')\b' /var/log/syslog
grep -E '\bImage\s?=\s?.*ruby.*\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.* -e.*\b' | grep -E '\bCommandLine\s?=\s?.*rsocket.*\b' | grep -E '\bCommandLine\s?=\s?.*TCPSocket.*\b' | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.* ash.*|.* bash.*|.* bsh.*|.* csh.*|.* ksh.*|.* pdksh.*|.* sh.*|.* tcsh.*)' /var/log/syslog )
grep -E '\bImage\s?=\s?.*crontab\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*/tmp/.*\b'
grep -E '\bImage\s?=\s?.*/service\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*iptables.*\b' | grep -E '\bCommandLine\s?=\s?.*stop.*\b' ; grep -E '\bImage\s?=\s?.*/service\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*ip6tables.*\b' | grep -E '\bCommandLine\s?=\s?.*stop.*\b' ; grep -E '\bImage\s?=\s?.*/chkconfig\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*iptables.*\b' | grep -E '\bCommandLine\s?=\s?.*stop.*\b' ; grep -E '\bImage\s?=\s?.*/chkconfig\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*ip6tables.*\b' | grep -E '\bCommandLine\s?=\s?.*stop.*\b' ; grep -E '\bImage\s?=\s?.*/systemctl\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*firewalld.*\b' | grep -E '\bCommandLine\s?=\s?.*stop.*\b' ; grep -E '\bImage\s?=\s?.*/systemctl\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*firewalld.*\b' | grep -E '\bCommandLine\s?=\s?.*disable.*\b' ; grep -E '\bImage\s?=\s?.*/service\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*cbdaemon.*\b' | grep -E '\bCommandLine\s?=\s?.*stop.*\b' ; grep -E '\bImage\s?=\s?.*/chkconfig\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*cbdaemon.*\b' | grep -E '\bCommandLine\s?=\s?.*off.*\b' ; grep -E '\bImage\s?=\s?.*/systemctl\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*cbdaemon.*\b' | grep -E '\bCommandLine\s?=\s?.*stop.*\b' ; grep -E '\bImage\s?=\s?.*/systemctl\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*cbdaemon.*\b' | grep -E '\bCommandLine\s?=\s?.*disable.*\b' ; grep -E '\bImage\s?=\s?.*/setenforce\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*0.*\b' ; grep -E '\bImage\s?=\s?.*/systemctl\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*stop.*\b' | grep -E '\bCommandLine\s?=\s?.*falcon-sensor.*\b' ; grep -E '\bImage\s?=\s?.*/systemctl\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*disable.*\b' | grep -E '\bCommandLine\s?=\s?.*falcon-sensor.*\b'
grep -Ff <( grep -E '\bImage\s?=\s?(.*/service|.*/systemctl|.*/chkconfig)' /var/log/syslog ) | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.*stop.*|.*disable.*)' /var/log/syslog )
grep -E '\bImage\s?=\s?.*/amazon-ssm-agent\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*-register .*\b' | grep -E '\bCommandLine\s?=\s?.*-code .*\b' | grep -E '\bCommandLine\s?=\s?.*-id .*\b' | grep -E '\bCommandLine\s?=\s?.*-region .*\b'
grep -E '\bImage\s?=\s?.*/chmod\b' /var/log/syslog | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.*/tmp/.*|.*/\.Library/.*|.*/etc/.*|.*/opt/.*)' /var/log/syslog )
grep -E '\bImage\s?=\s?.*/curl\b' /var/log/syslog | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.* --form.*|.* --upload-file .*|.* --data .*|.* --data-.*)' /var/log/syslog ; grep -E '\bCommandLine\s?=\s?\s-[FTd]\s\b' /var/log/syslog ) | grep -v -Ff <( grep -E '\bCommandLine\s?=\s?(.*://localhost.*|.*://127\.0\.0\.1.*)' /var/log/syslog )
grep -E '\bImage\s?=\s?.*/curl\b' /var/log/syslog | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.* -A .*|.* --user-agent .*)' /var/log/syslog )
grep -E '\bImage\s?=\s?.*/find\b' /var/log/syslog | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.*-perm -4000.*|.*-perm -2000.*|.*-perm 0777.*|.*-perm -222.*|.*-perm -o w.*|.*-perm -o x.*|.*-perm -u=s.*|.*-perm -g=s.*)' /var/log/syslog )
grep -E '\bImage\s?=\s?.*/git\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.* clone .*\b' | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.*exploit.*|.*Vulns.*|.*vulnerability.*|.*RCE.*|.*RemoteCodeExecution.*|.*Invoke-.*|.*CVE-.*|.*poc-.*|.*ProofOfConcept.*|.*proxyshell.*|.*log4shell.*|.*eternalblue.*|.*eternal-blue.*|.*MS17-.*)' /var/log/syslog )
grep -Ff <( grep -E '\bImage\s?=\s?(.*/cat|.*/head|.*/tail|.*/more)' /var/log/syslog ) | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.*/\.bash_history.*|.*/\.zsh_history.*)' /var/log/syslog ; grep -E '\bCommandLine\s?=\s?(.*_history|.*\.history|.*zhistory)' /var/log/syslog )
grep -E '\bParentCommandLine\s?=\s?bash -i\b' /var/log/syslog | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.*-c import .*|.*base64.*|.*pty\.spawn.*)' /var/log/syslog ; grep -E '\bImage\s?=\s?(.*whoami|.*iptables|.*/ncat|.*/nc|.*/netcat)' /var/log/syslog )
grep -Ff <( grep -E '\bCommandLine\s?=\s?(sh -c .*|bash -c .*)' /var/log/syslog ) | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.*\| bash .*|.*\| sh .*|.*\|bash .*|.*\|sh .*)' /var/log/syslog ; grep -E '\bCommandLine\s?=\s?(.*\| bash|.*\| sh|.*\|bash|.* \|sh)' /var/log/syslog )
grep -Ff <( grep -Ff <( grep -E '\bImage\s?=\s?(.*/cat|.*/echo|.*/grep|.*/head|.*/more|.*/tail)' /var/log/syslog ) | grep -E '\bCommandLine\s?=\s?.*>.*\b' ; grep -E '\bImage\s?=\s?(.*/emacs|.*/nano|.*/sed|.*/vi|.*/vim)' /var/log/syslog ) | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.*/bin/login.*|.*/bin/passwd.*|.*/boot/.*|.*/etc/.*\.conf.*|.*/etc/cron\..*|.*/etc/crontab.*|.*/etc/hosts.*|.*/etc/init\.d.*|.*/etc/sudoers.*|.*/opt/bin/.*|.*/sbin.*|.*/usr/bin/.*|.*/usr/local/bin/.*)' /var/log/syslog )
#grep -Ff <( grep -E '\bImage\s?=\s?(.*/bash|.*/csh|.*/dash|.*/fish|.*/ksh|.*/sh|.*/zsh)' /var/log/syslog ) | grep -E '\bCommandLine\s?=\s?.* -c .*\b' | grep -E '\bCommandLine\s?=\s?.*/tmp/.*\b'
grep -E '\bImage\s?=\s?.*/touch\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.* -t .*\b' | grep -E '\bCommandLine\s?=\s?.*\.service\b'
grep -E '\bImage\s?=\s?.*/userdel\b' /var/log/syslog
grep -E '\bImage\s?=\s?.*/usermod\b' /var/log/syslog | grep -Ff <( grep -E '\bCommandLine\s?=\s?(.*-aG root.*|.*-aG sudoers.*)' /var/log/syslog )
grep -E '\bImage\s?=\s?.*/wget\b' /var/log/syslog | grep -Ff <( grep -E '\bCommandLine\s?=\s?\s-O\s\b' /var/log/syslog ; grep -E '\bCommandLine\s?=\s?.*--output-document.*\b' /var/log/syslog ) | grep -E '\bCommandLine\s?=\s?.*/tmp/.*\b'
grep -E '\bImage\s?=\s?.*xterm.*\b' /var/log/syslog | grep -E '\bCommandLine\s?=\s?.*-display.*\b' | grep -E '\bCommandLine\s?=\s?.*:1\b'