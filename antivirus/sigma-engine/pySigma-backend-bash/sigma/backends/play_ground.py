from sigma.collection import SigmaCollection
from sigma.backends.bash import bashBackend

def bash_backend():
    return bashBackend()

# #generic test rule # #TODO make the next rule work in the future - the problem is that convert_as_in dosn't work on cidr, make it work!!!
# print(bash_backend().convert(
#         SigmaCollection.from_yaml("""
#             title: Potentially Suspicious Malware Callback Communication - Linux
#             id: dbfc7c98-04ab-4ab7-aa94-c74d22aa7376
#             # related:
#             #     - id: 4b89abaa-99fe-4232-afdd-8f9aa4d20382
#             #     type: derived
#             status: experimental
#             description: |
#                 Detects programs that connect to known malware callback ports based on threat intelligence reports.
#             references:
#                 - https://www.mandiant.com/resources/blog/triton-actor-ttp-profile-custom-attack-tools-detections
#                 - https://www.mandiant.com/resources/blog/ukraine-and-sandworm-team
#                 - https://www.elastic.co/guide/en/security/current/potential-non-standard-port-ssh-connection.html
#                 - https://thehackernews.com/2024/01/systembc-malwares-c2-server-analysis.html
#                 - https://www.cybereason.com/blog/sliver-c2-leveraged-by-many-threat-actors
#             author: hasselj
#             date: 2024-05-10
#             tags:
#                 - attack.persistence
#                 - attack.command-and-control
#                 - attack.t1571
#             logsource:
#                 category: network_connection
#                 product: linux
#             detection:
#                 selection:
#                     Initiated: 'true'
#                     DestinationPort:
#                         - 888
#                         - 999
#                         - 2200
#                         - 2222
#                         - 4000
#                         - 4444
#                         - 6789
#                         - 8531
#                         - 50501
#                         - 51820
#                 filter_main_local_ranges:
#                     DestinationIp|cidr:
#                         - '127.0.0.0/8'
#                         - '10.0.0.0/8'
#                         - '172.16.0.0/12'
#                         - '192.168.0.0/16'
#                         - '169.254.0.0/16'
#                         - '::1/128'         # IPv6 loopback
#                         - 'fe80::/10'       # IPv6 link-local addresses
#                         - 'fc00::/7'        # IPv6 private addresses
#                 condition: selection and not 1 of filter_main_*
#             falsepositives:
#                 - Unknown
#             level: high
#         """)
#     ))

# # generic test rule
# print(bash_backend().convert(
#         SigmaCollection.from_yaml("""
#             title: Triple Cross eBPF Rootkit Default Persistence
#             id: 1a2ea919-d11d-4d1e-8535-06cda13be20f
#             status: test
#             description: Detects the creation of "ebpfbackdoor" files in both "cron.d" and "sudoers.d" directories. Which both are related to the TripleCross persistence method
#             references:
#                 - https://github.com/h3xduck/TripleCross/blob/12629558b8b0a27a5488a0b98f1ea7042e76f8ab/apps/deployer.sh
#             author: Nasreddine Bencherchali (Nextron Systems)
#             date: 2022-07-05
#             modified: 2022-12-31
#             tags:
#                 - attack.persistence
#                 - attack.defense-evasion
#                 - attack.t1053.003

#             logsource:
#                 product: linux
#                 category: file_event
#             detection:
#                 selection:
#                     TargetFilename|endswith: 'ebpfbackdoor'
#                 condition: selection
#             falsepositives:
#                 - Unlikely
#             level: high
#         """)
#     ))

# #generic test rule
# print(bash_backend().convert(
#         SigmaCollection.from_yaml("""
#             title: Wget Creating Files in Tmp Directory
#             id: 35a05c60-9012-49b6-a11f-6bab741c9f74
#             status: test
#             description: Detects the use of wget to download content in a temporary directory such as "/tmp" or "/var/tmp"
#             references:
#                 - https://blogs.jpcert.or.jp/en/2023/05/gobrat.html
#                 - https://jstnk9.github.io/jstnk9/research/GobRAT-Malware/
#                 - https://www.virustotal.com/gui/file/60bcd645450e4c846238cf0e7226dc40c84c96eba99f6b2cffcd0ab4a391c8b3/detection
#                 - https://www.virustotal.com/gui/file/3e44c807a25a56f4068b5b8186eee5002eed6f26d665a8b791c472ad154585d1/detection
#             author: Joseliyo Sanchez, @Joseliyo_Jstnk
#             date: 2023-06-02
#             tags:
#                 - attack.command-and-control
#                 - attack.t1105
#             logsource:
#                 product: linux
#                 category: file_event
#             detection:
#                 selection:
#                     Image|endswith: '/wget'
#                     TargetFilename|startswith:
#                         - '/tmp/'
#                         - '/var/tmp/'
#                 condition: selection
#             falsepositives:
#                 - Legitimate downloads of files in the tmp folder.
#             level: medium
#         """)
#     ))

# #TODO make the next rule work in the future - the problem is the windash modifier but the rule is desinde for linux so you should make it work.
# print(bash_backend().convert(
#         SigmaCollection.from_yaml("""
#             title: Capabilities Discovery - Linux
#             id: d8d97d51-122d-4cdd-9e2f-01b4b4933530
#             status: test
#             description: Detects usage of "getcap" binary. This is often used during recon activity to determine potential binaries that can be abused as GTFOBins or other.
#             references:
#                 - https://github.com/SaiSathvik1/Linux-Privilege-Escalation-Notes
#                 - https://github.com/carlospolop/PEASS-ng
#                 - https://github.com/diego-treitos/linux-smart-enumeration
#             author: Nasreddine Bencherchali (Nextron Systems)
#             date: 2022-12-28
#             modified: 2024-03-05
#             tags:
#                 - attack.discovery
#                 - attack.t1083
#             logsource:
#                 category: process_creation
#                 product: linux
#             detection:
#                 selection:
#                     Image|endswith: '/getcap'
#                     CommandLine|contains|windash: ' -r '
#                 condition: selection
#             falsepositives:
#                 - Unknown
#             level: low
#         """)
#     ))

# # audit log sigma rule
# print(bash_backend().convert(
#         SigmaCollection.from_yaml("""
#             title: Audio Capture
#             id: a7af2487-9c2f-42e4-9bb9-ff961f0561d5
#             status: test
#             description: Detects attempts to record audio with arecord utility
#             references:
#                 - https://linux.die.net/man/1/arecord
#                 - https://linuxconfig.org/how-to-test-microphone-with-audio-linux-sound-architecture-alsa
#             author: 'Pawel Mazur'
#             date: 2021/09/04
#             modified: 2022/10/09
#             tags:
#                 - attack.collection
#                 - attack.t1123
#             logsource:
#                 product: linux
#                 service: auditd
#             detection:
#                 selection:
#                     type: EXECVE
#                     a0: arecord
#                     a1: '-vv'
#                     a2: '-fdat'
#                 condition: selection
#             falsepositives:
#                 - Unknown
#             level: low
#         """)
#     ))

# # # syslog sigma rule
# print(bash_backend().convert(
#         SigmaCollection.from_yaml("""
#             title: Suspicious Named Error
#             id: c8e35e96-19ce-4f16-aeb6-fd5588dc5365
#             status: test
#             description: Detects suspicious DNS error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
#             references:
#                 - https://github.com/ossec/ossec-hids/blob/1ecffb1b884607cb12e619f9ab3c04f530801083/etc/rules/named_rules.xml
#             author: Florian Roth (Nextron Systems)
#             date: 2018/02/20
#             modified: 2022/10/05
#             tags:
#                 - attack.initial_access
#                 - attack.t1190
#             logsource:
#                 product: linux
#                 service: syslog
#             detection:
#                 keywords:
#                     - ' dropping source port zero packet from '
#                     - ' denied AXFR from '
#                     - ' exiting (due to fatal error)'
#                 condition: keywords
#             falsepositives:
#                 - Unknown
#             level: high
#         """)
#     ))


# #sudo sigma rule
# print(bash_backend().convert(
#         SigmaCollection.from_yaml("""
#             title: Sudo Privilege Escalation CVE-2019-14287 - Builtin
#             id: 7fcc54cb-f27d-4684-84b7-436af096f858
#             type: derived
#             status: test
#             description: Detects users trying to exploit sudo vulnerability reported in CVE-2019-14287
#             references:
#                 - https://www.openwall.com/lists/oss-security/2019/10/14/1
#                 - https://access.redhat.com/security/cve/cve-2019-14287
#                 - https://twitter.com/matthieugarin/status/1183970598210412546
#             author: Florian Roth (Nextron Systems)
#             date: 2019/10/15
#             modified: 2022/11/26
#             tags:
#                 - attack.privilege_escalation
#                 - attack.t1068
#                 - attack.t1548.003
#                 - cve.2019.14287
#             logsource:
#                 product: linux
#                 service: sudo
#             # detection:
#             #     selection_user:
#             #         USER|re:
#             #             - '^#-*\$' #*********************** TODO: delete ^ and $ once finised working on re modifier
#             #             - '#*4294967295' 
#             #     condition: selection_user
#             # detection:
#             #     selection:
#             #         fieldname|lte: 125
#             #     condition: selection
#             # detection:
#             #     selection:
#             #         fieldname:
#             #             - 'raz the king'
#             #             - 'raz the god'
#             #             - 'raz the legend'
#             #     condition: selection
#             # detection:
#             #     selection:
#             #         c-uri|contains|all:
#             #         - "/ecp/default.aspx"
#             #         - "__VIEWSTATEGENERATOR="
#             #         - "__VIEWSTATE="
#             #     condition: selection
#             # detection:
#             #     selection:
#             #         fieldname|re: '.*needle$'
#             #     condition: selection
#             detection:
#                 sel1:
#                     field1|re: '.*needle$'
#                 sel2:
#                     fieldname:
#                         - 'raz the king'
#                         - 'raz the god'
#                         - 'raz the legend'
#                 sel3:
#                     field2|contains: 'raz'
#                 condition: not sel1 and not (sel2 or sel3)
#             falsepositives:
#                 - Unlikely
#             level: critical
#         """)
#     )) 

