from sigma.collection import SigmaCollection
from sigma.backends.bash import bashBackend
from pathlib import Path

def bash_backend():
    return bashBackend()

def del_path(path: Path, sigma_collection: SigmaCollection) -> SigmaCollection:
    return SigmaCollection.from_yaml(path.open(encoding="utf-8"))


# Specify the directory you want to list files from
directory = Path('C:/Users/razic/Downloads/linux/')

# List all files (recursive)
file_paths = [file.as_posix() for file in directory.rglob('*') if file.is_file()]

# If you want the file paths as strings, convert them like this
file_paths = [str(file) for file in file_paths]

# Print the file paths
for file in file_paths:
    print(file)
print(len(file_paths))
# file_paths.pop(0)

print(bash_backend().convert(
    SigmaCollection.load_ruleset(file_paths[0:], on_load=del_path)
))

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
#             title: Buffer Overflow Attempts
#             id: 18b042f0-2ecd-4b6e-9f8d-aa7a7e7de781
#             status: stable
#             description: Detects buffer overflow attempts in Unix system log files
#             references:
#                 - https://github.com/ossec/ossec-hids/blob/1ecffb1b884607cb12e619f9ab3c04f530801083/etc/rules/attack_rules.xml
#             author: Florian Roth (Nextron Systems)
#             date: 2017-03-01
#             tags:
#                 - attack.t1068
#                 - attack.privilege-escalation
#             logsource:
#                 product: linux
#             detection:
#                 keywords:
#                     - 'attempt to execute code on stack by'
#                     - 'FTP LOGIN FROM .* 0bin0sh'
#                     - 'rpc.statd[\d+]: gethostbyname error for'
#                     - 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
#                 condition: keywords
#             falsepositives:
#                 - Unknown
#             level: high
#         """)
#     ))

# #generic test rule
# print(bash_backend().convert(
#         SigmaCollection.from_yaml("""
#             title: Commands to Clear or Remove the Syslog - Builtin
#             id: e09eb557-96d2-4de9-ba2d-30f712a5afd3
#             status: test
#             description: Detects specific commands commonly used to remove or empty the syslog
#             references:
#                 - https://www.virustotal.com/gui/file/fc614fb4bda24ae8ca2c44e812d12c0fab6dd7a097472a35dd12ded053ab8474
#             author: Max Altgelt (Nextron Systems)
#             date: 2021-09-10
#             modified: 2022-11-26
#             tags:
#                 - attack.impact
#                 - attack.t1565.001
#             logsource:
#                 product: linux
#             detection:
#                 selection:
#                     - 'rm /var/log/syslog'
#                     - 'rm -r /var/log/syslog'
#                     - 'rm -f /var/log/syslog'
#                     - 'rm -rf /var/log/syslog'
#                     - 'mv /var/log/syslog'
#                     - ' >/var/log/syslog'
#                     - ' > /var/log/syslog'
#                 falsepositives:
#                     - '/syslog.'
#                 condition: selection and not falsepositives
#             falsepositives:
#                 - Log rotation
#             level: high
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

