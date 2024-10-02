from sigma.collection import SigmaCollection
from sigma.backends.bash import bashBackend

def bash_backend():
    return bashBackend()

#generic test rule
print(bash_backend().convert(
        SigmaCollection.from_yaml("""
            title: Linux Base64 Encoded Pipe to Shell
            id: ba592c6d-6888-43c3-b8c6-689b8fe47337
            status: test
            description: Detects suspicious process command line that uses base64 encoded input for execution with a shell
            references:
                - https://github.com/arget13/DDexec
                - https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally
            author: pH-T (Nextron Systems)
            date: 2022-07-26
            modified: 2023-06-16
            tags:
                - attack.defense-evasion
                - attack.t1140
            logsource:
                product: linux
                category: process_creation
            detection:
                selection_base64:
                    CommandLine|contains: 'base64 '
                selection_exec:
                    - CommandLine|contains:
                        - '| bash '
                        - '| sh '
                        - '|bash '
                        - '|sh '
                    - CommandLine|endswith:
                        - ' |sh'
                        - '| bash'
                        - '| sh'
                        - '|bash'
                condition: all of selection_*
            falsepositives:
                - Legitimate administration activities
            level: medium
        """)
    ))

#generic test rule
print(bash_backend().convert(
        SigmaCollection.from_yaml("""
            title: Capabilities Discovery - Linux
            id: d8d97d51-122d-4cdd-9e2f-01b4b4933530
            status: test
            description: Detects usage of "getcap" binary. This is often used during recon activity to determine potential binaries that can be abused as GTFOBins or other.
            references:
                - https://github.com/SaiSathvik1/Linux-Privilege-Escalation-Notes
                - https://github.com/carlospolop/PEASS-ng
                - https://github.com/diego-treitos/linux-smart-enumeration
            author: Nasreddine Bencherchali (Nextron Systems)
            date: 2022-12-28
            modified: 2024-03-05
            tags:
                - attack.discovery
                - attack.t1083
            logsource:
                category: process_creation
                product: linux
            detection:
                selection:
                    Image|endswith: '/getcap'
                    CommandLine|contains|windash: ' -r '
                condition: selection
            falsepositives:
                - Unknown
            level: low
        """)
    ))

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
#     )) #check if * means literly * or its regex

