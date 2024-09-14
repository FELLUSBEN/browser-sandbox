from sigma.collection import SigmaCollection
from sigma.backends.bash import bashBackend
from sigma.pipelines.bash import bash_pipeline 

def bash_backend():
    return bashBackend()

#generic test rule
print(bash_backend().convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                product: linux
                service: test_category 
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """)
    ))

# audit log sigma rule
print(bash_backend().convert(
        SigmaCollection.from_yaml("""
            title: Audio Capture
            id: a7af2487-9c2f-42e4-9bb9-ff961f0561d5
            status: test
            description: Detects attempts to record audio with arecord utility
            references:
                - https://linux.die.net/man/1/arecord
                - https://linuxconfig.org/how-to-test-microphone-with-audio-linux-sound-architecture-alsa
            author: 'Pawel Mazur'
            date: 2021/09/04
            modified: 2022/10/09
            tags:
                - attack.collection
                - attack.t1123
            logsource:
                product: linux
                service: auditd
            detection:
                selection:
                    type: EXECVE
                    a0: arecord
                    a1: '-vv'
                    a2: '-fdat'
                condition: selection
            falsepositives:
                - Unknown
            level: low
        """)
    ))

# syslog sigma rule
print(bash_backend().convert(
        SigmaCollection.from_yaml("""
            title: Suspicious Named Error
            id: c8e35e96-19ce-4f16-aeb6-fd5588dc5365
            status: test
            description: Detects suspicious DNS error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
            references:
                - https://github.com/ossec/ossec-hids/blob/1ecffb1b884607cb12e619f9ab3c04f530801083/etc/rules/named_rules.xml
            author: Florian Roth (Nextron Systems)
            date: 2018/02/20
            modified: 2022/10/05
            tags:
                - attack.initial_access
                - attack.t1190
            logsource:
                product: linux
                service: syslog
            detection:
                keywords:
                    - ' dropping source port zero packet from '
                    - ' denied AXFR from '
                    - ' exiting (due to fatal error)'
                condition: keywords
            falsepositives:
                - Unknown
            level: high
        """)
    ))


#sudo sigma rule
print(bash_backend().convert(
        SigmaCollection.from_yaml("""
            title: Sudo Privilege Escalation CVE-2019-14287 - Builtin
            id: 7fcc54cb-f27d-4684-84b7-436af096f858
            type: derived
            status: test
            description: Detects users trying to exploit sudo vulnerability reported in CVE-2019-14287
            references:
                - https://www.openwall.com/lists/oss-security/2019/10/14/1
                - https://access.redhat.com/security/cve/cve-2019-14287
                - https://twitter.com/matthieugarin/status/1183970598210412546
            author: Florian Roth (Nextron Systems)
            date: 2019/10/15
            modified: 2022/11/26
            tags:
                - attack.privilege_escalation
                - attack.t1068
                - attack.t1548.003
                - cve.2019.14287
            logsource:
                product: linux
                service: sudo
            # detection:
            #     selection_user:
            #         USER:
            #             - '#-*'
            #             - '#*4294967295' 
            #     condition: selection_user
            detection:
                selection:
                    fieldname|lte: 125
                condition: selection
            # detection:
            #     selection:
            #         fieldname|re: (?i)stam.*
            #     condition: selection
            falsepositives:
                - Unlikely
            level: critical
        """)
    )) #check if * means literly * or its regex

