from sigma.collection import SigmaCollection
from sigma.backends.bash import bashBackend
from sigma.pipelines.bash import bash_pipeline 

def bash_backend():
    return bashBackend(processing_pipeline=bash_pipeline())

print(bash_backend().convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                product: test_product
                service: test_category 
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """)
    ))


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