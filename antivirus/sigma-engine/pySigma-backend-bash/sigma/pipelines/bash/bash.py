from sigma.pipelines.common import logsource_linux, logsource_linux_file_create, logsource_linux_network_connection, logsource_linux_process_creation,logsource_windows,windows_logsource_mapping
from sigma.pipelines.base import Pipeline
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation, ChangeLogsourceTransformation
from sigma.processing.postprocessing import EmbedQueryTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline, QueryPostprocessingItem

# TODO: the following code is just an example extend/adapt as required.
# See https://sigmahq-pysigma.readthedocs.io/en/latest/Processing_Pipelines.html for further documentation.

linux_logsource_mapping = { # map all linux services to files
    "auditd":"/var/log/audit/audit.log",
    "auth":"/var/log/auth.log",
    "clamav":"/var/log/ ", #By default, ClamAV on Ubuntu does not generate a log file. The output goes to stdout
    "cron":"/var/log/syslog", #cron jobs and their outputs are typically logged by the syslog daemon, not in a dedicated cron log file. By default, these logs are routed to /var/log/syslog
    "guacamole":"/var/log/syslog", # Troubleshooting Guacamole usually boils down to checking either syslog or your servlet container’s logs (likely Tomcat). Please note that the exact locations and commands might vary depending on your specific Ubuntu configuration
    "modsecurity":"/var/log/apache2/modsec_audit.log",
    "sshd":"/var/log/auth.log",
    "sudo":"/var/log/auth.log",
    "syslog":"/var/log/syslog",
    "vsftpd":"/var/log/vsftpd.log"
    # "test_product":"/var/log/test_product.log",
    # "test_category":"/var/log/test_category.log"
}
windows_logsource_mapping

@Pipeline
# def bash_pipeline() -> ProcessingPipeline:        # Processing pipelines should be defined as functions that return a ProcessingPipeline object.
#     return ProcessingPipeline(
#         name="bash example pipeline",
#         allowed_backends=frozenset(),                                               # Set of identifiers of backends (from the backends mapping) that are allowed to use this processing pipeline. This can be used by frontends like Sigma CLI to warn the user about inappropriate usage.
#         priority=20,            # The priority defines the order pipelines are applied. See documentation for common values.
#         items=[
#             ProcessingItem(     # This is an example for processing items generated from the mapping above.
#                 identifier=f"bash_windows_{service}",
#                 transformation=AddConditionTransformation({ "source": source}),
#                 rule_conditions=[logsource_windows(service)],
#             )
#             for service, source in windows_logsource_mapping.items()
#         ] + [
#             ProcessingItem(     # Field mappings
#                 identifier="bash_field_mapping",
#                 transformation=FieldMappingTransformation({
#                     "EventID": "event_id",      # TODO: define your own field mappings
#                 })
#             )
#         ],
#         postprocessing_items=[
#             QueryPostprocessingItem(
#                 transformation=EmbedQueryTransformation(prefix="...", suffix="..."),
#                 rule_condition_linking=any,
#                 rule_conditions=[
#                 ],
#                 identifier="example",
#             )
#         ],
#         finalizers=[ConcatenateQueriesFinalizer()],
#     )
#******************this was the initial template ***********

@Pipeline
def bash_pipeline() -> ProcessingPipeline: #copid powershell_pipeline funq, changed begining
    print("pipline works!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    return ProcessingPipeline(
        name = "Bash pipeline",
        allowed_backends=frozenset(),    # Set of identifiers of backends (from the backends mapping) that are allowed to use this processing pipeline. This can be used by frontends like Sigma CLI to warn the user about inappropriate usage.
        priority=50,            # The priority defines the order pipelines are applied. See documentation for common values.

        items = [
            ProcessingItem(
                # rule_condition_negation = True,
                rule_conditions = [LogsourceCondition(product = "linux")],
                transformation = RuleFailureTransformation(message = "Invalid logsource product.")
            )
        ] + [
            ProcessingItem(
                identifier=f"bash_{logsource}",
                rule_conditions = [logsource_linux(logsource)], # if rule matches what is returned by logsource_linux func (e.g., product = linux, service = auth)
                transformation = ChangeLogsourceTransformation(service = channel) # change service value (e.g., sysmon) to channel value (e.g., Microsoft-Windows-Sysmon/Operational)
            )
            for logsource, channel in linux_logsource_mapping.items() # returns multiple kv pairs (service:channel mappings)
        ] + [ #****************************************************************************************************************
            ProcessingItem(     # Field mappings
                identifier="bash_field_mapping",
                transformation=FieldMappingTransformation({
                    "EventID": "event_id",      # TODO: define your own field mappings
                    # "keywords": "grep"
                })
            )
        ],
        postprocessing_items=[
            QueryPostprocessingItem(
                transformation=EmbedQueryTransformation(prefix="...", suffix="..."),
                rule_condition_linking=any,
                rule_conditions=[
                ],
                identifier="example",
            )
        ]
        # finalizers=[ConcatenateQueriesFinalizer()],
    )