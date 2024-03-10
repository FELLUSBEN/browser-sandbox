from sigma.pipelines.common import logsource_linux, logsource_linux_file_create, logsource_linux_network_connection, logsource_linux_process_creation
from sigma.pipelines.base import Pipeline
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation, ChangeLogsourceTransformation
from sigma.processing.postprocessing import EmbedQueryTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline, QueryPostprocessingItem

# TODO: the following code is just an example extend/adapt as required.
# See https://sigmahq-pysigma.readthedocs.io/en/latest/Processing_Pipelines.html for further documentation.

linux_logsource_mapping = { # map all linux services to files
    "auditd":"/var/log/ ",
    "auth":"/var/log/ ",
    "clamav":"/var/log/ ",
    "cron":"/var/log/ ",
    "guacamole":"/var/log/ ",
    "modsecurity":"/var/log/ ",
    "sshd":"/var/log/ ",
    "sudo":"/var/log/ ",
    "syslog":"/var/log/ ",
    "vsftpd":"/var/log/ "
}

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

def bash_pipeline() -> ProcessingPipeline: #copid powershell_pipeline funq, changed begining
    return ProcessingPipeline(
        name = "PowerShell pipeline",
        items = [
            ProcessingItem(
                # rule_condition_negation = True,
                rule_conditions = [LogsourceCondition(product = "linux")],
                transformation = RuleFailureTransformation(message = "Invalid logsource product.")
            )
        ] + [
            ProcessingItem(
                rule_conditions = [logsource_linux(logsource)], # if rule matches what is returned by logsource_linux func (e.g., product = linux, service = auth)
                transformation = ChangeLogsourceTransformation(service = channel) # change service value (e.g., sysmon) to channel value (e.g., Microsoft-Windows-Sysmon/Operational)
            )
            for logsource, channel in linux_logsource_mapping.items() # returns multiple kv pairs (service:channel mappings)
        ] + [ #**********************************************************************************************************************************************
            ProcessingItem(
                rule_conditions = [logsource_windows_network_connection()], # TODO: scale this so all sysmon event categories are covered
                transformation = ChangeLogsourceTransformation(service = windows_logsource_mapping['sysmon']) 
            )
        ] + [
            ProcessingItem(
                transformation = RemoveWhiteSpaceTransformation()
            )
        ] + [
            ProcessingItem(
                # field name conditions are evaluated against fields in detection items and in the component-level field list of a rule
                field_name_conditions = [IncludeFieldCondition(
                    fields = ["[eE][vV][eE][nN][tT][iI][dD]"],
                    type = "re"
                )],
                # TODO: change logic to automatically grab the same field specified for IncludeFieldCondition
                transformation = PromoteDetectionItemTransformation(field = "EventID")
            )
        ] + [
            ProcessingItem(
                # field name conditions are evaluated against fields in detection items and in the component-level field list of a rule
                field_name_conditions = [IncludeFieldCondition(
                    fields = ["[eE][vV][eE][nN][tT][iI][dD]"],
                    type = "re"
                )],
                transformation = DropDetectionItemTransformation()
            )
        ] + [
            ProcessingItem(
                transformation = AddFieldnamePrefixTransformation(prefix = "$_.")
            )
        ]
    )