from sigma.pipelines.common import logsource_linux, logsource_linux_file_create, logsource_linux_network_connection, logsource_linux_process_creation,logsource_windows,windows_logsource_mapping
from sigma.pipelines.base import Pipeline
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation, ChangeLogsourceTransformation,ReplaceStringTransformation,DropDetectionItemTransformation, Transformation
from sigma.processing.postprocessing import EmbedQueryTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition, field_name_conditions, MatchStringCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline, QueryPostprocessingItem
from sigma.rule import SigmaRule
from sigma.modifiers import SigmaGreaterThanEqualModifier,SigmaGreaterThanModifier,SigmaLessThanEqualModifier,SigmaLessThanModifier
from sigma.types import * 



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
    "vsftpd":"/var/log/vsftpd.log",
    "test_product":"/var/log/test_product.log",
    "test_category":"/var/log/test_category.log"
}


#functions used to implement gt,gte,lt,lte regex
def generate_greater_than_regex(n):
    str_n = str(n)
    length = len(str_n)

    # Create parts of the regex for numbers with different lengths
    regex_parts = []

    # Match numbers with more digits than n
    regex_parts.append('\d{%d,}' % (length + 1))

    # Match numbers with the same number of digits as n
    for i in range(length):
        prefix = str_n[:i]
        digit = int(str_n[i])
        if digit < 9:
            regex_parts.append('%s[%d-9]\d{%d}' % (prefix, digit + 1, length - i - 1))

    return '|'.join(regex_parts)

def generate_greater_equals_regex(n):
    str_n = str(n)
    length = len(str_n)

    # Create parts of the regex for numbers with different lengths
    regex_parts = []

    # Match numbers with more digits than n
    regex_parts.append('\d{%d,}' % (length + 1))

    #match equal number
    regex_parts.append(str_n)

    # Match numbers with the same number of digits as n
    for i in range(length):
        prefix = str_n[:i]
        digit = int(str_n[i])
        if digit < 9:
            regex_parts.append('%s[%d-9]\d{%d}' % (prefix, digit + 1, length - i - 1))

    return '|'.join(regex_parts)

def generate_less_than_regex(n):
    str_n = str(n)
    length = len(str_n)

    # Create parts of the regex for numbers with different lengths
    regex_parts = []

    # Match numbers with less digits than n
    if length > 1:
        regex_parts.append('\d{1,%d}' % (length - 1))

    # Match numbers with the same number of digits as n
    for i in range(length):
        prefix = str_n[:i]
        digit = int(str_n[i])
        if digit < 9:
            regex_parts.append('%s[0-%d]\d{%d}' % (prefix, digit - 1, length - i - 1))

    return '(' + '|'.join(regex_parts) + ')([^\d]|$)' 

def generate_less_equals_regex(n):
    str_n = str(n)
    length = len(str_n)

    # Create parts of the regex for numbers with different lengths
    regex_parts = []

    # Match numbers with less digits than n
    if length > 1:
        regex_parts.append('\d{1,%d}' % (length - 1))

    #match equal number
    regex_parts.append(str_n)

    # Match numbers with the same number of digits as n
    for i in range(length):
        prefix = str_n[:i]
        digit = int(str_n[i])
        if digit < 9:
            regex_parts.append('%s[0-%d]\d{%d}' % (prefix, digit - 1, length - i - 1))

    return '(' + '|'.join(regex_parts) + ')([^\d]|$)'

# prossing function that switch numbers after Numeric comparison operators with its regex
class PromoteDetectionItemTransformation(Transformation):
    """Promotes a detection item to the rule component level."""
    field: str
    def apply(self, pipeline, rule: SigmaRule) -> None:
        super().apply(pipeline, rule)
        for detection in rule.detection.detections.values():
            for detection_item in detection.detection_items:
                if SigmaGreaterThanEqualModifier in detection_item.modifiers:
                    setattr(detection_item, "value", [SigmaString('(' + str(generate_greater_equals_regex(detection_item.value[0].number.number)) + ')')])
                    detection_item.modifiers.remove(SigmaGreaterThanEqualModifier)
                    return
                if SigmaGreaterThanModifier in detection_item.modifiers:
                    setattr(detection_item, "value", [SigmaString('(' + str(generate_greater_than_regex(detection_item.value[0].number.number)) + ')')])
                    detection_item.modifiers.remove(SigmaGreaterThanModifier)
                    return
                if SigmaLessThanEqualModifier in detection_item.modifiers:
                    setattr(detection_item, "value", [SigmaString('(' + str(generate_less_equals_regex(detection_item.value[0].number.number)) + ')')])
                    detection_item.modifiers.remove(SigmaLessThanEqualModifier)
                    return
                if SigmaLessThanModifier in detection_item.modifiers:
                    setattr(detection_item, "value", [SigmaString('(' + str(generate_less_than_regex(detection_item.value[0].number.number)) + ')')])
                    detection_item.modifiers.remove(SigmaLessThanModifier)
                    return
                
                setattr(detection_item, "value", [SigmaString('(' + str(val) + ')') for val in detection_item.value]) #TODO: check if needed(if not needed, change the above setattr)


# pipelins
@Pipeline
def bash_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name = "Bash pipeline",
        allowed_backends={"bash"},# Set of identifiers of backends (from the backends mapping) that are allowed to use this processing pipeline. This can be used by frontends like Sigma CLI to warn the user about inappropriate usage.
        priority=50,            # The priority defines the order pipelines are applied. See documentation for common values.

        items = [
            ProcessingItem(
                identifier=f"linux_rule_validator", #rising an error for ruls for products diffrent from linux
                rule_condition_negation = True,
                rule_conditions = [LogsourceCondition(product = "linux")],
                transformation = RuleFailureTransformation(message = "Invalid logsource product :(")
            )
        ] + [
            ProcessingItem(
                identifier=f"bash_{logsource}",
                rule_conditions = [logsource_linux(logsource)], # if rule matches what is returned by logsource_linux func (e.g., product = linux, service = auth)
                transformation = ChangeLogsourceTransformation(service = service) # change service value (e.g., sysmon) to log file path
            )
            for logsource, service in linux_logsource_mapping.items() # returns multiple kv pairs (service:channel mappings)
        ] + [ 
            ProcessingItem(
                identifier="compare_operators_preprosseing", #calls the PromoteDetectionItemTransformation that currently used for diling with gt,gte,lt,lte modifiers 
                transformation = PromoteDetectionItemTransformation()
            )
        ]
    )