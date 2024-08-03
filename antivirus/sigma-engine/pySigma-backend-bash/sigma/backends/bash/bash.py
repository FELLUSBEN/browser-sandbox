from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT
from sigma.types import SigmaCompareExpression, SigmaRegularExpression, SigmaRegularExpressionFlag
from sigma.pipelines.bash import bash_pipeline
import re
from typing import ClassVar, Dict, Tuple, Pattern, List, Any, Optional

class bashBackend(TextQueryBackend):
    """bash"""
    # TODO: change the token definitions according to the syntax. Delete these not supported by your backend.
    # See the pySigma documentation for further infromation:
    # https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    name : ClassVar[str] = "bash"
    formats : Dict[str, str] = {
        "default": "Plain bash queries",
        
    }

    requires_pipeline : bool = False            #Todo:does the backend requires that a processing pipeline is provided? This information can be used by user interface programs like Sigma CLI to warn users about inappropriate usage of the backend.
    processing_pipeline : bash_pipeline
    # last_processing_pipeline: bash_pipeline
    # output_format_processing_pipeline: ClassVar[Dict[str, ProcessingPipeline]] = defaultdict(bash_pipeline)

    precedence : ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    group_expression : ClassVar[str] = "({expr})"   # Expression for precedence override grouping as format string with {expr} placeholder

    # Generated query tokens
    token_separator : str = ""     # separator inserted between all boolean operators
    or_token : ClassVar[str] = "|"
    and_token : ClassVar[str] = ".*" 
    not_token : ClassVar[str] = "[^{expr}]" # TODO:needs ferther inspection ||| ^((?!word).)*$ used for finding lines without word***********************
    eq_token : ClassVar[str] = "="  # Token inserted between field and value (without separator)  # TODO:needs ferther inspection

    # String output # TODO:deside if to add "" for every quote or for every string
    ## Fields
    ### Quoting
    field_quote : ClassVar[str] = ''                              # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    field_quote_pattern : ClassVar[Pattern] = re.compile("^\\w+$")   # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    field_quote_pattern_negation : ClassVar[bool] = True            # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).

    # ### Escaping  #TODO:needs ferther inspection
    # field_escape : ClassVar[str] = "\\"               # Character to escape particular parts defined in field_escape_pattern.
    # field_escape_quote : ClassVar[bool] = True        # Escape quote string defined in field_quote
    # field_escape_pattern : ClassVar[Pattern] = re.compile("\\s")   # All matches of this pattern are prepended with the string contained in field_escape.

    ## Values
    str_quote       : ClassVar[str] = ''     # string quoting character (added as escaping character)
    escape_char     : ClassVar[str] = "\\"    # Escaping character for special characrers inside string
    wildcard_multi  : ClassVar[str] = "*"     # Character used as multi-character wildcard # TODO:needs ferther inspection
    wildcard_single : ClassVar[str] = "."     # Character used as single-character wildcard # TODO:needs ferther inspection
    add_escaped     : ClassVar[str] = "\\"    # Characters quoted in addition to wildcards and string quote # TODO:needs ferther inspection
    # filter_chars    : ClassVar[str] = ""      # Characters filtered # TODO:needs ferther inspection
    bool_values     : ClassVar[Dict[bool, str]] = {   # Values to which boolean values are mapped.
        True: "[Tt][Rr][Uu][Ee]", #mybe 0
        False: "[Ff][Aa][Ll][Ss][Ee]", #mybe 1 
    }

    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression : ClassVar[str] = "{field}\\s?=\\s?{value}.*"
    endswith_expression   : ClassVar[str] = "{field}\\s?=\\s?.*{value}"
    contains_expression   : ClassVar[str] = "{field}\\s?=\\s?.*{value}.*" #RAZ: might need to add "" around the value
    # wildcard_match_expression : ClassVar[str] = "{field} match {value}"      # Special expression if wildcards can't be matched with the eq_token operator #RAZ: I think that might not be needed # TODO:needs ferther inspection

    # Regular expressions
    # Regular expression query as format string with placeholders {field}, {regex}, {flag_x} where x
    # is one of the flags shortcuts supported by Sigma (currently i, m and s) and refers to the
    # token stored in the class variable re_flags.
    re_expression : ClassVar[str] = "{field}\\s?=\\s?{regex}"
    re_escape_char : ClassVar[str] = "\\"               # Character used for escaping in regular expressions
    re_escape : ClassVar[Tuple[str]] = ()               # List of strings that are escaped TODO:needs ferther inspection
    re_escape_escape_char : bool = True                 # If True, the escape character is also escaped
    re_flag_prefix : bool = True                        # If True, the flags are prepended as (?x) group at the beginning of the regular expression, e.g. (?i). If this is not supported by the target, it should be set to False. # TODO:needs ferther inspection
    
    # Mapping from SigmaRegularExpressionFlag values to static string templates that are used in
    # flag_x placeholders in re_expression template.
    # By default, i, m and s are defined. If a flag is not supported by the target query language,
    # remove it from re_flags or don't define it to ensure proper error handling in case of appearance.
    re_flags : Dict[SigmaRegularExpressionFlag, str] = {
        SigmaRegularExpressionFlag.IGNORECASE: "i",
        SigmaRegularExpressionFlag.MULTILINE : "m",
        SigmaRegularExpressionFlag.DOTALL    : "s",
    }

    # Case sensitive string matching expression. String is quoted/escaped like a normal string. #RAZ: might need to delete or implement # TODO:needs ferther inspection
    # # Placeholders {field} and {value} are replaced with field name and quoted/escaped string.
    # case_sensitive_match_expression : ClassVar[str] = "{field} casematch {value}"
    # # Case sensitive string matching operators similar to standard string matching. If not provided,
    # # case_sensitive_match_expression is used.
    # case_sensitive_startswith_expression : ClassVar[str] = "{field} casematch_startswith {value}"
    # case_sensitive_endswith_expression   : ClassVar[str] = "{field} casematch_endswith {value}"
    # case_sensitive_contains_expression   : ClassVar[str] = "{field} casematch_contains {value}"

    # CIDR expressions: define CIDR matching if backend has native support. Else pySigma expands
    # CIDR values into string wildcard matches.
    # cidr_expression : ClassVar[Optional[str]] = None  # CIDR expression query as format string with placeholders {field}, {value} (the whole CIDR value), {network} (network part only), {prefixlen} (length of network mask prefix) and {netmask} (CIDR network mask only).

    # Numeric comparison operators
    compare_op_expression : ClassVar[str] = "{field}"+generate_comper_regex("{operator}","{value}")  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {#*****************************************************************************************
        SigmaCompareExpression.CompareOperators.LT: "lt",
        SigmaCompareExpression.CompareOperators.LTE: "le",
        SigmaCompareExpression.CompareOperators.GT: "gt",
        SigmaCompareExpression.CompareOperators.GTE: "ge",
    }

    # Expression for comparing two event fields
    # field_equals_field_expression : ClassVar[Optional[str]] = None  # Field comparison expression with the placeholders {field1} and {field2} corresponding to left field and right value side of Sigma detection item
    # field_equals_field_escaping_quoting : Tuple[bool, bool] = (True, True)   # If regular field-escaping/quoting is applied to field1 and field2. A custom escaping/quoting can be implemented in the convert_condition_field_eq_field_escape_and_quote method.

    # Null/None expressions
    field_null_expression : ClassVar[str] = "{field} is null"          # Expression for field has null value as format string with {field} placeholder for field name TODO:needs ferther inspection

    # Field existence condition expressions. TODO:needs ferther inspection-> delete or leave exists as {field} and find axpression for not
    # field_exists_expression : ClassVar[str] = "exists({field})"             # Expression for field existence as format string with {field} placeholder for field name
    # field_not_exists_expression : ClassVar[str] = "notexists({field})"      # Expression for field non-existence as format string with {field} placeholder for field name. If not set, field_exists_expression is negated with boolean NOT.

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in : ClassVar[bool] = True                     # Convert OR as in-expression
    convert_and_as_in : ClassVar[bool] = False                   # Convert AND as in-expression
    in_expressions_allow_wildcards : ClassVar[bool] = True       # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    field_in_list_expression : ClassVar[str] = "{field}{op}{list}"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    or_in_operator : ClassVar[str] = f"\\s?=\\s?"               # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    # and_in_operator : ClassVar[str] = "contains-all"    # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    list_separator : ClassVar[str] = "|"               # List element separator

    # Value not bound to a field
    unbound_value_str_expression : ClassVar[str] = '{value}'   # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression : ClassVar[str] = '{value}'     # Expression for number value not bound to a field as format string with placeholder {value}
    unbound_value_re_expression : ClassVar[str] = '{value}'   # Expression for regular expression not bound to a field as format string with placeholder {value} and {flag_x} as described for re_expression

    # Query finalization: appending and concatenating deferred query part
    deferred_start : ClassVar[str] = "\n| "               # String used as separator between main query and deferred parts
    deferred_separator : ClassVar[str] = "\n| "           # String used to join multiple deferred query parts
    deferred_only_query : ClassVar[str] = "*"            # String used as query if final query only contains deferred expression

    # TODO: implement custom methods for query elements not covered by the default backend base.
    # Documentation: https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html *************************************************************

    def finalize_query_default(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        # TODO: implement the per-query output for the output format {{ format }} here. Usually, the generated query is
        # embedded into a template, e.g. a JSON format with additional information from the Sigma rule.
        # # TODO: proper type annotation.
        # if hasattr(rule, "eventid"): 
        #     filter = f'-FilterHashTable @{{LogName = "{rule.logsource.service}"; Id = {rule.eventid}}} | '
        # else:
        #     filter = f'-LogName "{rule.logsource.service}" | '
        return f"grep -e {query} {rule.logsource.service}"

    def finalize_output_default(self, queries: List[str]) -> str:
        # TODO: implement the output finalization for all generated queries for the format {{ format }} here. Usually,
        # the single generated queries are embedded into a structure, e.g. some JSON or XML that can be imported into
        # the SIEM.
        # TODO: proper type annotation. Sigma CLI supports:
        # - str: output as is.
        # - bytes: output in file only (e.g. if a zip package is output).
        # - dict: output serialized as JSON.
        # - list of str: output each item as is separated by two newlines.
        # - list of dict: serialize each item as JSON and output all separated by newlines.
        return "\n".join(queries)

    # def finalize_query_default(self, rule: SigmaRule, query: Any, index: int, state: ConversionState) -> Any:
    #     if hasattr(rule, "eventid"): 
    #         filter = f'-FilterHashTable @{{LogName = "{rule.logsource.service}"; Id = {rule.eventid}}} | '
    #     else:
    #         filter = f'-LogName "{rule.logsource.service}" | '
    #     return "Get-WinEvent " + filter + f"Read-WinEvent | Where-Object {{{query}}}"

    # def finalize_output_default(self, queries: List[str]) -> Any:
    #     return queries

    #additional fanctions
    def generate_greater_than_regex(n):
        str_n = str(n)
        length = len(str_n)

        # Create parts of the regex for numbers with different lengths
        regex_parts = []

        # Match numbers with more digits than n
        regex_parts.append(r'\d{%d,}' % (length + 1))

        # Match numbers with the same number of digits as n
        for i in range(length):
            prefix = str_n[:i]
            digit = int(str_n[i])
            if digit < 9:
                regex_parts.append(r'%s[%d-9]\d{%d}' % (prefix, digit + 1, length - i - 1))

        return r'|'.join(regex_parts)
    
    def generate_greater_equals_regex(n):
        str_n = str(n)
        length = len(str_n)

        # Create parts of the regex for numbers with different lengths
        regex_parts = []

        # Match numbers with more digits than n
        regex_parts.append(r'\d{%d,}' % (length + 1))

        #match equal number
        regex_parts.append("123")

        # Match numbers with the same number of digits as n
        for i in range(length):
            prefix = str_n[:i]
            digit = int(str_n[i])
            if digit < 9:
                regex_parts.append(r'%s[%d-9]\d{%d}' % (prefix, digit, length - i - 1))

        return r'|'.join(regex_parts)
    
    def generate_less_than_regex(n):
        str_n = str(n)
        length = len(str_n)

        # Create parts of the regex for numbers with different lengths
        regex_parts = []

        # Match numbers with more digits than n
        regex_parts.append(r'\d{,%d}' % (length - 1))

        # Match numbers with the same number of digits as n
        for i in range(length):
            prefix = str_n[:i]
            digit = int(str_n[i])
            if digit < 9:
                regex_parts.append(r'%s[0-%d]\d{%d}' % (prefix, digit - 1, length - i - 1))

        return r'|'.join(regex_parts)

    def generate_less_equals_regex(n):
        str_n = str(n)
        length = len(str_n)

        # Create parts of the regex for numbers with different lengths
        regex_parts = []

        # Match numbers with more digits than n
        regex_parts.append(r'\d{,%d}' % (length - 1))

        #match equal number
        regex_parts.append("123")

        # Match numbers with the same number of digits as n
        for i in range(length):
            prefix = str_n[:i]
            digit = int(str_n[i])
            if digit < 9:
                regex_parts.append(r'%s[0-%d]\d{%d}' % (prefix, digit - 1, length - i - 1))

        return r'|'.join(regex_parts)
    
    def generate_comper_regex(op_flag,value):
        if op_flag == "gt":
            return generate_greater_than_regex(value)
        elif op_flag == "ge":
            return generate_greater_equals_regex(value)
        elif op_flag == "le":
            return generate_less_equals_regexecho(value)
        else:
            generate_less_than_regex(value)
        
        