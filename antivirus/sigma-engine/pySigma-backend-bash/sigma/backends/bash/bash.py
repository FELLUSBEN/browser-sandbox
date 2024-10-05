from sigma.conditions import ConditionAND, ConditionOR
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import *
from sigma.types import *
import sigma.pipelines.bash #import bash_pipeline
import re
from typing import ClassVar, Dict, Tuple, Pattern, List, Any, Optional


class bashBackend(TextQueryBackend):
    """bash"""
    name : ClassVar[str] = "bash"
    formats : Dict[str, str] = {
        "default": "grep commands",
    }

    requires_pipeline : bool = True
    preprocessing_pipelin : sigma.pipelines.bash.bash_pipeline
    
    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    precedence : ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    group_expression : ClassVar[str] = "< ( grep {expr} )"   # Expression for precedence override grouping as format string with {expr} placeholder

    # Generated query tokens
    token_separator : str = ""     # separator inserted between all boolean operators
    or_token : ClassVar[str] = " ; grep " # |
    and_token : ClassVar[str] = " | grep " # .*
    not_token : ClassVar[str] = "-v "
    eq_token : ClassVar[str] = "\\s?=\\s?"  # Token inserted between field and value (without separator)

    # String output
    ## Fields
    ### Quoting
    field_quote : ClassVar[str] = ''                              # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    field_quote_pattern : ClassVar[Pattern] = re.compile("^\\w+$")   # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    field_quote_pattern_negation : ClassVar[bool] = True            # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).

    ## Values
    str_quote       : ClassVar[str] = ''     # string quoting character (added as escaping character)
    escape_char     : ClassVar[str] = "\\"    # Escaping character for special characrers inside string
    wildcard_multi  : ClassVar[str] = ".*"     # Character used as multi-character wildcard
    wildcard_single : ClassVar[str] = "."     # Character used as single-character wildcard
    add_escaped     : ClassVar[str] = "\\^$.|?*+()[]{}"    # Characters quoted in addition to wildcards and string quote # 
    filter_chars    : ClassVar[str] = ""      # Characters filtered
    bool_values     : ClassVar[Dict[bool, str]] = {   # Values to which boolean values are mapped.
        True: "[Tt][Rr][Uu][Ee]", #mybe 0
        False: "[Ff][Aa][Ll][Ss][Ee]", #mybe 1 
    }

    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression : ClassVar[str] = "{field}\\s?=\\s?{value}.*"
    endswith_expression   : ClassVar[str] = "{field}\\s?=\\s?.*{value}"
    contains_expression   : ClassVar[str] = "{field}\\s?=\\s?.*{value}.*" 

    # Regular expressions
    # Regular expression query as format string with placeholders {field}, {regex}, {flag_x} where x
    # is one of the flags shortcuts supported by Sigma (currently i, m and s) and refers to the
    # token stored in the class variable re_flags.
    re_expression : ClassVar[str] = "{field}\\s?=\\s?{regex}{flag_i}"
    re_escape_char : ClassVar[str] = "\\"               # Character used for escaping in regular expressions
    re_escape : ClassVar[Tuple[str]] = ()               # List of strings that are escaped 
    re_escape_escape_char : bool = False                 # If True, the escape character is also escaped
    re_flag_prefix : bool = True                       # If True, the flags are prepended as (?x) group at the beginning of the regular expression, e.g. (?i). If this is not supported by the target, it should be set to False. # TODO:needs ferther inspection
    
    # Mapping from SigmaRegularExpressionFlag values to static string templates that are used in
    # flag_x placeholders in re_expression template.
    # By default, i, m and s are defined. If a flag is not supported by the target query language,
    # remove it from re_flags or don't define it to ensure proper error handling in case of appearance.
    re_flags : Dict[SigmaRegularExpressionFlag, str] = { #TODO figureout how dose it works
        SigmaRegularExpressionFlag.IGNORECASE: "i",
    }

    # Numeric comparison operators
    compare_op_expression : ClassVar[str] = "{field}\\s?=\\s?{value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "lt",
        SigmaCompareExpression.CompareOperators.LTE: "le",
        SigmaCompareExpression.CompareOperators.GT: "gt",
        SigmaCompareExpression.CompareOperators.GTE: "ge",
    }

    # Expression for comparing two event fields
    field_equals_field_expression : ClassVar[Optional[str]] = "{field1}\\s?=\\s?{field2}"  # Field comparison expression with the placeholders {field1} and {field2} corresponding to left field and right value side of Sigma detection item

    # Null/None expressions
    field_null_expression : ClassVar[str] = "{field}\\s?=\\s?\\^@"          # Expression for field has null value as format string with {field} placeholder for field name 

    # Field existence condition expressions.
    field_exists_expression : ClassVar[str] = "{field}\\s?(=|:)"             # Expression for field existence as format string with {field} placeholder for field name
    field_not_exists_expression : ClassVar[str] = "[^({field}\\s?(=|:))]"      # Expression for field non-existence as format string with {field} placeholder for field name. If not set, field_exists_expression is negated with boolean NOT.

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)" 
    convert_or_as_in : ClassVar[bool] = True                     # Convert OR as in-expression
    convert_and_as_in : ClassVar[bool] = True                   # Convert AND as in-expression 
    in_expressions_allow_wildcards : ClassVar[bool] = True       # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    field_in_list_expression : ClassVar[str] = "{field}{op}({list})"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    or_in_operator : ClassVar[str] = f"\\s?=\\s?"               # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    and_in_operator : ClassVar[str] = f"\\s?=\\s?"              # Operator used to convert and into in-expressions. Must be set if convert_and_as_in is set
    list_separator : ClassVar[str] = "|"               # List element separator

    # Value not bound to a field
    unbound_value_str_expression : ClassVar[str] = '{value}'   # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression : ClassVar[str] = '{value}'     # Expression for number value not bound to a field as format string with placeholder {value}
    unbound_value_re_expression : ClassVar[str] = '{value}'   # Expression for regular expression not bound to a field as format string with placeholder {value} and {flag_x} as described for re_expression TODO:needs ferther inspection

    # Query finalization: appending and concatenating deferred query part TODO:needs ferther inspection
    deferred_start : ClassVar[str] = "\n| "               # String used as separator between main query and deferred parts
    deferred_separator : ClassVar[str] = "\n| "           # String used to join multiple deferred query parts
    deferred_only_query : ClassVar[str] = "*"            # String used as query if final query only contains deferred expression

    def __init__(self, processing_pipeline: ProcessingPipeline | None = sigma.pipelines.bash.bash_pipeline(), collect_errors: bool = False):
        super().__init__(processing_pipeline, collect_errors)
    
    def convert_condition(self, cond: ConditionOR | ConditionAND | ConditionNOT | ConditionFieldEqualsValueExpression | ConditionValueExpression, state: ConversionState) -> Any:
        return super().convert_condition(cond, state) + " " + str(cond.source.path) if cond.source and (not isinstance(cond,(ConditionAND,ConditionOR)) or (isinstance(cond,(ConditionOR)) and self.decide_convert_condition_as_in_expression(cond, state))) else super().convert_condition(cond, state)
    
    def decide_convert_condition_as_in_expression(self, cond: Union[ConditionOR, ConditionAND], state: ConversionState) -> bool:
        # Check if conversion of condition type is enabled
        if (
            not self.convert_or_as_in
            and isinstance(cond, ConditionOR)
            or not self.convert_and_as_in
            and isinstance(cond, ConditionAND)
        ):
            return False

        # All arguments of the given condition must reference a field
        if not all((isinstance(arg, ConditionFieldEqualsValueExpression) for arg in cond.args)) and not all((isinstance(arg, ConditionValueExpression)  for arg in cond.args)):
            return False

        # Build a set of all fields appearing in condition arguments
        if isinstance(cond.args[0],ConditionFieldEqualsValueExpression):
            fields = {arg.field for arg in cond.args}
            # All arguments must reference the same field
            if len(fields) != 1:
                return False
        else:
            parent = cond.args[0].parent
            # All arguments must reference the same parent
            if not all([parent == arg.parent for arg in cond.args]):
                return False
            

        # All argument values must be strings or numbers
        if not all([isinstance(arg.value, (SigmaString, SigmaNumber)) for arg in cond.args]):
            return False

        # Check for plain strings if wildcards are not allowed for string expressions.
        if not self.in_expressions_allow_wildcards and any(
            [
                arg.value.contains_special()
                for arg in cond.args
                if isinstance(arg.value, SigmaString)
            ]
        ):
            return False

        # All checks passed, expression can be converted to in-expression
        return True

    def convert_condition_as_in_expression(self, cond: Union[ConditionOR, ConditionAND], state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field in value list conditions."""
        if isinstance(cond.args[0],ConditionFieldEqualsValueExpression):
            if isinstance(cond, ConditionAND):
                field = self.escape_and_quote_field(cond.args[0].field)  # The assumption that the field is the same for all argument is valid because this is checked before
                op = self.and_in_operator
                values = [
                    str(field + op + self.convert_value_str(arg.value, state))
                    if isinstance(arg.value, SigmaString)  # string escaping and qouting
                    else str(field + op + arg.value)  # value is number
                    for arg in cond.args
                ]
                values[0] += " " + str(cond.source.path) if cond.source else None
                return " | grep ".join(values)
            
            else:
                return super().convert_condition_as_in_expression(cond, state)
        
        else:
            if isinstance(cond, ConditionAND):
                values = [
                    str(self.convert_value_str(arg.value, state))
                    if isinstance(arg.value, SigmaString)  # string escaping and qouting
                    else str(arg.value)  # value is number
                    for arg in cond.args
                ]
                values[0] += " " + str(cond.source.path) if cond.source else ''
                return " | grep ".join(values)
            
            else:
                return self.field_in_list_expression.format(
                    field = '',
                    op = '',
                    list=self.list_separator.join(
                        [
                            self.convert_value_str(arg.value, state)
                            if isinstance(arg.value, SigmaString)  # string escaping and qouting
                            else str(arg.value)  # value is number
                            for arg in cond.args
                        ]
                    ),
                )
       
    def finalize_query_default(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        # TODO: implement the per-query output for the output format {{ format }} here. Usually, the generated query is
        # embedded into a template, e.g. a JSON format with additional information from the Sigma rule.
        # # TODO: proper type annotation.
        # if hasattr(rule, "eventid"): 
        #     filter = f'-FilterHashTable @{{LogName = "{rule.logsource.service}"; Id = {rule.eventid}}} | '
        # else:
        #     filter = f'-LogName "{rule.logsource.service}" | '
        return f"grep {query} {rule.level}"

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
        return "\n;\n".join(queries)


    
    