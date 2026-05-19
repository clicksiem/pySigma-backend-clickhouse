from collections import defaultdict
from typing import Any, ClassVar, Dict, Union
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.conditions import (
    ConditionFieldEqualsValueExpression,
    ConditionItem,
    ConditionAND,
    ConditionNOT,
    ConditionOR,
)
from sigma.types import (
    CompareOperators,
    SigmaRegularExpressionFlag,
    SigmaRegularExpression,
    SpecialChars,
    TimestampPart,
)
from sigma.correlations import SigmaCorrelationConditionOperator
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.exceptions import SigmaError
import re


class ClickhouseBackend(TextQueryBackend):
    name: ClassVar[str] = "Clickhouse backend"
    formats: ClassVar[Dict[str, str]] = {
        "default": "Plain SQL",
        "clickdetect": "Clickdetect rule format",
    }

    requires_pipeline: ClassVar[bool] = (
        False  # Does the backend requires that a processing pipeline is provided?
    )

    # Backends can offer different methods of correlation query generation. That are described by
    # correlation_methods:
    correlation_methods: ClassVar[dict[str, str] | None] = None
    # The following class variable defines the default method that should be chosen if none is provided.
    default_correlation_method: ClassVar[str] = "default"

    processing_pipeline: ProcessingPipeline | None
    last_processing_pipeline: ProcessingPipeline
    backend_processing_pipeline: ClassVar[ProcessingPipeline] = ProcessingPipeline()
    output_format_processing_pipeline: ClassVar[dict[str, ProcessingPipeline]] = (
        defaultdict(ProcessingPipeline)
    )
    default_format: ClassVar[str] = "default"
    collect_errors: bool = False
    errors: list[tuple[SigmaRule, SigmaError]]

    # Perform finalization on all queries used in a correl
    finalize_correlation_subqueries = False

    # in-expressions
    convert_or_as_in: ClassVar[bool] = False  # Convert OR as in-expression
    convert_and_as_in: ClassVar[bool] = False  # Convert AND as in-expression
    in_expressions_allow_wildcards: ClassVar[bool] = (
        False  # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    )

    # not exists: convert as "not exists-expression" or as dedicated expression
    explicit_not_exists_expression: ClassVar[bool] = False

    # use not_eq_token, not_eq_expression, etc. to implement != as a separate expression instead of not_token in ConditionNOT
    convert_not_as_not_eq: ClassVar[bool] = False

    # Return value for empty AND and OR expressions
    empty_or_expression: ClassVar[str | None] = (
        None  # Value returned when OR expression has no arguments
    )
    empty_and_expression: ClassVar[str | None] = (
        None  # Value returned when AND expression has no arguments
    )
    precedence: ClassVar[
        tuple[type[ConditionItem], type[ConditionItem], type[ConditionItem]]
    ] = (
        ConditionNOT,
        ConditionAND,
        ConditionOR,
    )
    group_expression: ClassVar[str | None] = "{{expr}}"

    parenthesize: bool = False  # Reflect parse tree by putting parenthesis around all expressions - use this for target systems without strict precedence rules.

    # Generated query tokens
    token_separator: str = " "  # separator inserted between all boolean operators
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = "="
    not_eq_token: ClassVar[str | None] = (
        None  # Token inserted between field and value (without separator) if using not_eq_expression over not_token
    )
    eq_expression: ClassVar[str] = (
        "{field}{backend.eq_token}{value}"  # Expression for field = value
    )
    not_eq_expression: ClassVar[str] = (
        "{field}{backend.not_eq_token}{value}"  # Expression for field != value
    )

    # Query structure
    # The generated query can be embedded into further structures. One common example are data
    # source commands that are prepended to the matching condition and specify data repositories or
    # tables from which the data is queried.
    # This is specified as format string that contains the following placeholders:
    # * {query}: The generated query
    # * {rule}: The Sigma rule from which the query was generated
    # * {state}: Conversion state at the end of query generation. This state is initialized with the
    #   pipeline state.
    query_expression: ClassVar[str] = "{query}"
    # The following dict defines default values for the conversion state. They are used if
    # the respective state is not set.
    state_defaults: ClassVar[dict[str, str]] = dict()

    # String output
    ## Fields
    ### Quoting
    field_quote: ClassVar[str | None] = (
        None  # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    )
    field_quote_pattern: ClassVar[re.Pattern[str] | None] = (
        None  # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    )
    field_quote_pattern_negation: ClassVar[bool] = (
        True  # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).
    )

    ### Escaping
    field_escape: ClassVar[str | None] = (
        None  # Character to escape particular parts defined in field_escape_pattern.
    )
    field_escape_quote: ClassVar[bool] = (
        True  # Escape quote string defined in field_quote
    )
    field_escape_pattern: ClassVar[re.Pattern[str] | None] = (
        None  # All matches of this pattern are prepended with the string contained in field_escape.
    )

    # Characters to escape in addition in regular expression representation of string (regex
    # template variable) to default escaping characters.
    add_escaped_re: ClassVar[str] = ""

    ## Values
    ### String quoting
    str_quote: ClassVar[str] = (
        "'"  # string quoting character (added as escaping character)
    )
    str_quote_pattern: ClassVar[re.Pattern[str] | None] = (
        None  # Quote string values that match (or don't match) this pattern
    )
    str_quote_pattern_negation: ClassVar[bool] = True  # Negate str_quote_pattern result
    ### String escaping and filtering
    escape_char: ClassVar[str | None] = (
        "\\"  # Escaping character for special characters inside string
    )

    # TODO: revise this
    wildcard_multi: ClassVar[str | None] = (
        "%"  # Character used as multi-character wildcard
    )

    # TODO: revise this
    wildcard_single: ClassVar[str | None] = (
        "_"  # Character used as single-character wildcard
    )
    # TODO: revise this
    add_escaped: ClassVar[str] = (
        "\\"  # Characters quoted in addition to wildcards and string quote
    )
    filter_chars: ClassVar[str] = ""  # Characters filtered
    ### Booleans
    bool_values: ClassVar[
        dict[bool, str | None]
    ] = {  # Values to which boolean values are mapped.
        True: None,
        False: None,
    }

    # String matching operators. if none is appropriate eq_token (or not_eq_token) is used.
    startswith_expression: ClassVar[str | None] = "{field} LIKE '{value}%'"
    not_startswith_expression: ClassVar[str | None] = "{field} NOT LIKE '{value}%'"
    startswith_expression_allow_special: ClassVar[bool] = False
    endswith_expression: ClassVar[str | None] = "{field} LIKE '%{value}'"
    not_endswith_expression: ClassVar[str | None] = "{field} NOT LIKE '%{value}'"
    endswith_expression_allow_special: ClassVar[bool] = False
    contains_expression: ClassVar[str | None] = "{field} LIKE '%{value}%'"
    not_contains_expression: ClassVar[str | None] = "{field} NOT LIKE '%{value}%'"
    contains_expression_allow_special: ClassVar[bool] = False
    wildcard_match_expression: ClassVar[str | None] = (
        None  # Special expression if wildcards can't be matched with the eq_token operator.
    )

    # Regular expressions
    # Regular expression query as format string with placeholders {field}, {regex}, {flag_x} where x
    # is one of the flags shortcuts supported by Sigma (currently i, m and s) and refers to the
    # token stored in the class variable re_flags.
    re_expression: ClassVar[str | None] = None
    not_re_expression: ClassVar[str | None] = None
    re_escape_char: ClassVar[str] = (
        "\\"  # Character used for escaping in regular expressions
    )
    re_escape: ClassVar[list[str]] = []  # List of strings that are escaped
    re_escape_escape_char: bool = True  # If True, the escape character is also escaped
    re_flag_prefix: bool = True  # If True, the flags are prepended as (?x) group at the beginning of the regular expression, e.g. (?i). If this is not supported by the target, it should be set to False.
    # Mapping from SigmaRegularExpressionFlag values to static string templates that are used in
    # flag_x placeholders in re_expression template.
    # By default, i, m and s are defined. If a flag is not supported by the target query language,
    # remove it from re_flags or don't define it to ensure proper error handling in case of appearance.
    re_flags: dict[SigmaRegularExpressionFlag, str] = (
        SigmaRegularExpression.sigma_to_re_flag
    )

    # Case sensitive string matching expression. String is quoted/escaped like a normal string.
    # Placeholders {field} and {value} are replaced with field name and quoted/escaped string.
    # {regex} contains the value expressed as regular expression.
    case_sensitive_match_expression: ClassVar[str | None] = None
    # Case sensitive string matching operators similar to standard string matching. If not provided,
    # case_sensitive_match_expression is used.
    case_sensitive_startswith_expression: ClassVar[str | None] = None
    case_sensitive_not_startswith_expression: ClassVar[str | None] = None
    case_sensitive_startswith_expression_allow_special: ClassVar[bool] = False
    case_sensitive_endswith_expression: ClassVar[str | None] = None
    case_sensitive_not_endswith_expression: ClassVar[str | None] = None
    case_sensitive_endswith_expression_allow_special: ClassVar[bool] = False
    case_sensitive_contains_expression: ClassVar[str | None] = None
    case_sensitive_not_contains_expression: ClassVar[str | None] = None
    case_sensitive_contains_expression_allow_special: ClassVar[bool] = False

    # CIDR expressions: define CIDR matching if backend has native support. Else pySigma expands
    # CIDR values into string wildcard matches.
    cidr_expression: ClassVar[str | None] = (
        None  # CIDR expression query as format string with placeholders {field}, {value} (the whole CIDR value), {network} (network part only), {prefixlen} (length of network mask prefix) and {netmask} (CIDR network mask only)
    )
    not_cidr_expression: ClassVar[str | None] = None

    # Numeric comparison operators
    compare_op_expression: ClassVar[str | None] = (
        "{field} {operator} {value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    )

    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators: ClassVar[dict[CompareOperators, str] | None] = {
        CompareOperators.LT: "<",
        CompareOperators.LTE: "<=",
        CompareOperators.GT: ">",
        CompareOperators.GTE: ">=",
        CompareOperators.NEQ: "!=",
    }

    # Expression for comparing two event fields
    # Field comparison expression with the placeholders {field1} and {field2} corresponding to left field and right value side of Sigma detection item
    field_equals_field_expression: ClassVar[str | None] = None  # "{field1} = {field2}"
    field_equals_field_startswith_expression: ClassVar[str | None] = None
    field_equals_field_endswith_expression: ClassVar[str | None] = None
    field_equals_field_contains_expression: ClassVar[str | None] = None

    field_timestamp_part_expression: ClassVar[str | None] = None
    """Expression for timestamp part modifiers like |minute, |day, etc."""

    timestamp_part_mapping: ClassVar[dict[TimestampPart, str] | None] = None
    """Mapping to map a TimestampPart enum value to it's string representation of the target SIEM. Example value: '%M' for minute."""

    field_equals_field_escaping_quoting: tuple[bool, bool] = (
        True,
        True,
    )  # If regular field-escaping/quoting is applied to field1 and field2. A custom escaping/quoting can be implemented in the convert_condition_field_eq_field_escape_and_quote method.

    # Null/None expressions
    field_null_expression: ClassVar[str | None] = (
        None  # Expression for field has null value as format string with {field} placeholder for field name
    )

    # Field existence condition expressions.
    field_exists_expression: ClassVar[str | None] = (
        "{field} IS NOT NULL"  # Expression for field existence as format string with {field} placeholder for field name
    )
    field_not_exists_expression: ClassVar[str | None] = (
        "{field} IS NULL"  # Expression for field non-existence as format string with {field} placeholder for field name. If not set, field_exists_expression is negated with boolean NOT.
    )

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    field_in_list_expression: ClassVar[str | None] = (
        "{field} {op} {{list}}"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    )
    or_in_operator: ClassVar[str | None] = (
        "IN"  # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    )
    and_in_operator: ClassVar[str | None] = (
        None  # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    )
    list_separator: ClassVar[str | None] = None  # List element separator

    # Value not bound to a field
    unbound_value_str_expression: ClassVar[str | None] = (
        None  # Expression for string value not bound to a field as format string with placeholder {value} and {regex} (value as regular expression)
    )
    unbound_value_num_expression: ClassVar[str | None] = (
        None  # Expression for number value not bound to a field as format string with placeholder {value} and {regex} (value as regular expression)
    )
    unbound_value_re_expression: ClassVar[str | None] = (
        None  # Expression for regular expression not bound to a field as format string with placeholder {value} and {flag_x} as described for re_expression
    )

    # Query finalization: appending and concatenating deferred query part
    deferred_start: ClassVar[str | None] = (
        ""  # String used as separator between main query and deferred parts
    )
    deferred_separator: ClassVar[str | None] = (
        ""  # String used to join multiple deferred query parts
    )
    deferred_only_query: ClassVar[str] = (
        ""  # String used as query if final query only contains deferred expression
    )

    ### Correlation rule templates
    ## Correlation query frame
    # The correlation query frame is the basic structure of a correlation query for each correlation
    # type. It contains the following placeholders:
    # * {search} is the search expression generated by the correlation query search phase.
    # * {typing} is the event typing expression generated by the correlation query typing phase.
    # * {aggregate} is the aggregation expression generated by the correlation query aggregation
    #   phase.
    # * {condition} is the condition expression generated by the correlation query condition phase.
    # If a correlation query template for a specific correlation type is not defined, the default correlation query template is used.
    default_correlation_query: ClassVar[dict[str, str] | None] = None
    event_count_correlation_query: ClassVar[dict[str, str] | None] = None
    value_count_correlation_query: ClassVar[dict[str, str] | None] = None
    temporal_correlation_query: ClassVar[dict[str, str] | None] = None
    temporal_ordered_correlation_query: ClassVar[dict[str, str] | None] = None
    temporal_extended_correlation_query: ClassVar[dict[str, str] | None] = None
    temporal_ordered_extended_correlation_query: ClassVar[dict[str, str] | None] = None
    value_sum_correlation_query: ClassVar[dict[str, str] | None] = None
    value_avg_correlation_query: ClassVar[dict[str, str] | None] = None
    value_percentile_correlation_query: ClassVar[dict[str, str] | None] = None
    value_median_correlation_query: ClassVar[dict[str, str] | None] = None

    ## Correlation query search phase
    # The first step of a correlation query is to match events described by the referred Sigma
    # rules. A main difference is made between single and multiple rule searches.
    # A single rule search expression defines the search expression emitted if only one rule is
    # referred by the correlation rule. It contains the following placeholders:
    # * {rule} is the referred Sigma rule.
    # * {ruleid} is the rule name or if not available the id of the rule.
    # * {query} is the query generated from the referred Sigma rule.
    # * {normalization} is the expression that normalizes the rule field names to unified alias
    #   field names that can be later used for aggregation. The expression is defined by
    #   correlation_search_field_normalization_expression defined below.
    correlation_search_single_rule_expression: ClassVar[str | None] = None
    # If no single rule query expression is defined, the multi query template expressions below are
    # used and must be suitable for this purpose.

    # A multiple rule search expression defines the search expression emitted if multiple rules are
    # referred by the correlation rule. This is split into the expression for the query itself:
    correlation_search_multi_rule_expression: ClassVar[str | None] = None
    # This template contains only one placeholder {queries} which contains the queries generated
    # from single queries joined with a query separator:
    # * A query template for each query generated from the referred Sigma rules similar to the
    #   search_single_rule_expression defined above:
    correlation_search_multi_rule_query_expression: ClassVar[str | None] = None
    #   Usually the expression must contain some an expression that marks the matched event type as
    #   such, e.g. by using the rule name or uuid.
    # * A joiner string that is put between each search_multi_rule_query_expression:
    correlation_search_multi_rule_query_expression_joiner: ClassVar[str | None] = None

    ## Correlation query typing phase (optional)
    # Event typing expression. In some query languages the initial search query only allows basic
    # boolean expressions without the possibility to mark the matched events with a type, which is
    # especially required by temporal correlation rules to distinguish between the different matched
    # event types.
    # This is the template for the event typing expression that is used to mark the matched events.
    # It contains only a {queries} placeholder that is replaced by the result of joining
    # typing_rule_query_expression with typing_rule_query_expression_joiner defined afterwards.
    typing_expression: ClassVar[str | None] = None
    # This is the template for the event typing expression for each query generated from the
    # referred Sigma rules. It contains the following placeholders:
    # * {rule} is the referred Sigma rule.
    # * {ruleid} is the rule name or if not available the id of the rule.
    # * {query} is the query generated from the referred Sigma rule.
    typing_rule_query_expression: ClassVar[str | None] = None
    # String that is used to join the event typing expressions for each rule query referred by the
    # correlation rule:
    typing_rule_query_expression_joiner: ClassVar[str | None] = None

    # Event field normalization expression. This is used to normalize field names in events matched
    # by the Sigma rules referred by the correlation rule. This is a dictionary mapping from
    # correlation_method names to format strings hat can contain the following placeholders:
    # * {alias} is the field name to which the event field names are normalized and that is used as
    #   group-by field in the aggregation phase.
    # * {field} is the field name from the rule that is normalized.
    # The expression is generated for each Sigma rule referred by the correlation rule and each
    # alias field definition that contains a field definition for the Sigma rule for which the
    # normalization expression is generated. All such generated expressions are joined with the
    # correlation_search_field_normalization_expression_joiner and the result is passed as
    # {normalization} to the correlation_search_*_rule_expression.
    correlation_search_field_normalization_expression: ClassVar[str | None] = None
    correlation_search_field_normalization_expression_joiner: ClassVar[str | None] = (
        None
    )

    ## Correlation query aggregation phase
    # All of the following class variables are dictionaries of mappings from
    # correlation_method names to format strings with the following placeholders:
    # * {rule} contains the whole correlation rule object.
    # * {referenced_rules} contains the Sigma rules that are referred by the correlation rule.
    # * {field} contains the field specified in the condition.
    # * {timespan} contains the timespan converted into the target format by the convert_timespan
    #   method.
    # * {groupby} contains the group by expression generated by the groupby_* templates below.
    # * {search} contains the search expression generated by the correlation query search phase.
    event_count_aggregation_expression: ClassVar[dict[str, str] | None] = (
        None  # Expression for event count correlation rules
    )
    value_count_aggregation_expression: ClassVar[dict[str, str] | None] = (
        None  # Expression for value count correlation rules
    )
    temporal_aggregation_expression: ClassVar[dict[str, str] | None] = (
        None  # Expression for temporal correlation rules
    )
    temporal_ordered_aggregation_expression: ClassVar[dict[str, str] | None] = (
        None  # Expression for ordered temporal correlation rules
    )
    temporal_extended_aggregation_expression: ClassVar[dict[str, str] | None] = (
        None  # Expression for extended temporal correlation rules
    )
    temporal_ordered_extended_aggregation_expression: ClassVar[
        dict[str, str] | None
    ] = None  # Expression for extended ordered temporal correlation rules
    value_sum_aggregation_expression: ClassVar[dict[str, str] | None] = (
        None  # Expression for value sum correlation rules
    )
    value_avg_aggregation_expression: ClassVar[dict[str, str] | None] = (
        None  # Expression for value average correlation rules
    )
    value_percentile_aggregation_expression: ClassVar[dict[str, str] | None] = (
        None  # Expression for value percentile correlation rules
    )
    value_median_aggregation_expression: ClassVar[dict[str, str] | None] = (
        None  # Expression for value median correlation rules
    )

    # Mapping from Sigma timespan to target format timespan specification. This can be:
    # * A dictionary mapping Sigma timespan specifications to target format timespan specifications,
    #   e.g. the Sigma timespan specifier "m" to "min".
    # * None if the target query language uses the same timespan specification as Sigma or expects
    #   seconds (see timespan_seconds) or a custom timespan conversion is implemented in the method
    #   convert_timespan.
    # The mapping can be incomplete. Non-existent timespan specifiers will be passed as-is if no
    # mapping is defined for them.
    timespan_mapping: ClassVar[dict[str, str] | None] = None
    timespan_seconds: ClassVar[bool] = (
        False  # If True, timespan is converted to seconds instead of using a more readable timespan specification like 5m.
    )

    # Expression for a referenced rule as format string with {ruleid} placeholder that is replaced
    # with the rule name or id similar to the search query expression.
    referenced_rules_expression: ClassVar[dict[str, str] | None] = None
    # All referenced rules expressions are joined with the following joiner:
    referenced_rules_expression_joiner: ClassVar[dict[str, str] | None] = None

    # The following class variables defined the templates for the group by expression.
    # First an expression frame is definied:
    groupby_expression: ClassVar[dict[str, str] | None] = {"default": " GROUP BY ALL"}
    # This expression only contains the {fields} placeholder that is replaced by the result of
    # groupby_field_expression for each group by field joined by groupby_field_expression_joiner. The expression template
    # itself can only contain a {field} placeholder for a single field name.
    groupby_field_expression: ClassVar[dict[str, str] | None] = None
    groupby_field_expression_joiner: ClassVar[dict[str, str] | None] = None
    # Groupy by expression in the case that no fields were provided in the correlation rule:
    groupby_expression_nofield: ClassVar[dict[str, str] | None] = None

    # The following class variables defined the templates for the correlation fields expression, which are collecetd from
    # referenced rules and then appended to the correlation rule.
    # First an expression frame is definied:
    correlation_fields_expression: ClassVar[dict[str, str] | None] = None
    # This expression only contains the {fields} placeholder that is replaced by the result of
    # correlation_fields_field_expression for each group by field joined by correlation_fields_field_expression_joiner. The expression template
    # itself can only contain a {field} placeholder for a single field name.
    correlation_fields_field_expression: ClassVar[dict[str, str] | None] = None
    correlation_fields_field_expression_joiner: ClassVar[dict[str, str] | None] = None

    ## Correlation query condition phase
    # The final correlation query phase adds a final filter that filters the aggregated events
    # according to the given conditions. The following class variables define the templates for the
    # different correlation rule types and correlation methods (dict keys).
    # Each template gets the following placeholders:
    # * {op} is the condition operator mapped according o correlation_condition_mapping.
    # * {count} is the value specified in the condition.
    # * {field} is the field specified in the condition.
    # * {referenced_rules} contains the Sigma rules that are referred by the correlation rule. This
    #   expression is generated by the referenced_rules_expression template in combination with the
    #   referenced_rules_expression_joiner defined above.
    # For extended conditions, the template also gets:
    # * {extended_condition} is the parsed extended condition expression with rule references
    #   replaced by appropriate query fragments.
    event_count_condition_expression: ClassVar[dict[str, str] | None] = None
    value_count_condition_expression: ClassVar[dict[str, str] | None] = None
    temporal_condition_expression: ClassVar[dict[str, str] | None] = None
    temporal_ordered_condition_expression: ClassVar[dict[str, str] | None] = None
    temporal_extended_condition_expression: ClassVar[dict[str, str] | None] = None
    temporal_ordered_extended_condition_expression: ClassVar[dict[str, str] | None] = (
        None
    )
    value_sum_condition_expression: ClassVar[dict[str, str] | None] = None
    value_avg_condition_expression: ClassVar[dict[str, str] | None] = None
    value_percentile_condition_expression: ClassVar[dict[str, str] | None] = None
    value_median_condition_expression: ClassVar[dict[str, str] | None] = None
    # The following mapping defines the mapping from Sigma correlation condition operators like
    # "lt", "gte" into the operatpors expected by the target query language.
    correlation_condition_mapping: ClassVar[
        dict[SigmaCorrelationConditionOperator, str | None]
    ] = {
        SigmaCorrelationConditionOperator.LT: "<",
        SigmaCorrelationConditionOperator.LTE: "<=",
        SigmaCorrelationConditionOperator.GT: ">",
        SigmaCorrelationConditionOperator.GTE: ">=",
        SigmaCorrelationConditionOperator.EQ: "=",
        SigmaCorrelationConditionOperator.NEQ: "!=",
    }

    def finalize_query_default(
        self, rule: SigmaRule, query: Any, index: int, state: ConversionState
    ) -> Any:
        return f"SELECT * FROM logs WHERE {query}"
