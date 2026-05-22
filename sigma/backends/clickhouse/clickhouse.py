from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import (
    ConditionItem,
    ConditionAND,
    ConditionOR,
    ConditionNOT,
    ConditionValueExpression,
    ConditionFieldEqualsValueExpression,
)
from sigma.types import (
    CompareOperators,
    SigmaCompareExpression,
    SigmaString,
    SpecialChars,
    TimestampPart,
)
from sigma.correlations import (
    SigmaCorrelationConditionOperator,
    SigmaCorrelationRule,
    SigmaCorrelationTypeLiteral,
)

import re
import yaml
from typing import ClassVar, Dict, List, Optional, Pattern, Tuple, Type, Union, Any


class ClickhouseBackend(TextQueryBackend):
    """ClickHouse backend."""

    name: ClassVar[str] = "ClickHouse backend"
    formats: ClassVar[Dict[str, str]] = {
        "default": "Plain ClickHouse SQL queries",
        "clickdetect": "ClickDetect rule format",
    }
    requires_pipeline: ClassVar[bool] = False

    correlation_methods: ClassVar[Optional[Dict[str, str]]] = {
        "default": "Default ClickHouse correlation using subqueries and aggregate functions",
    }

    precedence: ClassVar[
        tuple[Type[ConditionItem], Type[ConditionItem], Type[ConditionItem]]
    ] = (
        ConditionNOT,
        ConditionAND,
        ConditionOR,
    )
    parenthesize: bool = True
    group_expression: ClassVar[Optional[str]] = "({expr})"

    token_separator: str = " "
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = "="

    # ClickHouse quotes identifiers with backticks (same as MySQL)
    field_quote: ClassVar[Optional[Optional[str]]] = "`"
    field_quote_pattern: ClassVar[Optional[Pattern]] = re.compile("^[a-zA-Z0-9_]*$")
    field_quote_pattern_negation: ClassVar[bool] = True

    str_quote: ClassVar[str] = "'"
    escape_char: ClassVar[Optional[str]] = "\\"
    wildcard_multi: ClassVar[Optional[str]] = "%"
    wildcard_single: ClassVar[Optional[str]] = "_"
    add_escaped: ClassVar[str] = "\\"
    bool_values: ClassVar[Dict[bool, Optional[Optional[str]]]] = {
        True: "true",
        False: "false",
    }

    # ClickHouse ILIKE is case-insensitive (Sigma default), LIKE is case-sensitive.
    # No ESCAPE keyword needed; backslash is the default escape character.
    startswith_expression: ClassVar[Optional[Optional[str]]] = (
        "{field} ILIKE '{value}%'"
    )
    endswith_expression: ClassVar[Optional[Optional[str]]] = "{field} ILIKE '%{value}'"
    contains_expression: ClassVar[Optional[str]] = "{field} ILIKE '%{value}%'"
    wildcard_match_expression: ClassVar[Optional[str]] = "{field} ILIKE '{value}'"

    # Field existence
    field_exists_expression: ClassVar[Optional[str]] = "isNotNull({field})"
    field_not_exists_expression: ClassVar[Optional[str]] = "isNull({field})"

    # Regular expressions use match() in ClickHouse
    re_expression: ClassVar[Optional[str]] = "match({field}, '{regex}')"
    re_escape_char: ClassVar[str] = ""
    re_escape: ClassVar[list[str]] = []
    re_escape_escape_char: bool = True
    re_flag_prefix: bool = True

    # Case-sensitive: LIKE is case-sensitive in ClickHouse for ASCII.
    # Fallback uses match() regex which is always case-sensitive.
    case_sensitive_startswith_expression: ClassVar[Optional[Optional[str]]] = None
    case_sensitive_endswith_expression: ClassVar[Optional[Optional[str]]] = None
    case_sensitive_contains_expression: ClassVar[Optional[Optional[str]]] = None
    case_sensitive_match_expression: ClassVar[Optional[str]] = (
        "match({field}, '{regex}')"
    )

    # CIDR: ClickHouse has native isIPAddressInRange()
    cidr_expression: ClassVar[Optional[str]] = "isIPAddressInRange({field}, '{value}')"

    compare_op_expression: ClassVar[Optional[str]] = "{field} {operator} {value}"

    compare_operators: ClassVar[Optional[dict[CompareOperators, str]]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
        SigmaCompareExpression.CompareOperators.NEQ: "!=",
    }

    field_equals_field_expression: ClassVar[Optional[Optional[str]]] = (
        "{field1}={field2}"
    )
    field_equals_field_startswith_expression: ClassVar[Optional[Optional[str]]] = (
        "{field1} ILIKE {field2} || '%'"
    )
    field_equals_field_endswith_expression: ClassVar[Optional[Optional[str]]] = (
        "{field1} ILIKE '%' || {field2}"
    )
    field_equals_field_contains_expression: ClassVar[Optional[Optional[str]]] = (
        "{field1} ILIKE '%' || {field2} || '%'"
    )
    field_equals_field_escaping_quoting: Tuple[bool, bool] = (True, True)

    # ClickHouse timestamp functions: toHour(), toMinute(), toDayOfMonth(), etc.
    field_timestamp_part_expression: ClassVar[Optional[Optional[str]]] = (
        "{timestamp_part}({field})"
    )
    timestamp_part_mapping: ClassVar[Optional[Dict[TimestampPart, str]]] = {
        TimestampPart.MINUTE: "toMinute",
        TimestampPart.HOUR: "toHour",
        TimestampPart.DAY: "toDayOfMonth",
        TimestampPart.WEEK: "toISOWeek",
        TimestampPart.MONTH: "toMonth",
        TimestampPart.YEAR: "toYear",
    }

    field_null_expression: ClassVar[Optional[str]] = "isNull({field})"

    convert_or_as_in: ClassVar[bool] = True
    convert_and_as_in: ClassVar[bool] = False
    in_expressions_allow_wildcards: ClassVar[bool] = False
    field_in_list_expression: ClassVar[Optional[str]] = "{field} {op} ({list})"
    or_in_operator: ClassVar[Optional[str]] = "IN"
    list_separator: ClassVar[Optional[str]] = ", "

    deferred_start: ClassVar[Optional[str]] = ""
    deferred_separator: ClassVar[Optional[str]] = ""
    deferred_only_query: ClassVar[str] = ""

    # ========== Correlation Rule Templates ==========

    correlation_search_single_rule_expression: ClassVar[Optional[str]] = (
        "SELECT * FROM logs WHERE {query}{normalization}"
    )
    correlation_search_multi_rule_expression: ClassVar[Optional[str]] = "{queries}"
    correlation_search_multi_rule_query_expression: ClassVar[Optional[str]] = (
        "SELECT *, '{ruleid}' AS sigma_rule_id FROM logs WHERE {query}{normalization}"
    )
    correlation_search_multi_rule_query_expression_joiner: ClassVar[Optional[str]] = (
        " UNION ALL "
    )

    correlation_search_field_normalization_expression: ClassVar[Optional[str]] = (
        "{field} AS {alias}"
    )
    correlation_search_field_normalization_expression_joiner: ClassVar[
        Optional[str]
    ] = ", "

    timespan_seconds: ClassVar[bool] = True

    groupby_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": " GROUP BY {fields}",
    }
    groupby_field_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": "{field}",
    }
    groupby_field_expression_joiner: ClassVar[Optional[Dict[str, str]]] = {
        "default": ", ",
    }
    groupby_expression_nofield: ClassVar[Optional[Dict[str, str]]] = {
        "default": "",
    }

    event_count_correlation_query: ClassVar[Optional[Dict[str, str]]] = {
        "default": "SELECT {select_fields}{aggregate} FROM ({search}) AS subquery{groupby} HAVING {condition}",
    }
    event_count_aggregation_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": ", count(*) AS event_count",
    }
    event_count_condition_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": "event_count {op} {count}",
    }

    value_count_correlation_query: ClassVar[Optional[Dict[str, str]]] = {
        "default": "SELECT {select_fields}{aggregate} FROM ({search}) AS subquery{groupby} HAVING {condition}",
    }
    value_count_aggregation_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": ", uniqExact({field}) AS value_count",
    }
    value_count_condition_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": "value_count {op} {count}",
    }

    # toUnixTimestamp() used instead of julianday() for timespan comparison
    temporal_correlation_query: ClassVar[Optional[Dict[str, str]]] = {
        "default": "SELECT {select_fields}{aggregate} FROM ({search}) AS subquery{groupby} HAVING {condition} AND toUnixTimestamp(last_event) - toUnixTimestamp(first_event) <= {timespan}",
    }
    temporal_aggregation_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": ", uniqExact(sigma_rule_id) AS rule_count, min(timestamp) AS first_event, max(timestamp) AS last_event",
    }
    temporal_condition_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": "rule_count {op} {count}",
    }

    temporal_ordered_correlation_query: ClassVar[Optional[Dict[str, str]]] = {
        "default": "SELECT {select_fields}{aggregate} FROM ({search}) AS subquery{groupby} HAVING {condition} AND toUnixTimestamp(last_event) - toUnixTimestamp(first_event) <= {timespan}",
    }
    # groupArray() + arrayStringConcat() replaces GROUP_CONCAT() which ClickHouse doesn't have
    temporal_ordered_aggregation_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": ", arrayStringConcat(groupArray(sigma_rule_id), ',') AS rule_sequence, uniqExact(sigma_rule_id) AS rule_count, min(timestamp) AS first_event, max(timestamp) AS last_event",
    }
    temporal_ordered_condition_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": "rule_count {op} {count}",
    }

    value_sum_correlation_query: ClassVar[Optional[Dict[str, str]]] = {
        "default": "SELECT {select_fields}{aggregate} FROM ({search}) AS subquery{groupby} HAVING {condition}",
    }
    value_sum_aggregation_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": ", sum({field}) AS value_sum",
    }
    value_sum_condition_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": "value_sum {op} {count}",
    }

    value_avg_correlation_query: ClassVar[Optional[Dict[str, str]]] = {
        "default": "SELECT {select_fields}{aggregate} FROM ({search}) AS subquery{groupby} HAVING {condition}",
    }
    value_avg_aggregation_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": ", avg({field}) AS value_avg",
    }
    value_avg_condition_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": "value_avg {op} {count}",
    }

    value_percentile_correlation_query: ClassVar[Optional[Dict[str, str]]] = {
        "default": "SELECT {select_fields}{aggregate} FROM ({search}) AS subquery{groupby} HAVING {condition}",
    }
    value_percentile_aggregation_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": ", quantile({percentile} / 100)({field}) AS value_percentile",
    }
    value_percentile_condition_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": "value_percentile {op} {count}",
    }

    value_median_correlation_query: ClassVar[Optional[Dict[str, str]]] = {
        "default": "SELECT {select_fields}{aggregate} FROM ({search}) AS subquery{groupby} HAVING {condition}",
    }
    value_median_aggregation_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": ", median({field}) AS value_median",
    }
    value_median_condition_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": "value_median {op} {count}",
    }

    correlation_condition_mapping: ClassVar[
        Optional[Dict[SigmaCorrelationConditionOperator, str]]
    ] = {
        SigmaCorrelationConditionOperator.LT: "<",
        SigmaCorrelationConditionOperator.LTE: "<=",
        SigmaCorrelationConditionOperator.GT: ">",
        SigmaCorrelationConditionOperator.GTE: ">=",
        SigmaCorrelationConditionOperator.EQ: "=",
        SigmaCorrelationConditionOperator.NEQ: "!=",
    }

    referenced_rules_expression: ClassVar[Optional[Dict[str, str]]] = {
        "default": "'{ruleid}'",
    }
    referenced_rules_expression_joiner: ClassVar[Optional[Dict[str, str]]] = {
        "default": ", ",
    }

    # unbound_value_str_expression: ClassVar[Optional[str]] = "ILIKE '%{value}%'"
    # unbound_value_num_expression: ClassVar[Optional[str]] = "ILIKE '%{value}%'"

    table: str = ""
    full_log: Optional[str]
    timestamp_field: str = "timestamp"

    # Sigma level to ClickDetect numeric risk score
    _level_map: ClassVar[Dict[str, int]] = {
        "informational": 1,
        "low": 3,
        "medium": 5,
        "high": 8,
        "critical": 10,
    }

    def __init__(
        self,
        processing_pipeline: Optional[ProcessingPipeline] = None,
        collect_errors: bool = False,
        table_name: str = "logs",
        full_log_column: Optional[str] = "full_log",
        **kwargs,
    ):
        super().__init__(processing_pipeline, collect_errors, **kwargs)
        self.table = table_name
        self.full_log = full_log_column

    def convert_correlation_rule_from_template(
        self,
        rule: SigmaCorrelationRule,
        correlation_type: SigmaCorrelationTypeLiteral,
        method: str,
    ) -> List[str]:
        """
        Override to inject {select_fields} and substitute the configurable timestamp_field.
        When GROUP BY is used, only the grouped fields are selected to avoid undefined
        behavior in ClickHouse (unlike SELECT *, GROUP BY in ClickHouse requires selecting
        only grouped columns or aggregate expressions).
        """
        from sigma.exceptions import SigmaConversionError

        template = (
            getattr(self, f"{correlation_type}_correlation_query")
            or self.default_correlation_query
        )
        if template is None:
            raise NotImplementedError(
                f"Correlation rule type '{correlation_type}' is not supported by backend."
            )

        if method not in template:
            raise SigmaConversionError(
                rule,
                rule.source,
                f"Correlation method '{method}' is not supported by backend for correlation type '{correlation_type}'.",
            )

        search = self.convert_correlation_search(rule)

        if rule.group_by:
            select_fields = ", ".join(
                self.escape_and_quote_field(f) for f in rule.group_by
            )
        else:
            select_fields = "*"

        aggregate = self.convert_correlation_aggregation_from_template(
            rule, correlation_type, method, search
        )
        aggregate = aggregate.replace("timestamp", self.timestamp_field)

        query = template[method].format(
            search=search,
            typing=self.convert_correlation_typing(rule),
            timespan=self.convert_timespan(rule.timespan, method),
            aggregate=aggregate,
            condition=self.convert_correlation_condition_from_template(
                rule.condition, rule.rules, correlation_type, method
            ),
            groupby=self.convert_correlation_aggregation_groupby_from_template(
                rule.group_by, method
            ),
            select_fields=select_fields,
        )

        return [query]

    def convert_value_str(
        self,
        s: SigmaString,
        state: ConversionState,
        no_quote: bool = False,
    ) -> str:
        """Convert a SigmaString into a plain string usable in a query."""
        converted = s.convert(
            escape_char=self.escape_char,
            wildcard_multi=self.wildcard_multi,
            wildcard_single=self.wildcard_single,
            add_escaped=self.add_escaped,
            filter_chars=self.filter_chars,
        )
        converted = converted.replace("'", "''")

        if self.decide_string_quoting(s) and not no_quote:
            return self.quote_string(converted)
        else:
            return converted

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = string value expressions."""
        try:
            # ILIKE/LIKE templates already embed single quotes around {value},
            # so we must skip the outer quoting from convert_value_str.
            remove_quote = True

            if (
                self.startswith_expression is not None
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)
                and not cond.value[:-1].contains_special()
            ):
                expr = self.startswith_expression
                value = cond.value[:-1]
            elif (
                self.endswith_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and not cond.value[1:].contains_special()
            ):
                expr = self.endswith_expression
                value = cond.value[1:]
            elif (
                self.contains_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)
                and not cond.value[1:-1].contains_special()
            ):
                expr = self.contains_expression
                value = cond.value[1:-1]
            elif self.wildcard_match_expression is not None and (
                cond.value.contains_special()
                or self.wildcard_multi in cond.value
                or self.wildcard_single in cond.value
                or self.escape_char in cond.value
            ):
                expr = self.wildcard_match_expression
                value = cond.value
            else:
                expr = "{field}" + self.eq_token + "{value}"
                value = cond.value
                remove_quote = False

            return expr.format(
                field=self.escape_and_quote_field(cond.field),
                value=self.convert_value_str(value, state, no_quote=remove_quote),
            )
        except TypeError:  # pragma: no cover
            raise NotImplementedError(
                "Field equals string value expressions are not supported by the backend."
            )

    def finalize_query_default(
        self,
        rule: Union[SigmaRule, SigmaCorrelationRule],
        query: str,
        index: int,
        state: ConversionState,
    ) -> Any:
        if isinstance(rule, SigmaCorrelationRule):
            return query
        return f"SELECT * FROM {self.table} WHERE {query}"

    def finalize_query_clickdetect(
        self,
        rule: Union[SigmaRule, SigmaCorrelationRule],
        query: str,
        index: int,
        state: ConversionState,
    ) -> Any:
        if isinstance(rule, SigmaCorrelationRule):
            sql_query = query
        else:
            sql_query = f"SELECT * FROM {self.table} WHERE {query}"

        level_name = rule.level.name.lower() if rule.level else "informational"
        level_score = self._level_map.get(level_name, 0)

        return {
            "id": str(rule.id) if rule.id else "",
            "name": rule.title or "",
            "level": level_score,
            "size": ">0",
            "active": True,
            "author": [rule.author] if rule.author else [],
            "group": rule.logsource.product or ""
            if not isinstance(rule, SigmaCorrelationRule)
            else "",
            "tags": [str(tag) for tag in rule.tags] if rule.tags else [],
            "rule": sql_query,
        }

    def finalize_output_clickdetect(self, queries: List[Dict]) -> str:
        return yaml.dump(
            list(queries),
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
        )

    def convert_condition_val_str(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        if not self.full_log:
            raise SigmaFeatureNotSupportedByBackendError(
                "Value-only string expressions (i.e Full Text Search or 'keywords' search) are not supported by the backend."
            )

        return "hasToken({field}, {value})".format(
            field=self.full_log, value=self.convert_value_str(cond.value, state)
        )

    def convert_condition_val_num(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:

        if not self.full_log:
            raise SigmaFeatureNotSupportedByBackendError(
                "Value-only number expressions (i.e Full Text Search or 'keywords' search) are not supported by the backend."
            )
        return "hasToken({field}, '{value}')".format(
            field=self.full_log,
            value=cond.value,
        )
