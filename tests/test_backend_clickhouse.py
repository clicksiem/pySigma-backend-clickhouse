import yaml
import pytest
from sigma.collection import SigmaCollection
from sigma.backends.clickhouse import ClickhouseBackend
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from logging import getLogger

@pytest.fixture
def backend():
    return ClickhouseBackend()


# ==================== Basic Boolean Logic ====================


def test_and_expression(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE fieldA='valueA' AND fieldB='valueB'"]


def test_or_expression(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """)
    ) == ["SELECT * FROM logs WHERE fieldA='valueA' OR fieldB='valueB'"]


def test_and_or_expression(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == [
        "SELECT * FROM logs WHERE (fieldA IN ('valueA1', 'valueA2')) AND (fieldB IN ('valueB1', 'valueB2'))"
    ]


def test_or_and_expression(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """)
    ) == [
        "SELECT * FROM logs WHERE (fieldA='valueA1' AND fieldB='valueB1') OR (fieldA='valueA2' AND fieldB='valueB2')"
    ]


def test_not_condition(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                filter:
                    fieldB: valueB
                condition: sel and not filter
        """)
    ) == ["SELECT * FROM logs WHERE fieldA='valueA' AND (NOT fieldB='valueB')"]


# ==================== String Matching ====================


def test_startswith(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|startswith: value
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE fieldA ILIKE 'value%'"]


def test_endswith(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|endswith: value
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE fieldA ILIKE '%value'"]


def test_contains(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|contains: value
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE fieldA ILIKE '%value%'"]


def test_startswith_with_escaped_wildcard(backend: ClickhouseBackend):
    """Percent sign in value must be escaped for ILIKE."""
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|startswith: wildcard%value
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE fieldA ILIKE 'wildcard\\%value%'"]


def test_endswith_with_escaped_wildcard(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|endswith: wildcard%value
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE fieldA ILIKE '%wildcard\\%value'"]


def test_contains_with_escaped_wildcard(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|contains: wildcard%value
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE fieldA ILIKE '%wildcard\\%value%'"]


def test_wildcard_value_percent_and_underscore(backend: ClickhouseBackend):
    """Both % and _ in plain values must be escaped in ILIKE."""
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: wildcard%value
                    fieldB: wildcard_value
                condition: sel
        """)
    ) == [
        "SELECT * FROM logs WHERE fieldA ILIKE 'wildcard\\%value' AND fieldB ILIKE 'wildcard\\_value'"
    ]


def test_value_with_single_quote(backend: ClickhouseBackend):
    """Single quotes in values must be doubled for SQL safety."""
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: "it's a value"
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE fieldA='it''s a value'"]


# ==================== All Modifier ====================


def test_all_modifier(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|all:
                        - value1
                        - value2
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE fieldA='value1' AND fieldA='value2'"]


def test_all_contains_modifier(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|all|contains:
                        - part1
                        - part2
                condition: sel
        """)
    ) == [
        "SELECT * FROM logs WHERE fieldA ILIKE '%part1%' AND fieldA ILIKE '%part2%'"
    ]


# ==================== Field Name Quoting ====================


def test_field_name_with_whitespace(backend: ClickhouseBackend):
    """Fields with spaces must be backtick-quoted."""
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: value
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE `field name`='value'"]


def test_field_name_with_dot(backend: ClickhouseBackend):
    """Fields with dots must be backtick-quoted."""
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    alert.data.field: value
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE `alert.data.field`='value'"]


def test_plain_field_name_no_quote(backend: ClickhouseBackend):
    """Fields with only alphanumeric and underscore must NOT be quoted."""
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: value
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE fieldA='value'"]


# ==================== Regex ====================


def test_regex(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE match(fieldA, 'foo.*bar') AND fieldB='foo'"]


def test_regex_case_insensitive_flag(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re|i: foo.*bar
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE match(fieldA, '(?i)foo.*bar')"]


# ==================== CIDR ====================


def test_cidr_query(backend: ClickhouseBackend):
    """ClickHouse has native isIPAddressInRange() for CIDR matching."""
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE isIPAddressInRange(field, '192.168.0.0/16')"]


def test_cidr_ipv6(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: "2001:db8::/32"
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE isIPAddressInRange(field, '2001:db8::/32')"]


# ==================== Case-Sensitive ====================


def test_case_sensitive_contains(backend: ClickhouseBackend):
    """Case-sensitive matching uses match() with regex in ClickHouse.
    pySigma converts |contains to .*value.* in regex form."""
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|contains|cased: VaLuE
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE match(fieldA, '.*VaLuE.*')"]


def test_case_sensitive_startswith(backend: ClickhouseBackend):
    """pySigma converts |startswith to value.* in regex form.
    ClickHouse match() anchors at start by default."""
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|startswith|cased: VaLuE
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE match(fieldA, 'VaLuE.*')"]


def test_case_sensitive_endswith(backend: ClickhouseBackend):
    """pySigma converts |endswith to .*value in regex form."""
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|endswith|cased: VaLuE
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE match(fieldA, '.*VaLuE')"]


# ==================== Comparison Modifiers ====================


def test_compare_gt(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|gt: 100
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE fieldA > 100"]


def test_compare_gte(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|gte: 100
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE fieldA >= 100"]


def test_compare_lt(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|lt: 50
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE fieldA < 50"]


def test_compare_lte(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|lte: 50
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE fieldA <= 50"]


# ==================== Timestamp Part Modifiers ====================


def test_timestamp_hour(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    timestamp|hour: 14
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE toHour(timestamp)=14"]


def test_timestamp_minute(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    timestamp|minute: 30
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE toMinute(timestamp)=30"]


def test_timestamp_day(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    timestamp|day: 15
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE toDayOfMonth(timestamp)=15"]


def test_timestamp_week(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    timestamp|week: 42
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE toISOWeek(timestamp)=42"]


def test_timestamp_month(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    timestamp|month: 12
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE toMonth(timestamp)=12"]


def test_timestamp_year(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    timestamp|year: 2024
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE toYear(timestamp)=2024"]


# ==================== Null / Existence ====================


def test_null_value(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: null
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE isNull(fieldA)"]


def test_exists_true(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|exists: true
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE isNotNull(fieldA)"]


def test_exists_false(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|exists: false
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE isNull(fieldA)"]


# ==================== Boolean Values ====================


def test_boolean_true(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: true
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE fieldA=true"]


def test_boolean_false(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: false
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE fieldA=false"]


# ==================== Field Reference (fieldref) ====================


def test_fieldref_equals(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|fieldref: fieldB
                condition: sel
        """)
    ) == ["SELECT * FROM logs WHERE fieldA=fieldB"]


def test_fieldref_multiple_values(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|fieldref:
                        - fieldD
                        - fieldE
                    fieldB: foo
                condition: sel
        """)
    ) == [
        "SELECT * FROM logs WHERE (fieldA=fieldD OR fieldA=fieldE) AND fieldB='foo'"
    ]


# ==================== FTS ====================


def test_fts_keywords_str(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keywords:
                    - value1
                    - value2
                condition: keywords
        """)
    ) == ["SELECT * FROM logs WHERE hasToken(full_log, 'value1') OR hasToken(full_log, 'value2')"]

def test_fts_keywords_num(backend: ClickhouseBackend):
    assert backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    keywords:
                        - 1
                        - 2
                    condition: keywords
            """)
    ) == ["SELECT * FROM logs WHERE hasToken(full_log, '1') OR hasToken(full_log, '2')"]
        

def test_fts_keywords_single_quot_escape(backend: ClickhouseBackend):
    assert backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    keywords:
                        - "'Value1"
                    condition: keywords
            """)
    ) == ["SELECT * FROM logs WHERE hasToken(full_log, '\\'Value1')"]
        


# ==================== Custom Table ====================

def test_custom_table():
    backend = ClickhouseBackend()
    backend.table = "wazuh_alerts_dist"
    result = backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                condition: sel
        """)
    )
    assert result == ["SELECT * FROM wazuh_alerts_dist WHERE fieldA='valueA'"]


# ==================== ClickDetect Output Format ====================


def test_clickdetect_output_basic(backend: ClickhouseBackend):
    rule = SigmaCollection.from_yaml("""
        title: Test Rule
        id: 12345678-1234-1234-1234-123456789012
        status: test
        author: Test Author
        tags:
            - attack.t1234
        level: high
        logsource:
            category: test_category
            product: windows
        detection:
            sel:
                fieldA: value
            condition: sel
    """)
    result = yaml.safe_load(backend.convert(rule, "clickdetect"))
    assert len(result) == 1
    r = result[0]
    assert r["name"] == "Test Rule"
    assert r["id"] == "12345678-1234-1234-1234-123456789012"
    assert r["rule"] == "SELECT * FROM logs WHERE fieldA='value'"
    assert r["level"] == 8
    assert r["active"] is True
    assert r["author"] == ["Test Author"]
    assert "attack.t1234" in r["tags"]


def test_clickdetect_level_mapping(backend: ClickhouseBackend):
    levels = {
        "informational": 1,
        "low": 3,
        "medium": 5,
        "high": 8,
        "critical": 10,
    }
    for sigma_level, expected_score in levels.items():
        rule = SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            level: {sigma_level}
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: value
                condition: sel
        """)
        result = yaml.safe_load(backend.convert(rule, "clickdetect"))
        assert result[0]["level"] == expected_score, f"Failed for level {sigma_level}"


def test_clickdetect_output_is_yaml_list(backend: ClickhouseBackend):
    rule = SigmaCollection.from_yaml("""
        title: Test
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                fieldA: value
            condition: sel
    """)
    raw = backend.convert(rule, "clickdetect")
    parsed = yaml.safe_load(raw)
    assert isinstance(parsed, list)


# ==================== Correlation Rules ====================


def test_correlation_event_count_basic(backend: ClickhouseBackend):
    rules = SigmaCollection.from_yaml("""
        title: Base Rule
        name: base_rule
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                EventID: 1234
            condition: sel
---
        title: Event Count Correlation
        status: test
        correlation:
            type: event_count
            rules: base_rule
            timespan: 5m
            condition:
                gte: 10
    """)
    assert backend.convert(rules) == [
        "SELECT *, count(*) AS event_count FROM (SELECT * FROM logs WHERE EventID=1234) AS subquery HAVING event_count >= 10"
    ]


def test_correlation_event_count_with_groupby(backend: ClickhouseBackend):
    rules = SigmaCollection.from_yaml("""
        title: Base Rule
        name: base_rule
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                EventID: 1234
            condition: sel
---
        title: Event Count with Group By
        status: test
        correlation:
            type: event_count
            rules: base_rule
            group-by:
                - SourceIP
            timespan: 5m
            condition:
                gte: 5
    """)
    assert backend.convert(rules) == [
        "SELECT SourceIP, count(*) AS event_count FROM (SELECT * FROM logs WHERE EventID=1234) AS subquery GROUP BY SourceIP HAVING event_count >= 5"
    ]


def test_correlation_value_count(backend: ClickhouseBackend):
    rules = SigmaCollection.from_yaml("""
        title: Base Rule
        name: base_rule
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                EventID: 1234
            condition: sel
---
        title: Value Count Correlation
        status: test
        correlation:
            type: value_count
            rules: base_rule
            timespan: 5m
            condition:
                field: TargetUserName
                gte: 3
    """)
    assert backend.convert(rules) == [
        "SELECT *, uniqExact(TargetUserName) AS value_count FROM (SELECT * FROM logs WHERE EventID=1234) AS subquery HAVING value_count >= 3"
    ]


def test_correlation_temporal(backend: ClickhouseBackend):
    rules = SigmaCollection.from_yaml("""
        title: Rule A
        name: rule_a
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                EventID: 1234
            condition: sel
---
        title: Rule B
        name: rule_b
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                EventID: 5678
            condition: sel
---
        title: Temporal Correlation
        status: test
        correlation:
            type: temporal
            rules:
                - rule_a
                - rule_b
            timespan: 5m
            group-by:
                - TargetUserName
    """)
    result = backend.convert(rules)
    assert len(result) == 1
    q = result[0]
    assert "uniqExact(sigma_rule_id) AS rule_count" in q
    assert "min(timestamp) AS first_event" in q
    assert "max(timestamp) AS last_event" in q
    assert "GROUP BY TargetUserName" in q
    assert "toUnixTimestamp(last_event) - toUnixTimestamp(first_event) <= 300" in q
    assert "UNION ALL" in q


def test_correlation_value_sum(backend: ClickhouseBackend):
    rules = SigmaCollection.from_yaml("""
        title: Base Rule
        name: base_rule
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                EventID: 1234
            condition: sel
---
        title: Value Sum Correlation
        status: test
        correlation:
            type: value_sum
            rules: base_rule
            timespan: 1h
            condition:
                field: BytesSent
                gte: 1000000
    """)
    assert backend.convert(rules) == [
        "SELECT *, sum(BytesSent) AS value_sum FROM (SELECT * FROM logs WHERE EventID=1234) AS subquery HAVING value_sum >= 1000000"
    ]


def test_correlation_value_avg(backend: ClickhouseBackend):
    rules = SigmaCollection.from_yaml("""
        title: Base Rule
        name: base_rule
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                EventID: 1234
            condition: sel
---
        title: Value Avg Correlation
        status: test
        correlation:
            type: value_avg
            rules: base_rule
            timespan: 1h
            condition:
                field: BytesSent
                gte: 50000
    """)
    assert backend.convert(rules) == [
        "SELECT *, avg(BytesSent) AS value_avg FROM (SELECT * FROM logs WHERE EventID=1234) AS subquery HAVING value_avg >= 50000"
    ]


def test_correlation_condition_operators(backend: ClickhouseBackend):
    """All correlation condition operators must produce the correct SQL operator."""
    operators = {
        "gte": ">=",
        "gt": ">",
        "lte": "<=",
        "lt": "<",
        "eq": "=",
    }
    for sigma_op, sql_op in operators.items():
        rules = SigmaCollection.from_yaml(f"""
            title: Base Rule
            name: base_rule
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    EventID: 1
                condition: sel
---
            title: Correlation
            status: test
            correlation:
                type: event_count
                rules: base_rule
                timespan: 1m
                condition:
                    {sigma_op}: 5
        """)
        result = backend.convert(rules)[0]
        assert f"event_count {sql_op} 5" in result, f"Failed for operator {sigma_op}"


def test_correlation_custom_timestamp_field():
    """The timestamp_field attribute is substituted in temporal aggregate expressions."""
    backend = ClickhouseBackend()
    backend.timestamp_field = "event_time"

    rules = SigmaCollection.from_yaml("""
        title: Base Rule
        name: base_rule
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                EventID: 1234
            condition: sel
---
        title: Temporal Correlation
        status: test
        correlation:
            type: temporal
            rules: base_rule
            timespan: 5m
            condition:
                gte: 2
    """)
    result = backend.convert(rules)[0]
    assert "min(event_time) AS first_event" in result
    assert "max(event_time) AS last_event" in result
    assert "min(timestamp)" not in result
    assert "max(timestamp)" not in result


def test_correlation_select_fields_no_groupby(backend: ClickhouseBackend):
    """Without GROUP BY, select_fields should be * (all columns)."""
    rules = SigmaCollection.from_yaml("""
        title: Base Rule
        name: base_rule
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                EventID: 1234
            condition: sel
---
        title: Event Count
        status: test
        correlation:
            type: event_count
            rules: base_rule
            timespan: 5m
            condition:
                gte: 10
    """)
    result = backend.convert(rules)[0]
    assert result.startswith("SELECT *,")


def test_correlation_select_fields_with_groupby(backend: ClickhouseBackend):
    """With GROUP BY, only the grouped fields should appear in SELECT (not *)."""
    rules = SigmaCollection.from_yaml("""
        title: Base Rule
        name: base_rule
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                EventID: 1234
            condition: sel
---
        title: Event Count with Group By
        status: test
        correlation:
            type: event_count
            rules: base_rule
            group-by:
                - SourceIP
                - UserName
            timespan: 5m
            condition:
                gte: 5
    """)
    result = backend.convert(rules)[0]
    assert result.startswith("SELECT SourceIP, UserName,")
    assert "SELECT *," not in result


# ==================== In-Expression (mixed list) ====================


def test_in_expression_mixed_plain_and_wildcard(backend: ClickhouseBackend):
    """A list with plain values and a wildcard generates OR conditions.
    The wildcard entry uses ILIKE; plain entries use equality."""
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    ) == [
        "SELECT * FROM logs WHERE fieldA='valueA' OR fieldA='valueB' OR fieldA ILIKE 'valueC%'"
    ]


def test_in_expression_all_plain_values(backend: ClickhouseBackend):
    """A list of purely plain values generates OR-equality conditions."""
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - val1
                        - val2
                        - val3
                condition: sel
        """)
    ) == [
        "SELECT * FROM logs WHERE fieldA IN ('val1', 'val2', 'val3')"
    ]


# ==================== All + Startswith / Endswith ====================


def test_all_startswith_modifier(backend: ClickhouseBackend):
    """All values must match as startswith — generates AND ILIKE conditions."""
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|all|startswith:
                        - cmd
                        - pow
                condition: sel
        """)
    ) == [
        "SELECT * FROM logs WHERE fieldA ILIKE 'cmd%' AND fieldA ILIKE 'pow%'"
    ]


def test_all_endswith_modifier(backend: ClickhouseBackend):
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|all|endswith:
                        - .exe
                        - .dll
                condition: sel
        """)
    ) == [
        "SELECT * FROM logs WHERE fieldA ILIKE '%.exe' AND fieldA ILIKE '%.dll'"
    ]


# ==================== Correlation: Temporal Ordered ====================


def test_correlation_temporal_ordered(backend: ClickhouseBackend):
    """Ordered temporal correlation uses arrayStringConcat(groupArray()) instead of GROUP_CONCAT."""
    rules = SigmaCollection.from_yaml("""
        title: Rule A
        name: rule_a
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                EventID: 1
            condition: sel
---
        title: Rule B
        name: rule_b
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                EventID: 2
            condition: sel
---
        title: Temporal Ordered Correlation
        status: test
        correlation:
            type: temporal_ordered
            rules:
                - rule_a
                - rule_b
            timespan: 5m
            group-by:
                - UserName
    """)
    result = backend.convert(rules)[0]
    assert "arrayStringConcat(groupArray(sigma_rule_id), ',') AS rule_sequence" in result
    assert "uniqExact(sigma_rule_id) AS rule_count" in result
    assert "min(timestamp) AS first_event" in result
    assert "max(timestamp) AS last_event" in result
    assert "GROUP BY UserName" in result
    assert "toUnixTimestamp(last_event) - toUnixTimestamp(first_event) <= 300" in result


# ==================== Correlation: Value Count with Group By ====================


def test_correlation_value_count_with_groupby(backend: ClickhouseBackend):
    """Value count with group-by selects only the grouped fields."""
    rules = SigmaCollection.from_yaml("""
        title: Base Rule
        name: base_rule
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                EventID: 1234
            condition: sel
---
        title: Value Count with Group By
        status: test
        correlation:
            type: value_count
            rules: base_rule
            group-by:
                - SourceIP
            timespan: 5m
            condition:
                field: TargetUserName
                gte: 3
    """)
    assert backend.convert(rules) == [
        "SELECT SourceIP, uniqExact(TargetUserName) AS value_count FROM (SELECT * FROM logs WHERE EventID=1234) AS subquery GROUP BY SourceIP HAVING value_count >= 3"
    ]


# ==================== Correlation: NEQ Condition Operator ====================


def test_correlation_condition_neq(backend: ClickhouseBackend):
    """NEQ operator in correlation condition maps to !=."""
    rules = SigmaCollection.from_yaml("""
        title: Base Rule
        name: base_rule
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                EventID: 1
            condition: sel
---
        title: Event Count NEQ
        status: test
        correlation:
            type: event_count
            rules: base_rule
            timespan: 1m
            condition:
                neq: 5
    """)
    result = backend.convert(rules)[0]
    assert "event_count != 5" in result


# ==================== ClickDetect: Extra Field Validation ====================


def test_clickdetect_required_fields(backend: ClickhouseBackend):
    """All required ClickDetect fields must be present in every rule output."""
    rule = SigmaCollection.from_yaml("""
        title: Minimal Rule
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                fieldA: value
            condition: sel
    """)
    result = yaml.safe_load(backend.convert(rule, "clickdetect"))
    r = result[0]
    for field in ("id", "name", "level", "size", "active", "author", "group", "tags", "rule"):
        assert field in r, f"Missing required field: {field}"


def test_clickdetect_rule_contains_sql(backend: ClickhouseBackend):
    """The 'rule' field in ClickDetect output must contain a SELECT statement."""
    rule = SigmaCollection.from_yaml("""
        title: Test
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                fieldA: value
            condition: sel
    """)
    result = yaml.safe_load(backend.convert(rule, "clickdetect"))
    assert result[0]["rule"].startswith("SELECT * FROM logs WHERE")
