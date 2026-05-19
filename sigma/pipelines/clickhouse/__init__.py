from .clickhouse import clickhouse_wazuh_pipeline

__all__ = (
    'clickhouse_wazuh_pipeline',
)

pipelines = {
    'clickhouse_wazuh_pipeline': clickhouse_wazuh_pipeline
}
