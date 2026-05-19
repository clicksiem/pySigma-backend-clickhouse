from sigma.pipelines.common import (
    ProcessingItem,
    logsource_azure_azureactivity,
    logsource_windows,
    windows_logsource_mapping,
)
from sigma.pipelines.base import Pipeline, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation

def clickhouse_wazuh_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="clickhouse wazuh pipeline",
        allowed_backends=frozenset(),
        priority=20,
        items=[
            ProcessingItem(
                identifier="clickhouse_wazuh_fieldmapping",
                transformation=FieldMappingTransformation({"test": ""}),
            )
        ],
    )
