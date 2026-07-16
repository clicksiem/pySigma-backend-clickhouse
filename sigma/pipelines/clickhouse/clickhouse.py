from sigma.pipelines.common import (
    ProcessingItem,
    logsource_azure_azureactivity,
    logsource_windows,
    windows_logsource_mapping,
)
from sigma.pipelines.base import ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation

clicksiem_mapping: dict[str | None, str | list[str]] = {
    "EventID": "alert.data.win.system.eventID",
    "Channel": "alert.data.win.system.channel",
    "ComputerName": "alert.data.win.system.computer",
    "Image": "data.win.eventdata.image",
    "SubjectUserName": "alert.data.win.eventdata.subjectUserName",
    "TargetUserName": "alert.data.win.eventdata.targetUserName",
}


def clickhouse_clicksiem_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="clickhouse clicksiem pipeline",
        allowed_backends=frozenset(),
        priority=20,
        items=[
            ProcessingItem(
                identifier="clicksiem_mapping",
                transformation=FieldMappingTransformation(clicksiem_mapping),
            )
        ],
    )
