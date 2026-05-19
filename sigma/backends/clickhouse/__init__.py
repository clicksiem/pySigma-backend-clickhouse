from .clickhouse import ClickhouseBackend

__all__ = ('ClickhouseBackend',)

backends = {
    'clickhouse': ClickhouseBackend,
}
