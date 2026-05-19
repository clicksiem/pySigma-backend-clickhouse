from sigma.backends.clickhouse import ClickhouseBackend
from sigma.collection import SigmaCollection
import pytest

@pytest.fixture
def backend():
    return ClickhouseBackend()

def test_where(backend: ClickhouseBackend):
    test = backend.convert(
        SigmaCollection.from_yaml("""
        title: test
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            test:
                fieldA: valueA
                fieldB: valueB
            condition: test
        """)
    )
    assert( test == ["SELECT * FROM logs WHERE fieldA='valueA' AND fieldB='valueB'"])
