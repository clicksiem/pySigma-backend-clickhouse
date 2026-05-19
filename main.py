from sigma.backends.clickhouse import ClickhouseBackend
from sigma.collection import SigmaCollection


def print_only(backend: ClickhouseBackend):
    sigtest1 = backend.convert(
        SigmaCollection.from_yaml("""
        title: test
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            test:
                alert.a: valueAC
                alert.b: valueB
            condition: test
        """)
    ) 

    sigtest2 = backend.convert(
        SigmaCollection.from_yaml("""
        title: test2
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            test1:
                alert.a: valueA
            test2:
                alert.b: valueB
            condition: 1 of test*
        """)
    ) 

 #   sigtest3 = backend.convert(
 #       SigmaCollection.from_yaml("""
 #       title: test2
 #       status: test
 #       logsource:
 #           category: test_category
 #           product: test_product
 #       detection:
 #           test_list:
 #               - field1
 #               - field2
 #               - field3
 #           condition: test_list
 #       """)
 #   ) 
    print(sigtest1[0])
    print(sigtest2[0])


print_only(ClickhouseBackend())
