# pySigma Clickhouse Backend

This is the Clickhouse backend for pySigma. It provides the package `sigma.backends.clickhouse` with the `ClickhouseBackend` class.

It supports the following output formats for Sigma rules:
* `default`: plain clickhouse SQL querie
* `clicksiem`: rule format for [clickdetect](https://github.com/clicksiem/clickdetect)

# Thanks

To implement this Clickhouse backend I have leanerd a lot of code, and this is my thanks to most helpful to me.
* Thanks for [SQLite implementation](https://github.com/SigmaHQ/pySigma-backend-sqlite/blob/main/sigma/backends/sqlite/sqlite.py)
* Thanks for the incredible blog post [Creating a Sigma Backend for Fun (and no profit)](https://micahbabinski.medium.com/creating-a-sigma-backend-for-fun-and-no-profit-ed16d20da142)

# How To

### Converting sigma to clickhouse 

```python
from sigma.backends.clickhouse.clickhouse import ClickhouseBackend
from sigma.collection import SigmaCollection

rule = """
title: Run Whoami Showing Privileges
id: 97a80ec7-0e2f-4d05-9ef4-65760e634f6b
status: experimental
description: Detects a whoami.exe executed with the /priv command line flag instructing the tool to show all current user privieleges. This is often used after a privilege escalation attempt. 
references:
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/whoami
author: Florian Roth
date: 2021/05/05
modified: 2022/05/13
tags:
    - attack.privilege_escalation
    - attack.discovery
    - attack.t1033
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\whoami.exe'
        - OriginalFileName: 'whoami.exe'
    selection_cli:
        CommandLine|contains: '/priv'
    condition: all of selection*
falsepositives:
    - Administrative activity (rare lookups on current privileges)
level: high
"""

backend = ClickhouseBackend()
rule_sigma = SigmaCollection.from_yaml(rule)
print(backend.convert(rule_sigma)[0])
```

# Maintainer

Created an maintaned by `souzo`

- [https://github.com/souzomain](https://github.com/souzomain)
- [https://medium.com/@souzo](https://medium.com/@souzo)

# Dev

Setup your dev environment

```sh
uv sync
source .venv/bin/activate
```
