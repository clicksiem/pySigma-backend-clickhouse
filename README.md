## WARNING

This project is under development and does not provide a production ready implementation.

# pySigma Clickhouse Backend

This is the Clickhouse backend for pySigma. It provides the package `sigma.backends.clickhouse` with the `ClickhouseBackend` class.

Further it contains the following processing pipelines under `sigma.pipelines.clickhouse`:
* clickhouse_wazuh_pipeline
* clickhouse_logstash_pipeline

It supports the following output formats for Sigma rules:
* `default`: plain clickhouse SQL querie
* `clicksiem`: rule format for [clickdetect](https://github.com/clicksiem/clickdetect)

# Thanks

To implement this Clickhouse backend I have leanerd a lot of code, and this is my thanks to most helpful to me.
* Thanks for [SQLite implementation](https://github.com/SigmaHQ/pySigma-backend-sqlite/blob/main/sigma/backends/sqlite/sqlite.py)
* Thanks for the incredible blog post [Creating a Sigma Backend for Fun (and no profit)](https://micahbabinski.medium.com/creating-a-sigma-backend-for-fun-and-no-profit-ed16d20da142)

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
