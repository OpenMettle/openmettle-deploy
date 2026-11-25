# Core contract fixture

`process-contract.json` is an unmodified copy of `runtime/process-contract.json` from [openmettle-core](https://github.com/OpenMettle/openmettle-core) (MIT) at commit `11f86638cdfbea938f3ea3230b38c0bf1bfa79a7`.

`tests/chart/test_chart.py` checks the chart defaults against it. Hosted CI fetches the file at that commit and compares it byte for byte. Change the pin only in an explicit PR that updates the root `CORE_COMMIT` file, refreshes `process-contract.json` (and this note / `UPSTREAM.md`), and reviews any contract change.
