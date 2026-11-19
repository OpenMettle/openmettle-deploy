# Core contract fixture

`process-contract.json` is an unmodified copy of `runtime/process-contract.json` from [openmettle-core](https://github.com/OpenMettle/openmettle-core) (MIT) at commit `5cd8a9dcdd31989eb09adb425115e3d187a5d0e7`.

`tests/chart/test_chart.py` checks the chart defaults against it. Hosted CI fetches the file at that commit and compares it byte for byte. Change the pin only in an explicit PR that renames this directory, updates `CORE_COMMIT` in `.github/workflows/checks.yml` and the test path, and reviews any contract change.
