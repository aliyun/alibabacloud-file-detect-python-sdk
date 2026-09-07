2022-07-01 Version: 1.0.0
- First Version.
2022-09-19 Version: 1.0.1
- fix README.md some errors.
2024-04-18 Version: 1.1.0
- add scan compressed files and scan URL files.
2024-09-13 Version: 1.1.1
- Supports global parameter configuration and STS Token.
2025-07-17 Version: 1.1.2
- Fix dependency package versions and add support for endpoint configuration.
2026-09-04 Version: 1.1.3
- Relax the `alibabacloud_tea_openapi` requirement to `>=0.3.3, !=0.3.14, <1.0.0`, so this SDK can be installed alongside packages that need either the previously supported versions or a newer tea-openapi, including `alibabacloud_dysmsapi20170525` 4.6.0. Python 3.6 remains on 0.3.12 because newer tea-openapi releases require Python >=3.7.
- Exclude tea-openapi 0.3.14 because it fails API calls with `AttributeError` for compatible older credential packages even though dependency checks pass.
- Cap `alibabacloud_sas20181203` at `<11.0.0`. Relaxing tea-openapi moved the resolved version from 4.5.3 to 10.1.2, which is generated on `darabonba-core` instead of `alibabacloud_tea`; this release is tested against 10.1.2, and the cap keeps a future major from swapping the stack out silently. Python 3.6 still resolves to 4.5.3.
- Fix HTTP timeouts never being applied. `RuntimeOptions` exposes `connect_timeout` / `read_timeout`; the previous `connectTimeout` / `readTimeout` assignments only created dead attributes and left the real ones at `None`. Because the configured values now take effect for the first time, the default `http_read_timeout` moves to 10000ms to match the 10s the HTTP layer was already falling back to, so behaviour is unchanged. `http_connect_timeout` stays at 6000ms, slightly more lenient than the 5s fallback it replaces.
