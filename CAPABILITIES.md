# Native HTTPRouter capability matrix

All rows use the same two native HTTPRouter registration helpers, `MountSDK` and `MountRequest`, with a mandatory application access policy and an optional customer-owned upstream API key. `httprouter.go` supplies registration/response handling, `transport.go` supplies origin/credential/limit controls and `httprouter_test.go` verifies actual native routing. Every listed family is **native**. Empty-key requests remain unauthenticated and the API decides entitlement. No operator credentials are distributed.

| FXMacroData capability | Target platform surface | Auth model | Implemented files | Tests | Status |
| --- | --- | --- | --- | --- | --- |
| Catalogue/discovery | Native HTTPRouter GET routes and full JSON | Application policy; optional API key | httprouter.go, transport.go | All SDK operations; no-key raw request | native |
| Macro history/releases/revisions | Native HTTPRouter SDK or HTTP callbacks | Application policy; API entitlement | httprouter.go, transport.go | Announcement builders; raw revision/null retention | native |
| Calendar | HTTPRouter URL parameters and SDK callbacks | Application policy; optional API key | httprouter.go, transport.go | Calendar builder; route example | native |
| Predictions/coverage | Complete SDK/HTTP JSON | Application policy; API entitlement | httprouter.go, transport.go | Prediction and coverage builders | native |
| Central-bank press releases | Complete SDK/HTTP JSON | Application policy; API entitlement | httprouter.go, transport.go | Press-release builder | native |
| FX and source/reference metadata | Complete SDK/HTTP JSON | Application policy; API entitlement | httprouter.go, transport.go | All FX/source builders | native |
| COT/commodities | Complete SDK/HTTP JSON | Application policy; API entitlement | httprouter.go, transport.go | COT/commodity builders | native |
| Sessions/financial prices | Complete SDK/HTTP JSON | Application policy; API entitlement | httprouter.go, transport.go | Sessions/financial-price builders | native |
| Curves/factors/differentials/sentiment | Complete SDK/HTTP JSON | Application policy; API entitlement | httprouter.go, transport.go | All corresponding builders | native |
| Research panels | Standard JSON POST body via SDK/HTTP | Application policy; API entitlement | httprouter.go, transport.go | Research body preserved | native |
| Other public v1 JSON (including seasonality/news where entitled) | Standard HTTP request builder, no endpoint whitelist | Application policy; API entitlement | httprouter.go, transport.go | Generic full JSON transport | native |

The SDK callback exposes all 27 published operations and 156 parameters unchanged. The HTTP builder is endpoint agnostic; it does not invent undocumented paths, claim data availability or impose a new data model. The last row verifies the generic transport mechanism, not each live endpoint. Native request-builder tests use fictional responses, not customer data or live endpoint evidence. HTTP APIs outside the public v1 JSON surface, streaming and automatic pagination are not provided by this JSON adapter.
