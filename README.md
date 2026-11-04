# FXMacroData for HTTPRouter

Connect FXMacroData to native HTTPRouter routes in your Go application. The adapter uses public API requests, preserves complete JSON responses, and requires your application's own access policy before any route can fetch data. It contains no data collector, datastore, automatic API proxy or built-in user authorization decision.

```go
client, err := fxmdhttprouter.NewClient(os.Getenv("FXMD_API_KEY"), fxmdhttprouter.Options{})
if err != nil { return err }
// authorize is your application's policy for the caller and requested data.
err = client.MountSDK(router, "GET", "/macro/calendar/:currency", authorize,
    func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
        _, _, err := api.FXMacroDataAPI.GetCalendar(ctx,
            httprouter.ParamsFromContext(in.Context()).ByName("currency")).Execute()
        return err
    })
```

Use an empty key for unauthenticated public requests. The API enforces each customer's coverage and entitlements; the adapter does not guess which requests require a key. USD catalogue, history and calendar requests can use the public client flow. An application route still requires an explicit access policy, even when its upstream request is public. For protected data, use your own key from your application's secret store. Do not expose a shared paid key's data to callers unless your agreement and application access rules permit it.

## Complete response and request access

`MountSDK` callbacks retain every operation and parameter in the published Go SDK v0.1.0: 27 operations and 156 required-path/query/body parameters. `MountRequest` instead accepts a builder returning a standard `*http.Request`, supporting any public `/v1/` GET or POST JSON operation without an endpoint dispatch table or replacement data schema. Build only the endpoint your application intends; there is no generic incoming-path forwarding route.

Successful HTTP JSON is returned byte-for-byte, including unknown fields, original numeric spelling, pagination, provenance, quality flags, nulls, revisions and timestamps. SDK response-decoding errors caused by unknown fields do not narrow a successful complete JSON response. No values, release times, forecasts or future events are inferred. Pagination remains explicit and each route invocation permits one upstream request. Handle multiple pages as separate authorized invocations.

## Request and access boundaries

Nil policies/builders are refused. Access denial occurs before building a request. Outgoing requests go only to `https://api.fxmacrodata.com/v1/`, using GET or POST. Redirects, other origins, userinfo, path traversal, credential query strings and extra upstream calls are blocked. Inbound cookies and Authorization headers are not forwarded; the configured customer key is added only after the origin check. Only JSON/request-conditional headers are retained; cookies, authorization and trailers from the built request are discarded. A public HTTP 304 conditional response retains its status and validators without a body. Responses expose JSON plus ETag/Last-Modified when supplied, with `Cache-Control: no-store` and `nosniff`.

Requests and responses are limited to 4 MiB. The default timeout is 30 seconds, configurable up to five minutes. Inbound cancellation reaches the outgoing transport. API failures, redirects, invalid JSON and oversized bodies become a generic HTTP 502 without private bodies, URLs or credentials; timeout/cancellation becomes 504; an application policy denial becomes 403. These local error responses are adapter errors, not FXMacroData observations. Trusted application callbacks must perform a single bounded request; they are ordinary Go code and are not sandboxed by the library.

## Example and verification

`examples/router` constructs a native route protected by a deny policy, prints its registration, and exits. It starts no server and makes no API request. Replace the policy with your application's own checks. Tests use native HTTPRouter routing and an in-memory transport with fictional JSON, covering every SDK request builder/parameter, access denial, raw response preservation, concurrent isolation, redirects, cancellation, limits and credential scoping. They do not test a live API account.

This release uses HTTPRouter v1.3.0 and FXMacroData Go SDK v0.1.0. [FXMacroData](https://fxmacrodata.com/?utm_source=github&utm_medium=integration&utm_campaign=open_source&utm_content=httprouter_fxm) supplies official-source macroeconomic data. This companion adapter is independent of the HTTPRouter project; no endorsement is implied. Code is MIT licensed; API data access and redistribution rights remain governed by each customer's plan and agreement.

Native paths use named parameters such as `/macro/calendar/:currency` and terminal catch-all parameters such as `/files/*resource`. Read them with `httprouter.ParamsFromContext(in.Context()).ByName("currency")`. Prefix your registered paths to group routes. HTTPRouter handles method mismatches and its configured redirects before upstream access. It does not support regex route constraints or subrouters; enforce input constraints in the application policy. Invalid or conflicting registration returns a configuration error. Discard and rebuild the router after a registration error, since the native tree has no rollback contract. The offline example uses native `Lookup` without starting a server.
