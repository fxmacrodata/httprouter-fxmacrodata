package fxmdhttprouter

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/fxmacrodata/fxmacrodata-go"
	"github.com/julienschmidt/httprouter"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func upstream(status int, raw string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(raw))}
}
func allowFixture(*http.Request) bool { return true }
func health(ctx context.Context, api *sdk.APIClient, _ *http.Request) error {
	_, _, err := api.FXMacroDataAPI.GetHealth(ctx).Execute()
	return err
}
func mustClient(t *testing.T, key string, base http.RoundTripper) *Client {
	t.Helper()
	c, err := NewClient(key, Options{Transport: base})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNativeHTTPRouterPolicyBlocksBeforeRequestConstruction(t *testing.T) {
	c := mustClient(t, "fictional-fixture-key", roundTrip(func(*http.Request) (*http.Response, error) {
		t.Fatal("unauthorized request dispatched")
		return nil, nil
	}))
	r := httprouter.New()
	if err := c.MountSDK(r, "GET", "/data", nil, health); err == nil {
		t.Fatal("nil policy accepted")
	}
	if err := c.MountSDK(r, "GET", "/data", func(*http.Request) bool { return false }, func(context.Context, *sdk.APIClient, *http.Request) error {
		t.Fatal("callback ran before authorization")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	out := httptest.NewRecorder()
	r.ServeHTTP(out, httptest.NewRequest("GET", "/data", nil))
	if out.Code != 403 || out.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(out.Code, out.Header())
	}
}

func TestSDKHandlerPreservesFullJSONDespiteUnknownFields(t *testing.T) {
	raw := ` {"status":"ok","service":"fixture","future":{"n":9007199254740993,"decimal":1.2300,"missing":null,"data":[]}} `
	c := mustClient(t, "fictional-fixture-key", roundTrip(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("X-API-Key") != "fictional-fixture-key" || req.Header.Get("Authorization") != "" {
			t.Fatal("incorrect headers")
		}
		return upstream(200, raw), nil
	}))
	r := httprouter.New()
	if err := c.MountSDK(r, "GET", "/data", allowFixture, health); err != nil {
		t.Fatal(err)
	}
	out := httptest.NewRecorder()
	r.ServeHTTP(out, httptest.NewRequest("GET", "/data", nil))
	if out.Code != 200 || out.Body.String() != raw || out.Header().Get("Content-Type") != "application/json" {
		t.Fatal(out.Code, out.Body.String())
	}
}

func TestRawRequestSupportsAdditionalPublicJSONWithoutKey(t *testing.T) {
	calls := 0
	raw := `{"currency":"USD","data":[],"quality":{"source":"fictional"},"new_field":null}`
	c := mustClient(t, "", roundTrip(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Header.Get("X-API-Key") != "" || req.Header.Get("Cookie") != "" || req.Header.Get("Authorization") != "" {
			t.Fatal("incoming credentials forwarded")
		}
		if req.URL.Query().Get("limit") != "0" {
			t.Fatal("query changed")
		}
		return upstream(200, raw), nil
	}))
	r := httprouter.New()
	err := c.MountRequest(r, "GET", "/macro/:currency", allowFixture, func(ctx context.Context, in *http.Request) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", "https://api.fxmacrodata.com/v1/data_catalogue/"+httprouter.ParamsFromContext(in.Context()).ByName("currency")+"?limit=0", nil)
		req.Header.Set("Authorization", "fictional incoming identity")
		req.Header.Set("Cookie", "fictional incoming cookie")
		return req, err
	})
	if err != nil {
		t.Fatal(err)
	}
	out := httptest.NewRecorder()
	r.ServeHTTP(out, httptest.NewRequest("GET", "/macro/USD", nil))
	if out.Code != 200 || out.Body.String() != raw || calls != 1 {
		t.Fatal(out.Code, out.Body.String(), calls)
	}
}

func TestOriginMethodTraversalAndQueryCredentialGuards(t *testing.T) {
	for _, tc := range []struct{ method, url string }{
		{"GET", "https://foreign.example/v1/data"}, {"GET", "http://api.fxmacrodata.com/v1/data"}, {"GET", "https://api.fxmacrodata.com:443/v1/data"}, {"DELETE", "https://api.fxmacrodata.com/v1/data"}, {"GET", "https://api.fxmacrodata.com/private"}, {"GET", "https://api.fxmacrodata.com/v1/../private"}, {"GET", "https://api.fxmacrodata.com/v1/data?api_key=fictional"},
	} {
		t.Run(tc.url, func(t *testing.T) {
			c := mustClient(t, "fictional-fixture-key", roundTrip(func(*http.Request) (*http.Response, error) {
				t.Fatal("blocked request reached transport")
				return nil, nil
			}))
			r := httprouter.New()
			err := c.MountRequest(r, "GET", "/data", allowFixture, func(ctx context.Context, _ *http.Request) (*http.Request, error) {
				return http.NewRequestWithContext(ctx, tc.method, tc.url, nil)
			})
			if err != nil {
				t.Fatal(err)
			}
			out := httptest.NewRecorder()
			r.ServeHTTP(out, httptest.NewRequest("GET", "/data", nil))
			if out.Code != 502 {
				t.Fatal(out.Code)
			}
		})
	}
}

func TestRedirectAndPrivateErrorsDoNotLeak(t *testing.T) {
	for _, status := range []int{302, 401, 403, 429, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			c := mustClient(t, "fictional-fixture-key", roundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				r := upstream(status, `{"private":"fictional-fixture-key"}`)
				r.Header.Set("Location", "https://foreign.example/")
				r.Header.Set("Set-Cookie", "private=fictional")
				return r, nil
			}))
			r := httprouter.New()
			if err := c.MountSDK(r, "GET", "/data", allowFixture, health); err != nil {
				t.Fatal(err)
			}
			out := httptest.NewRecorder()
			r.ServeHTTP(out, httptest.NewRequest("GET", "/data", nil))
			if out.Code != 502 || calls != 1 || strings.Contains(out.Body.String(), "fictional") || out.Header().Get("Set-Cookie") != "" {
				t.Fatal(out.Code, out.Body.String(), calls)
			}
		})
	}
}

func TestCancellationAndConcurrentRequestIsolation(t *testing.T) {
	c := mustClient(t, "", roundTrip(func(req *http.Request) (*http.Response, error) {
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		default:
		}
		return upstream(200, `{"value":"`+req.URL.Query().Get("value")+`"}`), nil
	}))
	r := httprouter.New()
	if err := c.MountRequest(r, "GET", "/data", allowFixture, func(ctx context.Context, in *http.Request) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, "GET", "https://api.fxmacrodata.com/v1/health?value="+in.URL.Query().Get("value"), nil)
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := httptest.NewRecorder()
	r.ServeHTTP(out, httptest.NewRequest("GET", "/data", nil).WithContext(ctx))
	if out.Code != 504 {
		t.Fatal(out.Code)
	}
	var wait sync.WaitGroup
	for _, value := range []string{"first", "second", "third"} {
		wait.Add(1)
		go func(value string) {
			defer wait.Done()
			out := httptest.NewRecorder()
			r.ServeHTTP(out, httptest.NewRequest("GET", "/data?value="+value, nil))
			if out.Code != 200 || out.Body.String() != `{"value":"`+value+`"}` {
				t.Error("response crossed request boundary", out.Code, out.Body.String())
			}
		}(value)
	}
	wait.Wait()
}

func TestInvalidJSONResponseAndBodyLimits(t *testing.T) {
	for _, raw := range []string{"not JSON", strings.Repeat("x", MaxResponseBytes+1)} {
		c := mustClient(t, "", roundTrip(func(*http.Request) (*http.Response, error) { return upstream(200, raw), nil }))
		r := httprouter.New()
		if err := c.MountSDK(r, "GET", "/data", allowFixture, health); err != nil {
			t.Fatal(err)
		}
		out := httptest.NewRecorder()
		r.ServeHTTP(out, httptest.NewRequest("GET", "/data", nil))
		if out.Code != 502 {
			t.Fatal("invalid response accepted")
		}
	}
	c := mustClient(t, "", roundTrip(func(*http.Request) (*http.Response, error) {
		t.Fatal("oversized body reached upstream")
		return nil, nil
	}))
	r := httprouter.New()
	if err := c.MountRequest(r, "POST", "/data", allowFixture, func(ctx context.Context, _ *http.Request) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, "POST", "https://api.fxmacrodata.com/v1/research/panel", strings.NewReader(strings.Repeat("x", MaxRequestBytes+1)))
	}); err != nil {
		t.Fatal(err)
	}
	out := httptest.NewRecorder()
	r.ServeHTTP(out, httptest.NewRequest("POST", "/data", nil))
	if out.Code != 502 {
		t.Fatal(out.Code)
	}
	if _, err := NewClient("", Options{Timeout: -time.Second}); err == nil {
		t.Fatal("negative timeout accepted")
	}
}

func TestSecondUpstreamRequestIsRejected(t *testing.T) {
	calls := 0
	c := mustClient(t, "", roundTrip(func(*http.Request) (*http.Response, error) {
		calls++
		return upstream(200, `{"status":"ok","service":"fixture"}`), nil
	}))
	r := httprouter.New()
	if err := c.MountSDK(r, "GET", "/data", allowFixture, func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
		_ = health(ctx, api, in)
		return health(ctx, api, in)
	}); err != nil {
		t.Fatal(err)
	}
	out := httptest.NewRecorder()
	r.ServeHTTP(out, httptest.NewRequest("GET", "/data", nil))
	if calls != 1 || out.Code != 502 {
		t.Fatal("multiple request attempt did not fail closed", calls, out.Code)
	}
}

func TestAllSDKOperationsAndParametersThroughNativeHTTPRouterRoutes(t *testing.T) {
	cases := []struct {
		name, route, path string
		call              SDKCall
	}{
		{name: "GetAnnouncementChanges", route: "/v1/announcements/changes", path: "/v1/announcements/changes", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.GetAnnouncementChanges(ctx)
			r = r.Currencies("fixture")
			r = r.Indicators("fixture")
			r = r.Since("fixture")
			r = r.Limit(int64(0))
			r = r.Payload("fixture")
			_, _, err := r.Execute()
			return err
		}},
		{name: "GetAnnouncements", route: "/v1/announcements/:currency/:indicator", path: "/v1/announcements/USD/cpi", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.GetAnnouncements(ctx, httprouter.ParamsFromContext(in.Context()).ByName("currency"), httprouter.ParamsFromContext(in.Context()).ByName("indicator"))
			r = r.StartDate("fixture")
			r = r.EndDate("fixture")
			r = r.SeriesMode("fixture")
			r = r.Limit(int64(0))
			r = r.Offset(int64(0))
			r = r.Page(int64(0))
			r = r.Seasonality("fixture")
			r = r.Frequency("fixture")
			r = r.Annualization("fixture")
			r = r.PeriodAggregation("fixture")
			r = r.Revisions("fixture")
			r = r.Basis("fixture")
			r = r.OfficialOnly(false)
			r = r.AsOf("fixture")
			r = r.Availability("fixture")
			r = r.DatasetVersion("fixture")
			r = r.ValueMode("fixture")
			_, _, err := r.Execute()
			return err
		}},
		{name: "GetCalendar", route: "/v1/calendar/:currency", path: "/v1/calendar/USD", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.GetCalendar(ctx, httprouter.ParamsFromContext(in.Context()).ByName("currency"))
			r = r.Indicator("fixture")
			r = r.StartDate("fixture")
			r = r.EndDate("fixture")
			r = r.Timezone("fixture")
			_, _, err := r.Execute()
			return err
		}},
		{name: "GetCommodities", route: "/v1/commodities/:indicator", path: "/v1/commodities/cpi", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.GetCommodities(ctx, httprouter.ParamsFromContext(in.Context()).ByName("indicator"))
			r = r.StartDate("fixture")
			r = r.EndDate("fixture")
			r = r.Limit(int64(0))
			r = r.Offset(int64(0))
			r = r.Page(int64(0))
			_, _, err := r.Execute()
			return err
		}},
		{name: "GetCot", route: "/v1/cot/:currency", path: "/v1/cot/USD", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.GetCot(ctx, httprouter.ParamsFromContext(in.Context()).ByName("currency"))
			r = r.StartDate("fixture")
			r = r.EndDate("fixture")
			r = r.Limit(int64(0))
			r = r.Offset(int64(0))
			r = r.Page(int64(0))
			_, _, err := r.Execute()
			return err
		}},
		{name: "GetCurves", route: "/v1/curves/:currency", path: "/v1/curves/USD", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.GetCurves(ctx, httprouter.ParamsFromContext(in.Context()).ByName("currency"))
			r = r.CurveFamily("fixture")
			r = r.Metric("fixture")
			r = r.View("fixture")
			r = r.Method("fixture")
			r = r.Date("fixture")
			r = r.AsOf("fixture")
			r = r.Availability("fixture")
			r = r.MaxStalenessDays(int64(0))
			r = r.RequireCommonDate(false)
			_, _, err := r.Execute()
			return err
		}},
		{name: "GetDataCatalogue", route: "/v1/data_catalogue/:currency", path: "/v1/data_catalogue/USD", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.GetDataCatalogue(ctx, httprouter.ParamsFromContext(in.Context()).ByName("currency"))
			r = r.IncludeCapabilities(false)
			r = r.IncludeCoverage(false)
			r = r.Indicator("fixture")
			_, _, err := r.Execute()
			return err
		}},
		{name: "GetFactor", route: "/v1/factors/:currency/:factor", path: "/v1/factors/USD/carry", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.GetFactor(ctx, httprouter.ParamsFromContext(in.Context()).ByName("currency"), httprouter.ParamsFromContext(in.Context()).ByName("factor"))
			r = r.StartDate("fixture")
			r = r.EndDate("fixture")
			r = r.IncludeComponents(false)
			r = r.IncludeSources(false)
			r = r.Limit(int64(0))
			r = r.Offset(int64(0))
			_, _, err := r.Execute()
			return err
		}},
		{name: "GetFinancialPrices", route: "/v1/financial_prices/:currency", path: "/v1/financial_prices/USD", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.GetFinancialPrices(ctx, httprouter.ParamsFromContext(in.Context()).ByName("currency"))
			r = r.Source("fixture")
			r = r.StartDate("fixture")
			r = r.EndDate("fixture")
			r = r.Measure("fixture")
			r = r.InstrumentId("fixture")
			r = r.Issuer("fixture")
			r = r.Limit(int64(0))
			r = r.Offset(int64(0))
			_, _, err := r.Execute()
			return err
		}},
		{name: "GetForex", route: "/v1/forex/:base/:quote", path: "/v1/forex/USD/EUR", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.GetForex(ctx, httprouter.ParamsFromContext(in.Context()).ByName("base"), httprouter.ParamsFromContext(in.Context()).ByName("quote"))
			r = r.StartDate("fixture")
			r = r.EndDate("fixture")
			r = r.Limit(int64(0))
			r = r.Offset(int64(0))
			r = r.Page(int64(0))
			r = r.Indicators("fixture")
			r = r.DatasetVersion("fixture")
			_, _, err := r.Execute()
			return err
		}},
		{name: "GetFxIntradayReferenceRates", route: "/v1/fx/intraday-reference-rates/:base/:quote", path: "/v1/fx/intraday-reference-rates/USD/EUR", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.GetFxIntradayReferenceRates(ctx, httprouter.ParamsFromContext(in.Context()).ByName("base"), httprouter.ParamsFromContext(in.Context()).ByName("quote"))
			r = r.StartTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			r = r.EndTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			_, _, err := r.Execute()
			return err
		}},
		{name: "GetFxReferenceRates", route: "/v1/fx/reference-rates/:base/:quote", path: "/v1/fx/reference-rates/USD/EUR", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.GetFxReferenceRates(ctx, httprouter.ParamsFromContext(in.Context()).ByName("base"), httprouter.ParamsFromContext(in.Context()).ByName("quote"))
			r = r.Date("fixture")
			r = r.StartDate("fixture")
			r = r.EndDate("fixture")
			r = r.Source("fixture")
			r = r.TimestampType("fixture")
			r = r.NativeOnly(false)
			r = r.IncludeSourceLegs(false)
			r = r.Order("fixture")
			r = r.Limit(int64(0))
			r = r.Offset(int64(0))
			r = r.Page(int64(0))
			r = r.DatasetVersion("fixture")
			_, _, err := r.Execute()
			return err
		}},
		{name: "GetFxSessionRates", route: "/v1/fx/session-rates/:base/:quote", path: "/v1/fx/session-rates/USD/EUR", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.GetFxSessionRates(ctx, httprouter.ParamsFromContext(in.Context()).ByName("base"), httprouter.ParamsFromContext(in.Context()).ByName("quote"))
			r = r.Session("fixture")
			r = r.Date("fixture")
			r = r.StartDate("fixture")
			r = r.EndDate("fixture")
			r = r.Order("fixture")
			r = r.Limit(int64(0))
			r = r.Offset(int64(0))
			r = r.Page(int64(0))
			r = r.DatasetVersion("fixture")
			_, _, err := r.Execute()
			return err
		}},
		{name: "GetFxSourceUniverse", route: "/v1/fx/source-universe", path: "/v1/fx/source-universe", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.GetFxSourceUniverse(ctx)
			r = r.Currency("fixture")
			r = r.Source("fixture")
			_, _, err := r.Execute()
			return err
		}},
		{name: "GetFxSources", route: "/v1/fx/sources", path: "/v1/fx/sources", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.GetFxSources(ctx)
			_, _, err := r.Execute()
			return err
		}},
		{name: "GetHealth", route: "/v1/health", path: "/v1/health", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.GetHealth(ctx)
			_, _, err := r.Execute()
			return err
		}},
		{name: "GetLatestAnnouncements", route: "/v1/announcements/:currency/latest", path: "/v1/announcements/USD/latest", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.GetLatestAnnouncements(ctx, httprouter.ParamsFromContext(in.Context()).ByName("currency"))
			_, _, err := r.Execute()
			return err
		}},
		{name: "GetLatestCommodities", route: "/v1/commodities/latest", path: "/v1/commodities/latest", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.GetLatestCommodities(ctx)
			_, _, err := r.Execute()
			return err
		}},
		{name: "GetMarketSessions", route: "/v1/market_sessions", path: "/v1/market_sessions", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.GetMarketSessions(ctx)
			r = r.At("fixture")
			_, _, err := r.Execute()
			return err
		}},
		{name: "GetPredictionCoverage", route: "/v1/predictions/coverage", path: "/v1/predictions/coverage", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.GetPredictionCoverage(ctx)
			_, _, err := r.Execute()
			return err
		}},
		{name: "GetPredictionCoverageForCurrency", route: "/v1/predictions/coverage/:currency", path: "/v1/predictions/coverage/USD", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.GetPredictionCoverageForCurrency(ctx, httprouter.ParamsFromContext(in.Context()).ByName("currency"))
			_, _, err := r.Execute()
			return err
		}},
		{name: "GetPredictions", route: "/v1/predictions/:currency/:indicator", path: "/v1/predictions/USD/cpi", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.GetPredictions(ctx, httprouter.ParamsFromContext(in.Context()).ByName("currency"), httprouter.ParamsFromContext(in.Context()).ByName("indicator"))
			r = r.PredictionClass("fixture")
			r = r.PredictionType("fixture")
			r = r.PredictionSource("fixture")
			r = r.OfficialLimit(int64(0))
			r = r.PreReleaseOnly(false)
			r = r.Seasonality("fixture")
			r = r.Frequency("fixture")
			r = r.Annualization("fixture")
			r = r.PeriodAggregation("fixture")
			r = r.Basis("fixture")
			r = r.StartDate("fixture")
			r = r.EndDate("fixture")
			r = r.Limit(int64(0))
			r = r.Offset(int64(0))
			r = r.Page(int64(0))
			r = r.BeforeDate("fixture")
			r = r.AsOf("fixture")
			r = r.EventCompatibleOnly(false)
			_, _, err := r.Execute()
			return err
		}},
		{name: "GetPressReleases", route: "/v1/press-releases/:currency", path: "/v1/press-releases/USD", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.GetPressReleases(ctx, httprouter.ParamsFromContext(in.Context()).ByName("currency"))
			r = r.Limit(int64(0))
			r = r.Offset(int64(0))
			_, _, err := r.Execute()
			return err
		}},
		{name: "GetRateDifferentials", route: "/v1/rate_differentials/:base/:quote", path: "/v1/rate_differentials/USD/EUR", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.GetRateDifferentials(ctx, httprouter.ParamsFromContext(in.Context()).ByName("base"), httprouter.ParamsFromContext(in.Context()).ByName("quote"))
			r = r.Measure("fixture")
			r = r.RateType("fixture")
			r = r.CurveFamily("fixture")
			r = r.StartTenorYears(1.5)
			r = r.EndTenorYears(1.5)
			r = r.StartDate("fixture")
			r = r.EndDate("fixture")
			r = r.Limit(int64(0))
			r = r.Offset(int64(0))
			r = r.AsOf("fixture")
			r = r.Availability("fixture")
			_, _, err := r.Execute()
			return err
		}},
		{name: "GetRiskSentiment", route: "/v1/risk_sentiment", path: "/v1/risk_sentiment", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.GetRiskSentiment(ctx)
			r = r.StartDate("fixture")
			r = r.EndDate("fixture")
			r = r.Limit(int64(0))
			r = r.Offset(int64(0))
			_, _, err := r.Execute()
			return err
		}},
		{name: "Ping", route: "/v1/ping", path: "/v1/ping", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.Ping(ctx)
			_, _, err := r.Execute()
			return err
		}},
		{name: "ResearchPanel", route: "/v1/research/panel", path: "/v1/research/panel", call: func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
			r := api.FXMacroDataAPI.ResearchPanel(ctx)
			var body sdk.ResearchPanelRequest
			_ = json.Unmarshal([]byte(`{"series":[],"decision_times":[],"start_date":"2026-01-01","end_date":"2026-01-02"}`), &body)
			r = r.ResearchPanelRequest(body)
			_, _, err := r.Execute()
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			c := mustClient(t, "fictional-fixture-key", roundTrip(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.URL.Path != tc.path || req.Header.Get("X-API-Key") == "" {
					t.Fatal("native route lost path arguments", req.URL.Path)
				}
				if req.Method == "POST" {
					raw, _ := io.ReadAll(req.Body)
					if !bytes.Contains(raw, []byte("decision_times")) {
						t.Fatal("research body lost")
					}
				}
				return upstream(400, `{"fixture":true}`), nil
			}))
			router := httprouter.New()
			if err := c.MountSDK(router, "GET", tc.route, allowFixture, tc.call); err != nil {
				t.Fatal(err)
			}
			out := httptest.NewRecorder()
			router.ServeHTTP(out, httptest.NewRequest("GET", tc.path, nil))
			if calls != 1 || out.Code != 502 {
				t.Fatal("operation was not dispatched", calls, out.Code, out.Body.String())
			}
		})
	}
}

func TestConditionalResponseAndTrailerCredentialIsolation(t *testing.T) {
	c := mustClient(t, "", roundTrip(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("If-None-Match") != "fixture-etag" || len(req.Trailer) != 0 {
			t.Fatal("conditional header lost or trailers leaked")
		}
		r := upstream(304, "")
		r.Header.Set("ETag", "fixture-etag")
		r.Header.Set("Set-Cookie", "private=fictional")
		return r, nil
	}))
	router := httprouter.New()
	err := c.MountRequest(router, "GET", "/data", allowFixture, func(ctx context.Context, _ *http.Request) (*http.Request, error) {
		r, err := http.NewRequestWithContext(ctx, "GET", "https://api.fxmacrodata.com/v1/health", nil)
		r.Header.Set("If-None-Match", "fixture-etag")
		r.Trailer = http.Header{"Authorization": []string{"fictional trailer"}}
		return r, err
	})
	if err != nil {
		t.Fatal(err)
	}
	out := httptest.NewRecorder()
	router.ServeHTTP(out, httptest.NewRequest("GET", "/data", nil))
	if out.Code != 304 || out.Body.Len() != 0 || out.Header().Get("ETag") != "fixture-etag" || out.Header().Get("Set-Cookie") != "" {
		t.Fatal(out.Code, out.Header(), out.Body.String())
	}
}

func TestMalformedQueryEncodingIsRejectedBeforeTransport(t *testing.T) {
	c := mustClient(t, "fictional-fixture-key", roundTrip(func(*http.Request) (*http.Response, error) { t.Fatal("malformed query dispatched"); return nil, nil }))
	router := httprouter.New()
	if err := c.MountRequest(router, "GET", "/data", allowFixture, func(ctx context.Context, _ *http.Request) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, "GET", "https://api.fxmacrodata.com/v1/health?api_key=%invalid", nil)
	}); err != nil {
		t.Fatal(err)
	}
	out := httptest.NewRecorder()
	router.ServeHTTP(out, httptest.NewRequest("GET", "/data", nil))
	if out.Code != 502 {
		t.Fatal(out.Code)
	}
}

func TestNativeHTTPRouterParamsLookupAndMethodMatching(t *testing.T) {
	calls := 0
	client := mustClient(t, "", roundTrip(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.Path != "/v1/calendar/USD" {
			t.Fatal("native variable lost", req.URL.Path)
		}
		return upstream(200, `{"currency":"USD","data":[]}`), nil
	}))
	router := httprouter.New()
	if err := client.MountSDK(router, "GET", "/macro/calendar/:currency", allowFixture, func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
		_, _, err := api.FXMacroDataAPI.GetCalendar(ctx, httprouter.ParamsFromContext(in.Context()).ByName("currency")).Execute()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	handle, params, redirect := router.Lookup("GET", "/macro/calendar/USD")
	if handle == nil || params.ByName("currency") != "USD" || redirect {
		t.Fatal("native lookup mismatch")
	}
	for _, tc := range []struct {
		method, path string
		status       int
	}{{"GET", "/macro/calendar/USD", 200}, {"GET", "/macro/calendar/USD/", 301}, {"POST", "/macro/calendar/USD", 405}, {"GET", "/macro/calendar/", 404}} {
		out := httptest.NewRecorder()
		router.ServeHTTP(out, httptest.NewRequest(tc.method, tc.path, nil))
		if out.Code != tc.status {
			t.Fatal(tc, out.Code, out.Body.String())
		}
	}
	if calls != 1 {
		t.Fatal("redirect/method rejection reached upstream", calls)
	}
}
func TestNativeHTTPRouterCatchAllContext(t *testing.T) {
	client := mustClient(t, "", roundTrip(func(*http.Request) (*http.Response, error) { return upstream(200, `{"data":[]}`), nil }))
	router := httprouter.New()
	if err := client.MountRequest(router, "GET", "/files/*resource", allowFixture, func(ctx context.Context, in *http.Request) (*http.Request, error) {
		if httprouter.ParamsFromContext(in.Context()).ByName("resource") != "/macro/calendar" {
			t.Fatal("catch-all context lost")
		}
		return http.NewRequestWithContext(ctx, "GET", "https://api.fxmacrodata.com/v1/health", nil)
	}); err != nil {
		t.Fatal(err)
	}
	out := httptest.NewRecorder()
	router.ServeHTTP(out, httptest.NewRequest("GET", "/files/macro/calendar", nil))
	if out.Code != 200 {
		t.Fatal(out.Code)
	}
}
func TestNativeHTTPRouterRegistrationErrors(t *testing.T) {
	client := mustClient(t, "", roundTrip(func(*http.Request) (*http.Response, error) {
		t.Fatal("registration dispatched request")
		return nil, nil
	}))
	if err := client.MountSDK(httprouter.New(), "GET", "/calendar/:", allowFixture, health); err == nil {
		t.Fatal("unnamed wildcard accepted")
	}
	router := httprouter.New()
	if err := client.MountSDK(router, "GET", "/calendar/:currency", allowFixture, health); err != nil {
		t.Fatal(err)
	}
	if err := client.MountSDK(router, "GET", "/calendar/:currency", allowFixture, health); err == nil {
		t.Fatal("duplicate route accepted")
	}
}
