// Package fxmdhttprouter binds FXMacroData JSON consumers to native HTTPRouter routes.
// It contains no data store, background collector or automatic API proxy.
package fxmdhttprouter

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
	"unicode/utf8"

	sdk "github.com/fxmacrodata/fxmacrodata-go"
	"github.com/julienschmidt/httprouter"
)

const MaxResponseBytes = 4 << 20
const MaxRequestBytes = 4 << 20

type Options struct {
	Timeout time.Duration
	// Transport is optional, primarily for tests and application-owned transports.
	// The origin/method/credential guard still runs before this transport.
	Transport http.RoundTripper
}

type Client struct {
	key     string
	timeout time.Duration
	base    http.RoundTripper
}

// Authorize must enforce the embedding application's own user/data access rules.
// It runs before request construction or upstream access. Nil is never allowed.
type Authorize func(*http.Request) bool

// SDKCall uses the published SDK's complete request builders. The supplied
// context is cancelled with the inbound request. Perform exactly one API call.
type SDKCall func(context.Context, *sdk.APIClient, *http.Request) error

// RequestBuilder constructs a single standard HTTP request to the public API.
// It supports endpoints beyond a particular SDK release without schema changes.
type RequestBuilder func(context.Context, *http.Request) (*http.Request, error)

// NewClient accepts an optional customer-owned key. Empty keys are sent without
// authentication; FXMacroData, rather than the adapter, decides free/paid access.
func NewClient(key string, options Options) (*Client, error) {
	if options.Timeout == 0 {
		options.Timeout = 30 * time.Second
	}
	if options.Timeout < 0 || options.Timeout > 5*time.Minute {
		return nil, errors.New("timeout must be positive and no greater than five minutes")
	}
	if options.Transport == nil {
		options.Transport = &http.Transport{Proxy: nil, MaxIdleConns: 8, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	}
	return &Client{key: key, timeout: options.Timeout, base: options.Transport}, nil
}

// MountSDK registers a native HTTPRouter route with a mandatory application policy.
// The callback may use any operation and parameter in the public Go SDK.
func (c *Client) MountSDK(router *httprouter.Router, method, pattern string, authorize Authorize, call SDKCall) error {
	if call == nil {
		return errors.New("an SDK callback is required")
	}
	return c.mount(router, method, pattern, authorize, func(ctx context.Context, r *http.Request, transport *captureTransport) error {
		config := sdk.NewConfiguration()
		config.Debug = false
		config.UserAgent = "FXMacroData-HTTPRouter/0.1.0"
		config.HTTPClient = guardedHTTPClient(transport, c.timeout)
		return call(ctx, sdk.NewAPIClient(config), r)
	})
}

// MountRequest registers a native route whose trusted application builder uses
// standard HTTP JSON requests. No path, query, response or pagination schema is
// invented by this adapter. Only GET and POST to the fixed API origin are allowed.
func (c *Client) MountRequest(router *httprouter.Router, method, pattern string, authorize Authorize, build RequestBuilder) error {
	if build == nil {
		return errors.New("a request builder is required")
	}
	return c.mount(router, method, pattern, authorize, func(ctx context.Context, r *http.Request, transport *captureTransport) error {
		request, err := build(ctx, r)
		if err != nil {
			return err
		}
		if request == nil {
			return errors.New("request builder returned no request")
		}
		response, err := guardedHTTPClient(transport, c.timeout).Do(request)
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		return err
	})
}

func guardedHTTPClient(transport http.RoundTripper, timeout time.Duration) *http.Client {
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (c *Client) mount(router *httprouter.Router, method, pattern string, authorize Authorize, run func(context.Context, *http.Request, *captureTransport) error) (err error) {
	if c == nil || router == nil || authorize == nil || pattern == "" || pattern[0] != '/' || (method != http.MethodGet && method != http.MethodPost) {
		return errors.New("a client, HTTPRouter router, GET/POST route and explicit authorization policy are required")
	}
	// HTTPRouter rejects invalid or conflicting paths during registration.
	// Convert only synchronous registration panics to configuration errors.
	defer func() {
		if recover() != nil {
			err = errors.New("invalid HTTPRouter route registration")
		}
	}()
	router.Handler(method, pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !authorize(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), c.timeout)
		defer cancel()
		r = r.Clone(ctx)
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBytes)
		}
		captured := &captureTransport{base: c.base, key: c.key, ctx: ctx}
		_ = run(ctx, r, captured)
		// SDK versions can reject unknown response fields. HTTP success plus a
		// complete valid JSON body is the output boundary, preserving all fields.
		if ctx.Err() != nil {
			http.Error(w, "Upstream request timed out or was cancelled", http.StatusGatewayTimeout)
			return
		}
		if captured.complete && captured.status == http.StatusNotModified {
			for _, name := range []string{"ETag", "Last-Modified"} {
				if value := captured.headers.Get(name); value != "" {
					w.Header().Set(name, value)
				}
			}
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if !captured.complete || captured.status < 200 || captured.status >= 300 || !utf8.Valid(captured.raw) || !json.Valid(captured.raw) {
			http.Error(w, "Upstream JSON request failed", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		for _, name := range []string{"ETag", "Last-Modified"} {
			if value := captured.headers.Get(name); value != "" {
				w.Header().Set(name, value)
			}
		}
		w.WriteHeader(captured.status)
		_, _ = w.Write(captured.raw)
	}))
	return nil
}
