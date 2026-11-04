package fxmdhttprouter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type captureTransport struct {
	base     http.RoundTripper
	key      string
	ctx      context.Context
	raw      []byte
	headers  http.Header
	status   int
	complete bool
	calls    int
}

func (t *captureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	t.calls++
	if t.calls != 1 {
		t.complete = false
		return nil, errors.New("one upstream request is allowed per route invocation")
	}
	if request == nil || request.URL == nil || request.URL.Scheme != "https" || request.URL.Host != "api.fxmacrodata.com" || request.URL.User != nil || request.URL.Opaque != "" || request.URL.Fragment != "" {
		return nil, errors.New("request origin is not permitted")
	}
	if request.Method != http.MethodGet && request.Method != http.MethodPost {
		return nil, errors.New("only data GET/POST requests are permitted")
	}
	if !strings.HasPrefix(request.URL.Path, "/v1/") {
		return nil, errors.New("only public v1 API paths are permitted")
	}
	for _, segment := range strings.Split(request.URL.Path, "/") {
		if segment == "." || segment == ".." {
			return nil, errors.New("path traversal is forbidden")
		}
	}
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		return nil, errors.New("malformed query encoding")
	}
	for name := range query {
		switch strings.ToLower(name) {
		case "api_key", "apikey", "access_token", "authorization", "x-api-key", "fxmd_api_key", "fxmacrodata_api_key":
			return nil, errors.New("credentials must not appear in query strings")
		}
	}
	copy := request.Clone(t.ctx)
	copy.Host = ""
	copy.Header = make(http.Header)
	copy.Trailer = nil
	copy.TransferEncoding = nil
	copy.ContentLength = 0
	copy.GetBody = nil
	for _, name := range []string{"Accept", "Content-Type", "If-None-Match", "If-Modified-Since"} {
		if value := request.Header.Get(name); value != "" {
			copy.Header.Set(name, value)
		}
	}
	if copy.Header.Get("Accept") == "" {
		copy.Header.Set("Accept", "application/json")
	}
	if t.key != "" {
		copy.Header.Set("X-API-Key", t.key)
	}
	if request.Body != nil {
		defer request.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(request.Body, MaxRequestBytes+1))
		if err != nil || len(raw) > MaxRequestBytes {
			return nil, errors.New("request body exceeds bounds or could not be read")
		}
		copy.Body = io.NopCloser(bytes.NewReader(raw))
		copy.ContentLength = int64(len(raw))
		copy.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil }
	}
	response, err := t.base.RoundTrip(copy)
	if err != nil {
		return nil, errors.New("upstream transport failed")
	}
	if response == nil || response.Body == nil {
		return nil, errors.New("upstream response is empty")
	}
	defer response.Body.Close()
	t.status = response.StatusCode
	raw, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil || len(raw) > MaxResponseBytes {
		return nil, errors.New("response body exceeds bounds or could not be read")
	}
	t.raw = raw
	t.headers = response.Header.Clone()
	t.complete = true
	response.Body = io.NopCloser(bytes.NewReader(raw))
	response.ContentLength = int64(len(raw))
	return response, nil
}
