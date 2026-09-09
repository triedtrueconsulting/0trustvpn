package gui

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSameOriginGuardRejectsRebinding drives the DNS-rebinding attack the
// Host check exists to stop.
//
// The check used to be `strings.HasPrefix(host, "localhost")`, and a prefix
// test is not a host test: it accepts "localhost.evil.example". That is the
// entire attack. An attacker registers such a name, serves a page from it,
// lets the DNS record rebind to 127.0.0.1, and their page is now SAME-ORIGIN
// with this server. A same-origin GET carries no Origin header, so the Origin
// check never fires — and /api/devices, /api/notices and /api/state all
// answer GET. Any page the customer visited could read their device list,
// mesh IPs and subscription state, on a product whose entire value is that
// nobody gets to see those.
func TestSameOriginGuardRejectsRebinding(t *testing.T) {
	reached := false
	h := withSameOrigin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	cases := []struct {
		name   string
		host   string
		origin string
		method string
		path   string
		allow  bool
	}{
		{"loopback literal", "127.0.0.1:51827", "", "GET", "/api/state", true},
		{"loopback name", "localhost:51827", "", "GET", "/api/state", true},
		{"loopback v6", "[::1]:51827", "", "GET", "/api/state", true},
		{"no port", "localhost", "", "GET", "/api/state", true},

		// The bug, in the two shapes a prefix test lets through.
		{"rebound suffix on the name", "localhost.evil.example:51827", "",
			"GET", "/api/devices", false},
		{"rebound suffix on the literal", "127.0.0.1.evil.example:51827", "",
			"GET", "/api/devices", false},

		{"plain foreign host", "evil.example:51827", "", "GET", "/api/state", false},
		{"foreign host on a POST", "evil.example:51827", "", "POST", "/api/connect", false},

		// Origin is still checked when the browser sends one.
		{"loopback host, foreign origin", "127.0.0.1:51827",
			"http://evil.example", "POST", "/api/connect", false},
		{"loopback host, loopback origin", "127.0.0.1:51827",
			"http://127.0.0.1:51827", "POST", "/api/connect", true},
		// The same suffix trick in the Origin header.
		{"loopback host, near-miss origin", "127.0.0.1:51827",
			"http://localhost.evil.example:51827", "POST", "/api/connect", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reached = false
			req := httptest.NewRequest(tc.method, "http://x"+tc.path, nil)
			req.Host = tc.host
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if tc.allow && !reached {
				t.Fatalf("Host %q Origin %q: blocked, should have been allowed (got %d)",
					tc.host, tc.origin, rec.Code)
			}
			if !tc.allow && reached {
				t.Fatalf("Host %q Origin %q: REACHED THE HANDLER — a web page "+
					"could read this endpoint", tc.host, tc.origin)
			}
			if !tc.allow && rec.Code != http.StatusForbidden {
				t.Fatalf("Host %q: want 403, got %d", tc.host, rec.Code)
			}
		})
	}
}

// The GET endpoints are the exposed half: a same-origin GET sends no Origin
// header, so for those the Host check is the only thing standing there. If a
// method check is ever added to one of these, this test should be updated
// rather than deleted — the point is that they are reachable by GET.
func TestStateEndpointsAnswerGet(t *testing.T) {
	for _, path := range []string{"/api/state", "/api/devices", "/api/notices"} {
		reached := false
		h := withSameOrigin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
		}))
		req := httptest.NewRequest("GET", "http://x"+path, nil)
		req.Host = "localhost.evil.example:51827"
		h.ServeHTTP(httptest.NewRecorder(), req)
		if reached {
			t.Fatalf("%s: a rebound host reached the handler with no Origin header", path)
		}
	}
}
