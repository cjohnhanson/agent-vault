package mitm

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// TestMITMForwardMatchedPassthrough401BodyIntact: a 401 from the upstream on a
// MATCHED service with no injectable headers (auth: passthrough) must be
// relayed to the client complete — status, WWW-Authenticate challenge, AND
// body. The OAuth-401-retry path used to close the upstream body before
// discovering it had nothing to retry with, so the client saw the 401's
// headers with a Content-Length it could never satisfy. That truncation
// breaks standard HTTP auth negotiation: git's probe-then-retry basic auth
// aborts on the incomplete response and reports "Authentication failed"
// even though its credential was valid.
func TestMITMForwardMatchedPassthrough401BodyIntact(t *testing.T) {
	const challengeBody = "Repository not found."
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, challengeBody)
			return
		}
		_, _ = io.WriteString(w, "authed-ok")
	}))
	defer upstream.Close()

	upstreamHost, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	// A matched passthrough service: no headers to inject, Passthrough is
	// false (that flag marks only the unmatched-host-allow case).
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{
			MatchedName: "github-git",
			MatchedHost: upstreamHost,
		}},
	}}

	proxyURL, clientRoots, _ := setupProxy(t, sr, cp)
	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)

	// Unauthenticated probe — the first half of git's auth handshake.
	resp, err := client.Get(upstream.URL + "/repo.git/info/refs")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got == "" {
		t.Errorf("WWW-Authenticate challenge missing from relayed 401")
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading 401 body: %v (body truncated — auth negotiation breaks)", err)
	}
	if string(body) != challengeBody {
		t.Errorf("401 body = %q, want %q", body, challengeBody)
	}

	// Authenticated retry — the second half — must pass through untouched.
	req, _ := http.NewRequest("GET", upstream.URL+"/repo.git/info/refs", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatalf("authed retry: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("authed retry status = %d, want 200", resp2.StatusCode)
	}
	body2, _ := io.ReadAll(resp2.Body)
	if string(body2) != "authed-ok" {
		t.Errorf("authed body = %q, want authed-ok", body2)
	}
}
