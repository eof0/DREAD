// Concurrent HTTP GET fast-core for DREAD's Probe crawler.
//
// Reads one JSON request object from stdin and writes a JSON array of results to
// stdout. It exists to collapse the many sequential, rate-limited existence probes
// (content discovery over common routes) into one concurrent batch — the request-heavy
// hot path Python is slow at. Stdlib only, so `go build` needs no modules.
package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

type request struct {
	URLs           []string          `json:"urls"`
	TimeoutMs      int               `json:"timeout_ms"`
	Concurrency    int               `json:"concurrency"`
	Headers        map[string]string `json:"headers"`
	Proxy          string            `json:"proxy"`
	MaxBody        int               `json:"max_body"`
	AllowRedirects bool              `json:"allow_redirects"`
	UserAgent      string            `json:"user_agent"`
	// Insecure skips TLS verification — mirrors RequestHandler(verify_ssl=False), for
	// scanning targets with self-signed/broken certs. Defaults to verifying.
	Insecure bool `json:"insecure"`
}

type result struct {
	URL     string            `json:"url"`
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Error   string            `json:"error"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		os.Stdout.WriteString("dread-http-fetch 1.0\n")
		return
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(1)
	}
	var req request
	if err := json.Unmarshal(data, &req); err != nil {
		os.Exit(1)
	}
	if req.Concurrency <= 0 {
		req.Concurrency = 50
	}
	if req.TimeoutMs <= 0 {
		req.TimeoutMs = 8000
	}
	if req.MaxBody <= 0 {
		req.MaxBody = 200000
	}

	// Verify by default (TLS 1.2 minimum); only skip when the caller opts in.
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
	tlsConf.InsecureSkipVerify = req.Insecure
	transport := &http.Transport{TLSClientConfig: tlsConf}
	if req.Proxy != "" {
		if pu, perr := url.Parse(req.Proxy); perr == nil {
			transport.Proxy = http.ProxyURL(pu)
		}
	}
	client := &http.Client{
		Timeout:   time.Duration(req.TimeoutMs) * time.Millisecond,
		Transport: transport,
	}
	if !req.AllowRedirects {
		client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	results := make([]result, len(req.URLs))
	sem := make(chan struct{}, req.Concurrency)
	var wg sync.WaitGroup

	for i, u := range req.URLs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, u string) {
			defer wg.Done()
			defer func() { <-sem }()
			res := result{URL: u, Headers: map[string]string{}}
			httpReq, rerr := http.NewRequest("GET", u, nil)
			if rerr != nil {
				res.Error = rerr.Error()
				results[i] = res
				return
			}
			if req.UserAgent != "" {
				httpReq.Header.Set("User-Agent", req.UserAgent)
			}
			for k, v := range req.Headers {
				httpReq.Header.Set(k, v)
			}
			resp, derr := client.Do(httpReq)
			if derr != nil {
				res.Error = derr.Error()
				results[i] = res
				return
			}
			defer resp.Body.Close()
			res.Status = resp.StatusCode
			for k := range resp.Header {
				res.Headers[k] = resp.Header.Get(k)
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(req.MaxBody)))
			res.Body = string(body)
			results[i] = res
		}(i, u)
	}
	wg.Wait()
	json.NewEncoder(os.Stdout).Encode(results)
}
