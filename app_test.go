package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xuri/excelize/v2"
)

func runProcessLines(lines []string, options ProcessOptions, counters *Counters, logs *[]string) []string {
	return processLines(context.Background(), newProcessControl(), lines, options, counters, logs)
}

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "bare host", in: "example.com/path", want: "http://example.com/path"},
		{name: "uppercase scheme", in: "HTTPS://Example.com/path", want: "https://Example.com/path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeURL(tt.in); got != tt.want {
				t.Fatalf("normalizeURL(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestNormalizeURLRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{
		"",
		"ftp://example.com",
		"http://",
		"http://example.com:0",
		"http://example.com:65536",
		"http://example .com",
		"http://117.71.47.8089",
	} {
		if got := normalizeURL(input); got != "" {
			t.Errorf("normalizeURL(%q) = %q, want empty", input, got)
		}
	}
}

func TestNormalizeURLAcceptsTCPEndpoint(t *testing.T) {
	for _, input := range []string{
		"tcp://117.71.47.102",
		"tcp://117.71.47.102:18081",
	} {
		if got := normalizeURL(input); got != input {
			t.Errorf("normalizeURL(%q) = %q, want %q", input, got, input)
		}
		if got := getHost(input); got != "117.71.47.102" {
			t.Errorf("getHost(%q) = %q, want 117.71.47.102", input, got)
		}
	}
}

func TestProcessLinesAcceptsTCPEndpoint(t *testing.T) {
	var counters Counters
	var logs []string
	got := runProcessLines([]string{"tcp://117.71.47.102"}, ProcessOptions{
		EnableDedup: true,
		RemoveProto: false,
	}, &counters, &logs)
	if len(got) != 1 || got[0] != "tcp://117.71.47.102" {
		t.Fatalf("expected TCP endpoint to be kept, got results=%#v logs=%#v", got, logs)
	}
}

func TestNormalizeURLExtractsURLFromCopiedText(t *testing.T) {
	tests := map[string]string{
		"http://h.ucallclub.com:9038   这个是跳转到上方的 URL（http 转 https）": "http://h.ucallclub.com:9038",
		"\"https://h.ucallclub.com:9070/": "https://h.ucallclub.com:9070/",
	}
	for input, want := range tests {
		if got := normalizeURL(input); got != want {
			t.Errorf("normalizeURL(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestExtractAssets(t *testing.T) {
	app := &App{}
	input := `http://public.example.com:8080/api?id=1
https://sub.example.com/
192.168.1.10:80
8.8.8.8:53
foo.example.com
http://invalid.example.com:99999`

	got := app.ExtractAssets(input, true)
	if !containsString(got.URLs, "http://public.example.com:8080/api?id=1") {
		t.Fatalf("expected public URL, got %#v", got.URLs)
	}
	if !containsString(got.URLs, "https://sub.example.com/") {
		t.Fatalf("expected HTTPS URL, got %#v", got.URLs)
	}
	if !containsString(got.RootDomains, "example.com") {
		t.Fatalf("expected root domain, got %#v", got.RootDomains)
	}
	if !containsString(got.Subdomains, "public.example.com") || !containsString(got.Subdomains, "sub.example.com") || !containsString(got.Subdomains, "foo.example.com") {
		t.Fatalf("expected subdomains, got %#v", got.Subdomains)
	}
	if containsString(got.IPs, "192.168.1.10") {
		t.Fatalf("private IP should be filtered, got %#v", got.IPs)
	}
	if !containsString(got.IPs, "8.8.8.8") || !containsString(got.CNetworks, "8.8.8.0/24") {
		t.Fatalf("expected public IP and C network, got IPs=%#v CNetworks=%#v", got.IPs, got.CNetworks)
	}
	if containsString(got.URLs, "http://invalid.example.com:99999") {
		t.Fatalf("invalid port URL should not be extracted, got %#v", got.URLs)
	}
}

func TestExtractAssetsDoesNotTreatURLPathsAsDomains(t *testing.T) {
	app := &App{}
	input := `电信电视团队	[http://ahdx.tv.game.vcache.cn:18081/api/gateway.do](http://ahdx.tv.game.vcache.cn:18081/api/gateway.do)
电信电视团队	[http://ahdx.tv.game.vcache.cn:18082/web/epg/epg.html](http://117.71.47.101:18082/web/epg/epg.html)
电信电视团队	http://117.71.47.141:18081/bgtjdd/static/games/redhat/index.html
电信电视团队	http://117.71.47.8089/zabbix`

	got := app.ExtractAssets(input, false)
	if !containsString(got.RootDomains, "vcache.cn") {
		t.Fatalf("expected vcache.cn, got %#v", got.RootDomains)
	}
	for _, unwanted := range []string{"gateway.do", "epg.html", "index.html", "47.8089"} {
		if containsString(got.RootDomains, unwanted) {
			t.Fatalf("path or malformed IP %q was extracted as root domain: %#v", unwanted, got.RootDomains)
		}
	}
	if containsString(got.URLs, "http://ahdx.tv.game.vcache.cn:18081/api/gateway.do](http://ahdx.tv.game.vcache.cn:18081/api/gateway.do)") {
		t.Fatalf("markdown delimiters were included in URL result: %#v", got.URLs)
	}
}

func TestExtractAssetsAcceptsEndpointFormats(t *testing.T) {
	app := &App{}
	input := `http://ahdx.tv.game.vcache.cn:18081/api/gateway.do
http://ahdx.tv.game.vcache.cn:18082
http://117.71.47.141:18081/bgtjdd/static/games/redhat/index.html
http://117.71.47.102/
117.71.47.102:18081
117.71.47.102
tcp://117.71.47.102
ahdx.tv.game.vcache.cn
ahdx.tv.game.vcache.cn:18082
http://117.71.47.102
http://ahdx.tv.game.vcache.cn`

	got := app.ExtractAssets(input, false)
	for _, want := range []string{
		"http://ahdx.tv.game.vcache.cn:18081/api/gateway.do",
		"http://ahdx.tv.game.vcache.cn:18082",
		"http://117.71.47.141:18081/bgtjdd/static/games/redhat/index.html",
		"http://117.71.47.102/",
		"tcp://117.71.47.102",
		"http://117.71.47.102",
		"http://ahdx.tv.game.vcache.cn",
	} {
		if !containsString(got.URLs, want) {
			t.Errorf("expected URL %q, got %#v", want, got.URLs)
		}
	}
	if !containsString(got.RootDomains, "vcache.cn") {
		t.Errorf("expected root domain vcache.cn, got %#v", got.RootDomains)
	}
	if !containsString(got.Subdomains, "ahdx.tv.game.vcache.cn") {
		t.Errorf("expected subdomain ahdx.tv.game.vcache.cn, got %#v", got.Subdomains)
	}
	if !containsString(got.IPs, "117.71.47.102") || !containsString(got.IPs, "117.71.47.141") {
		t.Errorf("expected IPv4 assets, got %#v", got.IPs)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestGetHost(t *testing.T) {
	tests := map[string]string{
		"http://Example.com:8080/path":             "example.com",
		"https://user:pass@[2001:db8::1]:443/path": "2001:db8::1",
		"http://example.com.":                      "example.com",
	}

	for input, want := range tests {
		if got := getHost(input); got != want {
			t.Errorf("getHost(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestAssetRootDomainUsesPublicSuffixRules(t *testing.T) {
	tests := map[string]string{
		"aaa.com":                "aaa.com",
		"a.bbb.com":              "bbb.com",
		"api.example.com.cn":     "example.com.cn",
		"console.example.co.uk":  "example.co.uk",
		"service.example.com.au": "example.com.au",
		"a.github.io":            "a.github.io",
		"EXAMPLE.COM.":           "example.com",
	}
	for input, want := range tests {
		if got := assetRootDomain(input); got != want {
			t.Errorf("assetRootDomain(%q) = %q, want %q", input, got, want)
		}
	}
	for _, input := range []string{"", "localhost", "127.0.0.1", "bad host"} {
		if got := assetRootDomain(input); got != "" {
			t.Errorf("assetRootDomain(%q) = %q, want empty", input, got)
		}
	}
}

func TestNormalizeProcessOptions(t *testing.T) {
	opts := normalizeProcessOptions(ProcessOptions{
		Timeout:      -1,
		Threads:      1000,
		AllowedCodes: map[int]bool{200: true, 99: true, 600: true, 301: false},
	})

	if opts.Timeout != defaultTimeoutSeconds {
		t.Errorf("Timeout = %d, want %d", opts.Timeout, defaultTimeoutSeconds)
	}
	if opts.Threads != defaultThreads {
		t.Errorf("Threads = %d, want %d", opts.Threads, defaultThreads)
	}
	if !opts.AllowedCodes[200] || len(opts.AllowedCodes) != 1 {
		t.Errorf("AllowedCodes = %#v, want only 200", opts.AllowedCodes)
	}
	if opts.BlackDomains == nil || opts.WhiteDomains == nil {
		t.Fatal("domain maps should be initialized")
	}
}

func TestProcessLinesPreservesInputOrder(t *testing.T) {
	lines := []string{"z.example", "a.example", "m.example"}
	logs := []string{}
	results := runProcessLines(lines, ProcessOptions{
		EnableDedup: true,
		RemoveProto: true,
		Threads:     3,
	}, &Counters{}, &logs)

	wantResults := []string{"z.example", "a.example", "m.example"}
	if strings.Join(results, "\n") != strings.Join(wantResults, "\n") {
		t.Fatalf("results = %#v, want %#v", results, wantResults)
	}
	for i, line := range logs[:len(lines)] {
		if !strings.HasSuffix(line, lines[i]) {
			t.Errorf("log %d = %q, want input %q", i, line, lines[i])
		}
	}
}

func TestWriteLogsAndProcessError(t *testing.T) {
	path := t.TempDir() + "\\url-filter.log"
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	app := &App{logFile: file}
	if err := app.writeLogs([]string{"first", "second"}); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "first\nsecond\n" {
		t.Fatalf("log contents = %q", data)
	}

	if _, err := (&App{}).ProcessURLs("example.com", ProcessOptions{Threads: 1}); err == nil {
		t.Fatal("ProcessURLs should return an error when the log file is unavailable")
	}
}

func TestFilterPriority(t *testing.T) {
	lines := []string{
		"white.gov.cn",
		"blocked.gov.cn",
		"black-keyword.example",
		"keyword.example",
		"plain.example",
	}
	options := ProcessOptions{
		EnableGov:     true,
		EnableBlack:   true,
		EnableWhite:   true,
		EnableKeyword: true,
		EnableDedup:   true,
		Keyword:       "keyword",
		RemoveProto:   true,
		Threads:       1,
		BlackDomains: map[string]bool{
			"black-keyword.example": true,
			"blocked.gov.cn":        true,
		},
		WhiteDomains: map[string]bool{
			"white.gov.cn": true,
		},
	}
	counters := &Counters{}
	logs := []string{}
	results := runProcessLines(lines, options, counters, &logs)

	if strings.Join(results, "\n") != "white.gov.cn\nplain.example" {
		t.Fatalf("results = %#v", results)
	}
	if counters.White != 1 || counters.Gov != 1 || counters.Black != 1 || counters.KeyBlock != 1 || counters.Keep != 2 {
		t.Fatalf("unexpected counters: %s", counters.String())
	}
	for i, input := range lines {
		if !strings.HasSuffix(logs[i], input) {
			t.Errorf("log %d = %q, want input %q", i, logs[i], input)
		}
	}
}

func TestDeduplication(t *testing.T) {
	counters := &Counters{}
	logs := []string{}
	results := runProcessLines([]string{
		"example.com/one",
		"example.com/two",
		"other.example",
	}, ProcessOptions{
		EnableDedup: true,
		RemoveProto: true,
		Threads:     1,
	}, counters, &logs)

	if strings.Join(results, "\n") != "example.com\nother.example" {
		t.Fatalf("results = %#v", results)
	}
	if counters.Dup != 1 || counters.Keep != 2 {
		t.Fatalf("unexpected counters: %s", counters.String())
	}
}

func TestStatusCodeFiltering(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ok" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	counters := &Counters{}
	logs := []string{}
	results := runProcessLines([]string{server.URL + "/ok", server.URL + "/missing"}, ProcessOptions{
		EnableStatus: true,
		AllowedCodes: map[int]bool{http.StatusOK: true},
		RemoveProto:  true,
		Timeout:      1,
		Threads:      2,
	}, counters, &logs)

	if len(results) != 1 || !strings.HasSuffix(results[0], " 200") {
		t.Fatalf("results = %#v", results)
	}
	if counters.StatusBlock != 1 || counters.Keep != 1 {
		t.Fatalf("unexpected counters: %s", counters.String())
	}
	if !strings.HasSuffix(logs[0], "/ok") || !strings.HasSuffix(logs[1], "/missing") {
		t.Fatalf("logs are not in input order: %#v", logs)
	}
}

func TestCSVImport(t *testing.T) {
	app := &App{}
	content := "\ufeffname,url,notes\n" +
		"one,https://example.com/path,\"note,with comma\"\n" +
		"two,\"http://test.example/a,b\",ok\n" +
		"three,example.org,\n"

	got, err := app.ParseCSVFile(content)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://example.com/path", "http://test.example/a,b", "example.org"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("CSV values = %#v, want %#v", got, want)
	}

	if _, err := app.ParseCSVFile("broken,\"unterminated\n"); err == nil {
		t.Fatal("malformed CSV should return an error")
	}
}

func TestXLSXImportAndExport(t *testing.T) {
	f := excelize.NewFile()
	if err := f.SetCellValue("Sheet1", "A1", "URL"); err != nil {
		t.Fatal(err)
	}
	if err := f.SetCellValue("Sheet1", "A2", "https://example.com"); err != nil {
		t.Fatal(err)
	}
	var source bytes.Buffer
	if err := f.Write(&source); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	app := &App{}
	imported, err := app.ParseExcelFile(base64.StdEncoding.EncodeToString(source.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if len(imported) != 1 || imported[0] != "https://example.com" {
		t.Fatalf("XLSX values = %#v", imported)
	}

	encoded, err := app.ExportXlsx("example.com\nsecond.example")
	if err != nil {
		t.Fatal(err)
	}
	exportedBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	exported, err := excelize.OpenReader(bytes.NewReader(exportedBytes))
	if err != nil {
		t.Fatal(err)
	}
	defer exported.Close()
	for cell, want := range map[string]string{"A1": "保留域名", "A2": "example.com", "A3": "second.example"} {
		got, err := exported.GetCellValue("Sheet1", cell)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s = %q, want %q", cell, got, want)
		}
	}
}

func TestProcessControl(t *testing.T) {
	control := newProcessControl()
	if !control.pause() {
		t.Fatal("pause should succeed")
	}

	released := make(chan bool, 1)
	go func() { released <- control.wait() }()
	select {
	case <-released:
		t.Fatal("paused work should wait")
	default:
	}

	if !control.resume() {
		t.Fatal("resume should succeed")
	}
	if !<-released {
		t.Fatal("resumed work should continue")
	}
	control.cancel()
	if control.wait() {
		t.Fatal("canceled work should stop")
	}
}

func TestConfigPersistence(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	app, err := NewApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.shutdown(context.Background())

	config := defaultAppConfig()
	config.EnableGov = false
	config.Timeout = 12
	config.Threads = 4
	config.BlackDomains = []string{"Example.com", "example.com"}
	config.WhiteDomains = []string{"allowed.example"}
	if err := app.SaveConfig(config); err != nil {
		t.Fatal(err)
	}

	loaded, err := app.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.EnableGov || loaded.Timeout != 12 || loaded.Threads != 4 {
		t.Fatalf("loaded config = %#v", loaded)
	}
	if strings.Join(loaded.BlackDomains, ",") != "example.com" {
		t.Fatalf("blacklist was not normalized: %#v", loaded.BlackDomains)
	}
	if len(loaded.WhiteDomains) != 1 || loaded.WhiteDomains[0] != "allowed.example" {
		t.Fatalf("whitelist = %#v", loaded.WhiteDomains)
	}
}

func TestCancelProcessingStopsHTTPRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	logFile, err := os.Create(t.TempDir() + "\\cancel.log")
	if err != nil {
		t.Fatal(err)
	}
	app := &App{logFile: logFile}
	defer app.shutdown(context.Background())

	done := make(chan ProcessResult, 1)
	go func() {
		result, _ := app.ProcessURLs(server.URL, ProcessOptions{
			EnableStatus: true,
			AllowedCodes: map[int]bool{http.StatusOK: true},
			Timeout:      300,
			Threads:      1,
		})
		done <- result
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		app.jobMu.Lock()
		active := app.activeJob != nil
		app.jobMu.Unlock()
		if active {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("processing task did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}

	if !app.CancelProcessing() {
		t.Fatal("CancelProcessing should find the active task")
	}
	select {
	case result := <-done:
		if !result.Canceled {
			t.Fatal("result should be marked canceled")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled processing did not stop")
	}
}
