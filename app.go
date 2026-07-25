package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/xuri/excelize/v2"
	"golang.org/x/net/publicsuffix"
)

// Counters 统计计数器
type Counters struct {
	Total, Keep, Gov, Black, White int64
	KeyBlock, StatusBlock, Dup     int64
	Invalid                        int64
}

func (c *Counters) String() string {
	return fmt.Sprintf(
		"总数:%d  保留:%d  政府:%d  黑名单:%d  白名单:%d  关键词:%d  状态码:%d  重复:%d  无效:%d",
		atomic.LoadInt64(&c.Total), atomic.LoadInt64(&c.Keep),
		atomic.LoadInt64(&c.Gov), atomic.LoadInt64(&c.Black),
		atomic.LoadInt64(&c.White), atomic.LoadInt64(&c.KeyBlock),
		atomic.LoadInt64(&c.StatusBlock), atomic.LoadInt64(&c.Dup),
		atomic.LoadInt64(&c.Invalid),
	)
}

// ProcessOptions 处理选项
type ProcessOptions struct {
	EnableGov, EnableBlack, EnableWhite bool
	EnableDedup, EnableKeyword          bool
	RemoveProto, EnableStatus           bool
	Keyword                             string
	AllowedCodes                        map[int]bool
	Timeout, Threads                    int
	BlackDomains, WhiteDomains          map[string]bool
}

// ProcessResult 处理结果
type ProcessResult struct {
	Results  []string
	Logs     []string
	Counters *Counters
	Canceled bool
}

type AppConfig struct {
	EnableGov, EnableBlack, EnableWhite bool
	EnableDedup, EnableKeyword          bool
	RemoveProto, EnableStatus           bool
	Keyword                             string
	AllowedCodes                        map[int]bool
	Timeout, Threads                    int
	BlackDomains, WhiteDomains          []string
}

type ProcessingState struct {
	Active          bool
	Paused          bool
	CancelRequested bool
	Finished        bool
}

type AssetExtractionResult struct {
	URLs        []string
	RootDomains []string
	Subdomains  []string
	IPs         []string
	CNetworks   []string
}

const (
	defaultTimeoutSeconds = 5
	minTimeoutSeconds     = 1
	maxTimeoutSeconds     = 300
	defaultThreads        = 20
	minThreads            = 1
	maxThreads            = 256
)

// App struct
type App struct {
	ctx          context.Context
	logFile      *os.File
	blackDomains map[string]bool
	whiteDomains map[string]bool
	mu           sync.Mutex
	logMu        sync.Mutex
	configMu     sync.Mutex
	jobMu        sync.Mutex
	activeJob    *processingJob
}

type processingJob struct {
	ctx      context.Context
	control  *processControl
	cancel   context.CancelFunc
	done     chan struct{}
	mu       sync.Mutex
	result   ProcessResult
	err      error
	finished bool
}

type processControl struct {
	mu       sync.Mutex
	cond     *sync.Cond
	paused   bool
	canceled bool
}

func newProcessControl() *processControl {
	control := &processControl{}
	control.cond = sync.NewCond(&control.mu)
	return control
}

func (c *processControl) wait() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.paused && !c.canceled {
		c.cond.Wait()
	}
	return !c.canceled
}

func (c *processControl) pause() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.canceled {
		return false
	}
	c.paused = true
	return true
}

func (c *processControl) resume() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.canceled {
		return false
	}
	c.paused = false
	c.cond.Broadcast()
	return true
}

func (c *processControl) cancel() {
	c.mu.Lock()
	c.canceled = true
	c.paused = false
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *processControl) isCanceled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.canceled
}

func (c *processControl) state() (paused, canceled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.paused, c.canceled
}

// NewApp creates a new App application struct
func NewApp() (*App, error) {
	logFile, err := openLogFile()
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}
	return &App{
		logFile:      logFile,
		blackDomains: make(map[string]bool),
		whiteDomains: make(map[string]bool),
	}, nil
}

// SetBlacklist 设置黑名单（自动提取 host，与处理逻辑一致）
func (a *App) SetBlacklist(domains []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.blackDomains = make(map[string]bool)
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		// 用和 processLines 相同的方式提取 host
		normalized := normalizeURL(d)
		if normalized != "" {
			host := getHost(normalized)
			if host != "" {
				a.blackDomains[host] = true
			}
		} else {
			// 如果 normalize 失败，直接存原始小写
			a.blackDomains[strings.ToLower(d)] = true
		}
	}
}

// SetWhitelist 设置白名单（自动提取 host，与处理逻辑一致）
func (a *App) SetWhitelist(domains []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.whiteDomains = make(map[string]bool)
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		normalized := normalizeURL(d)
		if normalized != "" {
			host := getHost(normalized)
			if host != "" {
				a.whiteDomains[host] = true
			}
		} else {
			a.whiteDomains[strings.ToLower(d)] = true
		}
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

func (a *App) shutdown(ctx context.Context) {
	a.jobMu.Lock()
	job := a.activeJob
	a.jobMu.Unlock()
	if job != nil {
		job.control.cancel()
		job.cancel()
		<-job.done
	}

	a.logMu.Lock()
	defer a.logMu.Unlock()
	if a.logFile != nil {
		_ = a.logFile.Close()
		a.logFile = nil
	}
}

func (a *App) beginJob() (*processingJob, error) {
	a.jobMu.Lock()
	defer a.jobMu.Unlock()
	if a.activeJob != nil {
		return nil, fmt.Errorf("another processing task is already running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	job := &processingJob{
		ctx:     ctx,
		control: newProcessControl(),
		cancel:  cancel,
		done:    make(chan struct{}),
	}
	a.activeJob = job
	return job, nil
}

// PauseProcessing pauses work between individual input items.
func (a *App) PauseProcessing() bool {
	a.jobMu.Lock()
	defer a.jobMu.Unlock()
	job := a.activeJob
	if job == nil {
		return false
	}
	job.mu.Lock()
	finished := job.finished
	job.mu.Unlock()
	if finished {
		return false
	}
	return job != nil && job.control.pause()
}

// ResumeProcessing resumes a paused processing task.
func (a *App) ResumeProcessing() bool {
	a.jobMu.Lock()
	defer a.jobMu.Unlock()
	job := a.activeJob
	if job == nil {
		return false
	}
	job.mu.Lock()
	finished := job.finished
	job.mu.Unlock()
	if finished {
		return false
	}
	return job != nil && job.control.resume()
}

// CancelProcessing cancels the active task and its in-flight HTTP requests.
func (a *App) CancelProcessing() bool {
	a.jobMu.Lock()
	defer a.jobMu.Unlock()
	job := a.activeJob
	if job == nil {
		return false
	}
	job.mu.Lock()
	finished := job.finished
	job.mu.Unlock()
	if finished {
		return false
	}
	job.control.cancel()
	job.cancel()
	return true
}

func (a *App) executeProcessing(job *processingJob, input string, opts ProcessOptions) (ProcessResult, error) {
	opts = normalizeProcessOptions(opts)
	lines := strings.Split(input, "\n")
	ct := &Counters{}
	logs := []string{}

	// 使用后端存储的黑白名单（优先于选项传入的）
	a.mu.Lock()
	if len(a.blackDomains) > 0 {
		opts.BlackDomains = a.blackDomains
	}
	if len(a.whiteDomains) > 0 {
		opts.WhiteDomains = a.whiteDomains
	}
	a.mu.Unlock()

	results := processLines(job.ctx, job.control, lines, opts, ct, &logs)
	result := ProcessResult{
		Results:  results,
		Logs:     logs,
		Counters: ct,
		Canceled: job.control.isCanceled(),
	}
	if err := a.writeLogs(logs); err != nil {
		return result, err
	}
	return result, nil
}

func (a *App) runProcessing(job *processingJob, input string, opts ProcessOptions) {
	result, err := a.executeProcessing(job, input, opts)
	job.mu.Lock()
	job.result = result
	job.err = err
	job.finished = true
	job.mu.Unlock()
	close(job.done)
}

// StartProcessing starts a background processing task and returns immediately.
func (a *App) StartProcessing(input string, opts ProcessOptions) error {
	job, err := a.beginJob()
	if err != nil {
		return err
	}
	go a.runProcessing(job, input, opts)
	return nil
}

func (a *App) takeProcessingResult(job *processingJob) (ProcessResult, error) {
	job.mu.Lock()
	result := job.result
	err := job.err
	job.mu.Unlock()

	a.jobMu.Lock()
	if a.activeJob == job {
		a.activeJob = nil
	}
	a.jobMu.Unlock()
	return result, err
}

// GetProcessingState returns the state of the active background task.
func (a *App) GetProcessingState() ProcessingState {
	a.jobMu.Lock()
	job := a.activeJob
	a.jobMu.Unlock()
	if job == nil {
		return ProcessingState{}
	}
	paused, canceled := job.control.state()
	job.mu.Lock()
	finished := job.finished
	job.mu.Unlock()
	return ProcessingState{
		Active:          true,
		Paused:          paused,
		CancelRequested: canceled,
		Finished:        finished,
	}
}

// GetProcessingResult returns the finished result without blocking.
func (a *App) GetProcessingResult() (ProcessResult, error) {
	a.jobMu.Lock()
	job := a.activeJob
	a.jobMu.Unlock()
	if job == nil {
		return ProcessResult{}, fmt.Errorf("no processing task is active")
	}
	job.mu.Lock()
	finished := job.finished
	job.mu.Unlock()
	if !finished {
		return ProcessResult{}, fmt.Errorf("processing task is not finished")
	}
	<-job.done
	return a.takeProcessingResult(job)
}

// ProcessURLs is kept as a synchronous compatibility API for callers outside
// the UI. The frontend uses StartProcessing and GetProcessingResult instead.
func (a *App) ProcessURLs(input string, opts ProcessOptions) (ProcessResult, error) {
	if err := a.StartProcessing(input, opts); err != nil {
		return ProcessResult{}, err
	}
	job := func() *processingJob {
		a.jobMu.Lock()
		defer a.jobMu.Unlock()
		return a.activeJob
	}()
	if job == nil {
		return ProcessResult{}, fmt.Errorf("processing task was not created")
	}
	<-job.done
	return a.takeProcessingResult(job)
}

func (a *App) GetCounters() *Counters {
	return &Counters{}
}

// ExportTxt 导出为TXT，返回文本内容
func (a *App) ExportTxt(content string) string {
	return content
}

// ExportXlsx 导出为XLSX，返回base64编码的二进制数据
func (a *App) ExportXlsx(content string) (string, error) {
	lines := strings.Split(content, "\n")
	f := excelize.NewFile()
	defer f.Close()

	if err := f.SetCellValue("Sheet1", "A1", "保留域名"); err != nil {
		return "", fmt.Errorf("write XLSX header: %w", err)
	}

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if err := f.SetCellValue("Sheet1", fmt.Sprintf("A%d", i+2), line); err != nil {
			return "", fmt.Errorf("write XLSX cell: %w", err)
		}
	}

	if err := f.SetColWidth("Sheet1", "A", "A", 60); err != nil {
		return "", fmt.Errorf("set XLSX column width: %w", err)
	}

	var buf strings.Builder
	if err := f.Write(&buf); err != nil {
		return "", fmt.Errorf("encode XLSX: %w", err)
	}
	return base64.StdEncoding.EncodeToString([]byte(buf.String())), nil
}

func defaultAppConfig() AppConfig {
	return AppConfig{
		EnableGov:    true,
		EnableBlack:  true,
		EnableWhite:  true,
		EnableDedup:  true,
		RemoveProto:  true,
		AllowedCodes: map[int]bool{200: true, 301: true, 302: true},
		Timeout:      defaultTimeoutSeconds,
		Threads:      defaultThreads,
		BlackDomains: []string{},
		WhiteDomains: []string{},
	}
}

func normalizeConfigDomains(domains []string) []string {
	result := make([]string, 0, len(domains))
	seen := make(map[string]bool, len(domains))
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain != "" && !seen[domain] {
			seen[domain] = true
			result = append(result, domain)
		}
	}
	return result
}

func normalizeAppConfig(config AppConfig) AppConfig {
	options := normalizeProcessOptions(ProcessOptions{
		Timeout:      config.Timeout,
		Threads:      config.Threads,
		AllowedCodes: config.AllowedCodes,
	})
	config.Timeout = options.Timeout
	config.Threads = options.Threads
	config.AllowedCodes = options.AllowedCodes
	config.BlackDomains = normalizeConfigDomains(config.BlackDomains)
	config.WhiteDomains = normalizeConfigDomains(config.WhiteDomains)
	return config
}

// LoadConfig loads persisted UI and filtering settings. Missing config is a
// first-run condition and returns defaults without an error.
func (a *App) LoadConfig() (AppConfig, error) {
	a.configMu.Lock()
	defer a.configMu.Unlock()

	path, err := configFilePath()
	if err != nil {
		return AppConfig{}, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		config := defaultAppConfig()
		a.SetBlacklist(config.BlackDomains)
		a.SetWhitelist(config.WhiteDomains)
		return config, nil
	}
	if err != nil {
		return AppConfig{}, fmt.Errorf("read config: %w", err)
	}

	config := defaultAppConfig()
	if err := json.Unmarshal(data, &config); err != nil {
		return AppConfig{}, fmt.Errorf("parse config: %w", err)
	}
	config = normalizeAppConfig(config)
	a.SetBlacklist(config.BlackDomains)
	a.SetWhitelist(config.WhiteDomains)
	return config, nil
}

// SaveConfig persists UI and filtering settings as JSON.
func (a *App) SaveConfig(config AppConfig) error {
	a.configMu.Lock()
	defer a.configMu.Unlock()

	config = normalizeAppConfig(config)
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	dir, err := appDataDir()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), data, 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	a.SetBlacklist(config.BlackDomains)
	a.SetWhitelist(config.WhiteDomains)
	return nil
}

// LoadBlacklist 加载黑名单文件
func (a *App) LoadBlacklist(filePath string) ([]string, error) {
	domains, _, err := loadDomainFileFromPath(filePath)
	return domains, err
}

// LoadWhitelist 加载白名单文件
func (a *App) LoadWhitelist(filePath string) ([]string, error) {
	domains, _, err := loadDomainFileFromPath(filePath)
	return domains, err
}

// loadDomainFileFromPath 从路径加载域名文件
func loadDomainFileFromPath(filePath string) ([]string, int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()

	domains := []string{}
	seen := map[string]bool{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		l := strings.TrimSpace(scanner.Text())
		if l != "" {
			d := strings.ToLower(l)
			if !seen[d] {
				domains = append(domains, d)
				seen[d] = true
			}
		}
	}
	return domains, len(domains), scanner.Err()
}

// processLines 处理行
func processLines(ctx context.Context, control *processControl, lines []string, opts ProcessOptions, ct *Counters, logs *[]string) []string {
	opts = normalizeProcessOptions(opts)
	var resultMu sync.Mutex
	orderedResults := make([]string, len(lines))
	orderedLogs := make([]string, len(lines))
	seen := map[string]bool{}
	statusCache.Clear() // 每次处理清空缓存

	type job struct {
		idx  int
		line string
	}
	ch := make(chan job, len(lines))
	for i, l := range lines {
		ch <- job{idx: i + 1, line: l}
	}
	close(ch)

	var wg sync.WaitGroup
	var logsMu sync.Mutex
	setLog := func(index int, line string) {
		logsMu.Lock()
		orderedLogs[index] = line
		logsMu.Unlock()
	}
	for t := 0; t < opts.Threads; t++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range ch {
				raw := strings.TrimRight(j.line, "\r\n")
				atomic.AddInt64(&ct.Total, 1)
				if !control.wait() {
					setLog(j.idx-1, fmt.Sprintf("[取消] [-] %s", raw))
					continue
				}
				code := 0
				codeStr := "-"
				hasCode := false

				normalized := normalizeURL(raw)
				if normalized == "" {
					atomic.AddInt64(&ct.Invalid, 1)
					setLog(j.idx-1, fmt.Sprintf("[无效] [格式错误] [-] %s", raw))
					continue
				}
				host := getHost(normalized)

				// 状态码检测（提前获取，后续需要用到）
				if opts.EnableStatus && isHTTPURL(normalized) {
					code = getStatus(ctx, normalized, opts.Timeout)
					codeStr = statusText(code)
					hasCode = true
				}
				if control.isCanceled() {
					setLog(j.idx-1, fmt.Sprintf("[取消] [-] %s", raw))
					continue
				}

				if opts.EnableWhite && opts.WhiteDomains[host] {
					out := host
					if !opts.RemoveProto {
						out = normalized
					}
					atomic.AddInt64(&ct.White, 1)
					resultMu.Lock()
					if opts.EnableDedup && seen[out] {
						atomic.AddInt64(&ct.Dup, 1)
						setLog(j.idx-1, fmt.Sprintf("[重复] [白名单] [%s] %s", codeStr, raw))
					} else {
						seen[out] = true
						if hasCode {
							out = fmt.Sprintf("%s %d", out, code)
						}
						orderedResults[j.idx-1] = out
						atomic.AddInt64(&ct.Keep, 1)
						setLog(j.idx-1, fmt.Sprintf("[保留] [白名单] [%s] %s", codeStr, raw))
					}
					resultMu.Unlock()
					continue
				}

				if opts.EnableGov && isGovernment(host) {
					atomic.AddInt64(&ct.Gov, 1)
					setLog(j.idx-1, fmt.Sprintf("[过滤] [政府域名] [%s] %s", codeStr, raw))
					continue
				}

				if opts.EnableBlack && opts.BlackDomains[host] {
					atomic.AddInt64(&ct.Black, 1)
					setLog(j.idx-1, fmt.Sprintf("[过滤] [黑名单] [%s] %s", codeStr, raw))
					continue
				}

				if opts.EnableKeyword && matchKeyword(host, opts.Keyword) {
					atomic.AddInt64(&ct.KeyBlock, 1)
					setLog(j.idx-1, fmt.Sprintf("[过滤] [关键词:%s] [%s] %s", opts.Keyword, codeStr, raw))
					continue
				}

				if hasCode && !opts.AllowedCodes[code] {
					atomic.AddInt64(&ct.StatusBlock, 1)
					setLog(j.idx-1, fmt.Sprintf("[过滤] [状态码:%s] [%s] %s", codeStr, codeStr, raw))
					continue
				}

				out := host
				if !opts.RemoveProto {
					out = normalized
				}
				resultMu.Lock()
				if opts.EnableDedup && seen[out] {
					atomic.AddInt64(&ct.Dup, 1)
					setLog(j.idx-1, fmt.Sprintf("[重复] [去重] [%s] %s", codeStr, raw))
				} else {
					seen[out] = true
					if hasCode {
						out = fmt.Sprintf("%s %d", out, code)
					}
					orderedResults[j.idx-1] = out
					atomic.AddInt64(&ct.Keep, 1)
					setLog(j.idx-1, fmt.Sprintf("[保留] [通过] [%s] %s", codeStr, raw))
				}
				resultMu.Unlock()
			}
		}()
	}
	wg.Wait()

	results := make([]string, 0, len(lines))
	for i := range orderedResults {
		if orderedResults[i] != "" {
			results = append(results, orderedResults[i])
		}
		if orderedLogs[i] != "" {
			*logs = append(*logs, orderedLogs[i])
		}
	}
	*logs = append(*logs, fmt.Sprintf("[完成] 处理完成，保留 %d 条", len(results)))

	return results
}

// ===== 智能识别规则（导入用） =====

func cleanLine(raw string) string {
	s := raw

	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	if strings.HasPrefix(s, "#") || strings.HasPrefix(s, "//") || strings.HasPrefix(s, ";") {
		return ""
	}

	s = strings.TrimLeft(s, "-*+ ")

	if len(s) > 2 && s[0] >= '0' && s[0] <= '9' {
		dotIdx := strings.Index(s, ". ")
		if dotIdx > 0 && dotIdx <= 3 {
			s = strings.TrimSpace(s[dotIdx+2:])
		}
	}

	if strings.Contains(s, "](") {
		start := strings.Index(s, "](")
		rest := s[start+2:]
		end := strings.Index(rest, ")")
		if end != -1 {
			s = rest[:end]
		}
	}

	s = strings.Trim(s, "\"'`")

	if protoIdx := strings.Index(s, "://"); protoIdx >= 0 {
		authority := s[protoIdx+3:]
		if end := strings.IndexAny(authority, "/?#"); end >= 0 {
			authority = authority[:end]
		}
		if space := strings.IndexFunc(authority, unicode.IsSpace); space >= 0 {
			remainder := strings.TrimSpace(authority[space:])
			if strings.HasPrefix(remainder, ".") || strings.HasPrefix(remainder, ":") || strings.HasPrefix(remainder, "@") {
				return ""
			}
		}
	}

	if idx := strings.Index(s, " "); idx > 0 {
		if strings.Contains(s, "://") {
			protoIdx := strings.Index(s, "://")
			start := strings.LastIndex(s[:protoIdx], " ")
			if start == -1 {
				start = 0
			} else {
				start++
			}
			rest := s[protoIdx+3:]
			end := strings.IndexAny(rest, " \t")
			if end != -1 {
				s = s[start : protoIdx+3+end]
			} else {
				s = s[start:]
			}
		} else {
			s = s[:idx]
		}
	}

	s = strings.TrimRight(s, ".,;:!?)]}>\"'")
	s = strings.TrimSpace(s)

	return s
}

func extractURL(raw string) string {
	s := raw

	lower := strings.ToLower(s)
	hrefIdx := strings.Index(lower, "href=\"")
	if hrefIdx == -1 {
		hrefIdx = strings.Index(lower, "href='")
	}
	if hrefIdx != -1 {
		quote := s[hrefIdx+5 : hrefIdx+6]
		rest := s[hrefIdx+6:]
		end := strings.Index(rest, quote)
		if end != -1 {
			s = rest[:end]
			return cleanLine(s)
		}
	}

	return cleanLine(s)
}

func isImportCandidate(value string) bool {
	if len(value) < 4 {
		return false
	}
	lower := strings.ToLower(value)
	return strings.Contains(value, ".") || strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

func appendImportedValue(result []string, value string) []string {
	cleaned := extractURL(strings.TrimSpace(value))
	if cleaned == "" || !isImportCandidate(cleaned) {
		return result
	}
	return append(result, cleaned)
}

// ParseURLFile 解析 TXT 文件，保留原始数据，仅清理格式，不去重。
func (a *App) ParseURLFile(content string) []string {
	result := make([]string, 0)
	for _, line := range strings.Split(strings.TrimPrefix(content, "\ufeff"), "\n") {
		result = appendImportedValue(result, line)
	}
	return result
}

// ParseCSVFile 使用标准 CSV 解析器读取所有单元格，不假设或跳过表头。
func (a *App) ParseCSVFile(content string) ([]string, error) {
	content = strings.TrimPrefix(content, "\ufeff")
	reader := csv.NewReader(strings.NewReader(content))
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true

	result := make([]string, 0)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse CSV: %w", err)
		}
		for _, cell := range record {
			result = appendImportedValue(result, cell)
		}
	}
	return result, nil
}

// ParseExcelFile 解析 XLSX 文件，保留原始数据，仅清理格式，不去重。
func (a *App) ParseExcelFile(base64Data string) ([]string, error) {
	data, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return nil, fmt.Errorf("decode XLSX data: %w", err)
	}

	f, err := excelize.OpenReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("open XLSX file: %w", err)
	}
	defer f.Close()

	result := make([]string, 0)
	for _, sheet := range f.GetSheetList() {
		rows, err := f.GetRows(sheet)
		if err != nil {
			return nil, fmt.Errorf("read XLSX sheet %q: %w", sheet, err)
		}
		for _, row := range rows {
			for _, cell := range row {
				result = appendImportedValue(result, cell)
			}
		}
	}
	return result, nil
}

var (
	assetURLPattern        = regexp.MustCompile(`(?i)\b(?:https?|tcp)://[^\s"'<>()[\]]+`)
	assetIPv4Pattern       = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	assetDomainPattern     = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\b`)
	assetDomainHostPattern = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$`)
)

func isPrivateAssetIP(raw string) bool {
	ip := net.ParseIP(raw)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

func assetRootDomain(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || net.ParseIP(host) != nil || !assetDomainHostPattern.MatchString(host) {
		return ""
	}
	root, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(root, "."))
}

func assetSubdomain(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if !assetDomainHostPattern.MatchString(host) {
		return ""
	}
	root := assetRootDomain(host)
	if root == "" || host == root {
		return ""
	}
	return host
}

func assetDomainIsInPath(line string, start int) bool {
	if start == 0 {
		return false
	}
	switch line[start-1] {
	case '/', '?', '&', '=', '#':
		return true
	default:
		return false
	}
}

func normalizeAssetURL(raw string) (string, *url.URL) {
	raw = strings.TrimRight(strings.TrimSpace(raw), ".,;:!?)]}>\"'，。；：！？）】")
	parsed, err := url.Parse(raw)
	if err != nil || !isSupportedEndpointScheme(parsed.Scheme) || parsed.Hostname() == "" {
		return "", nil
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if !isValidEndpointHost(host) {
		return "", nil
	}
	if port := parsed.Port(); port != "" {
		portNumber, portErr := strconv.Atoi(port)
		if portErr != nil || portNumber < 1 || portNumber > 65535 {
			return "", nil
		}
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.Replace(parsed.Host, parsed.Hostname(), host, 1)
	return parsed.String(), parsed
}

// ExtractAssets extracts and categorizes assets from mixed local text.
// It performs no network requests and only parses local input.
func (a *App) ExtractAssets(input string, filterPrivate bool) AssetExtractionResult {
	result := AssetExtractionResult{
		URLs:        []string{},
		RootDomains: []string{},
		Subdomains:  []string{},
		IPs:         []string{},
		CNetworks:   []string{},
	}
	seen := map[string]map[string]bool{
		"url": {}, "domain": {}, "subdomain": {}, "ip": {}, "c": {},
	}
	add := func(kind, value string) {
		value = strings.TrimSpace(value)
		if value == "" || seen[kind][value] {
			return
		}
		seen[kind][value] = true
		switch kind {
		case "url":
			result.URLs = append(result.URLs, value)
		case "domain":
			result.RootDomains = append(result.RootDomains, value)
		case "subdomain":
			result.Subdomains = append(result.Subdomains, value)
		case "ip":
			result.IPs = append(result.IPs, value)
		case "c":
			result.CNetworks = append(result.CNetworks, value)
		}
	}
	addIP := func(raw string) {
		ip := net.ParseIP(raw)
		if ip == nil || ip.To4() == nil || filterPrivate && isPrivateAssetIP(raw) {
			return
		}
		v4 := ip.To4()
		add("ip", v4.String())
		add("c", fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2]))
	}

	for _, line := range strings.Split(input, "\n") {
		urlMatches := assetURLPattern.FindAllStringIndex(line, -1)
		maskedLine := []byte(line)
		for _, match := range urlMatches {
			for i := match[0]; i < match[1]; i++ {
				maskedLine[i] = ' '
			}
		}

		for _, match := range urlMatches {
			rawURL := line[match[0]:match[1]]
			normalized, parsed := normalizeAssetURL(rawURL)
			if normalized == "" {
				continue
			}
			host := parsed.Hostname()
			if ip := net.ParseIP(host); ip != nil {
				if filterPrivate && isPrivateAssetIP(host) {
					continue
				}
				addIP(host)
			} else if domain := assetRootDomain(host); domain != "" {
				add("domain", domain)
				if subdomain := assetSubdomain(host); subdomain != "" {
					add("subdomain", subdomain)
				}
			}
			add("url", normalized)
		}

		for _, rawIP := range assetIPv4Pattern.FindAllString(string(maskedLine), -1) {
			addIP(rawIP)
		}
		for _, match := range assetDomainPattern.FindAllStringIndex(string(maskedLine), -1) {
			if assetDomainIsInPath(line, match[0]) {
				continue
			}
			rawDomain := string(maskedLine[match[0]:match[1]])
			if domain := assetRootDomain(rawDomain); domain != "" {
				add("domain", domain)
				if subdomain := assetSubdomain(rawDomain); subdomain != "" {
					add("subdomain", subdomain)
				}
			}
		}
	}
	return result
}

// normalizeURL 规范化URL
func normalizeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	// 输入可能来自复制的说明文本，例如：
	// "http://example.com:9038 该地址会跳转到 HTTPS"。
	// 先提取 URL，再进行严格解析；没有 URL 标记的普通文本仍按整行校验。
	lowerRaw := strings.ToLower(raw)
	if strings.Contains(lowerRaw, "://") || strings.Contains(lowerRaw, "href=\"") || strings.Contains(lowerRaw, "href='") {
		raw = extractURL(raw)
	} else {
		raw = strings.Trim(raw, "\"'`")
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	if strings.IndexFunc(raw, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) != -1 {
		return ""
	}

	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}

	scheme := strings.ToLower(parsed.Scheme)
	if !isSupportedEndpointScheme(scheme) {
		return ""
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return ""
	}
	if !isValidEndpointHost(parsed.Hostname()) {
		return ""
	}
	if port := parsed.Port(); port != "" {
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return ""
		}
	}

	parsed.Scheme = scheme
	return parsed.String()
}

func isSupportedEndpointScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "http", "https", "tcp":
		return true
	default:
		return false
	}
}

func isHTTPURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(parsed.Scheme)
	return scheme == "http" || scheme == "https"
}

func isValidEndpointHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if net.ParseIP(host) != nil {
		return true
	}
	return assetDomainHostPattern.MatchString(host)
}

// getHost 获取主机名
func getHost(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || !isSupportedEndpointScheme(parsed.Scheme) {
		return ""
	}

	return strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
}

func normalizeProcessOptions(opts ProcessOptions) ProcessOptions {
	if opts.Timeout < minTimeoutSeconds || opts.Timeout > maxTimeoutSeconds {
		opts.Timeout = defaultTimeoutSeconds
	}
	if opts.Threads < minThreads || opts.Threads > maxThreads {
		opts.Threads = defaultThreads
	}

	allowedCodes := make(map[int]bool, len(opts.AllowedCodes))
	for code, allowed := range opts.AllowedCodes {
		if allowed && code >= 100 && code <= 599 {
			allowedCodes[code] = true
		}
	}
	opts.AllowedCodes = allowedCodes

	if opts.BlackDomains == nil {
		opts.BlackDomains = map[string]bool{}
	}
	if opts.WhiteDomains == nil {
		opts.WhiteDomains = map[string]bool{}
	}

	return opts
}

// isGovernment 检查政府域名
func isGovernment(domain string) bool {
	d := strings.ToLower(domain)
	govSuffixes := []string{".gov.cn", ".gov", ".government"}
	for _, suf := range govSuffixes {
		if strings.HasSuffix(d, suf) || strings.Contains(d, suf+".") {
			return true
		}
	}
	return false
}

// matchKeyword 匹配关键词
func matchKeyword(domain, keyword string) bool {
	if keyword == "" {
		return false
	}
	return strings.Contains(strings.ToLower(domain), strings.ToLower(keyword))
}

// Clone the standard transport so proxy handling, HTTP/2 and TLS certificate
// verification remain enabled.
var sharedTransport = http.DefaultTransport.(*http.Transport).Clone()

var statusCache sync.Map

const (
	StatusErr     = 0  // 未知错误
	StatusRefused = -1 // 连接被拒绝
	StatusTimeout = -2 // 超时
	StatusDNSFail = -3 // DNS解析失败
	StatusTLSFail = -4 // TLS/SSL错误
	StatusUnreach = -5 // 无路由到主机
)

func statusText(code int) string {
	switch code {
	case StatusErr:
		return "ERR"
	case StatusRefused:
		return "REFUSED"
	case StatusTimeout:
		return "TIMEOUT"
	case StatusDNSFail:
		return "DNS_FAIL"
	case StatusTLSFail:
		return "TLS_ERR"
	case StatusUnreach:
		return "UNREACH"
	default:
		if code > 0 {
			return fmt.Sprintf("%d", code)
		}
		return fmt.Sprintf("ERR_%d", code)
	}
}

// getStatus 获取状态码（带缓存，先HEAD后GET）
func getStatus(ctx context.Context, rawURL string, timeoutSec int) int {
	if code, ok := statusCache.Load(rawURL); ok {
		return code.(int)
	}

	client := &http.Client{
		Timeout:   time.Duration(timeoutSec) * time.Second,
		Transport: sharedTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	doRequest := func() (int, error) {
		headRequest, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
		if err != nil {
			return 0, err
		}
		resp, err := client.Do(headRequest)
		if err == nil {
			defer resp.Body.Close()
			return resp.StatusCode, nil
		}
		// HEAD 失败再 GET
		getRequest, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if requestErr != nil {
			return 0, requestErr
		}
		resp, err = client.Do(getRequest)
		if err == nil {
			defer resp.Body.Close()
			return resp.StatusCode, nil
		}
		return 0, err
	}

	code, err := doRequest()
	if err != nil {
		// 判断具体错误类型
		errStr := err.Error()
		switch {
		case strings.Contains(errStr, "connection refused"):
			code = StatusRefused
		case strings.Contains(errStr, "timeout"), strings.Contains(errStr, "Timeout"), strings.Contains(errStr, "deadline"):
			code = StatusTimeout
		case strings.Contains(errStr, "no such host"), strings.Contains(errStr, "DNS"), strings.Contains(errStr, "dns"):
			code = StatusDNSFail
		case strings.Contains(errStr, "tls"), strings.Contains(errStr, "TLS"), strings.Contains(errStr, "certificate"):
			code = StatusTLSFail
		case strings.Contains(errStr, "no route"), strings.Contains(errStr, "unreachable"):
			code = StatusUnreach
		default:
			code = StatusErr
		}
	}

	statusCache.Store(rawURL, code)
	return code
}

func (a *App) writeLogs(logs []string) error {
	a.logMu.Lock()
	defer a.logMu.Unlock()

	if a.logFile == nil {
		return fmt.Errorf("log file is not available")
	}
	for _, line := range logs {
		if _, err := fmt.Fprintln(a.logFile, line); err != nil {
			return fmt.Errorf("write log entry: %w", err)
		}
	}
	if err := a.logFile.Sync(); err != nil {
		return fmt.Errorf("flush log file: %w", err)
	}
	return nil
}

func appDataDir() (string, error) {
	configDir := os.Getenv("LOCALAPPDATA")
	if configDir == "" {
		if userProfile := os.Getenv("USERPROFILE"); userProfile != "" {
			configDir = filepath.Join(userProfile, "AppData", "Local")
		} else if userConfigDir, err := os.UserConfigDir(); err == nil {
			configDir = userConfigDir
		}
	}
	if configDir == "" {
		configDir = "."
	}

	logDir := filepath.Join(configDir, "URLFilter")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return "", fmt.Errorf("create log directory: %w", err)
	}
	return logDir, nil
}

func configFilePath() (string, error) {
	dir, err := appDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

func openLogFile() (*os.File, error) {
	logDir, err := appDataDir()
	if err != nil {
		return nil, err
	}

	timestamp := time.Now().Format("20060102_150405.000")
	logPath := filepath.Join(logDir, fmt.Sprintf("url-filter-%s.log", timestamp))
	file, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return nil, fmt.Errorf("create log file: %w", err)
	}
	return file, nil
}
