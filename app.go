package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xuri/excelize/v2"
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
}

// App struct
type App struct {
	ctx          context.Context
	logFile      *os.File
	blackDomains map[string]bool
	whiteDomains map[string]bool
	mu           sync.Mutex
}

// NewApp creates a new App application struct
func NewApp() *App {
	logFile, _ := openLogFile()
	return &App{
		logFile:      logFile,
		blackDomains: make(map[string]bool),
		whiteDomains: make(map[string]bool),
	}
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

// ProcessURLs 处理URL列表
func (a *App) ProcessURLs(input string, opts ProcessOptions) ProcessResult {
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

	results := processLines(lines, opts, ct, &logs, a.logFile)
	return ProcessResult{
		Results:  results,
		Logs:     logs,
		Counters: ct,
	}
}

func (a *App) GetCounters() *Counters {
	return &Counters{}
}

// ExportTxt 导出为TXT，返回文本内容
func (a *App) ExportTxt(content string) string {
	return content
}

// ExportXlsx 导出为XLSX，返回base64编码的二进制数据
func (a *App) ExportXlsx(content string) string {
	lines := strings.Split(content, "\n")
	f := excelize.NewFile()
	defer f.Close()

	f.SetCellValue("Sheet1", "A1", "保留域名")

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f.SetCellValue("Sheet1", fmt.Sprintf("A%d", i+2), line)
	}

	f.SetColWidth("Sheet1", "A", "A", 60)

	var buf strings.Builder
	f.Write(&buf)
	return base64.StdEncoding.EncodeToString([]byte(buf.String()))
}

// LoadBlacklist 加载黑名单文件
func (a *App) LoadBlacklist(filePath string) []string {
	domains, _, _ := loadDomainFileFromPath(filePath)
	return domains
}

// LoadWhitelist 加载白名单文件
func (a *App) LoadWhitelist(filePath string) []string {
	domains, _, _ := loadDomainFileFromPath(filePath)
	return domains
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
func processLines(lines []string, opts ProcessOptions, ct *Counters, logs *[]string, logFile *os.File) []string {
	var resultMu sync.Mutex
	results := []string{}
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
	for t := 0; t < opts.Threads; t++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range ch {
				raw := strings.TrimRight(j.line, "\r\n")
				atomic.AddInt64(&ct.Total, 1)
				code := 0
				codeStr := "-"
				hasCode := false

				normalized := normalizeURL(raw)
				if normalized == "" {
					atomic.AddInt64(&ct.Invalid, 1)
					logsMu.Lock()
					*logs = append(*logs, fmt.Sprintf("[无效] [格式错误] [-] %s", raw))
					logsMu.Unlock()
					continue
				}
				host := getHost(normalized)

				// 状态码检测（提前获取，后续需要用到）
				if opts.EnableStatus {
					code = getStatus(normalized, opts.Timeout)
					codeStr = statusText(code)
					hasCode = true
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
						logsMu.Lock()
						*logs = append(*logs, fmt.Sprintf("[重复] [白名单] [%s] %s", codeStr, raw))
						logsMu.Unlock()
					} else {
						seen[out] = true
						if hasCode {
							out = fmt.Sprintf("%s %d", out, code)
						}
						results = append(results, out)
						atomic.AddInt64(&ct.Keep, 1)
						logsMu.Lock()
						*logs = append(*logs, fmt.Sprintf("[保留] [白名单] [%s] %s", codeStr, raw))
						logsMu.Unlock()
					}
					resultMu.Unlock()
					continue
				}

				if opts.EnableGov && isGovernment(host) {
					atomic.AddInt64(&ct.Gov, 1)
					logsMu.Lock()
					*logs = append(*logs, fmt.Sprintf("[过滤] [政府域名] [%s] %s", codeStr, raw))
					logsMu.Unlock()
					continue
				}

				if opts.EnableBlack && opts.BlackDomains[host] {
					atomic.AddInt64(&ct.Black, 1)
					logsMu.Lock()
					*logs = append(*logs, fmt.Sprintf("[过滤] [黑名单] [%s] %s", codeStr, raw))
					logsMu.Unlock()
					continue
				}

				if opts.EnableKeyword && matchKeyword(host, opts.Keyword) {
					atomic.AddInt64(&ct.KeyBlock, 1)
					logsMu.Lock()
					*logs = append(*logs, fmt.Sprintf("[过滤] [关键词:%s] [%s] %s", opts.Keyword, codeStr, raw))
					logsMu.Unlock()
					continue
				}

				if opts.EnableStatus && !opts.AllowedCodes[code] {
					atomic.AddInt64(&ct.StatusBlock, 1)
					logsMu.Lock()
					*logs = append(*logs, fmt.Sprintf("[过滤] [状态码:%s] [%s] %s", codeStr, codeStr, raw))
					logsMu.Unlock()
					continue
				}

				out := host
				if !opts.RemoveProto {
					out = normalized
				}
				resultMu.Lock()
				if opts.EnableDedup && seen[out] {
					atomic.AddInt64(&ct.Dup, 1)
					logsMu.Lock()
					*logs = append(*logs, fmt.Sprintf("[重复] [去重] [%s] %s", codeStr, raw))
					logsMu.Unlock()
				} else {
					seen[out] = true
					if hasCode {
						out = fmt.Sprintf("%s %d", out, code)
					}
					results = append(results, out)
					atomic.AddInt64(&ct.Keep, 1)
					logsMu.Lock()
					*logs = append(*logs, fmt.Sprintf("[保留] [通过] [%s] %s", codeStr, raw))
					logsMu.Unlock()
				}
				resultMu.Unlock()
			}
		}()
	}
	wg.Wait()

	logsMu.Lock()
	*logs = append(*logs, fmt.Sprintf("[完成] 处理完成，保留 %d 条", len(results)))
	logsMu.Unlock()

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

// ParseURLFile 解析TXT文件，保留原始数据，仅清理格式，不去重
func (a *App) ParseURLFile(content string) []string {
	lines := strings.Split(content, "\n")
	result := []string{}

	for _, line := range lines {
		cleaned := extractURL(line)
		if cleaned == "" {
			continue
		}

		hasDot := strings.Contains(cleaned, ".")
		hasProto := strings.HasPrefix(cleaned, "http://") || strings.HasPrefix(cleaned, "https://")
		if !hasDot && !hasProto {
			continue
		}
		if len(cleaned) < 4 {
			continue
		}

		result = append(result, cleaned)
	}

	return result
}

// ParseExcelFile 解析Excel文件，保留原始数据，仅清理格式，不去重
func (a *App) ParseExcelFile(base64Data string) []string {
	data, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return []string{}
	}

	f, err := excelize.OpenReader(strings.NewReader(string(data)))
	if err != nil {
		return []string{}
	}
	defer f.Close()

	result := []string{}

	for _, sheet := range f.GetSheetList() {
		rows, err := f.GetRows(sheet)
		if err != nil {
			continue
		}
		for _, row := range rows {
			for _, cell := range row {
				cell = strings.TrimSpace(cell)
				if cell == "" || len(cell) < 4 {
					continue
				}

				cleaned := extractURL(cell)
				if cleaned == "" || len(cleaned) < 4 {
					continue
				}

				hasDot := strings.Contains(cleaned, ".")
				hasProto := strings.HasPrefix(cleaned, "http://") || strings.HasPrefix(cleaned, "https://")
				if !hasDot && !hasProto {
					continue
				}

				result = append(result, cleaned)
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

	lower := strings.ToLower(raw)
	hasProto := strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
	if !hasProto {
		raw = "http://" + raw
	}

	lower = strings.ToLower(raw)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return ""
	}

	return raw
}

// getHost 获取主机名
func getHost(rawURL string) string {
	rawURL = strings.TrimPrefix(rawURL, "http://")
	rawURL = strings.TrimPrefix(rawURL, "https://")

	if atIdx := strings.Index(rawURL, "@"); atIdx != -1 {
		rawURL = rawURL[atIdx+1:]
	}

	// 去掉路径/参数/端口
	if idx := strings.IndexAny(rawURL, "/?#:"); idx != -1 {
		rawURL = rawURL[:idx]
	}

	return strings.ToLower(rawURL)
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

var sharedTransport = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}

var statusCache sync.Map

const (
	StatusErr       = 0    // 未知错误
	StatusRefused   = -1   // 连接被拒绝
	StatusTimeout   = -2   // 超时
	StatusDNSFail   = -3   // DNS解析失败
	StatusTLSFail   = -4   // TLS/SSL错误
	StatusUnreach   = -5   // 无路由到主机
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
func getStatus(rawURL string, timeoutSec int) int {
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
		resp, err := client.Head(rawURL)
		if err == nil {
			defer resp.Body.Close()
			return resp.StatusCode, nil
		}
		// HEAD 失败再 GET
		resp, err = client.Get(rawURL)
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

// openLogFile 打开日志文件
func openLogFile() (*os.File, error) {
	logDir := os.Getenv("LOCALAPPDATA")
	if logDir == "" {
		logDir = os.Getenv("USERPROFILE")
	}
	if logDir == "" {
		logDir = "."
	}
	logDir = logDir + "/AppData/Local/URLFilter"

	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, err
	}

	timestamp := time.Now().Format("20060102_150405")
	logPath := fmt.Sprintf("%s/url-filter-%s.log", logDir, timestamp)
	return os.Create(logPath)
}
