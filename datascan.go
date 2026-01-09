package main

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	MaxParamsPerCluster = 80
	MaxClusters         = 10
	MaxTotalParams      = MaxParamsPerCluster * MaxClusters
)

// -------------------- Variáveis Globais --------------------

var (
	headers       customheaders
	paramFile     string
	endpointFile  string
	paramCount    int
	endpointCount int
	proxy         string
	onlyPOC       bool
	concurrency   int
	htmlOnly      bool
	scanOpt       string
	scanFilter    map[int]bool
	workers       int
	paramMap      map[string][]string
	endpointList  []string
	requestTypes  string

	// Controle de shutdown
	shutdownChan chan struct{}
	wg           sync.WaitGroup
)

type customheaders []string

func (h *customheaders) String() string { return "Custom headers" }
func (h *customheaders) Set(val string) error {
	*h = append(*h, val)
	return nil
}

// TestCase structure
type TestCase struct {
	ID       int
	Name     string
	Payloads []string
	NeedHTML bool
	Detector func(method, urlStr string, resp *http.Response, body []byte, sentBody string) (bool, string)
}

// -------------------- Inicialização --------------------

func init() {
	flag.IntVar(&paramCount, "params", 0, "Number of parameters to inject (random sample)")
	flag.StringVar(&paramFile, "lp", "", "Path to parameter list file (formato: endpoint: [param1, param2] [count])")
	flag.StringVar(&endpointFile, "le", "", "Path to endpoint/path wordlist file (for path fuzzing)")
	flag.IntVar(&endpointCount, "paths", 0, "Number of random paths to test per URL")
	flag.StringVar(&proxy, "proxy", "", "Proxy URL (HTTP proxy supported for raw CRLF read)")
	flag.StringVar(&proxy, "x", "", "Proxy URL (HTTP proxy supported for raw CRLF read)")
	flag.BoolVar(&onlyPOC, "only-poc", false, "Show only PoC output (suppress Not Vulnerable)")
	flag.BoolVar(&onlyPOC, "s", false, "Show only PoC output (suppress Not Vulnerable)")
	flag.BoolVar(&htmlOnly, "html", false, "Only print XSS/Link results if Content-Type is text/html")
	flag.Var(&headers, "H", "Add header (repeatable)")
	flag.Var(&headers, "headers", "Add header (repeatable)")
	flag.IntVar(&concurrency, "t", 50, "Number of threads (default 50, minimum 15)")
	flag.StringVar(&scanOpt, "o", "", "Scan options (e.g. -o 1,2)\n"+
		"   1 = XSS (inclui XSS Script)\n"+
		"   2 = CRLF Injection\n"+
		"   3 = Redirect/SSRF + Open Redirect\n"+
		"   4 = Link Manipulation\n"+
		"   5 = SSTI\n"+
		"   6 = Path Traversal")
	flag.IntVar(&workers, "w", 0, "Workers para processamento paralelo (default: CPUs * 2)")
	flag.StringVar(&requestTypes, "r", "get,post", "Request types: get,post or both (default: get,post)")

	shutdownChan = make(chan struct{})
}

// -------------------- Main --------------------

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "PANIC: %v\n", r)
		}
	}()

	flag.Parse()

	// Setup básico
	setup()

	// Processar URLs
	processURLs()

	// Aguardar finalização
	wg.Wait()
}

func setup() {
	// Validação básica
	if paramFile == "" {
		fmt.Fprintln(os.Stderr, "Erro: -lp é obrigatório (arquivo de parâmetros)")
		flag.Usage()
		os.Exit(1)
	}

	// Validação do flag -r
	validRequestTypes := map[string]bool{
		"get":      true,
		"post":     true,
		"get,post": true,
		"post,get": true,
	}

	requestTypes = strings.ToLower(strings.TrimSpace(requestTypes))
	if !validRequestTypes[requestTypes] {
		fmt.Fprintln(os.Stderr, "Erro: -r deve ser 'get', 'post' ou 'get,post'")
		flag.Usage()
		os.Exit(1)
	}

	// Configura workers
	if workers <= 0 {
		workers = runtime.NumCPU() * 2
	}
	if workers > 1000 {
		workers = 1000
	}

	// Configura concurrency
	if concurrency < 15 {
		concurrency = 15
	}
	if concurrency > 500 {
		concurrency = 500
	}

	// Parse scan options
	scanFilter = parseScanOptions(scanOpt)
	if scanFilter == nil && len(scanOpt) > 0 {
		fmt.Fprintln(os.Stderr, "Erro: opções de scan inválidas para -o")
		os.Exit(1)
	}

	// Carrega parâmetros do arquivo
	paramMap = loadParamList(paramFile)
	if len(paramMap) == 0 {
		fmt.Fprintln(os.Stderr, "Erro: nenhum parâmetro carregado do arquivo")
		os.Exit(1)
	}

	// Carrega endpoints para path fuzzing (se especificado)
	if endpointFile != "" {
		var err error
		endpointList, err = readLines(endpointFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Erro lendo wordlist de endpoints:", err)
			os.Exit(1)
		}
		if len(endpointList) == 0 {
			fmt.Fprintln(os.Stderr, "Erro: wordlist de endpoints vazia")
			os.Exit(1)
		}
		rand.Seed(time.Now().UnixNano())
	}
}

func processURLs() {
	// Canais com buffer limitado
	jobs := make(chan string, 1000)
	results := make(chan string, 1000)

	// Worker para coletar resultados
	wg.Add(1)
	go func() {
		defer wg.Done()
		writer := bufio.NewWriter(os.Stdout)
		defer writer.Flush()

		for result := range results {
			if result != "" {
				fmt.Fprintln(writer, result)
			}
		}
	}()

	// Workers para processamento
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker(i, jobs, results)
	}

	// Reader de stdin
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(jobs)

		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 1024), 1024*1024*10) // 10MB max

		for scanner.Scan() {
			select {
			case <-shutdownChan:
				return
			default:
				line := strings.TrimSpace(scanner.Text())
				if line != "" {
					jobs <- line
				}
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Erro lendo stdin: %v\n", err)
		}
	}()

	// Aguardar finalização dos workers
	go func() {
		wg.Wait()
		close(results)
	}()
}

func worker(id int, jobs <-chan string, results chan<- string) {
	defer wg.Done()

	// Criar client próprio para cada worker (evita compartilhamento)
	client := buildClient()
	defer client.CloseIdleConnections()

	for urlStr := range jobs {
		select {
		case <-shutdownChan:
			return
		default:
			var vulnResults []string

			if endpointFile != "" && endpointCount > 0 {
				vulnResults = processPathAndParamFuzzing(urlStr, client)
			} else {
				vulnResults = processURLAndTest(urlStr, paramMap, client)
			}

			for _, result := range vulnResults {
				select {
				case results <- result:
				case <-shutdownChan:
					return
				}
			}
		}
	}
}

// -------------------- Funções do Worker --------------------

func processURLAndTest(rawURL string, paramMap map[string][]string, client *http.Client) []string {
	endpoint := normalizeEndpoint(rawURL)
	if endpoint == "" {
		return nil
	}

	// Consolida parâmetros do endpoint
	params := getEndpointParams(endpoint, paramMap)
	if len(params) == 0 {
		return nil
	}

	// Limitar parâmetros
	if paramCount > 0 && paramCount < len(params) {
		params = selectRandomParams(params, paramCount)
	}
	if len(params) > MaxTotalParams {
		params = params[:MaxTotalParams]
	}

	// Executar testes
	return runAllTests(rawURL, params, client)
}

func getEndpointParams(endpoint string, paramMap map[string][]string) []string {
	var result []string
	seen := make(map[string]struct{})

	for key, params := range paramMap {
		if strings.Contains(key, endpoint) {
			for _, p := range params {
				if _, exists := seen[p]; !exists {
					seen[p] = struct{}{}
					result = append(result, p)
				}
			}
		}
	}

	return result
}

func selectRandomParams(params []string, count int) []string {
	if count <= 0 || len(params) == 0 {
		return nil
	}
	if count >= len(params) {
		return params
	}

	// Shuffle parcial mais eficiente
	result := make([]string, count)
	for i := 0; i < count; i++ {
		j := i + rand.Intn(len(params)-i)
		params[i], params[j] = params[j], params[i]
		result[i] = params[i]
	}

	return result
}

func processPathAndParamFuzzing(baseURL string, client *http.Client) []string {
	if len(endpointList) == 0 || endpointCount <= 0 {
		return nil
	}

	// Selecionar endpoints
	selected := selectRandomEndpoints(endpointCount)

	var allResults []string
	for _, endpoint := range selected {
		pathURL := strings.TrimRight(baseURL, "/") + "/" + endpoint
		results := processURLAndTest(pathURL, paramMap, client)
		allResults = append(allResults, results...)
	}

	return allResults
}

func selectRandomEndpoints(count int) []string {
	if count <= 0 || len(endpointList) == 0 {
		return nil
	}
	if count >= len(endpointList) {
		return endpointList
	}

	result := make([]string, count)
	for i := 0; i < count; i++ {
		j := i + rand.Intn(len(endpointList)-i)
		endpointList[i], endpointList[j] = endpointList[j], endpointList[i]
		result[i] = endpointList[i]
	}

	return result
}

// -------------------- Testes de Vulnerabilidade --------------------

func runAllTests(baseURL string, params []string, client *http.Client) []string {
	if len(params) == 0 {
		return nil
	}

	var results []string

	tests := getTestCases()

	for _, tc := range tests {
		if scanFilter != nil && !scanFilter[tc.ID] {
			continue
		}

		for _, payload := range tc.Payloads {
			// GET requests
			if shouldDoGET() {
				// Teste GET normal
				if getURL, ok := buildGetURL(baseURL, params, payload); ok {
					if res := doRequest(client, "GET", getURL, tc, ""); res != "" {
						results = append(results, res)
					}
				}
			}

			// POST requests
			if shouldDoPOST() {
				body := buildFormBody(params, payload)
				if res := doRequest(client, "POST", baseURL, tc, body); res != "" {
					results = append(results, res)
				}
			}
		}
	}

	return results
}

func buildGetURL(baseURL string, params []string, payload string) (string, bool) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", false
	}

	query := buildQuery(params, payload)
	if u.RawQuery != "" {
		u.RawQuery = u.RawQuery + "&" + query
	} else {
		u.RawQuery = query
	}

	return u.String(), true
}

func buildQuery(params []string, value string) string {
	if len(params) == 0 {
		return ""
	}

	var b strings.Builder
	// Estimativa de tamanho
	b.Grow(len(params) * (len(value) + 20))

	for i, p := range params {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(url.QueryEscape(p))
		b.WriteByte('=')
		b.WriteString(value)
	}

	return b.String()
}

func buildFormBody(params []string, value string) string {
	return buildQuery(params, value)
}

// -------------------- Request e Detecção --------------------

func doRequest(client *http.Client, method, urlStr string, tc TestCase, body string) string {
	var req *http.Request
	var err error

	if method == "POST" {
		req, err = http.NewRequest("POST", urlStr, strings.NewReader(body))
		if err != nil {
			return ""
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req, err = http.NewRequest("GET", urlStr, nil)
		if err != nil {
			return ""
		}
	}

	// Headers mínimos para performance
	req.Header.Set("User-Agent", "Mozilla/5.0")
	if len(headers) > 0 {
		for _, h := range headers {
			if parts := strings.SplitN(h, ":", 2); len(parts) == 2 {
				req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}
	}

	// Timeout mais curto
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	// Ler body de forma eficiente
	var respBody []byte
	if tc.NeedHTML {
		if !isHTML(resp) {
			return ""
		}
		respBody, _ = readBody(resp, 512*1024) // 512KB max para HTML
	} else {
		respBody, _ = readBody(resp, 64*1024) // 64KB max para outros
	}

	vuln, detail := tc.Detector(method, urlStr, resp, respBody, body)
	if vuln {
		return formatVuln(tc.Name, method, urlStr, detail)
	}

	if !onlyPOC {
		return formatNotVuln(tc.Name, method, urlStr)
	}

	return ""
}

func readBody(resp *http.Response, maxBytes int64) ([]byte, error) {
	// Usar io.LimitReader para evitar ler muito
	limitedReader := io.LimitReader(resp.Body, maxBytes)
	return io.ReadAll(limitedReader)
}

// -------------------- Funções Auxiliares --------------------

func shouldDoGET() bool {
	return strings.Contains(requestTypes, "get")
}

func shouldDoPOST() bool {
	return strings.Contains(requestTypes, "post")
}

func normalizeEndpoint(u string) string {
	// Método rápido
	if idx := strings.Index(u, "?"); idx != -1 {
		u = u[:idx]
	}

	base := path.Base(u)
	if idx := strings.LastIndex(base, "."); idx > 0 {
		base = base[:idx]
	}

	return base
}

func buildClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        concurrency * 2,
		MaxIdleConnsPerHost: concurrency,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		ForceAttemptHTTP2:   true,
	}

	if proxy != "" {
		if p, err := url.Parse(proxy); err == nil {
			tr.Proxy = http.ProxyURL(p)
		}
	}

	return &http.Client{
		Transport: tr,
		Timeout:   8 * time.Second,
	}
}

// -------------------- Test Cases --------------------

func getTestCases() []TestCase {
	return []TestCase{
		{
			ID:       1,
			Name:     "XSS",
			Payloads: []string{`%27%22teste`},
			NeedHTML: true,
			Detector: func(method, urlStr string, resp *http.Response, body []byte, _ string) (bool, string) {
				if !isHTML(resp) {
					return false, ""
				}
				if strings.Contains(string(body), `'"teste`) {
					return true, `match: '"teste`
				}
				return false, ""
			},
		},
		{
			ID:       1,
			Name:     "XSS Script",
			Payloads: []string{`%3C%2Fscript%3E%3Cteste%3E`},
			NeedHTML: true,
			Detector: func(method, urlStr string, resp *http.Response, body []byte, _ string) (bool, string) {
				if !isHTML(resp) {
					return false, ""
				}
				if strings.Contains(string(body), "</script><teste>") {
					return true, "match: </script><teste>"
				}
				return false, ""
			},
		},
		{
			ID:       2,
			Name:     "CRLF Injection",
			Payloads: []string{`%0d%0aset-cookie:efx`, `%0d%0a%0d%0aset-cookie:efx`},
			NeedHTML: false,
			Detector: func(method, urlStr string, _ *http.Response, _ []byte, sentBody string) (bool, string) {
				rawHead, rawErr := fetchRawResponseHead(method, urlStr, sentBody, headers, proxy)
				if rawErr == nil {
					lines := strings.Split(rawHead, "\r\n")
					for _, ln := range lines {
						l := strings.ToLower(strings.TrimSpace(ln))
						if strings.HasPrefix(l, "set-cookie: efx") {
							return true, "raw-header: " + ln
						}
					}
				}
				return false, ""
			},
		},
		{
			ID: 3,
			Name: "Redirect/SSRF + Open Redirect",
			Payloads: []string{
				`https://example.com`,
				`//example.com`,
				`/%5cexample.com`,
			},
			NeedHTML: false,
			Detector: func(method, urlStr string, _ *http.Response, body []byte, _ string) (bool, string) {
				if strings.Contains(string(body), "Example Domain") {
					return true, "match: Example Domain"
				}
				return false, ""
			},
		},
		{
			ID:       4,
			Name:     "Link Manipulation",
			Payloads: []string{`https://efxtech.com`},
			NeedHTML: true,
			Detector: func(method, urlStr string, resp *http.Response, body []byte, _ string) (bool, string) {
				if !isHTML(resp) {
					return false, ""
				}
				return linkManipulationMatch(body, "efxtech.com")
			},
		},
		{
			ID:       5,
			Name:     "SSTI",
			Payloads: []string{
				`{{7*7}}efxtech`,
				`${{7*7}}efxtech`,
				`*{7*7}efxtech`,
			},
			NeedHTML: false,
			Detector: func(method, urlStr string, _ *http.Response, body []byte, _ string) (bool, string) {
				if strings.Contains(string(body), "49efxtech") {
					return true, "match: 49efxtech"
				}
				return false, ""
			},
		},
		{
			ID: 6,
			Name: "Path Traversal",
			Payloads: []string{
				`../../../../../../etc/passwd`,
				`////../../../../../../etc/passwd`,
				`file://etc/passwd`,
				`%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`,
			},
			NeedHTML: false,
			Detector: func(method, urlStr string, _ *http.Response, body []byte, _ string) (bool, string) {
				if strings.Contains(string(body), "root:x:") {
					return true, "match: root:x:"
				}
				return false, ""
			},
		},
	}
}

// -------------------- CRLF raw --------------------

func fetchRawResponseHead(method, fullURL, body string, addHeaders customheaders, proxyURL string) (string, error) {
	u, err := url.Parse(fullURL)
	if err != nil {
		return "", err
	}

	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	var conn net.Conn
	dialTimeout := 6 * time.Second

	base := defaultHeaderMap()
	user := userHeaderMap(addHeaders)
	final := mergeHeaders(base, user)

	readHead := func(c net.Conn, reqTarget string, tlsWrap bool) (string, error) {
		if tlsWrap {
			serverName := u.Hostname()
			tconn := tls.Client(c, &tls.Config{
				ServerName:         serverName,
				InsecureSkipVerify: true,
			})
			if err := tconn.Handshake(); err != nil {
				return "", err
			}
			c = tconn
		}

		if reqTarget == "" {
			reqTarget = u.RequestURI()
		}
		reqLine := method + " " + reqTarget + " HTTP/1.1\r\n"

		var b strings.Builder
		b.WriteString(reqLine)
		b.WriteString("Host: " + u.Host + "\r\n")

		for k, v := range final {
			if strings.EqualFold(k, "Host") {
				continue
			}
			if method == "POST" && strings.EqualFold(k, "Content-Type") {
				continue
			}
			b.WriteString(k + ": " + v + "\r\n")
		}

		if method == "POST" && body != "" {
			if _, hasCT := final["Content-Type"]; !hasCT {
				b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
			}
			b.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
		}

		b.WriteString("\r\n")
		if method == "POST" && body != "" {
			b.WriteString(body)
		}

		c.SetDeadline(time.Now().Add(8 * time.Second))
		if _, err := c.Write([]byte(b.String())); err != nil {
			return "", err
		}

		rd := bufio.NewReader(c)
		var head strings.Builder
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				return "", err
			}
			head.WriteString(line)
			if strings.HasSuffix(head.String(), "\r\n\r\n") {
				break
			}
			if head.Len() > 64*1024 {
				break
			}
		}
		return strings.TrimSuffix(head.String(), "\r\n\r\n"), nil
	}

	if proxyURL == "" {
		conn, err = net.DialTimeout("tcp", host, dialTimeout)
		if err != nil {
			return "", err
		}
		defer conn.Close()
		needTLS := (u.Scheme == "https")
		return readHead(conn, "", needTLS)
	}

	pURL, err := url.Parse(proxyURL)
	if err != nil {
		return "", err
	}
	if pURL.Scheme != "http" {
		return "", fmt.Errorf("proxy scheme not supported for raw read: %s", pURL.Scheme)
	}
	proxyHost := pURL.Host
	if !strings.Contains(proxyHost, ":") {
		proxyHost += ":80"
	}
	conn, err = net.DialTimeout("tcp", proxyHost, dialTimeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if u.Scheme == "http" {
		return readHead(conn, u.String(), false)
	}

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host, u.Host)
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		return "", err
	}
	br := bufio.NewReader(conn)
	var respHead strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", err
		}
		respHead.WriteString(line)
		if strings.HasSuffix(respHead.String(), "\r\n\r\n") {
			break
		}
		if respHead.Len() > 32*1024 {
			break
		}
	}
	if !strings.Contains(strings.ToLower(respHead.String()), " 200 ") {
		return "", fmt.Errorf("proxy CONNECT failed")
	}

	return readHead(conn, "", true)
}

// -------------------- Funções Restantes --------------------

func loadParamList(file string) map[string][]string {
	f, err := os.Open(file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "erro abrindo lp:", err)
		os.Exit(1)
	}
	defer f.Close()

	re := regexp.MustCompile(`^([^:]+):\s*\[(.*)\]\s*\[\d+\]$`)
	out := make(map[string][]string)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		m := re.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}
		out[m[1]] = splitParams(m[2])
	}
	return out
}

func splitParams(s string) []string {
	var out []string
	var buf strings.Builder
	inQuotes := false

	for _, r := range s {
		switch r {
		case '\'':
			inQuotes = !inQuotes
		case ',':
			if !inQuotes {
				out = append(out, strings.Trim(buf.String(), ` "'`))
				buf.Reset()
				continue
			}
			buf.WriteRune(r)
		default:
			buf.WriteRune(r)
		}
	}

	if buf.Len() > 0 {
		out = append(out, strings.Trim(buf.String(), ` "'`))
	}
	return out
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// ANSI colors
const (
	colorRed   = "\x1b[31m"
	colorReset = "\x1b[0m"
)

func formatVuln(kind, method, urlStr, detail string) string {
	// Vulnerável - em vermelho
	if onlyPOC {
		return fmt.Sprintf("%s%s | %s%s", colorRed, urlStr, kind, colorReset)
	}
	msg := fmt.Sprintf("Vulnerable [%s] - %s %s", kind, method, urlStr)
	if detail != "" {
		msg += " | " + detail
	}
	return colorRed + msg + colorReset
}

func formatNotVuln(kind, method, urlStr string) string {
	if onlyPOC {
		return ""
	}
	// Não vulnerável - normal (sem cor)
	return fmt.Sprintf("Not Vulnerable [%s] - %s %s", kind, method, urlStr)
}

func parseScanOptions(opt string) map[int]bool {
	opt = strings.TrimSpace(opt)
	if opt == "" {
		return nil
	}
	m := make(map[int]bool)
	for _, p := range strings.Split(opt, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			m[n] = true
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

func isHTML(resp *http.Response) bool {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

func readBodyDecodedLimit(resp *http.Response, max int64) ([]byte, error) {
	enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	var r io.Reader = io.LimitReader(resp.Body, max)

	switch enc {
	case "gzip":
		gr, err := gzip.NewReader(io.LimitReader(resp.Body, max))
		if err != nil {
			return io.ReadAll(r)
		}
		defer gr.Close()
		return io.ReadAll(gr)
	case "deflate":
		fr := flate.NewReader(io.LimitReader(resp.Body, max))
		defer fr.Close()
		return io.ReadAll(fr)
	default:
		return io.ReadAll(r)
	}
}

func linkManipulationMatch(body []byte, domain string) (bool, string) {
	low := strings.ToLower(string(body))
	dom := regexp.QuoteMeta(strings.ToLower(domain))

	patterns := []string{
		`src=["']https://` + dom,
		`href=["']https://` + dom,
		`action=["']https://` + dom,
		`\.href\s*=\s*["']https://` + dom,
		`html\s*=\s*["']https://` + dom,
		`eval\s*\(\s*['"]https://` + dom,
		`location\s*=\s*["']https://` + dom,
	}

	for _, p := range patterns {
		re := regexp.MustCompile(p)
		if loc := re.FindStringIndex(low); loc != nil {
			start := loc[0]
			end := loc[1]
			ctxStart := start - 40
			if ctxStart < 0 {
				ctxStart = 0
			}
			ctxEnd := end + 40
			if ctxEnd > len(low) {
				ctxEnd = len(low)
			}
			return true, "match: " + strings.TrimSpace(low[ctxStart:ctxEnd])
		}
	}
	return false, ""
}

func defaultHeaderMap() map[string]string {
	return map[string]string{
		"User-Agent":      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Encoding": "gzip, deflate, br",
		"Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
		"Connection":      "close",
	}
}

func userHeaderMap(h customheaders) map[string]string {
	m := make(map[string]string)
	for _, raw := range h {
		parts := strings.SplitN(raw, ":", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		if k != "" {
			m[http.CanonicalHeaderKey(k)] = v
		}
	}
	return m
}

func mergeHeaders(base, override map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(override))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range override {
		out[k] = v
	}
	return out
}
