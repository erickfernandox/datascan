package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path"
	"regexp"
	"runtime"
	"strings"
	"sync"
)

const (
	MaxParamsPerCluster = 80
	MaxClusters         = 10
	MaxTotalParams      = MaxParamsPerCluster * MaxClusters
	DefaultValue        = "%27%22efx"
)

/* ===================== MAIN ===================== */

func main() {
	lpFile := flag.String("lp", "", "arquivo de parametros por endpoint")
	paramValue := flag.String("p", DefaultValue, "valor do parametro")
	workers := flag.Int("w", runtime.NumCPU()*2, "numero de workers")
	flag.Parse()

	if *lpFile == "" {
		fmt.Fprintln(os.Stderr, "uso: -lp arquivo.txt [-p FUZZ] [-w 8]")
		os.Exit(1)
	}

	paramMap := loadParamList(*lpFile)

	jobs := make(chan string, 2000)
	results := make(chan string, 2000)

	var wg sync.WaitGroup

	/* ---------- workers ---------- */
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range jobs {
				for _, out := range processURL(url, paramMap, *paramValue) {
					results <- out
				}
			}
		}()
	}

	/* ---------- closer ---------- */
	go func() {
		wg.Wait()
		close(results)
	}()

	/* ---------- stdin reader ---------- */
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 1024), 1024*1024*50)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				jobs <- line
			}
		}
		close(jobs)
	}()

	/* ---------- output ---------- */
	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()

	for r := range results {
		fmt.Fprintln(writer, r)
	}
}

/* ===================== CORE ===================== */

func processURL(rawURL string, paramMap map[string][]string, value string) []string {
	endpoint := normalizeEndpoint(rawURL)
	if endpoint == "" {
		return nil
	}

	// consolida parametros
	paramSet := make(map[string]struct{})

	for key, params := range paramMap {
		if key == endpoint || strings.Contains(key, endpoint) {
			for _, p := range params {
				paramSet[p] = struct{}{}
			}
		}
	}

	if len(paramSet) == 0 {
		return nil
	}

	// transforma em slice
	var params []string
	for p := range paramSet {
		params = append(params, p)
	}

	// limite global anti-infinito
	if len(params) > MaxTotalParams {
		params = params[:MaxTotalParams]
	}

	var out []string
	clusterCount := 0

	for i := 0; i < len(params) && clusterCount < MaxClusters; i += MaxParamsPerCluster {
		end := i + MaxParamsPerCluster
		if end > len(params) {
			end = len(params)
		}
		out = append(out, rawURL+"?"+buildQuery(params[i:end], value))
		clusterCount++
	}

	return out
}

/* ===================== HELPERS ===================== */

func normalizeEndpoint(u string) string {
	u = strings.Split(u, "?")[0]
	base := path.Base(u)
	if idx := strings.LastIndex(base, "."); idx > 0 {
		base = base[:idx]
	}
	return base
}

func buildQuery(params []string, value string) string {
	var b strings.Builder
	for i, p := range params {
		if i > 0 {
			b.WriteString("&")
		}
		b.WriteString(p)
		b.WriteString("=")
		b.WriteString(value)
	}
	return b.String()
}

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
