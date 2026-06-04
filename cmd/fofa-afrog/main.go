package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	afrog "github.com/zan8in/afrog/v3"
	"github.com/zan8in/afrog/v3/pkg/result"

	"github.com/ikun245/fofa-aforg/pkg/fofa"
)

// ScanResult holds the combined FOFA + afrog output for JSON export.
type ScanResult struct {
	FofaQuery  string           `json:"fofa_query"`
	Targets    []string         `json:"targets"`
	ScanTime   string           `json:"scan_time"`
	Vulns      []*result.Result `json:"vulnerabilities"`
	TotalVulns int              `json:"total_vulnerabilities"`
}

func step(n, total int, title string) {
	fmt.Printf("\n\033[1;36m━━━ Step %d/%d: %s ━━━\033[0m\n", n, total, title)
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	const totalSteps = 8

	printBanner()

	// ── Step 1: Credentials ──────────────────────────────────────────────────
	step(1, totalSteps, "Credentials")
	cfg, err := fofa.LoadConfig()
	if err != nil {
		log.Printf("[!] Could not read config file: %v", err)
	}

	if cfg.Email == "" || cfg.APIKey == "" {
		fmt.Println("[*] No saved credentials found. Enter them once — they will be")
		fmt.Printf("    stored in %s for future runs.\n\n", fofa.ConfigPath())

		fmt.Print("[*] Enter your FOFA email: ")
		email, _ := reader.ReadString('\n')
		cfg.Email = strings.TrimSpace(email)

		fmt.Print("[*] Enter your FOFA API key: ")
		key, _ := reader.ReadString('\n')
		cfg.APIKey = strings.TrimSpace(key)

		if cfg.Email == "" || cfg.APIKey == "" {
			log.Fatal("[!] Email and API key are required.")
		}

		if err := fofa.SaveConfig(cfg); err != nil {
			log.Printf("[!] Could not save config: %v", err)
		} else {
			fmt.Printf("[+] Credentials saved to %s\n", fofa.ConfigPath())
		}
	} else {
		fmt.Printf("[+] Loaded from %s  (email: %s)\n", fofa.ConfigPath(), cfg.Email)
	}

	client := fofa.NewClient(cfg.Email, cfg.APIKey)

	// ── Step 2: FOFA Query ───────────────────────────────────────────────────
	step(2, totalSteps, "FOFA Query")
	fmt.Print("[*] Query (e.g. app=\"Apache-Shiro\"): ")
	query, _ := reader.ReadString('\n')
	query = strings.TrimSpace(query)
	if query == "" {
		log.Fatal("[!] Query cannot be empty.")
	}

	fmt.Print("[*] How many results to fetch? (default 100, max 10000): ")
	sizeStr, _ := reader.ReadString('\n')
	sizeStr = strings.TrimSpace(sizeStr)
	size := 100
	if sizeStr != "" {
		if n, err := strconv.Atoi(sizeStr); err == nil && n > 0 {
			size = n
		}
	}

	// ── Step 3: Fetch & Display Results ─────────────────────────────────────
	step(3, totalSteps, "Fetch & Display Results")
	fmt.Printf("[*] Querying FOFA: %s (size=%d) ...\n", query, size)
	params := fofa.DefaultParams(query)
	params.Size = size

	resp, err := client.Search(params)
	if err != nil {
		log.Fatalf("[!] FOFA query failed: %v", err)
	}

	if len(resp.Results) == 0 {
		fmt.Println("[!] No results returned from FOFA.")
		return
	}

	fieldNames := fofa.FieldNames(params.Fields)

	// Filter out invalid 0.0.0.0 rows
	filtered := filterResults(resp.Results, fieldNames)
	skipped := len(resp.Results) - len(filtered)
	fmt.Printf("[+] FOFA total matches: %d  |  Fetched: %d  |  Valid: %d",
		resp.Size, len(resp.Results), len(filtered))
	if skipped > 0 {
		fmt.Printf("  (dropped %d protected/invalid rows)", skipped)
	}
	fmt.Println()

	if len(filtered) == 0 {
		fmt.Println("[!] No valid results after filtering. Exiting.")
		return
	}

	printTable(filtered, fieldNames)

	// ── Step 4: Filter Rows ──────────────────────────────────────────────────
	step(4, totalSteps, "Filter Rows (optional)")
	fmt.Println("[*] Narrow down the table by keyword (searches all fields).")
	fmt.Print("[*] Filter keyword (leave blank to skip): ")
	filterKw, _ := reader.ReadString('\n')
	filterKw = strings.TrimSpace(filterKw)

	if filterKw != "" {
		before := len(filtered)
		filtered = keywordFilter(filtered, filterKw)
		fmt.Printf("[+] Kept %d/%d rows matching %q\n", len(filtered), before, filterKw)
		if len(filtered) == 0 {
			fmt.Println("[!] No rows match that filter. Exiting.")
			return
		}
		printTable(filtered, fieldNames)
	} else {
		fmt.Println("[*] Skipped.")
	}

	// ── Step 5: Select Targets ───────────────────────────────────────────────
	step(5, totalSteps, "Select Targets")
	fmt.Println("[*] Enter row numbers to scan: comma-separated, ranges (e.g. 1-5), or 'all'")
	fmt.Print("Selection: ")
	selStr, _ := reader.ReadString('\n')
	selStr = strings.TrimSpace(selStr)

	selected := parseSelection(selStr, len(filtered))
	if len(selected) == 0 {
		fmt.Println("[!] No valid targets selected. Exiting.")
		return
	}

	targets := extractTargets(filtered, fieldNames, selected)
	fmt.Printf("[+] %d unique target(s) selected:\n", len(targets))
	for _, t := range targets {
		fmt.Printf("    • %s\n", t)
	}

	// ── Step 6: Scan Configuration ───────────────────────────────────────────
	step(6, totalSteps, "Scan Configuration")
	fmt.Print("[*] POC directory (e.g. ./pocs/afrog-pocs): ")
	pocPathRaw, _ := reader.ReadString('\n')
	pocPathRaw = strings.TrimSpace(pocPathRaw)
	if pocPathRaw == "" {
		pocPathRaw = "./pocs/afrog-pocs"
	}
	pocPath, err := filepath.Abs(pocPathRaw)
	if err != nil || !dirExists(pocPath) {
		log.Fatalf("[!] POC path not found or invalid: %s", pocPath)
	}

	fmt.Print("[*] Severity (all/info/low/medium/high/critical, default high,critical): ")
	severityRaw, _ := reader.ReadString('\n')
	severity := strings.TrimSpace(severityRaw)
	switch severity {
	case "all":
		severity = "info,low,medium,high,critical"
	case "":
		severity = "high,critical"
	}

	fmt.Print("[*] POC keyword filter (leave blank for all): ")
	searchRaw, _ := reader.ReadString('\n')
	search := strings.TrimSpace(searchRaw)

	fmt.Print("[*] Output JSON file (default: scan_results.json): ")
	outFileRaw, _ := reader.ReadString('\n')
	outFile := strings.TrimSpace(outFileRaw)
	if outFile == "" {
		outFile = "scan_results.json"
	}

	// ── Step 7: Run Scan ─────────────────────────────────────────────────────
	step(7, totalSteps, "Running Scan")
	fmt.Printf("[*] Targets: %d  |  Severity: %s  |  Keyword: %q\n",
		len(targets), severity, search)

	options := afrog.NewSDKOptions()
	options.Targets = targets
	options.PocFile = pocPath
	options.Severity = severity
	options.Search = search
	options.Concurrency = 25
	options.RateLimit = 150
	options.Timeout = 10
	options.EnableStream = true

	scanner, err := afrog.NewSDKScanner(options)
	if err != nil {
		log.Fatalf("[!] Failed to create afrog scanner: %v", err)
	}
	defer scanner.Close()

	var vulns []*result.Result
	var tasksDone int64
	scanner.OnResult = func(r *result.Result) {
		done := atomic.AddInt64(&tasksDone, 1)
		vulns = append(vulns, r)
		sev := strings.ToUpper(r.PocInfo.Info.Severity)
		color := severityColor(sev)
		fmt.Printf("\r\033[K[%s%s\033[0m] [%d done] %-45s  %s\n",
			color, sev, done, r.Target, r.PocInfo.Info.Name)
	}

	startTime := time.Now()
	if err := scanner.Run(); err != nil {
		log.Printf("[!] Scan error: %v", err)
	}
	elapsed := time.Since(startTime)

	// ── Step 8: Results & Export ─────────────────────────────────────────────
	step(8, totalSteps, "Results & Export")
	stats := scanner.GetStats()
	fmt.Printf("[+] Completed in %s  |  Tasks: %d  |  Findings: %d\n\n",
		elapsed.Round(time.Second), stats.TotalScans, stats.FoundVulns)

	// Severity breakdown
	sevCount := map[string]int{}
	for _, v := range vulns {
		sevCount[strings.ToLower(v.PocInfo.Info.Severity)]++
	}
	if len(sevCount) > 0 {
		fmt.Println("  Severity breakdown:")
		for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
			if n := sevCount[sev]; n > 0 {
				color := severityColor(strings.ToUpper(sev))
				fmt.Printf("    %s%-8s\033[0m  %d\n", color, sev, n)
			}
		}
		fmt.Println()
	}

	output := ScanResult{
		FofaQuery:  query,
		Targets:    targets,
		ScanTime:   startTime.UTC().Format(time.RFC3339),
		Vulns:      vulns,
		TotalVulns: len(vulns),
	}
	saveJSON(output, outFile)
	fmt.Printf("[+] Results saved to %s\n", outFile)
}

// severityColor returns an ANSI color prefix for a severity string.
func severityColor(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return "\033[1;35m" // bold magenta
	case "HIGH":
		return "\033[1;31m" // bold red
	case "MEDIUM":
		return "\033[1;33m" // bold yellow
	case "LOW":
		return "\033[1;34m" // bold blue
	default:
		return "\033[0;37m" // grey
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func printBanner() {
	fmt.Println(`
  ███████╗ ██████╗ ███████╗ █████╗        █████╗ ███████╗██████╗  ██████╗  ██████╗
  ██╔════╝██╔═══██╗██╔════╝██╔══██╗      ██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔════╝
  █████╗  ██║   ██║█████╗  ███████║█████╗███████║█████╗  ██████╔╝██║   ██║██║  ███╗
  ██╔══╝  ██║   ██║██╔══╝  ██╔══██║╚════╝██╔══██║██╔══╝  ██╔══██╗██║   ██║██║   ██║
  ██║     ╚██████╔╝██║     ██║  ██║      ██║  ██║██║     ██║  ██║╚██████╔╝╚██████╔╝
  ╚═╝      ╚═════╝ ╚═╝     ╚═╝  ╚═╝      ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝

  FOFA Query  →  afrog Vulnerability Scanner  |  Interactive CLI
`)
}

func printTable(results [][]string, fields []string) {
	fmt.Printf("%-5s", "#")
	for _, f := range fields {
		fmt.Printf("  %-30s", f)
	}
	fmt.Println()
	fmt.Println(strings.Repeat("-", 5+len(fields)*32))

	for i, row := range results {
		fmt.Printf("%-5d", i+1)
		for j := range fields {
			val := ""
			if j < len(row) {
				val = row[j]
			}
			if len(val) > 29 {
				val = val[:26] + "..."
			}
			fmt.Printf("  %-30s", val)
		}
		fmt.Println()
	}
}

// parseSelection parses "all", "1,3,5", "1-5", or mixed combos.
func parseSelection(sel string, max int) []int {
	if strings.ToLower(sel) == "all" {
		out := make([]int, max)
		for i := range out {
			out[i] = i
		}
		return out
	}
	seen := map[int]bool{}
	var out []int
	for _, part := range strings.Split(sel, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 != nil || err2 != nil {
				continue
			}
			for i := lo; i <= hi; i++ {
				idx := i - 1
				if idx >= 0 && idx < max && !seen[idx] {
					seen[idx] = true
					out = append(out, idx)
				}
			}
		} else {
			n, err := strconv.Atoi(part)
			if err != nil {
				continue
			}
			idx := n - 1
			if idx >= 0 && idx < max && !seen[idx] {
				seen[idx] = true
				out = append(out, idx)
			}
		}
	}
	return out
}

// keywordFilter keeps only rows where at least one field contains kw (case-insensitive).
func keywordFilter(results [][]string, kw string) [][]string {
	kw = strings.ToLower(kw)
	var out [][]string
	for _, row := range results {
		for _, cell := range row {
			if strings.Contains(strings.ToLower(cell), kw) {
				out = append(out, row)
				break
			}
		}
	}
	return out
}

// filterResults removes rows where ip is 0.0.0.0 or port is 0 (FOFA protected/invalid rows).
func filterResults(results [][]string, fields []string) [][]string {
	fieldIdx := map[string]int{}
	for i, f := range fields {
		fieldIdx[f] = i
	}
	ipIdx, hasIP := fieldIdx["ip"]
	portIdx, hasPort := fieldIdx["port"]

	var out [][]string
	for _, row := range results {
		if hasIP && ipIdx < len(row) && row[ipIdx] == "0.0.0.0" {
			continue
		}
		if hasPort && portIdx < len(row) && row[portIdx] == "0" {
			continue
		}
		out = append(out, row)
	}
	return out
}

// extractTargets builds deduplicated target URLs from selected FOFA rows.
func extractTargets(results [][]string, fields []string, selected []int) []string {
	fieldIdx := map[string]int{}
	for i, f := range fields {
		fieldIdx[f] = i
	}

	seen := map[string]bool{}
	var targets []string
	for _, idx := range selected {
		row := results[idx]
		host := ""
		ip := ""
		port := ""
		proto := ""

		if i, ok := fieldIdx["host"]; ok && i < len(row) {
			host = row[i]
		}
		if i, ok := fieldIdx["ip"]; ok && i < len(row) {
			ip = row[i]
		}
		if i, ok := fieldIdx["port"]; ok && i < len(row) {
			port = row[i]
		}
		if i, ok := fieldIdx["protocol"]; ok && i < len(row) {
			proto = row[i]
		}

		target := buildTarget(host, ip, port, proto)
		if target != "" && !seen[target] {
			seen[target] = true
			targets = append(targets, target)
		}
	}
	return targets
}

func buildTarget(host, ip, port, proto string) string {
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		return host
	}
	base := host
	if base == "" {
		if ip == "" {
			return ""
		}
		if port != "" && port != "80" && port != "443" {
			base = ip + ":" + port
		} else {
			base = ip
		}
	}
	switch strings.ToLower(proto) {
	case "https":
		return "https://" + base
	case "http":
		return "http://" + base
	default:
		if port == "443" {
			return "https://" + base
		}
		return "http://" + base
	}
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func saveJSON(data interface{}, path string) {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Printf("[!] Failed to marshal JSON: %v", err)
		return
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		log.Printf("[!] Failed to write JSON file: %v", err)
	}
}
