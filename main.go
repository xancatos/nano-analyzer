package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	Version = "0.1-go"
)

var (
	activeScans   int32
	activeTriages int32

	defaultSystemPrompt = `You are a security researcher hunting for zero-day vulnerabilities. Analyze the code step by step, tracing how untrusted data flows into each function. For every function, ask yourself:
1. Can any parameter be NULL, too large, negative, or otherwise invalid when this function is called with malformed input?
2. Are there copies into fixed-size buffers without size validation?
3. Can integer arithmetic overflow, wrap, or produce negative values that are then used as sizes or indices?
4. Are tagged unions / variant types accessed without verifying the type discriminator first?
5. Are return values from fallible operations checked before use?

Focus on bugs that an external attacker can trigger through untrusted input. Deprioritize static helpers with safe call sites, allocation wrappers, platform-specific dead code, and theoretical issues.
After your analysis, output a JSON array of findings. Each finding must have severity, title, function, and description. Output ONLY the JSON array at the end — your reasoning goes before it.`

	fewshotExampleUser = `Analyze the following source file for zero-day vulnerabilities.

File: example/net/parser.c

` + "```c" + `
void parse_packet(struct packet *pkt, const char *data, int len) {
    char header[64];
    memcpy(header, data, len);
    process_header(header);
}

int handle_request(struct request *req) {
    struct session *sess = lookup_session(req->session_id);
    return sess->handler(req);
}

static void log_debug(const char *msg) {
    if (msg) printf("%s\n", msg);
}

int process_attr(struct attr_value *av) {
    return av->value.str_val->length;
}
` + "```" + `

Provide a detailed security analysis.`

	fewshotExampleAssistant = "`parse_packet`: `data` and `len` come from the network. Copies `len` bytes into 64-byte stack buffer with no bounds check — overflow if `len > 64`. `handle_request`: `lookup_session()` can return NULL but result is dereferenced. `log_debug`: safe, already checks NULL. `process_attr`: accesses union member without checking type tag.\n\n```json\n[\n  {\"severity\": \"critical\", \"title\": \"Stack buffer overflow via unchecked len\", \"function\": \"parse_packet()\", \"description\": \"memcpy copies attacker-controlled len bytes into 64-byte stack buffer without bounds check\"},\n  {\"severity\": \"high\", \"title\": \"NULL deref on failed session lookup\", \"function\": \"handle_request()\", \"description\": \"lookup_session() may return NULL for unknown session_id but result is dereferenced unconditionally\"},\n  {\"severity\": \"high\", \"title\": \"Type confusion on union access\", \"function\": \"process_attr()\", \"description\": \"Accesses av->value.str_val without checking av->type. If av is from parsed input, wrong union member is read\"}\n]\n```"

	contextGenPrompt = `You are preparing a security briefing for a vulnerability researcher. Write a concise (~250 word) context briefing covering:
1. What this code does and where it sits in the project
2. How untrusted input reaches this code (network, file, API?)
3. Which variables/fields carry attacker-controlled data — name them, trace the data flow from entry point to usage
4. All fixed-size buffers and size constants — name them with sizes. If sizes are defined by named constants (macros, #defines), use GREP to find the actual numeric value. State the resolved value explicitly, e.g. "buf[EVP_MAX_MD_SIZE] where EVP_MAX_MD_SIZE=64"
5. Dangerous data flows: attacker-controlled data → fixed-size buffer. Name source, destination, function, and the numeric buffer size for each
6. Parameters that could be NULL from malformed input but are dereferenced without checks
7. Tagged unions or variant types accessed without type-tag validation. Note whether the code checks the type tag before accessing type-specific union members
8. Which functions are public API vs static helpers (and whether static helpers are called safely)
9. What bug classes are most likely given this code's structure

Name actual variables and constants from the code. Do not find vulnerabilities — just provide context. Use your training knowledge of this project where helpful.
GREP TOOL: You can search the codebase by including GREP: pattern in your response. Use this to look up the actual values of constants, find callers of functions, or check how data flows between files. The results will be appended to your briefing.`

	severityEmoji = map[string]string{
		"critical":      "🔴",
		"high":          "🟠",
		"medium":        "🟡",
		"low":           "🔵",
		"informational": "⚪",
		"clean":         "🟢",
	}

	defaultExtensions = map[string]bool{
		".c": true, ".h": true, ".cc": true, ".cpp": true, ".cxx": true, ".hpp": true, ".hxx": true,
		".java": true, ".py": true, ".go": true, ".rs": true, ".js": true, ".ts": true, ".rb": true,
		".swift": true, ".m": true, ".mm": true, ".cs": true, ".php": true, ".pl": true, ".sh": true,
		".x": true,
	}
)

type TriageJob struct {
	Finding     TitleText
	Code        string
	Filepath    string
	ProjectName string
	Model       string
	RepoDir     string
	FileContext string
}

func main() {
	// Parse CLI arguments (support double and single hyphens natively in Go)
	modelFlag := flag.String("model", "gpt-5.4-nano", "Model for all stages")
	parallelFlag := flag.Int("parallel", 50, "Max concurrent scan calls")
	maxCharsFlag := flag.Int("max-chars", 200000, "Skip files larger than this")
	outputDirFlag := flag.String("output-dir", "", "Output directory (default: ~/nano-analyzer-results/<timestamp>/)")
	triageThreshFlag := flag.String("triage-threshold", "medium", "Triage findings at or above this severity")
	triageRoundsFlag := flag.Int("triage-rounds", 5, "Triage rounds per finding")
	triageParallelFlag := flag.Int("triage-parallel", 50, "Max concurrent triage calls")
	maxConnectionsFlag := flag.Int("max-connections", 0, "Max total concurrent API calls")
	minConfidenceFlag := flag.Float64("min-confidence", 0.0, "Only show findings above this confidence threshold")
	projectFlag := flag.String("project", "", "Project name for triage prompt")
	repoDirFlag := flag.String("repo-dir", "", "Root of the repo for triage grep lookups")
	verboseTriageFlag := flag.Bool("verbose-triage", false, "Show per-round triage progress")

	// SQLite caching options
	dbPathFlag := flag.String("db-path", "~/.nano-analyzer/nano-analyzer.db", "SQLite database path")
	noCacheFlag := flag.Bool("no-cache", false, "Bypass caching and force fresh LLM calls")
	clearCacheFlag := flag.Bool("clear-cache", false, "Clear cached results before scanning")

	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Println("Usage: nano-analyzer [options] <path>")
		os.Exit(1)
	}
	targetPath := args[0]

	if _, err := os.Stat(targetPath); err != nil {
		fmt.Printf("❌ Path not found: %s\n", targetPath)
		os.Exit(1)
	}

	// Initialize Database
	db, err := InitDB(*dbPathFlag)
	if err != nil {
		fmt.Printf("❌ Failed to initialize database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	if *clearCacheFlag {
		fmt.Println("🧹 Clearing SQLite cache...")
		if err := ClearCache(db); err != nil {
			fmt.Printf("❌ Failed to clear cache: %v\n", err)
		} else {
			fmt.Println("   Cache cleared successfully.")
		}
	}

	// Set API Semaphore connection limits
	maxConn := *parallelFlag + *triageParallelFlag
	if *maxConnectionsFlag > 0 {
		maxConn = *maxConnectionsFlag
	}
	InitAPISemaphore(maxConn)

	// Discover target files
	scannable, skipped, err := DiscoverFiles(targetPath, defaultExtensions, *maxCharsFlag)
	if err != nil {
		fmt.Printf("❌ Error discovering files: %v\n", err)
		os.Exit(1)
	}

	if len(scannable) == 0 {
		fmt.Println("❌ No scannable files found.")
		os.Exit(0)
	}

	totalLines := 0
	totalChars := 0
	for _, sf := range scannable {
		totalLines += sf.Lines
		totalChars += sf.Chars
	}

	// Output timestamp and directory creation
	timestamp := time.Now().Format("2006-01-02_150405")
	var outDir string
	if *outputDirFlag != "" {
		outDir = *outputDirFlag
	} else {
		home, _ := os.UserHomeDir()
		outDir = filepath.Join(home, "nano-analyzer-results", timestamp)
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Printf("❌ Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	// Resolve repo directory for grepping
	repoDir := *repoDirFlag
	if repoDir == "" {
		info, _ := os.Stat(targetPath)
		if !info.IsDir() {
			repoDir = filepath.Dir(targetPath)
		} else {
			repoDir = targetPath
		}
	}
	repoDir, _ = filepath.Abs(repoDir)

	// Resolve project name
	projectName := *projectFlag
	if projectName == "" {
		projectName = filepath.Base(repoDir)
	}

	// Print configuration briefing
	PrintLogo(5, Version)
	fmt.Println("🔍 nano-analyzer vulnerability scanner (Go edition)")
	fmt.Printf("📂 Target: %s\n", targetPath)
	fmt.Printf("🔎 Grep dir: %s\n", repoDir)
	fmt.Printf("📄 %d files to scan (%s lines, %s chars)\n", len(scannable), formatNumber(totalLines), formatNumber(totalChars))

	if len(skipped) > 0 {
		skipExt := 0
		skipSize := 0
		skipOther := 0
		for _, s := range skipped {
			if s.Reason == "extension" {
				skipExt++
			} else if strings.Contains(s.Reason, "large") {
				skipSize++
			} else {
				skipOther++
			}
		}
		var skipParts []string
		if skipExt > 0 {
			skipParts = append(skipParts, fmt.Sprintf("%d wrong extension", skipExt))
		}
		if skipSize > 0 {
			skipParts = append(skipParts, fmt.Sprintf("%d too large", skipSize))
		}
		if skipOther > 0 {
			skipParts = append(skipParts, fmt.Sprintf("%d unreadable", skipOther))
		}
		fmt.Printf("   ⏭️  %d skipped (%s)\n", len(skipped), strings.Join(skipParts, ", "))
	}
	fmt.Printf("🤖 Model: %s\n", *modelFlag)
	fmt.Printf("⚡ Parallelism: %d scan, %d triage (connection cap: %d)\n", *parallelFlag, *triageParallelFlag, maxConn)
	fmt.Printf("💾 Results → %s/\n", outDir)
	fmt.Printf("🔬 Triage: %s+ findings → skeptical review (%d rounds)\n\n", *triageThreshFlag, *triageRoundsFlag)

	// Setup channels & synchronizations
	scansChan := make(chan ScannableFile, len(scannable))
	for _, f := range scannable {
		scansChan <- f
	}
	close(scansChan)

	var scanResults []ScanResult
	var scanMutex sync.Mutex

	var triageResults []TriageResult
	var triageMutex sync.Mutex

	triageJobs := make(chan TriageJob, 1000)
	var triageWG sync.WaitGroup

	// Severity threshold indices mapping
	threshIdx := getSeverityIndex(*triageThreshFlag)

	// Start triage workers
	for w := 0; w < *triageParallelFlag; w++ {
		triageWG.Add(1)
		go func() {
			defer triageWG.Done()
			for job := range triageJobs {
				// Check SQLite Cache for Triage Verdict first
				if !*noCacheFlag {
					triageMutex.Lock()
					cached := getTriageFromList(triageResults, job.Filepath, job.Finding.Title)
					triageMutex.Unlock()
					if cached != nil {
						continue // Already retrieved from cache
					}

					// Fetch from DB cache
					cachedDBList, err := GetCachedTriages(db, job.Filepath, job.Model)
					if err == nil {
						var cachedDB *TriageResult
						for _, tr := range cachedDBList {
							if tr.FindingTitle == job.Finding.Title {
								cachedDB = &tr
								break
							}
						}
						if cachedDB != nil {
							triageMutex.Lock()
							triageResults = append(triageResults, *cachedDB)
							triageMutex.Unlock()
							continue // Cache Hit
						}
					}
				}

				// Run Triage
				var rounds []TriageResult
				var currentPrior []TriageResult
				failedTriage := false

				for round := 1; round <= *triageRoundsFlag; round++ {
					atomic.AddInt32(&activeTriages, 1)
					tr, err := TriageFindingSingle(job.Finding, job.Code, job.Filepath, job.ProjectName, job.Model, currentPrior, job.RepoDir, job.FileContext, round)
					atomic.AddInt32(&activeTriages, -1)

					if err != nil {
						failedTriage = true
						break
					}

					rounds = append(rounds, tr)

					if *triageRoundsFlag > 1 && *verboseTriageFlag {
						history := ""
						for _, r := range rounds {
							history += verdictEmoji[r.Verdict]
						}
						ts := time.Now().Format("15:04:05")
						sc := atomic.LoadInt32(&activeScans)
						at := atomic.LoadInt32(&activeTriages)
						shortTitle := job.Finding.Title
						if len(shortTitle) > 35 {
							shortTitle = shortTitle[:35] + "..."
						}
						fmt.Printf("  %s    R%d/%d %s %s: %s  [LLMs running S:%d T:%d]\n", ts, round, *triageRoundsFlag, history, filepath.Base(job.Filepath), shortTitle, sc, at)
					}

					// Setup prior history for next round, condensing any bulky greps
					reasoningText := tr.Reasoning
					if tr.GrepUsed {
						reasoningText += "\n\n[GREP RESULTS]:\n" + tr.GrepResults
					}

					// Condense older greps to keep prompt window clean
					var nextPrior []TriageResult
					for _, p := range currentPrior {
						nextPrior = append(nextPrior, TriageResult{
							Verdict:   p.Verdict,
							Reasoning: CondensePriorGreps(p.Reasoning),
						})
					}
					nextPrior = append(nextPrior, TriageResult{
						Verdict:   tr.Verdict,
						Reasoning: reasoningText,
					})
					currentPrior = nextPrior
				}

				if failedTriage || len(rounds) == 0 {
					continue
				}

				// Run Arbiter to decide final verdict
				var finalVerdict TriageResult
				if *triageRoundsFlag > 1 {
					atomic.AddInt32(&activeTriages, 1)
					fv, err := RunArbiter(job.Finding, job.Code, job.Filepath, job.ProjectName, job.Model, rounds)
					atomic.AddInt32(&activeTriages, -1)
					if err == nil {
						finalVerdict = fv
					} else {
						finalVerdict = rounds[len(rounds)-1]
					}
				} else {
					finalVerdict = rounds[0]
				}

				nValid := 0
				for _, r := range rounds {
					if r.Verdict == "VALID" {
						nValid++
					}
				}
				confidence := float64(nValid) / float64(len(rounds))
				verdictsStr := ""
				for _, r := range rounds {
					verdictsStr += string(r.Verdict[0])
				}
				if *triageRoundsFlag > 1 {
					verdictsStr += "→" + string(finalVerdict.Verdict[0])
				}

				finalVerdict.Confidence = confidence
				finalVerdict.VerdictsStr = verdictsStr
				finalVerdict.AllRounds = rounds

				// Write triage detailed markdown file
				triageDir := filepath.Join(outDir, "triages")
				_ = os.MkdirAll(triageDir, 0755)
				safeFile := strings.ReplaceAll(strings.ReplaceAll(job.Filepath, "/", "_"), "\\", "_")
				safeTitle := regexp.MustCompile(`[^\w\-]`).ReplaceAllString(job.Finding.Title, "_")
				if len(safeTitle) > 40 {
					safeTitle = safeTitle[:40]
				}

				triageMutex.Lock()
				triageIndex := len(triageResults) + 1
				triageMutex.Unlock()

				triageMDPath := filepath.Join(triageDir, fmt.Sprintf("T%04d_%s_%s.md", triageIndex, safeFile, safeTitle))
				writeTriageMarkdown(triageMDPath, triageIndex, job.Finding, job.Filepath, finalVerdict, rounds)

				finalVerdict.TriageMD = triageMDPath

				// Save to Triage Cache
				_ = SaveCachedTriage(db, job.Filepath, job.Model, &finalVerdict)

				triageMutex.Lock()
				triageResults = append(triageResults, finalVerdict)
				triageCount := len(triageResults)
				triageMutex.Unlock()

				// Log final triage result
				ts := time.Now().Format("15:04:05")
				sc := atomic.LoadInt32(&activeScans)
				at := atomic.LoadInt32(&activeTriages)
				shortTitle := job.Finding.Title
				if len(shortTitle) > 45 {
					shortTitle = shortTitle[:45] + "..."
				}
				emoji := verdictEmoji[finalVerdict.Verdict]
				confPct := int(confidence * 100)

				fmt.Printf("  %s 🔬 [triage %d] %s %d%% [%s] %s: %s  [LLMs running S:%d T:%d]\n",
					ts, triageCount, emoji, confPct, verdictsStr, filepath.Base(job.Filepath), shortTitle, sc, at)
				fmt.Printf("         📄 %s\n", triageMDPath)
			}
		}()
	}

	// Compute base path relative display
	var basePath string
	info, _ := os.Stat(targetPath)
	if info.IsDir() {
		basePath, _ = filepath.Abs(targetPath)
	} else {
		basePath = filepath.Dir(targetPath)
		basePath, _ = filepath.Abs(basePath)
	}

	completedScans := 0
	totalScans := len(scannable)

	// Start scan workers
	var scanWG sync.WaitGroup
	scanStart := time.Now()

	for w := 0; w < *parallelFlag; w++ {
		scanWG.Add(1)
		go func() {
			defer scanWG.Done()
			for fileJob := range scansChan {
				// Read code
				codeBytes, err := os.ReadFile(fileJob.Filepath)
				if err != nil {
					continue
				}
				codeStr := string(codeBytes)
				displayName, _ := filepath.Rel(basePath, fileJob.Filepath)

				contentHash := HashContent(codeBytes)
				var res *ScanResult
				var cacheHit bool

				// 1. Query Cache
				if !*noCacheFlag {
					res, cacheHit, err = GetCachedScan(db, fileJob.Filepath, *modelFlag, contentHash)
					if err == nil && cacheHit {
						// Retrieve cached triage verdicts
						cachedTriages, _ := GetCachedTriages(db, fileJob.Filepath, *modelFlag)
						triageMutex.Lock()
						for _, ct := range cachedTriages {
							triageResults = append(triageResults, ct)
						}
						triageMutex.Unlock()
					}
				}

				// 2. Cache Miss: Run Stage 1 & 2
				if !cacheHit {
					res = &ScanResult{
						File:        fileJob.Filepath,
						DisplayName: displayName,
						Model:       *modelFlag,
						Timestamp:   timestamp,
					}

					atomic.AddInt32(&activeScans, 1)
					err = runLLMScanPipeline(res, fileJob.Filepath, codeStr, displayName, *modelFlag, db, repoDir)
					atomic.AddInt32(&activeScans, -1)

					if err != nil {
						res.Status = "error"
						res.Error = err.Error()
						res.Severities = make(map[string]int)
					} else {
						res.Status = "ok"
						// Save to Scan Cache
						_ = SaveCachedScan(db, res, contentHash)
					}
				}

				res.Lines = fileJob.Lines
				res.Chars = fileJob.Chars

				// Write outputs
				safename := strings.ReplaceAll(strings.ReplaceAll(displayName, "/", "_"), "\\", "_")
				mdPath := filepath.Join(outDir, safename+".md")
				jsonPath := filepath.Join(outDir, safename+".json")
				ctxPath := filepath.Join(outDir, safename+".context.md")

				if res.Status == "ok" {
					_ = os.WriteFile(mdPath, []byte(fmt.Sprintf("# Scan: %s\n\n%s", displayName, res.Report)), 0644)
					_ = os.WriteFile(ctxPath, []byte(fmt.Sprintf("# Context: %s\n\n%s", displayName, res.Context)), 0644)
					resBytes, _ := json.MarshalIndent(res, "", "  ")
					_ = os.WriteFile(jsonPath, []byte(resBytes), 0644)
				}

				// Log Scan completion
				scanMutex.Lock()
				completedScans++
				cw := len(strconv.Itoa(totalScans))
				sc := atomic.LoadInt32(&activeScans)
				at := atomic.LoadInt32(&activeTriages)
				ts := time.Now().Format("15:04:05")

				cacheIcon := ""
				if cacheHit {
					cacheIcon = " ⏭️  [cache]"
				}

				if res.Status == "error" {
					fmt.Printf("  %s [file %*d/%d]%s ❌ %s  ERROR: %s  [LLMs running S:%d T:%d]\n",
						ts, cw, completedScans, totalScans, cacheIcon, filepath.Base(fileJob.Filepath), res.Error, sc, at)
				} else {
					dots := ""
					for _, lvl := range []string{"critical", "high", "medium", "low"} {
						dots += strings.Repeat(severityEmoji[lvl], res.Severities[lvl])
					}
					if dots == "" {
						dots = "⬜"
					}
					fmt.Printf("  %s [file %*d/%d]%s %s %s  %.0fs  [LLMs running S:%d T:%d]\n",
						ts, cw, completedScans, totalScans, cacheIcon, dots, filepath.Base(fileJob.Filepath), res.TotalElapsed, sc, at)
					fmt.Printf("         📋 %s\n", ctxPath)
					fmt.Printf("         📄 %s\n", mdPath)
				}

				scanResults = append(scanResults, *res)
				scanMutex.Unlock()

				// Queue triage findings if needed (on Cache Miss)
				if !cacheHit && res.Status == "ok" && threshIdx >= 0 {
					// Check if file has any findings above threshold
					hasTriageFindings := false
					for lvl, count := range res.Severities {
						if count > 0 && getSeverityIndex(lvl) <= threshIdx {
							hasTriageFindings = true
							break
						}
					}

					if hasTriageFindings {
						findings := ParseFindings(res.Report)
						for _, f := range findings {
							fIdx := getSeverityIndex(f.Severity)
							if fIdx >= 0 && fIdx <= threshIdx {
								triageJobs <- TriageJob{
									Finding:     TitleText{Title: f.Title, Text: f.Body},
									Code:        codeStr,
									Filepath:    fileJob.Filepath,
									ProjectName: projectName,
									Model:       *modelFlag,
									RepoDir:     repoDir,
									FileContext: res.Context,
								}
							}
						}
					}
				}
			}
		}()
	}

	// Wait for scans to complete
	scanWG.Wait()
	close(triageJobs) // Close triage channel to flush triage workers

	// Wait for triages to complete
	triageWG.Wait()

	wallTime := time.Since(scanStart).Seconds()

	// Sort results for final summary output
	sort.Slice(scanResults, func(i, j int) bool {
		si := scanResults[i].Severities
		sj := scanResults[j].Severities
		if si["critical"] != sj["critical"] {
			return si["critical"] > sj["critical"]
		}
		if si["high"] != sj["high"] {
			return si["high"] > sj["high"]
		}
		return si["medium"] > sj["medium"]
	})

	// Summarize results
	critFiles := 0
	critTotal := 0
	highFiles := 0
	highTotal := 0
	medFiles := 0
	cleanFiles := 0
	errorFiles := 0

	for _, r := range scanResults {
		if r.Status == "error" {
			errorFiles++
			continue
		}
		if r.Severities["critical"] > 0 {
			critFiles++
			critTotal += r.Severities["critical"]
		} else if r.Severities["high"] > 0 {
			highFiles++
			highTotal += r.Severities["high"]
		} else if r.Severities["medium"] > 0 {
			medFiles++
		} else {
			cleanFiles++
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("━", 60))
	fmt.Printf("📊 Summary: %d files scanned in %.0fs\n", len(scanResults), wallTime)
	if critFiles > 0 {
		fmt.Printf("   🔴 Critical: %d files (%d findings)\n", critFiles, critTotal)
		for _, r := range scanResults {
			if r.Severities["critical"] > 0 {
				fmt.Printf("      → %s\n", r.DisplayName)
			}
		}
	}
	if highFiles > 0 {
		fmt.Printf("   🟠 High:     %d files (%d findings)\n", highFiles, highTotal)
	}
	if medFiles > 0 {
		fmt.Printf("   🟡 Medium:   %d files\n", medFiles)
	}
	fmt.Printf("   🟢 Clean:    %d files\n", cleanFiles)
	if errorFiles > 0 {
		fmt.Printf("   ❌ Errors:   %d files\n", errorFiles)
	}
	fmt.Printf("💾 Results saved to: %s/\n", outDir)

	// Summary file generation
	writeSummaryJSON(filepath.Join(outDir, "summary.json"), scanResults, len(skipped), totalLines, wallTime, timestamp, targetPath, *modelFlag)
	writeSummaryMarkdown(filepath.Join(outDir, "summary.md"), scanResults, wallTime, timestamp, targetPath, *modelFlag)

	// Triage findings survivors
	if len(triageResults) > 0 {
		validCount := 0
		invalidCount := 0
		uncertainCount := 0
		for _, t := range triageResults {
			if t.Verdict == "VALID" {
				validCount++
			} else if t.Verdict == "INVALID" {
				invalidCount++
			} else {
				uncertainCount++
			}
		}

		fmt.Printf("\n🔬 Triage: ✅ %d valid | ❌ %d rejected | ❓ %d uncertain\n", validCount, invalidCount, uncertainCount)

		var survivors []TriageResult
		for _, t := range triageResults {
			if t.Verdict == "VALID" && t.Confidence >= *minConfidenceFlag {
				survivors = append(survivors, t)
			}
		}

		if len(survivors) > 0 {
			fmt.Println("\n   🚨 Findings that survived triage:")
			sort.Slice(survivors, func(i, j int) bool {
				return survivors[i].Confidence > survivors[j].Confidence
			})

			findingsDir := filepath.Join(outDir, "findings")
			_ = os.MkdirAll(findingsDir, 0755)

			for idx, s := range survivors {
				bar := "🤔"
				if s.Confidence >= 0.9 {
					bar = "🔥"
				} else if s.Confidence >= 0.7 {
					bar = "✅"
				}

				safeFile := strings.ReplaceAll(strings.ReplaceAll(s.File, "/", "_"), "\\", "_")
				findingFilename := fmt.Sprintf("VULN-%03d_%s.md", idx+1, safeFile)
				findingPath := filepath.Join(findingsDir, findingFilename)

				// Find raw description body
				body := s.Reasoning
				for _, r := range scanResults {
					if r.File == s.File {
						parsedF := ParseFindings(r.Report)
						for _, pf := range parsedF {
							if strings.Contains(pf.Title, s.FindingTitle) || strings.Contains(s.FindingTitle, pf.Title) {
								body = pf.Body
								break
							}
						}
					}
				}

				writeSurvivorMarkdown(findingPath, idx+1, s, body, projectName, timestamp)

				arbiterStr := ""
				if strings.Contains(s.VerdictsStr, "→") {
					arbiterV := s.VerdictsStr[strings.LastIndex(s.VerdictsStr, "→")+1:]
					arbiterEmoji := "❓"
					if arbiterV == "V" {
						arbiterEmoji = "✅"
					} else if arbiterV == "I" {
						arbiterEmoji = "❌"
					}
					arbiterStr = fmt.Sprintf(" (arbiter: %s)", arbiterEmoji)
				}

				fmt.Printf("      %s %d%% [%s]%s %s: %s\n", bar, int(s.Confidence*100), s.VerdictsStr, arbiterStr, filepath.Base(s.File), s.FindingTitle)
				fmt.Printf("         📄 %s\n", findingPath)
			}
		} else {
			fmt.Println("\n   🟢 No findings above confidence threshold.")
		}

		// Save triage summaries
		writeTriageJSON(filepath.Join(outDir, "triage.json"), triageResults)
		writeTriageSurvivorsMarkdown(filepath.Join(outDir, "triage_survivors.md"), triageResults, validCount, invalidCount, uncertainCount, timestamp, targetPath, *modelFlag, *triageThreshFlag)
	}
	fmt.Println()
}

func runLLMScanPipeline(res *ScanResult, filepathStr, codeStr, displayName, model string, db *sql.DB, repoDir string) error {
	ext := filepath.Ext(filepathStr)
	langFocus, focusAreas := GetFileFocus(db, ext)

	// Enable semantic analysis using Tree-sitter
	var semanticBrief string
	astInfo := ParseFileAST([]byte(codeStr), ext)
	if astInfo != nil {
		semanticBrief = GenerateSemanticBriefing(astInfo)
	}

	// 1. Context Generation Stage
	ctxSystem := contextGenPrompt
	if focusAreas != "" {
		ctxSystem += fmt.Sprintf("\n\nFor this file type (%s), focus especially on: %s", langFocus, focusAreas)
	}

	ctxUser := fmt.Sprintf("File: %s\n\n```\n%s\n```", displayName, codeStr)
	if semanticBrief != "" {
		ctxUser = semanticBrief + "\n" + ctxUser
	}

	ctxMessages := []ChatMessage{
		{Role: "system", Content: ctxSystem},
		{Role: "user", Content: ctxUser},
	}

	contextText, usage, elapsed, err := CallLLM(model, ctxMessages, false, 3, "")
	if err != nil {
		return fmt.Errorf("context generation failed: %w", err)
	}

	// Execute any grep requests emitted in briefing
	grepRes := ExecuteGrepRequests(contextText, repoDir)
	if grepRes != "" {
		contextText += "\n\n[GREP RESULTS from codebase]:\n" + grepRes
	}

	res.Context = contextText
	res.ContextTokens = usage.TotalTokens
	res.ContextElapsed = elapsed

	// 2. Vulnerability Scanning Stage
	scanSystem := defaultSystemPrompt + "\n\nSecurity context for the file being analyzed:\n" + contextText
	if focusAreas != "" {
		scanSystem += fmt.Sprintf("\n\nFor this file type (%s), pay extra attention to: %s", langFocus, focusAreas)
	}

	scanUser := fmt.Sprintf("Analyze the following source file for zero-day vulnerabilities.\n\nFile: %s\n\n```c\n%s\n```\n\nProvide a detailed security analysis.", displayName, codeStr)

	scanMessages := []ChatMessage{
		{Role: "system", Content: scanSystem},
		{Role: "user", Content: fewshotExampleUser},
		{Role: "assistant", Content: fewshotExampleAssistant},
		{Role: "user", Content: scanUser},
	}

	reportText, scanUsage, scanElapsed, err := CallLLM(model, scanMessages, false, 3, "")
	if err != nil {
		return fmt.Errorf("scan analysis failed: %w", err)
	}

	res.Report = reportText
	res.PromptTokens = scanUsage.PromptTokens
	res.CompletionTokens = scanUsage.CompletionTokens
	res.TotalTokens = scanUsage.TotalTokens
	res.ScanElapsed = scanElapsed
	res.TotalElapsed = res.ContextElapsed + scanElapsed

	// Parse severities count
	sevs := make(map[string]int)
	for _, lvl := range severityLevels {
		sevs[lvl] = 0
	}
	findings := ParseFindings(reportText)
	for _, f := range findings {
		if _, ok := sevs[f.Severity]; ok {
			sevs[f.Severity]++
		}
	}
	res.Severities = sevs

	return nil
}

func getSeverityIndex(sev string) int {
	for i, s := range severityLevels {
		if s == strings.ToLower(sev) {
			return i
		}
	}
	return -1
}

func getTriageFromList(list []TriageResult, file, title string) *TriageResult {
	for _, tr := range list {
		if tr.File == file && tr.FindingTitle == title {
			return &tr
		}
	}
	return nil
}

func formatNumber(n int) string {
	in := strconv.Itoa(n)
	if len(in) <= 3 {
		return in
	}
	var sb strings.Builder
	// Write characters and insert commas appropriately
	for i, c := range in {
		if i > 0 && (len(in)-i)%3 == 0 {
			sb.WriteRune(',')
		}
		sb.WriteRune(c)
	}
	return sb.String()
}

func writeTriageMarkdown(path string, index int, finding TitleText, filepathStr string, res TriageResult, rounds []TriageResult) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Triage T%04d: %s\n\n", index, finding.Title))
	sb.WriteString(fmt.Sprintf("- **File**: `%s`\n", filepathStr))
	sb.WriteString(fmt.Sprintf("- **Verdict**: %s\n", res.Verdict))
	sb.WriteString(fmt.Sprintf("- **Confidence**: %d%% [%s]\n\n", int(res.Confidence*100), res.VerdictsStr))
	sb.WriteString("---\n\n## Finding\n\n")
	sb.WriteString(finding.Text)
	sb.WriteString("\n\n---\n\n## Triage rounds\n\n")

	for _, r := range rounds {
		emoji := verdictEmoji[r.Verdict]
		sb.WriteString(fmt.Sprintf("### Round %d: %s %s\n\n", r.Round, emoji, r.Verdict))

		// Highlight crux if found in reasoning
		cruxRegex := regexp.MustCompile(`(?i)CRUX:\s*(.+)`)
		if m := cruxRegex.FindStringSubmatch(r.Reasoning); len(m) > 1 {
			sb.WriteString(fmt.Sprintf("**🎯 Crux:** %s\n\n", strings.TrimSpace(m[1])))
		}

		sb.WriteString(r.Reasoning)
		if r.GrepResults != "" {
			sb.WriteString(fmt.Sprintf("\n\n🔎 **Grep results:**\n\n%s", r.GrepResults))
		}
		sb.WriteString("\n\n")
	}

	_ = os.WriteFile(path, []byte(sb.String()), 0644)
}

func writeSurvivorMarkdown(path string, idx int, s TriageResult, body, project, date string) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# VULN-%03d: %s\n\n", idx, s.FindingTitle))
	sb.WriteString(fmt.Sprintf("- **File**: `%s`\n", s.File))
	sb.WriteString(fmt.Sprintf("- **Confidence**: %d%%", int(s.Confidence*100)))
	if s.VerdictsStr != "" {
		sb.WriteString(fmt.Sprintf(" [%s]", s.VerdictsStr))
	}
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("- **Project**: %s\n", project))
	sb.WriteString(fmt.Sprintf("- **Date**: %s\n\n", date))
	sb.WriteString("---\n\n## Scanner finding\n\n")
	sb.WriteString(body)
	sb.WriteString("\n\n---\n\n## Triage reasoning\n\n")

	for ri, rv := range s.AllRounds {
		emoji := verdictEmoji[rv.Verdict]
		sb.WriteString(fmt.Sprintf("### Round %d: %s %s\n\n", ri+1, emoji, rv.Verdict))
		sb.WriteString(rv.Reasoning)
		sb.WriteString("\n\n")
	}

	_ = os.WriteFile(path, []byte(sb.String()), 0644)
}

func writeSummaryJSON(path string, results []ScanResult, skipped, totalLines int, wallTime float64, timestamp, target, model string) {
	critFiles := 0
	highFiles := 0
	cleanFiles := 0
	errorFiles := 0

	type PerFileInfo struct {
		File       string         `json:"file"`
		Lines      int            `json:"lines"`
		Severities map[string]int `json:"severities"`
		Status     string         `json:"status"`
		Elapsed    float64        `json:"elapsed"`
	}

	var perFile []PerFileInfo
	for _, r := range results {
		if r.Status == "error" {
			errorFiles++
		} else if r.Severities["critical"] > 0 {
			critFiles++
		} else if r.Severities["high"] > 0 {
			highFiles++
		} else {
			cleanFiles++
		}
		perFile = append(perFile, PerFileInfo{
			File:       r.DisplayName,
			Lines:      r.Lines,
			Severities: r.Severities,
			Status:     r.Status,
			Elapsed:    r.TotalElapsed,
		})
	}

	summary := map[string]interface{}{
		"timestamp":         timestamp,
		"target":            target,
		"model":             model,
		"files_scanned":     len(results),
		"total_lines":       totalLines,
		"wall_time_seconds": wallTime,
		"files_skipped":     skipped,
		"critical_files":    critFiles,
		"high_files":        highFiles,
		"clean_files":       cleanFiles,
		"error_files":       errorFiles,
		"per_file":          perFile,
	}

	bytes, _ := json.MarshalIndent(summary, "", "  ")
	_ = os.WriteFile(path, bytes, 0644)
}

func writeSummaryMarkdown(path string, results []ScanResult, wallTime float64, timestamp, target, model string) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# nano-analyzer scan results\n\n"))
	sb.WriteString(fmt.Sprintf("- **Target**: `%s`\n", target))
	sb.WriteString(fmt.Sprintf("- **Date**: %s\n", timestamp))
	sb.WriteString(fmt.Sprintf("- **Model**: %s\n", model))
	sb.WriteString(fmt.Sprintf("- **Files scanned**: %d\n", len(results)))
	sb.WriteString(fmt.Sprintf("- **Wall time**: %.0fs\n\n", wallTime))
	sb.WriteString("| File | Lines | Critical | High | Medium | Low |\n")
	sb.WriteString("|------|-------|----------|------|--------|-----|\n")

	for _, r := range results {
		s := r.Severities
		sb.WriteString(fmt.Sprintf("| %s | %d | %d | %d | %d | %d |\n",
			r.DisplayName, r.Lines, s["critical"], s["high"], s["medium"], s["low"]))
	}

	_ = os.WriteFile(path, []byte(sb.String()), 0644)
}

func writeTriageJSON(path string, results []TriageResult) {
	bytes, _ := json.MarshalIndent(results, "", "  ")
	_ = os.WriteFile(path, bytes, 0644)
}

func writeTriageSurvivorsMarkdown(path string, results []TriageResult, valid, rejected, uncertain int, timestamp, target, model, thresh string) {
	var sb strings.Builder
	sb.WriteString("# nano-analyzer triage survivors\n\n")
	sb.WriteString(fmt.Sprintf("- **Target**: `%s`\n", target))
	sb.WriteString(fmt.Sprintf("- **Date**: %s\n", timestamp))
	sb.WriteString(fmt.Sprintf("- **Model**: %s\n", model))
	sb.WriteString(fmt.Sprintf("- **Threshold**: %s+\n", thresh))
	sb.WriteString(fmt.Sprintf("- **Results**: ✅ %d valid | ❌ %d rejected | ❓ %d uncertain\n\n", valid, rejected, uncertain))
	sb.WriteString("---\n\n")

	for _, t := range results {
		if t.Verdict != "VALID" {
			continue
		}
		sb.WriteString(fmt.Sprintf("## ✅ %s: %s\n\n", t.File, t.FindingTitle))
		sb.WriteString("**Verdict**: VALID\n\n")
		sb.WriteString("### Triage reasoning\n\n")
		sb.WriteString(t.Reasoning)
		sb.WriteString("\n\n---\n\n")
	}

	_ = os.WriteFile(path, []byte(sb.String()), 0644)
}
