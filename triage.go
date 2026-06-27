package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Finding represents a vulnerability finding reported by the LLM
type Finding struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Body     string `json:"body"`
}

// TriageResult represents a verdict round or summary for a single finding
type TriageResult struct {
	FindingTitle string         `json:"finding_title"`
	Verdict      string         `json:"verdict"` // VALID, INVALID, UNCERTAIN
	Reasoning    string         `json:"reasoning"`
	Elapsed      float64        `json:"elapsed"`
	Tokens       int            `json:"tokens"`
	Round        int            `json:"round"`
	File         string         `json:"file"`
	GrepUsed     bool           `json:"grep_used"`
	GrepResults  string         `json:"grep_results"`
	Confidence   float64        `json:"confidence"`
	VerdictsStr  string         `json:"verdicts_str"`
	AllRounds    []TriageResult `json:"all_rounds,omitempty"`
	TriageMD     string         `json:"triage_md,omitempty"`
}

var (
	severityLevels = []string{"critical", "high", "medium", "low", "informational"}
	bugKeywordRx   = regexp.MustCompile(`(?i)(overflow|underflow|use\.after\.free|double\.free|null\.pointer|null\.deref|out\.of\.bounds|oob|buffer|race|deadlock|injection|bypass|escalat|uncheck|missing\.check|missing\.bound|missing\.valid|unbounded|unchecked|integer\.overflow|uaf|memcpy|sprintf|strcpy|strcat|format\.string|denial\.of\.service|dos\b|crash|panic|corrupt|leak|disclosure|uninitiali|dangling|stale|sequence|replay|shift|xdr|length|size)`)
	junkTitleRx    = regexp.MustCompile(`(?i)(^summary|^overview|^what (this|to|i) |^threat model|^overall|^conclusion|^next step|^recommend|^note|^checklist|^audit |^action|^practical |^.?level\b|^/info|^.?impact\b|^.?risk\b|^.?confidence\b|exploitation path|candidates|^concurrency consider|^other |^ssues|^oncrete )`)
	funcSigRx      = regexp.MustCompile(`(?i)^[\x60\s]*\w+[\w_]*\s*[\(/]`)
	verdictEmoji   = map[string]string{
		"VALID":     "✅",
		"INVALID":   "❌",
		"UNCERTAIN": "❓",
		"ERROR":     "💥",
	}
)

// ParseFindings extracts findings array from LLM response text
func ParseFindings(text string) []Finding {
	// Method 1: >>> marker lines
	markerRx := regexp.MustCompile(`(?m)^>>>\s*(CRITICAL|HIGH|MEDIUM|LOW)\s*:\s*(.+)`)
	matches := markerRx.FindAllStringSubmatch(text, -1)
	if len(matches) > 0 {
		var findings []Finding
		for _, m := range matches {
			sev := strings.ToLower(m[1])
			rest := strings.TrimSpace(m[2])
			parts := strings.SplitN(rest, "|", 3)
			title := strings.TrimSpace(parts[0])
			findings = append(findings, Finding{
				Severity: sev,
				Title:    title,
				Body:     rest,
			})
		}
		return findings
	}

	// Method 2: JSON extraction
	extracted := ExtractJSON(text)
	if extracted != nil {
		var items []interface{}
		switch val := extracted.(type) {
		case []interface{}:
			items = val
		case map[string]interface{}:
			if f, ok := val["findings"]; ok {
				if fArr, ok := f.([]interface{}); ok {
					items = fArr
				}
			} else if _, ok := val["severity"]; ok {
				items = []interface{}{val}
			}
		}

		if len(items) > 0 {
			var findings []Finding
			for _, it := range items {
				m, ok := it.(map[string]interface{})
				if !ok {
					continue
				}

				sev := "medium"
				if s, ok := m["severity"].(string); ok {
					sev = strings.ToLower(s)
				}
				if sev == "none" {
					continue
				}

				title := "Untitled finding"
				if t, ok := m["title"].(string); ok {
					title = t
				}

				desc := ""
				if d, ok := m["description"].(string); ok {
					desc = d
				}
				if fix, ok := m["fix"].(string); ok && fix != "" {
					desc += "\n\nFix: " + fix
				}

				findings = append(findings, Finding{
					Severity: sev,
					Title:    title,
					Body:     desc,
				})
			}
			return findings
		}
	}

	// Method 3: Markdown Headings Parser fallback
	var findings []Finding
	headingRx := regexp.MustCompile(`(?m)^#{1,4}\s+(?:\d+[\.\)]\s*|(?:critical|high|medium|low)\b|[>\x60\w])(.*)`)
	matchesH := headingRx.FindAllStringIndex(text, -1)
	if len(matchesH) > 0 {
		for i := 0; i < len(matchesH); i++ {
			start := matchesH[i][0]
			end := len(text)
			if i+1 < len(matchesH) {
				end = matchesH[i+1][0]
			}
			section := text[start:end]

			// Extract title line
			lines := strings.Split(section, "\n")
			title := strings.TrimSpace(lines[0])
			title = regexp.MustCompile(`^#{1,4}\s+`).ReplaceAllString(title, "")
			title = strings.Trim(title, "*` ")
			title = regexp.MustCompile(`(?i)^severity\s*[:/]\s*`).ReplaceAllString(title, "")
			title = strings.TrimSpace(regexp.MustCompile(`(?i)^[\(\[]?\s*(critical|high|medium|low|informational)\s*[\)\]]?\s*[:/]?\s*`).ReplaceAllString(title, ""))

			if junkTitleRx.MatchString(title) || funcSigRx.MatchString(title) {
				continue
			}

			// Validate if section contains security bugs
			if !bugKeywordRx.MatchString(title) && !bugKeywordRx.MatchString(section) {
				continue
			}

			sev := "medium"
			for _, lvl := range severityLevels {
				match, _ := regexp.MatchString(`(?i)\b`+lvl+`\b`, section)
				if match {
					sev = lvl
					break
				}
			}

			findings = append(findings, Finding{
				Severity: sev,
				Title:    title,
				Body:     strings.TrimSpace(section),
			})
		}
	}

	// Fallback to full unstructured block if still nothing
	if len(findings) == 0 {
		for _, lvl := range severityLevels {
			match, _ := regexp.MatchString(`(?i)\b`+lvl+`\b`, text)
			if match {
				findings = append(findings, Finding{
					Severity: lvl,
					Title:    "Unstructured finding",
					Body:     text,
				})
				break
			}
		}
	}

	return findings
}

func executeGrep(pattern string, repoDir string) string {
	// Try executing ripgrep
	rgPath, err := exec.LookPath("rg")
	if err == nil {
		cmd := exec.Command(rgPath, "--no-heading", "-n", "--fixed-strings", "-g", "*.c", "-g", "*.h", "-g", "*.go", "-g", "*.py", "-g", "*.js", "-g", "*.ts", "-g", "*.rs", "-g", "*.java", pattern)
		cmd.Dir = repoDir
		var out bytes.Buffer
		cmd.Stdout = &out
		_ = cmd.Run() // ignore exit codes like 1 (no match)
		if out.Len() > 0 {
			return out.String()
		}
	}

	// Fallback: Programmatic search in Go
	var results []string
	maxLines := 30
	maxLineLen := 1000

	err = filepath.Walk(repoDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		isScannable := false
		for _, e := range []string{".c", ".h", ".cpp", ".cc", ".go", ".py", ".rs", ".js", ".ts", ".java"} {
			if ext == e {
				isScannable = true
				break
			}
		}

		if !isScannable {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()

		relPath, _ := filepath.Rel(repoDir, path)
		scanner := bufio.NewScanner(file)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			lineText := scanner.Text()
			if strings.Contains(lineText, pattern) {
				if len(lineText) > maxLineLen {
					lineText = lineText[:maxLineLen] + "..."
				}
				results = append(results, fmt.Sprintf("%s:%d:%s", relPath, lineNum, lineText))
				if len(results) >= maxLines {
					return filepath.SkipDir // Stop early
				}
			}
		}
		return nil
	})

	if len(results) > 0 {
		return strings.Join(results, "\n")
	}

	return "(no matches in repo)"
}

// ExecuteGrepRequests parses the LLM output for grep searches, executes them, and returns matching lines
func ExecuteGrepRequests(responseRaw string, repoDir string) string {
	if repoDir == "" {
		return ""
	}

	var requests []string

	// Check for "GREP: pattern"
	grepRx := regexp.MustCompile(`(?i)GREP:\s*(.+)`)
	for _, m := range grepRx.FindAllStringSubmatch(responseRaw, -1) {
		requests = append(requests, strings.Trim(m[1], "`'\" "))
	}

	// Check for "grep for `pattern`"
	grepForRx := regexp.MustCompile(`(?i)grep\s+(?:for\s+)?[\x60'"]([^\x60'"]+)[\x60'"]`)
	for _, m := range grepForRx.FindAllStringSubmatch(responseRaw, -1) {
		requests = append(requests, strings.TrimSpace(m[1]))
	}

	// Filter unique non-empty patterns, excluding generic words
	var unique []string
	seen := make(map[string]bool)
	junkWords := map[string]bool{
		"results": true, "call": true, "code": true, "function": true, "value": true,
		"null": true, "type": true, "data": true, "return": true, "void": true,
		"true": true, "false": true, "verification": true, "verify": true, "evidence": true,
	}

	for _, req := range requests {
		req = strings.TrimSpace(req)
		if len(req) < 3 || seen[req] || junkWords[strings.ToLower(req)] {
			continue
		}
		seen[req] = true
		unique = append(unique, req)
	}

	if len(unique) == 0 {
		return ""
	}

	var grepOutputs []string
	// Run up to 3 searches to avoid output overflow
	limit := 3
	if len(unique) < limit {
		limit = len(unique)
	}

	for _, pattern := range unique[:limit] {
		out := executeGrep(pattern, repoDir)
		grepOutputs = append(grepOutputs, fmt.Sprintf("GREP `%s`:\n```\n%s\n```", pattern, out))
	}

	return strings.Join(grepOutputs, "\n\n")
}

// CondensePriorGreps replaces full grep content in reviewer summaries to avoid token explosion
func CondensePriorGreps(reasoningText string) string {
	rx := regexp.MustCompile(`(?s)\n\n\[GREP RESULTS.*?\]:\n(.*)`)
	if !rx.MatchString(reasoningText) {
		return reasoningText
	}

	// Find the grep section and replace it with a shorter line limit
	loc := rx.FindStringSubmatchIndex(reasoningText)
	if len(loc) < 4 {
		return reasoningText
	}

	before := reasoningText[:loc[0]]
	grepContent := reasoningText[loc[2]:loc[3]]

	var condensed []string
	patternRx := regexp.MustCompile(`(?s)GREP \x60([^\x60]+)\x60:\n\` + "`" + `\` + "`" + `\` + "`" + `\n(.*?)\n\` + "`" + `\` + "`" + `\` + "`" + ``)
	matches := patternRx.FindAllStringSubmatch(grepContent, -1)

	for _, m := range matches {
		pattern := m[1]
		body := strings.TrimSpace(m[2])
		if body == "" || body == "(no matches in repo)" {
			condensed = append(condensed, fmt.Sprintf("  - `%s`: (no matches)", pattern))
		} else {
			lines := strings.Split(body, "\n")
			limit := 3
			if len(lines) < limit {
				limit = len(lines)
			}
			for i := 0; i < limit; i++ {
				condensed = append(condensed, fmt.Sprintf("  - %s", strings.TrimSpace(lines[i])))
			}
			if len(lines) > limit {
				condensed = append(condensed, fmt.Sprintf("    (+%d more matches)", len(lines)-limit))
			}
		}
	}

	return before + "\n\n[Prior grep evidence]:\n" + strings.Join(condensed, "\n")
}

// TriageFindingSingle runs a single round of skeptical review on a finding
func TriageFindingSingle(finding TitleText, code, filepath, projectName, model string, prior []TriageResult, repoDir string, fileContext string, round int) (TriageResult, error) {
	prompt := fmt.Sprintf("A vulnerability scanner flagged this in %s. Is it real?\n\nBe skeptical — most scanner findings are false positives.\n\nReported vulnerability:\n%s\n\nCode from %s:\n```c\n%s\n```\n", projectName, finding.Text, filepath, code)

	if fileContext != "" {
		// Cap context preview to avoid overloading prompt size
		limit := 2000
		if len(fileContext) < limit {
			limit = len(fileContext)
		}
		prompt += fmt.Sprintf("\n\n**Security context for this file:**\n%s\n", fileContext[:limit])
	}

	if len(prior) > 0 {
		prompt += "\n\n---\n\nPrior reviewers have weighed in below. Their reasoning is SPECULATIVE — it may contain errors or unfounded assumptions.\nYour job is NOT to repeat their analysis. Instead:\n- Find arguments they MISSED — new attack paths, new defenses, different callers.\n- Verify any cited defense with actual values (use GREP).\n- Do NOT rehash the same argument — add new information.\n\n"
		for i, p := range prior {
			prompt += fmt.Sprintf("**Reviewer %d (%s)**:\n%s\n\n", i+1, p.Verdict, p.Reasoning)
		}
	}

	systemPrompt := `You are a security engineer triaging vulnerability reports. Respond ONLY with JSON:
{
  "reasoning": "Analyze the evidence. State your conclusion clearly.",
  "crux": "the single key fact the verdict depends on",
  "grep": "search_pattern to verify the crux",
  "verdict": "VALID/INVALID/UNCERTAIN"
}
Rules:
- VALID: real bug, attacker reachable, causes meaningful harm.
- INVALID: false positive, code quality issue, or fully defended.
- UNCERTAIN: only if truly unknown. Use GREP to resolve constants/callers.`

	messages := []ChatMessage{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: prompt},
	}

	resText, usage, elapsed, err := CallLLM(model, messages, true, 3, "")
	if err != nil {
		return TriageResult{
			FindingTitle: finding.Title,
			Verdict:      "ERROR",
			Reasoning:    err.Error(),
		}, err
	}

	verdict := "UNCERTAIN"
	reasoning := resText
	grepReq := ""

	// Parse JSON output
	extracted := ExtractJSON(resText)
	if extracted != nil {
		if m, ok := extracted.(map[string]interface{}); ok {
			if v, ok := m["verdict"].(string); ok {
				v = strings.ToUpper(v)
				if v == "VALID" || v == "INVALID" || v == "UNCERTAIN" {
					verdict = v
				}
			}
			if r, ok := m["reasoning"].(string); ok {
				reasoning = r
			}
			if c, ok := m["crux"].(string); ok && c != "" {
				reasoning += "\n\nCRUX: " + c
			}
			if g, ok := m["grep"].(string); ok && g != "" {
				grepReq = g
			}
		}
	} else {
		// regex fallback
		clean := strings.ToUpper(resText)
		if strings.Contains(clean, "INVALID") {
			verdict = "INVALID"
		} else if strings.Contains(clean, "VALID") {
			verdict = "VALID"
		}
	}

	tr := TriageResult{
		FindingTitle: finding.Title,
		Verdict:      verdict,
		Reasoning:    reasoning,
		Elapsed:      elapsed,
		Tokens:       usage.TotalTokens,
		Round:        round,
		File:         filepath,
	}

	if grepReq != "" {
		grepResults := ExecuteGrepRequests("GREP: "+grepReq, repoDir)
		if grepResults != "" {
			tr.GrepUsed = true
			tr.GrepResults = grepResults
		}
	}

	return tr, nil
}

// TitleText holds key and body of a scanner finding
type TitleText struct {
	Title string
	Text  string
}

// RunArbiter settles conflicting review decisions in a final vote
func RunArbiter(finding TitleText, code, filepath, projectName, model string, rounds []TriageResult) (TriageResult, error) {
	nValid := 0
	nInvalid := 0
	var evidence []string

	for _, r := range rounds {
		emoji := verdictEmoji[r.Verdict]
		summary := r.Reasoning
		if len(summary) > 500 {
			summary = summary[:500] + "..."
		}
		evidence = append(evidence, fmt.Sprintf("**Round %d (%s %s):** %s", r.Round, emoji, r.Verdict, summary))
		if r.GrepResults != "" {
			evidence = append(evidence, r.GrepResults)
		}

		if r.Verdict == "VALID" {
			nValid++
		} else if r.Verdict == "INVALID" {
			nInvalid++
		}
	}

	verdictsStr := ""
	for _, r := range rounds {
		verdictsStr += string(r.Verdict[0])
	}

	arbiterPrompt := fmt.Sprintf(`A vulnerability was reported in %s:
%s

The reported finding:
%s

Key evidence from %d rounds of analysis:
%s

Verdicts so far: %s (%d valid, %d invalid)

The relevant source code from %s:
%s

Based on the code and evidence, is this a real security vulnerability? Respond in JSON:
{"verdict": "VALID/INVALID", "reasoning": "concise explanation"}`,
		projectName, finding.Title, finding.Text, len(rounds), strings.Join(evidence, "\n\n"), verdictsStr, nValid, nInvalid, filepath, code)

	messages := []ChatMessage{
		{Role: "system", Content: "You are an impartial judge. Decide based on evidence, not arguments. Respond with JSON only."},
		{Role: "user", Content: arbiterPrompt},
	}

	resText, usage, elapsed, err := CallLLM(model, messages, true, 3, "")
	if err != nil {
		return TriageResult{}, err
	}

	finalVerdict := rounds[len(rounds)-1].Verdict // fallback
	finalReasoning := "[ARBITER] " + resText

	extracted := ExtractJSON(resText)
	if m, ok := extracted.(map[string]interface{}); ok {
		if v, ok := m["verdict"].(string); ok {
			v = strings.ToUpper(v)
			if v == "VALID" || v == "INVALID" {
				finalVerdict = v
			}
		}
		if r, ok := m["reasoning"].(string); ok {
			finalReasoning = "[ARBITER] " + r
		}
	}

	return TriageResult{
		FindingTitle: finding.Title,
		Verdict:      finalVerdict,
		Reasoning:    finalReasoning,
		Elapsed:      elapsed,
		Tokens:       usage.TotalTokens,
		Round:        len(rounds) + 1,
		File:         filepath,
	}, nil
}

// ExecuteSemanticRequests parses the LLM output for AST/semantic helper commands, executes them, and returns formatted results.
func ExecuteSemanticRequests(responseRaw string, repoDir string) string {
	if repoDir == "" {
		return ""
	}

	var results []string

	// 1. Parse GET_FUNCTION: <relative_path>::<funcname>
	funcRx := regexp.MustCompile(`(?i)GET_FUNCTION:\s*([^\s:]+)::([^\s\n\r()]+)`)
	for _, m := range funcRx.FindAllStringSubmatch(responseRaw, -1) {
		relPath := strings.Trim(m[1], "`'\" ")
		funcName := strings.Trim(m[2], "`'\" ")
		absPath := filepath.Join(repoDir, relPath)

		code, err := GetFunctionCode(absPath, funcName)
		if err != nil {
			results = append(results, fmt.Sprintf("GET_FUNCTION error on %s::%s: %v", relPath, funcName, err))
		} else {
			results = append(results, fmt.Sprintf("### Function definition: %s in %s\n```%s\n%s\n```", funcName, relPath, GetLanguageName(filepath.Ext(relPath)), code))
		}
	}

	// 2. Parse GET_AST: <relative_path>
	astRx := regexp.MustCompile(`(?i)GET_AST:\s*([^\s\n\r]+)`)
	for _, m := range astRx.FindAllStringSubmatch(responseRaw, -1) {
		relPath := strings.Trim(m[1], "`'\" ")
		absPath := filepath.Join(repoDir, relPath)

		astSummary, err := GetASTSummary(absPath)
		if err != nil {
			results = append(results, fmt.Sprintf("GET_AST error on %s: %v", relPath, err))
		} else {
			results = append(results, fmt.Sprintf("### AST summary for %s:\n%s", relPath, astSummary))
		}
	}

	// 3. Parse FIND_DECLARATION: <symbol>
	declRx := regexp.MustCompile(`(?i)FIND_DECLARATION:\s*([^\s\n\r]+)`)
	for _, m := range declRx.FindAllStringSubmatch(responseRaw, -1) {
		symbol := strings.Trim(m[1], "`'\" ")
		declText, err := FindSymbolDeclaration(repoDir, symbol)
		if err != nil {
			results = append(results, fmt.Sprintf("FIND_DECLARATION error on %s: %v", symbol, err))
		} else {
			results = append(results, fmt.Sprintf("### Declarations found for '%s':\n%s", symbol, declText))
		}
	}

	if len(results) == 0 {
		return ""
	}

	return strings.Join(results, "\n\n")
}

