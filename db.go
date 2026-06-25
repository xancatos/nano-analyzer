package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

// DBFocus holds vulnerability focus area for a language/extension
type DBFocus struct {
	Extension       string
	Language        string
	Vulnerabilities string
}

// CachedScan matches the DB schema for cached scan results
type CachedScan struct {
	Filepath      string
	Model         string
	ContentHash   string
	Context       string
	Report        string
	Severities    string
	Status        string
	Error         string
	ScanTimestamp string
}

// InitDB initializes the SQLite database, creates tables, and seeds initial focus data
func InitDB(dbPath string) (*sql.DB, error) {
	// Expand home directory path if prefixed with ~
	if strings.HasPrefix(dbPath, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home dir: %w", err)
		}
		dbPath = filepath.Join(home, dbPath[2:])
	}

	// Create directory if not exists
	dbDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create db directory %s: %w", dbDir, err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Enable WAL mode for concurrency
	if _, err := db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to set WAL mode: %w", err)
	}

	// Create tables
	schema := []string{
		`CREATE TABLE IF NOT EXISTS file_focus (
			extension TEXT PRIMARY KEY,
			language TEXT NOT NULL,
			vulnerabilities TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS scan_cache (
			filepath TEXT NOT NULL,
			model TEXT NOT NULL,
			content_hash TEXT NOT NULL,
			context TEXT NOT NULL,
			report TEXT NOT NULL,
			severities TEXT NOT NULL,
			status TEXT NOT NULL,
			error TEXT NOT NULL,
			scan_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (filepath, model)
		);`,
		`CREATE TABLE IF NOT EXISTS triage_cache (
			filepath TEXT NOT NULL,
			model TEXT NOT NULL,
			finding_title TEXT NOT NULL,
			verdict TEXT NOT NULL,
			reasoning TEXT NOT NULL,
			confidence REAL NOT NULL,
			verdicts_str TEXT NOT NULL,
			triage_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (filepath, model, finding_title)
		);`,
	}

	for _, query := range schema {
		if _, err := db.Exec(query); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to run migration: %w", err)
		}
	}

	if err := seedFileFocus(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to seed focus data: %w", err)
	}

	return db, nil
}

func seedFileFocus(db *sql.DB) error {
	focusData := []DBFocus{
		{".c", "C", "Memory safety (buffer overflow, out of bounds read/write, gets/strcpy usage), NULL pointer dereference, use-after-free, double free, integer overflow/underflow, uninitialized memory, type confusion in unions."},
		{".h", "C Header", "Memory safety (buffer overflow, out of bounds read/write, gets/strcpy usage), NULL pointer dereference, use-after-free, double free, integer overflow/underflow, uninitialized memory, type confusion in unions."},
		{".cpp", "C++", "Memory safety (buffer overflow, out of bounds read/write, gets/strcpy usage), NULL pointer dereference, use-after-free, double free, integer overflow/underflow, uninitialized memory, type confusion in unions, unsafe type casting, iterator invalidation."},
		{".cc", "C++", "Memory safety (buffer overflow, out of bounds read/write, gets/strcpy usage), NULL pointer dereference, use-after-free, double free, integer overflow/underflow, uninitialized memory, type confusion in unions, unsafe type casting, iterator invalidation."},
		{".cxx", "C++", "Memory safety (buffer overflow, out of bounds read/write, gets/strcpy usage), NULL pointer dereference, use-after-free, double free, integer overflow/underflow, uninitialized memory, type confusion in unions, unsafe type casting, iterator invalidation."},
		{".hpp", "C++ Header", "Memory safety (buffer overflow, out of bounds read/write, gets/strcpy usage), NULL pointer dereference, use-after-free, double free, integer overflow/underflow, uninitialized memory, type confusion in unions, unsafe type casting, iterator invalidation."},
		{".hxx", "C++ Header", "Memory safety (buffer overflow, out of bounds read/write, gets/strcpy usage), NULL pointer dereference, use-after-free, double free, integer overflow/underflow, uninitialized memory, type confusion in unions, unsafe type casting, iterator invalidation."},
		{".go", "Go", "Nil pointer dereference, slice/array bounds out of range, goroutine leaks/deadlocks, race conditions, unsafe package usage, command/SQL injection, cryptography and TLS misconfigurations, unchecked errors from fallible operations."},
		{".py", "Python", "Command injection (eval, exec, subprocess with shell=True), SQL injection (string formatting in queries), insecure deserialization (pickle, yaml), path traversal, hardcoded credentials, unsafe temp file creation."},
		{".js", "JavaScript", "Prototype pollution, Command injection, Cross-Site Scripting (XSS), SQL/NoSQL injection, path traversal, unsafe eval/Function, security configuration, hardcoded secrets, weak crypto."},
		{".ts", "TypeScript", "Prototype pollution, Command injection, Cross-Site Scripting (XSS), SQL/NoSQL injection, path traversal, unsafe eval/Function, security configuration, hardcoded secrets, weak crypto."},
		{".rs", "Rust", "Unsafe block vulnerabilities (pointer math, unchecked indexing), integer wrapping in unsafe blocks, race conditions in multi-threaded code, logic bugs, dependency vulnerabilities."},
		{".java", "Java", "Insecure deserialization, XXE (XML External Entity injection), SQL injection, Path traversal, insecure cryptographic algorithms, thread-safety/concurrency issues, SSRF (Server-Side Request Forgery)."},
		{".php", "PHP", "SQL injection, remote/local file inclusion (RFI/LFI), command injection, object injection, cross-site scripting (XSS), weak typing issues, unsafe unserialize, file upload bypasses."},
		{".pl", "Perl", "Command injection, SQL injection, insecure eval, path traversal, unvalidated input regex injection."},
		{".sh", "Shell", "Command injection, argument injection, path traversal, privilege escalation, unquoted variables leading to globbing/word splitting, unsafe temp file usage."},
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO file_focus (extension, language, vulnerabilities) VALUES (?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, fd := range focusData {
		if _, err := stmt.Exec(fd.Extension, fd.Language, fd.Vulnerabilities); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetFileFocus retrieves the focus vulnerabilities for a given extension
func GetFileFocus(db *sql.DB, ext string) (string, string) {
	var lang, vulns string
	err := db.QueryRow("SELECT language, vulnerabilities FROM file_focus WHERE extension = ?", strings.ToLower(ext)).Scan(&lang, &vulns)
	if err != nil {
		// Fallback defaults
		return "", ""
	}
	return lang, vulns
}

// GetCachedScan retrieves a cached scan result if the content hash matches
func GetCachedScan(db *sql.DB, filepath, model, contentHash string) (*ScanResult, bool, error) {
	var res ScanResult
	var severitiesJSON string

	query := `SELECT context, report, severities, status, error 
	          FROM scan_cache 
	          WHERE filepath = ? AND model = ? AND content_hash = ?`
	err := db.QueryRow(query, filepath, model, contentHash).Scan(
		&res.Context, &res.Report, &severitiesJSON, &res.Status, &res.Error,
	)
	if err == sql.ErrNoRows {
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}

	res.File = filepath
	res.Model = model

	var sevs map[string]int
	if err := json.Unmarshal([]byte(severitiesJSON), &sevs); err == nil {
		res.Severities = sevs
	} else {
		res.Severities = make(map[string]int)
	}

	return &res, true, nil
}

// SaveCachedScan saves a scan result to cache
func SaveCachedScan(db *sql.DB, r *ScanResult, contentHash string) error {
	sevsJSON, err := json.Marshal(r.Severities)
	if err != nil {
		sevsJSON = []byte("{}")
	}

	query := `INSERT INTO scan_cache (filepath, model, content_hash, context, report, severities, status, error, scan_timestamp)
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	          ON CONFLICT(filepath, model) DO UPDATE SET
	            content_hash = excluded.content_hash,
	            context = excluded.context,
	            report = excluded.report,
	            severities = excluded.severities,
	            status = excluded.status,
	            error = excluded.error,
	            scan_timestamp = CURRENT_TIMESTAMP`
	_, err = db.Exec(query, r.File, r.Model, contentHash, r.Context, r.Report, string(sevsJSON), r.Status, r.Error)
	return err
}

// GetCachedTriages retrieves all cached triage results for a given file and model
func GetCachedTriages(db *sql.DB, filepath, model string) ([]TriageResult, error) {
	query := `SELECT finding_title, verdict, reasoning, confidence, verdicts_str 
	          FROM triage_cache 
	          WHERE filepath = ? AND model = ?`
	rows, err := db.Query(query, filepath, model)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []TriageResult
	for rows.Next() {
		var tr TriageResult
		tr.File = filepath
		err := rows.Scan(&tr.FindingTitle, &tr.Verdict, &tr.Reasoning, &tr.Confidence, &tr.VerdictsStr)
		if err != nil {
			return nil, err
		}
		results = append(results, tr)
	}
	return results, nil
}

// SaveCachedTriage saves a triage result to cache
func SaveCachedTriage(db *sql.DB, filepath, model string, t *TriageResult) error {
	query := `INSERT INTO triage_cache (filepath, model, finding_title, verdict, reasoning, confidence, verdicts_str, triage_timestamp)
	          VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	          ON CONFLICT(filepath, model, finding_title) DO UPDATE SET
	            verdict = excluded.verdict,
	            reasoning = excluded.reasoning,
	            confidence = excluded.confidence,
	            verdicts_str = excluded.verdicts_str,
	            triage_timestamp = CURRENT_TIMESTAMP`
	_, err := db.Exec(query, filepath, model, t.FindingTitle, t.Verdict, t.Reasoning, t.Confidence, t.VerdictsStr)
	return err
}

// ClearCache clears all scan and triage cache tables
func ClearCache(db *sql.DB) error {
	_, err := db.Exec("DELETE FROM scan_cache")
	if err != nil {
		return err
	}
	_, err = db.Exec("DELETE FROM triage_cache")
	return err
}
