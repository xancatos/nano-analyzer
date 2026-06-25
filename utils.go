package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// ScanResult holds the raw output and metadata for a single scanned file
type ScanResult struct {
	File             string         `json:"file"`
	DisplayName      string         `json:"display_name"`
	Model            string         `json:"model"`
	Context          string         `json:"context,omitempty"`
	ContextTokens    int            `json:"context_tokens,omitempty"`
	ContextElapsed   float64        `json:"context_elapsed,omitempty"`
	Report           string         `json:"report,omitempty"`
	PromptTokens     int            `json:"prompt_tokens,omitempty"`
	CompletionTokens int            `json:"completion_tokens,omitempty"`
	TotalTokens      int            `json:"total_tokens,omitempty"`
	ScanElapsed      float64        `json:"scan_elapsed,omitempty"`
	TotalElapsed     float64        `json:"total_elapsed,omitempty"`
	Severities       map[string]int `json:"severities"`
	Status           string         `json:"status"`
	Error            string         `json:"error,omitempty"`
	Lines            int            `json:"lines"`
	Chars            int            `json:"chars"`
	Timestamp        string         `json:"timestamp"`
}

// ScannableFile details a file discovered and verified for scanning
type ScannableFile struct {
	Filepath string
	Lines    int
	Chars    int
}

// SkipInfo records details about a file bypassed during file discovery
type SkipInfo struct {
	Filepath string
	Reason   string
}

// HashContent generates a SHA256 hash string for the file contents
func HashContent(content []byte) string {
	h := sha256.New()
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

// DiscoverFiles walks the given path and filters files by extensions and size limit
func DiscoverFiles(targetPath string, extensions map[string]bool, maxChars int) ([]ScannableFile, []SkipInfo, error) {
	var scannable []ScannableFile
	var skipped []SkipInfo

	info, err := os.Stat(targetPath)
	if err != nil {
		return nil, nil, err
	}

	var candidates []string
	if !info.IsDir() {
		candidates = append(candidates, targetPath)
	} else {
		err = filepath.Walk(targetPath, func(path string, fInfo os.FileInfo, err error) error {
			if err != nil {
				return nil // Skip unreadable paths
			}
			// Skip hidden directories (like .git)
			if fInfo.IsDir() && strings.HasPrefix(fInfo.Name(), ".") && path != targetPath {
				return filepath.SkipDir
			}
			if !fInfo.IsDir() {
				candidates = append(candidates, path)
			}
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	}

	for _, path := range candidates {
		// 1. Check if symlink
		lInfo, err := os.Lstat(path)
		if err == nil && (lInfo.Mode()&os.ModeSymlink != 0) {
			skipped = append(skipped, SkipInfo{Filepath: path, Reason: "symlink"})
			continue
		}

		// 2. Extension check
		ext := strings.ToLower(filepath.Ext(path))
		if len(extensions) > 0 && !extensions[ext] {
			skipped = append(skipped, SkipInfo{Filepath: path, Reason: "extension"})
			continue
		}

		// 3. File size check
		fileInfo, err := os.Stat(path)
		if err != nil {
			skipped = append(skipped, SkipInfo{Filepath: path, Reason: "unreadable"})
			continue
		}
		if int(fileInfo.Size()) > maxChars {
			skipped = append(skipped, SkipInfo{Filepath: path, Reason: fmt.Sprintf("too large (%d bytes)", fileInfo.Size())})
			continue
		}

		// 4. Readability and character check
		contentBytes, err := os.ReadFile(path)
		if err != nil {
			skipped = append(skipped, SkipInfo{Filepath: path, Reason: "unreadable"})
			continue
		}

		if !utf8.Valid(contentBytes) {
			skipped = append(skipped, SkipInfo{Filepath: path, Reason: "unreadable/binary"})
			continue
		}

		charCount := utf8.RuneCount(contentBytes)
		if charCount > maxChars {
			skipped = append(skipped, SkipInfo{Filepath: path, Reason: fmt.Sprintf("too large (%d chars)", charCount)})
			continue
		}

		// Count line breaks
		lineCount := 0
		for _, b := range contentBytes {
			if b == '\n' {
				lineCount++
			}
		}

		scannable = append(scannable, ScannableFile{
			Filepath: path,
			Lines:    lineCount,
			Chars:    charCount,
		})
	}

	return scannable, skipped, nil
}

// PrintLogo outputs the beautiful terminal ASCII art
func PrintLogo(offsetSpaces int, version string) string {
	logoStr := fmt.Sprintf(`
            I   I
           AI   IA
         AA#I   I#AA
       AA##V     V##AA
     AA###V       V###AA
   AA####V         V####AA
 TTT#####V           V#####TTT
 III####V             V####III
 III###V               V###III
 III##V  NANO-ANALYZER  V##III
 III#V    version %s    V#III
 IIIV                     VIII
           A I S L E
    `, version)

	var sb strings.Builder
	indent := strings.Repeat(" ", offsetSpaces)
	lines := strings.Split(logoStr, "\n")
	for _, l := range lines {
		if strings.TrimSpace(l) == "" && l == "" {
			continue
		}
		sb.WriteString(indent + l + "\n")
	}

	// Colored print
	colorGreen := "\033[32m"
	colorReset := "\033[0m"
	fmt.Printf("%s%s%s", colorGreen, sb.String(), colorReset)

	return sb.String()
}

// CopyFile copies a file from src to dest path
func CopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return out.Sync()
}
