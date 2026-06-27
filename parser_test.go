package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetFunctionCode(t *testing.T) {
	// Create a temporary file
	dir, err := os.MkdirTemp("", "test_parser")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	code := `package main

import "fmt"

func helloWorld() {
	fmt.Println("hello world")
}

func anotherFunc(x int) int {
	return x + 1
}
`
	tmpFile := filepath.Join(dir, "main.go")
	if err := os.WriteFile(tmpFile, []byte(code), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	// Extract helloWorld
	funcCode, err := GetFunctionCode(tmpFile, "helloWorld")
	if err != nil {
		t.Fatalf("failed to get helloWorld: %v", err)
	}
	if !strings.Contains(funcCode, `fmt.Println("hello world")`) {
		t.Errorf("extracted function helloWorld did not contain expected code, got: %s", funcCode)
	}

	// Extract anotherFunc
	funcCode2, err := GetFunctionCode(tmpFile, "anotherFunc")
	if err != nil {
		t.Fatalf("failed to get anotherFunc: %v", err)
	}
	if !strings.Contains(funcCode2, "return x + 1") {
		t.Errorf("extracted function anotherFunc did not contain expected code, got: %s", funcCode2)
	}
}

func TestGetASTSummary(t *testing.T) {
	dir, err := os.MkdirTemp("", "test_parser")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	code := `package main

func targetFunc() {
	// target func body
}
`
	tmpFile := filepath.Join(dir, "main.go")
	if err := os.WriteFile(tmpFile, []byte(code), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	summary, err := GetASTSummary(tmpFile)
	if err != nil {
		t.Fatalf("failed to get AST summary: %v", err)
	}
	if !strings.Contains(summary, "targetFunc") {
		t.Errorf("AST summary did not mention targetFunc: %s", summary)
	}
}

func TestFindSymbolDeclaration(t *testing.T) {
	dir, err := os.MkdirTemp("", "test_parser")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	code := `package main

type CustomStruct struct {
	Field int
}

func (c *CustomStruct) Process() {
}
`
	tmpFile := filepath.Join(dir, "main.go")
	if err := os.WriteFile(tmpFile, []byte(code), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	// Find CustomStruct
	decl, err := FindSymbolDeclaration(dir, "CustomStruct")
	if err != nil {
		t.Fatalf("failed to find CustomStruct: %v", err)
	}
	if !strings.Contains(decl, "type CustomStruct struct") {
		t.Errorf("expected declaration snippet to contain type definition, got: %s", decl)
	}
}
