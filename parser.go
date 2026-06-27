package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/c"
	"github.com/smacker/go-tree-sitter/cpp"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/smacker/go-tree-sitter/java"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/php"
	"github.com/smacker/go-tree-sitter/python"
	"github.com/smacker/go-tree-sitter/rust"
)

// ASTWarning represents a semantic vulnerability warning found via Tree-sitter
type ASTWarning struct {
	Line        int
	Description string
	Symbol      string
}

// ParsedFileInfo contains all the extracted semantic information about a file
type ParsedFileInfo struct {
	Language  string
	Functions []string
	Warnings  []ASTWarning
}

// GetLanguageGrammar returns the Tree-sitter Language for the given extension
func GetLanguageGrammar(ext string) *sitter.Language {
	switch strings.ToLower(ext) {
	case ".c", ".h":
		return c.GetLanguage()
	case ".cpp", ".cc", ".cxx", ".hpp", ".hxx":
		return cpp.GetLanguage()
	case ".go":
		return golang.GetLanguage()
	case ".py":
		return python.GetLanguage()
	case ".rs":
		return rust.GetLanguage()
	case ".js", ".ts":
		return javascript.GetLanguage() // Use JS grammar for TS files as fallback
	case ".java":
		return java.GetLanguage()
	case ".php":
		return php.GetLanguage()
	default:
		return nil
	}
}

// GetLanguageName returns the human-readable language name for the given extension
func GetLanguageName(ext string) string {
	switch strings.ToLower(ext) {
	case ".c", ".h":
		return "C"
	case ".cpp", ".cc", ".cxx", ".hpp", ".hxx":
		return "C++"
	case ".go":
		return "Go"
	case ".py":
		return "Python"
	case ".rs":
		return "Rust"
	case ".js":
		return "JavaScript"
	case ".ts":
		return "TypeScript"
	case ".java":
		return "Java"
	case ".php":
		return "PHP"
	default:
		return "Unknown"
	}
}

// ParseFileAST parses a file's code using Tree-sitter and returns extracted symbols and warnings
func ParseFileAST(code []byte, ext string) *ParsedFileInfo {
	lang := GetLanguageGrammar(ext)
	if lang == nil {
		return nil
	}

	parser := sitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(lang)

	tree, err := parser.ParseCtx(context.Background(), nil, code)
	if err != nil {
		return nil
	}
	defer tree.Close()

	info := &ParsedFileInfo{
		Language: GetLanguageName(ext),
	}

	traverse(tree.RootNode(), code, info, ext)
	return info
}

func traverse(n *sitter.Node, code []byte, info *ParsedFileInfo, ext string) {
	if n == nil {
		return
	}

	nodeType := n.Type()

	// Extract function names
	isFunc := false
	switch nodeType {
	case "function_declaration", "method_declaration", "function_definition", "function_item":
		isFunc = true
	}

	if isFunc {
		// Try to find the name identifier among children
		for i := 0; i < int(n.ChildCount()); i++ {
			child := n.Child(i)
			if child.Type() == "identifier" || child.Type() == "field_identifier" {
				funcName := string(code[child.StartByte():child.EndByte()])
				info.Functions = append(info.Functions, funcName)
				break
			}
		}
	}

	// Check for dangerous patterns
	checkDangerousPatterns(n, code, info, ext)

	// Recursive traversal
	for i := 0; i < int(n.ChildCount()); i++ {
		traverse(n.Child(i), code, info, ext)
	}
}

func checkDangerousPatterns(n *sitter.Node, code []byte, info *ParsedFileInfo, ext string) {
	nodeType := n.Type()
	ext = strings.ToLower(ext)

	// Language-specific static checks
	if nodeType == "call_expression" {
		// Extract function name/expression
		var funcName string
		// The first child is usually the function identifier or member access
		if n.ChildCount() > 0 {
			child := n.Child(0)
			funcName = string(code[child.StartByte():child.EndByte()])
		}

		line := int(n.StartPoint().Row) + 1

		switch {
		case ext == ".c" || ext == ".h" || ext == ".cpp" || ext == ".cc" || ext == ".cxx" || ext == ".hpp" || ext == ".hxx":
			// C/C++ Checks
			switch funcName {
			case "strcpy":
				info.Warnings = append(info.Warnings, ASTWarning{
					Line:        line,
					Description: "Call to unsafe function 'strcpy' (potential buffer overflow; use 'strncpy' or check bounds first).",
					Symbol:      "strcpy",
				})
			case "strcat":
				info.Warnings = append(info.Warnings, ASTWarning{
					Line:        line,
					Description: "Call to unsafe function 'strcat' (potential buffer overflow; use 'strncat').",
					Symbol:      "strcat",
				})
			case "gets":
				info.Warnings = append(info.Warnings, ASTWarning{
					Line:        line,
					Description: "Call to deprecated/unsafe function 'gets' (guaranteed buffer overflow vulnerability; use 'fgets').",
					Symbol:      "gets",
				})
			case "sprintf":
				info.Warnings = append(info.Warnings, ASTWarning{
					Line:        line,
					Description: "Call to 'sprintf' (potential stack overflow; use 'snprintf' with explicit size validation).",
					Symbol:      "sprintf",
				})
			case "memcpy":
				info.Warnings = append(info.Warnings, ASTWarning{
					Line:        line,
					Description: "Call to raw memory copy 'memcpy' (verify that copy size is bounded and fits target buffer).",
					Symbol:      "memcpy",
				})
			}

		case ext == ".go":
			// Go Checks
			if strings.Contains(funcName, "unsafe.Pointer") {
				info.Warnings = append(info.Warnings, ASTWarning{
					Line:        line,
					Description: "Usage of 'unsafe.Pointer' bypasses Go's memory safety guarantees.",
					Symbol:      "unsafe.Pointer",
				})
			}
			// Check for raw SQL concatenation in db queries: db.Exec("..." + var)
			if strings.Contains(funcName, "Exec") || strings.Contains(funcName, "Query") || strings.Contains(funcName, "QueryRow") {
				// The first argument is index 1 (usually the SQL string in Go db calls after the context, or index 0 if no ctx)
				// Let's check arguments list
				argsList := n.ChildByFieldName("arguments")
				if argsList != nil && argsList.ChildCount() > 1 {
					// Check the children of arguments (index 1 is usually the first arg, or check all args)
					for i := 0; i < int(argsList.ChildCount()); i++ {
						arg := argsList.Child(i)
						if arg.Type() == "binary_expression" {
							argText := string(code[arg.StartByte():arg.EndByte()])
							if strings.Contains(argText, "+") {
								info.Warnings = append(info.Warnings, ASTWarning{
									Line:        line,
									Description: "Potential SQL Injection: dynamic SQL query constructed via string concatenation in DB call.",
									Symbol:      funcName,
								})
								break
							}
						}
					}
				}
			}

		case ext == ".py":
			// Python Checks
			if funcName == "eval" {
				info.Warnings = append(info.Warnings, ASTWarning{
					Line:        line,
					Description: "Usage of dangerous function 'eval()' allows arbitrary code execution from untrusted inputs.",
					Symbol:      "eval",
				})
			}
			if funcName == "exec" {
				info.Warnings = append(info.Warnings, ASTWarning{
					Line:        line,
					Description: "Usage of dangerous function 'exec()' allows arbitrary code execution from untrusted inputs.",
					Symbol:      "exec",
				})
			}
			if strings.Contains(funcName, "subprocess") {
				// If subprocess is called, check if shell=True is passed
				argsList := n.ChildByFieldName("arguments")
				if argsList != nil {
					argsText := string(code[argsList.StartByte():argsList.EndByte()])
					if strings.Contains(argsText, "shell=True") || strings.Contains(argsText, "shell = True") {
						info.Warnings = append(info.Warnings, ASTWarning{
							Line:        line,
							Description: "Subprocess invocation with 'shell=True' is prone to Shell Command Injection.",
							Symbol:      funcName,
						})
					}
				}
			}

		case ext == ".js" || ext == ".ts":
			// JS/TS Checks
			if funcName == "eval" {
				info.Warnings = append(info.Warnings, ASTWarning{
					Line:        line,
					Description: "Usage of dangerous function 'eval()' allows dynamic evaluation of untrusted input.",
					Symbol:      "eval",
				})
			}
		case ext == ".php":
			// PHP Checks
			switch funcName {
			case "eval":
				info.Warnings = append(info.Warnings, ASTWarning{
					Line:        line,
					Description: "Usage of 'eval()' allows execution of arbitrary PHP code (extremely dangerous).",
					Symbol:      "eval",
				})
			case "exec", "shell_exec", "system", "passthru", "popen":
				info.Warnings = append(info.Warnings, ASTWarning{
					Line:        line,
					Description: fmt.Sprintf("Call to command execution function '%s()' is highly prone to Command Injection.", funcName),
					Symbol:      funcName,
				})
			case "unserialize":
				info.Warnings = append(info.Warnings, ASTWarning{
					Line:        line,
					Description: "Usage of 'unserialize()' with untrusted input can lead to Object Injection and RCE.",
					Symbol:      "unserialize",
				})
			}
		}
	}
}

// GenerateSemanticBriefing compiles the parsed AST info into a Markdown summary for the LLM
func GenerateSemanticBriefing(info *ParsedFileInfo) string {
	if info == nil {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("### [SEMANTIC ANALYSIS (Tree-sitter)]\n")
	sb.WriteString(fmt.Sprintf("- **Language detected**: %s\n", info.Language))

	if len(info.Functions) > 0 {
		sb.WriteString("- **Defined Functions/Methods**:\n")
		for _, fn := range info.Functions {
			sb.WriteString(fmt.Sprintf("  - `%s`\n", fn))
		}
	} else {
		sb.WriteString("- **Defined Functions/Methods**: None detected (or unsupported grammar layout)\n")
	}

	if len(info.Warnings) > 0 {
		sb.WriteString("- **AST Security Alerts (Potential structural issues)**:\n")
		for _, w := range info.Warnings {
			sb.WriteString(fmt.Sprintf("  - Line %d: [Symbol: `%s`] %s\n", w.Line, w.Symbol, w.Description))
		}
	} else {
		sb.WriteString("- **AST Security Alerts**: No obvious dangerous functions or structural flaws found by Tree-sitter static analyzer.\n")
	}

	sb.WriteString("\n")
	return sb.String()
}

// GetFunctionCode parses a file, traverses the AST to find a function matching targetFuncName, and returns its source code.
func GetFunctionCode(filepathStr, targetFuncName string) (string, error) {
	codeBytes, err := os.ReadFile(filepathStr)
	if err != nil {
		return "", err
	}
	ext := filepath.Ext(filepathStr)
	lang := GetLanguageGrammar(ext)
	if lang == nil {
		return "", fmt.Errorf("unsupported language for tree-sitter parsing: %s", ext)
	}

	parser := sitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(lang)

	tree, err := parser.ParseCtx(context.Background(), nil, codeBytes)
	if err != nil {
		return "", err
	}
	defer tree.Close()

	node := findFunctionNode(tree.RootNode(), codeBytes, targetFuncName)
	if node == nil {
		return "", fmt.Errorf("function '%s' not found in AST of %s", targetFuncName, filepathStr)
	}

	return string(codeBytes[node.StartByte():node.EndByte()]), nil
}

func findFunctionNode(n *sitter.Node, code []byte, targetName string) *sitter.Node {
	if n == nil {
		return nil
	}
	nodeType := n.Type()
	isFunc := false
	switch nodeType {
	case "function_declaration", "method_declaration", "function_definition", "function_item":
		isFunc = true
	}
	if isFunc {
		for i := 0; i < int(n.ChildCount()); i++ {
			child := n.Child(i)
			if child.Type() == "identifier" || child.Type() == "field_identifier" {
				name := string(code[child.StartByte():child.EndByte()])
				cleanTarget := strings.TrimSuffix(targetName, "()")
				if name == cleanTarget {
					return n
				}
			}
		}
	}
	for i := 0; i < int(n.ChildCount()); i++ {
		res := findFunctionNode(n.Child(i), code, targetName)
		if res != nil {
			return res
		}
	}
	return nil
}

// GetASTSummary parses a file and returns its semantic briefing.
func GetASTSummary(filepathStr string) (string, error) {
	code, err := os.ReadFile(filepathStr)
	if err != nil {
		return "", err
	}
	ext := filepath.Ext(filepathStr)
	info := ParseFileAST(code, ext)
	if info == nil {
		return "", fmt.Errorf("could not parse AST for %s", filepathStr)
	}
	return GenerateSemanticBriefing(info), nil
}

// FindSymbolDeclaration scans all source files in repoDir, parsing their ASTs to find a definition of the target symbol.
func FindSymbolDeclaration(repoDir, symbol string) (string, error) {
	var decls []string

	err := filepath.Walk(repoDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		lang := GetLanguageGrammar(ext)
		if lang == nil {
			return nil // Skip files with unsupported extensions
		}

		// Quick check: does the file contain the symbol text?
		codeBytes, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if !strings.Contains(string(codeBytes), symbol) {
			return nil
		}

		// Parse AST
		parser := sitter.NewParser()
		defer parser.Close()
		parser.SetLanguage(lang)

		tree, err := parser.ParseCtx(context.Background(), nil, codeBytes)
		if err != nil {
			return nil
		}
		defer tree.Close()

		node := findSymbolDeclarationNode(tree.RootNode(), codeBytes, symbol)
		if node != nil {
			lineNum := int(node.StartPoint().Row) + 1
			relPath, _ := filepath.Rel(repoDir, path)
			
			// Extract a snippet of the definition
			snippet := string(codeBytes[node.StartByte():node.EndByte()])
			// If snippet is too long, truncate it
			lines := strings.Split(snippet, "\n")
			if len(lines) > 20 {
				snippet = strings.Join(lines[:20], "\n") + "\n... (truncated)"
			}

			decls = append(decls, fmt.Sprintf("File: %s:%d\n```\n%s\n```", relPath, lineNum, snippet))
		}
		return nil
	})

	if err != nil {
		return "", err
	}

	if len(decls) == 0 {
		return fmt.Sprintf("Symbol '%s' declaration not found in codebase.", symbol), nil
	}

	return strings.Join(decls, "\n\n"), nil
}

func findSymbolDeclarationNode(n *sitter.Node, code []byte, symbol string) *sitter.Node {
	if n == nil {
		return nil
	}
	nodeType := n.Type()
	isDecl := false
	switch nodeType {
	case "function_declaration", "method_declaration", "function_definition", "function_item",
		"class_declaration", "class_definition", "struct_specifier", "interface_declaration",
		"type_spec", "type_declaration", "struct_type", "type_alias":
		isDecl = true
	}
	if isDecl {
		for i := 0; i < int(n.ChildCount()); i++ {
			child := n.Child(i)
			if child.Type() == "identifier" || child.Type() == "field_identifier" || child.Type() == "type_identifier" {
				name := string(code[child.StartByte():child.EndByte()])
				if name == symbol {
					curr := n
					for curr.Parent() != nil {
						pType := curr.Parent().Type()
						if pType == "type_declaration" || pType == "var_declaration" || pType == "const_declaration" {
							curr = curr.Parent()
						} else {
							break
						}
					}
					return curr
				}
			}
		}
	}
	for i := 0; i < int(n.ChildCount()); i++ {
		res := findSymbolDeclarationNode(n.Child(i), code, symbol)
		if res != nil {
			return res
		}
	}
	return nil
}

