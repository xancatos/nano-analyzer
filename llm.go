package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	OpenRouterAPIURL = "https://openrouter.ai/api/v1/chat/completions"
	OpenAIAPIURL     = "https://api.openai.com/v1/chat/completions"
)

// DynamicSemaphore implements dynamic concurrency limits to back off in-flight requests during rate limits/errors
type DynamicSemaphore struct {
	mu           sync.Mutex
	capacity     int
	maxCap       int
	inFlight     int
	successCount int
	cond         *sync.Cond
}

func NewDynamicSemaphore(maxCap int) *DynamicSemaphore {
	s := &DynamicSemaphore{
		capacity: maxCap,
		maxCap:   maxCap,
	}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *DynamicSemaphore) Acquire() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.inFlight >= s.capacity {
		s.cond.Wait()
	}
	s.inFlight++
}

func (s *DynamicSemaphore) Release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inFlight--
	s.cond.Broadcast()
}

func (s *DynamicSemaphore) Backoff() {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Instant drop to 1 connection
	oldCap := s.capacity
	s.capacity = 1
	s.successCount = 0
	if oldCap != s.capacity {
		fmt.Printf("⚠️  [API Congestion] High error rate/rate limit. INSTANTLY reducing in-flight request cap from %d to %d\n", oldCap, s.capacity)
	}
}

func (s *DynamicSemaphore) Recover() {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Increment capacity slowly back to maxCap (additive increase, e.g. every 10 successful requests)
	if s.capacity < s.maxCap {
		s.successCount++
		if s.successCount >= 10 {
			s.capacity++
			s.successCount = 0
			fmt.Printf("✅ [API Recovered] Scaling up concurrent request capacity to %d (max: %d)\n", s.capacity, s.maxCap)
			s.cond.Broadcast()
		}
	}
}

var apiSemaphore *DynamicSemaphore

// InitAPISemaphore sets up the global API concurrency limiter
func InitAPISemaphore(maxConcurrent int) {
	apiSemaphore = NewDynamicSemaphore(maxConcurrent)
}

// ChatMessage represents a single message in the LLM chat history
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ResponseFormat structure for JSON mode
type ResponseFormat struct {
	Type string `json:"type"`
}

// ChatRequest represents the POST payload to OpenAI/OpenRouter
type ChatRequest struct {
	Model           string          `json:"model"`
	Messages        []ChatMessage   `json:"messages"`
	ResponseFormat  *ResponseFormat `json:"response_format,omitempty"`
	ReasoningEffort string          `json:"reasoning_effort,omitempty"`
}

// ChatChoice represents a choice returned by the API
type ChatChoice struct {
	Message struct {
		Content          string `json:"content"`
		ReasoningContent string `json:"reasoning_content"`
	} `json:"message"`
}

// ChatUsage tracks token counts
type ChatUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ChatResponse represents the complete API response body
type ChatResponse struct {
	Choices []ChatChoice `json:"choices"`
	Usage   ChatUsage    `json:"usage"`
	Error   interface{}  `json:"error"`
}

// APIBackend details resolved authorization and endpoints
type APIBackend struct {
	URL     string
	Key     string
	Model   string
	Headers map[string]string
}

// ResolveBackend determines OpenRouter vs OpenAI based on model name and environment variables
func ResolveBackend(model string) (*APIBackend, error) {
	isOpenRouter := strings.Contains(model, "/") || strings.Contains(model, ":")
	if !isOpenRouter {
		// Fallback: if we have OPENROUTER_API_KEY and no OPENAI_API_KEY, use OpenRouter
		if os.Getenv("OPENROUTER_API_KEY") != "" && os.Getenv("OPENAI_API_KEY") == "" {
			isOpenRouter = true
		}
	}

	if isOpenRouter {
		apiKey := os.Getenv("OPENROUTER_API_KEY")
		if apiKey == "" {
			return nil, fmt.Errorf("Model '%s' routes through OpenRouter but OPENROUTER_API_KEY is not set. Set it via: export OPENROUTER_API_KEY=sk-or-...", model)
		}
		return &APIBackend{
			URL:   OpenRouterAPIURL,
			Key:   apiKey,
			Model: model,
			Headers: map[string]string{
				"HTTP-Referer": "https://github.com/weareaisle/nano-analyzer",
				"X-Title":      "nano-analyzer",
			},
		}, nil
	}

	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("Model '%s' routes through OpenAI but OPENAI_API_KEY is not set. Set it via: export OPENAI_API_KEY=sk-...", model)
	}
	return &APIBackend{
		URL:     OpenAIAPIURL,
		Key:     apiKey,
		Model:   model,
		Headers: make(map[string]string),
	}, nil
}

// CallLLM requests completions from the LLM, managing backoff retries and concurrency limits
func CallLLM(model string, messages []ChatMessage, jsonMode bool, maxRetries int, reasoningEffort string) (string, ChatUsage, float64, error) {
	backend, err := ResolveBackend(model)
	if err != nil {
		return "", ChatUsage{}, 0, err
	}

	client := &http.Client{
		Timeout: 120 * time.Second,
	}

	payload := ChatRequest{
		Model:    backend.Model,
		Messages: messages,
	}
	if jsonMode {
		payload.ResponseFormat = &ResponseFormat{Type: "json_object"}
	}
	if reasoningEffort != "" {
		payload.ReasoningEffort = reasoningEffort
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", ChatUsage{}, 0, fmt.Errorf("failed to marshal request: %w", err)
	}

	var lastErr error
	var responseText string
	var usage ChatUsage
	var elapsed float64

	for attempt := 0; ; attempt++ {
		// Backoff sleep (exponential backoff capped at 30 seconds)
		if attempt > 0 {
			if attempt >= 3 {
				fmt.Printf("⚠️  [LLM Request Retrying] Attempt %d failed. Last error: %v. Retrying with backoff...\n", attempt, lastErr)
			}
			backoffSec := 1 << attempt
			if backoffSec > 30 {
				backoffSec = 30
			}
			sleepDur := time.Duration(backoffSec)*time.Second + time.Duration(rand.Float64()*2000)*time.Millisecond
			time.Sleep(sleepDur)
		} else {
			time.Sleep(time.Duration(rand.Float64()*500) * time.Millisecond)
		}

		// Verify pause state
		checkPause()

		t0 := time.Now()

		// Acquire dynamic semaphore connection slot
		if apiSemaphore != nil {
			apiSemaphore.Acquire()
		}

		// Increment API call counter
		atomic.AddInt64(&totalLLMCalls, 1)

		req, err := http.NewRequest("POST", backend.URL, bytes.NewBuffer(payloadBytes))
		if err != nil {
			if apiSemaphore != nil {
				apiSemaphore.Release()
				apiSemaphore.Backoff()
			}
			lastErr = err
			continue
		}

		req.Header.Set("Authorization", "Bearer "+backend.Key)
		req.Header.Set("Content-Type", "application/json")
		for k, v := range backend.Headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		elapsed = time.Since(t0).Seconds()

		// Release dynamic semaphore connection slot
		if apiSemaphore != nil {
			apiSemaphore.Release()
		}

		if err != nil {
			if apiSemaphore != nil {
				apiSemaphore.Backoff()
			}
			lastErr = err
			continue
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			if apiSemaphore != nil {
				apiSemaphore.Backoff()
			}
			lastErr = err
			continue
		}

		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			if apiSemaphore != nil {
				apiSemaphore.Backoff()
			}
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))
			continue
		}

		if resp.StatusCode != 200 {
			if apiSemaphore != nil {
				apiSemaphore.Backoff()
			}
			lastErr = fmt.Errorf("API HTTP %d: %s", resp.StatusCode, string(bodyBytes))
			continue
		}

		var apiResp ChatResponse
		if err := json.Unmarshal(bodyBytes, &apiResp); err != nil {
			if apiSemaphore != nil {
				apiSemaphore.Backoff()
			}
			lastErr = fmt.Errorf("failed to parse API JSON response: %w", err)
			continue
		}

		if apiResp.Error != nil {
			if apiSemaphore != nil {
				apiSemaphore.Backoff()
			}
			lastErr = fmt.Errorf("API error: %v", apiResp.Error)
			continue
		}

		if len(apiResp.Choices) == 0 {
			if apiSemaphore != nil {
				apiSemaphore.Backoff()
			}
			lastErr = fmt.Errorf("API returned 0 choices")
			continue
		}

		choice := apiResp.Choices[0]
		responseText = choice.Message.Content
		if responseText == "" {
			responseText = choice.Message.ReasoningContent
		}

		if responseText == "" {
			if apiSemaphore != nil {
				apiSemaphore.Backoff()
			}
			lastErr = fmt.Errorf("API returned empty choice content")
			continue
		}

		if jsonMode && ExtractJSON(responseText) == nil {
			if apiSemaphore != nil {
				apiSemaphore.Backoff()
			}
			lastErr = fmt.Errorf("API response is not valid JSON under jsonMode: %q", responseText)
			continue
		}

		usage = apiResp.Usage

		// Success: trigger additive recovery for concurrent connection limit
		if apiSemaphore != nil {
			apiSemaphore.Recover()
		}

		return responseText, usage, elapsed, nil
	}
}

// ExtractJSON attempts to find and repair JSON structures in text
func ExtractJSON(text string) interface{} {
	text = strings.TrimSpace(text)

	// Pattern 1: Fenced code block
	fenceRegex := regexp.MustCompile("(?s)```(?:json)?\\s*\\n?(.*?)(?:\\n)?```")
	if match := fenceRegex.FindStringSubmatch(text); len(match) > 1 {
		text = strings.TrimSpace(match[1])
	}

	// Try standard parsing
	var v interface{}
	if err := json.Unmarshal([]byte(text), &v); err == nil {
		return v
	}

	// Repair common model malformations
	if strings.Contains(text, `"severity"`) {
		repaired := text

		// Remove leading key indices, e.g. "0: {" -> "{" or ", 1: {" -> ", {"
		idxRegex := regexp.MustCompile(`,?\s*\d+\s*:\s*\{`)
		repaired = idxRegex.ReplaceAllString(repaired, ", {")

		// Remove leading comma in array if exists
		repaired = strings.TrimSpace(repaired)
		if strings.HasPrefix(repaired, "[,") || strings.HasPrefix(repaired, "[ ,") {
			repaired = "[" + repaired[strings.Index(repaired, "{"):]
		}

		// Escape invalid backslashes (not followed by basic JSON escape codes)
		slashRegex := regexp.MustCompile(`\\([^"\\/bfnrtu])`)
		repaired = slashRegex.ReplaceAllString(repaired, `\\$1`)

		if err := json.Unmarshal([]byte(repaired), &v); err == nil {
			return v
		}

		// Last resort: extract individual { } objects containing "severity"
		objStartRegex := regexp.MustCompile(`\{\s*"severity"`)
		matches := objStartRegex.FindAllStringIndex(text, -1)
		var objects []interface{}
		for _, m := range matches {
			start := m[0]
			depth := 0
			for i := start; i < len(text); i++ {
				if text[i] == '{' {
					depth++
				} else if text[i] == '}' {
					depth--
					if depth == 0 {
						chunk := text[start : i+1]
						chunk = slashRegex.ReplaceAllString(chunk, `\\$1`)
						var obj interface{}
						if err := json.Unmarshal([]byte(chunk), &obj); err == nil {
							objects = append(objects, obj)
						}
						break
					}
				}
			}
		}
		if len(objects) > 0 {
			return objects
		}
	}

	// Try to slice text between first [ and last ] or first { and last }
	for _, chars := range [][]string{{"[", "]"}, {"{", "}"}} {
		start := strings.Index(text, chars[0])
		if start == -1 {
			continue
		}
		end := strings.LastIndex(text, chars[1])
		if end == -1 || end <= start {
			continue
		}
		candidate := text[start : end+1]
		if err := json.Unmarshal([]byte(candidate), &v); err == nil {
			return v
		}
	}

	return nil
}
