package main

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// MsgScanStart is sent when scanning begins
type MsgScanStart struct {
	TotalFiles int
}

// MsgScanProgress is sent when a file scan updates
type MsgScanProgress struct {
	Filepath   string
	Status     string // "success", "error", "skipped"
	Context    string
	Report     string
	Errors     string
	Elapsed    float64
	Cached     bool
	Severities map[string]int
}

// MsgTriageResult is sent when triage concludes for a finding
type MsgTriageResult struct {
	File         string
	FindingTitle string
	Verdict      string
	Reasoning    string
	Confidence   float64
	VerdictsStr  string
	AllRounds    []TriageResult
}

// MsgLog is sent to append a new log entry to the dashboard log view
type MsgLog string

// MsgSemaphoreUpdate is sent when API concurrent capacity changes
type MsgSemaphoreUpdate struct {
	Capacity int
	InFlight int
}

// MsgScanFinished is sent when the background scan terminates
type MsgScanFinished struct{}

// TUIState represents the active screen
type TUIState int

const (
	StateDashboard TUIState = iota
	StateExplorer
	StateFileMenu
	StateTextViewer
	StateTriageViewer
	StateTriageDetailViewer
	StateQueueManager
)

// UI Display styling
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#5F5FDF")).
			Padding(0, 1)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(lipgloss.Color("#8787AF")).
			Padding(0, 1)

	redStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FF5F5F"))

	orangeStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFAF5F"))

	yellowStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFF5F"))

	blueStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#5F87FF"))

	greenStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#5FFF5F"))

	whiteStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF"))

	greyStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#8A8A8A"))
)

// TUIFileItem holds explorer tracking state per file
type TUIFileItem struct {
	Filepath   string
	Scanned    bool
	Status     string
	Context    string
	Report     string
	Errors     string
	Severities map[string]int
	Triages    []TriageResult
}

// BubbleModel defines the state machine for the UI
type BubbleModel struct {
	db         *sql.DB
	state      TUIState
	targetPath string
	modelName  string
	startTime  time.Time
	isFinished bool

	// Process stats
	totalFiles     int
	completedScans int
	skippedScans   int
	errorScans     int
	cachedScans    int

	// Severity summaries
	criticalCount int
	highCount     int
	mediumCount   int
	lowCount      int

	// Concurrency
	capInFlight int
	capMax      int

	// Log queue
	logs []string

	// Explorer view
	files           []TUIFileItem
	selectedFileIdx int

	// Menu options
	selectedMenuIdx int

	// Text viewer
	viewTitle      string
	viewTextLines  []string
	viewTextOffset int

	// Triage viewer
	selectedTriageIdx int

	// Queue manager state
	selectedQueueIdx int
	inAddMode        bool
	selectedAddIdx   int

	// Terminal geometry
	terminalHeight int
	terminalWidth  int
}

type MsgTick struct{}

func doTick() tea.Cmd {
	return tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg {
		return MsgTick{}
	})
}

// Init initializes the bubbletea model
func (m BubbleModel) Init() tea.Cmd {
	return doTick()
}

// NewBubbleModel constructs the model
func NewBubbleModel(db *sql.DB, targetPath, model string, scannable []ScannableFile, maxConcurrent int) BubbleModel {
	files := make([]TUIFileItem, len(scannable))
	for i, sf := range scannable {
		files[i] = TUIFileItem{
			Filepath:   sf.Filepath,
			Status:     "pending",
			Severities: make(map[string]int),
		}
	}

	return BubbleModel{
		db:             db,
		state:          StateDashboard,
		targetPath:     targetPath,
		modelName:      model,
		startTime:      time.Now(),
		files:          files,
		capMax:         maxConcurrent,
		capInFlight:    0,
		terminalHeight: 24,
		terminalWidth:  80,
	}
}

// Update handles incoming messages and updates state
func (m BubbleModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.terminalHeight = msg.Height
		m.terminalWidth = msg.Width

	case MsgScanStart:
		m.totalFiles = msg.TotalFiles

	case MsgScanProgress:
		if msg.Status == "skipped" {
			m.skippedScans++
		} else if msg.Status == "error" {
			m.errorScans++
			m.completedScans++
		} else {
			m.completedScans++
		}
		if msg.Cached {
			m.cachedScans++
		}

		// Update file list info
		for i, f := range m.files {
			if f.Filepath == msg.Filepath {
				m.files[i].Scanned = true
				m.files[i].Status = msg.Status
				m.files[i].Context = msg.Context
				m.files[i].Report = msg.Report
				m.files[i].Errors = msg.Errors
				m.files[i].Severities = msg.Severities

				// Attempt to load triage findings from database for this file
				if m.db != nil {
					triages, _ := GetCachedTriages(m.db, msg.Filepath, m.modelName)
					m.files[i].Triages = triages
				}
				break
			}
		}

		// Accumulate severities
		m.criticalCount += msg.Severities["critical"]
		m.highCount += msg.Severities["high"]
		m.mediumCount += msg.Severities["medium"]
		m.lowCount += msg.Severities["low"]

	case MsgTriageResult:
		// Attach triage results to file
		for i, f := range m.files {
			if f.Filepath == msg.File {
				// Re-fetch all triages for this file to maintain correct cache
				if m.db != nil {
					triages, _ := GetCachedTriages(m.db, msg.File, m.modelName)
					m.files[i].Triages = triages
				}
				break
			}
		}

	case MsgLog:
		m.logs = append(m.logs, string(msg))
		if len(m.logs) > 500 {
			m.logs = m.logs[1:]
		}

	case MsgSemaphoreUpdate:
		m.capInFlight = msg.InFlight
		m.capMax = msg.Capacity

	case MsgTick:
		return m, doTick()

	case MsgScanFinished:
		m.isFinished = true
		m.logs = append(m.logs, "🏁 Scan completed successfully!")

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit

		case "p":
			if m.state == StateDashboard {
				scanPausedCond.L.Lock()
				scanPaused = !scanPaused
				if !scanPaused {
					scanPausedCond.Broadcast()
					m.logs = append(m.logs, "▶️ Scan process resumed.")
				} else {
					m.logs = append(m.logs, "⏸️ Scan process paused.")
				}
				scanPausedCond.L.Unlock()
			}
			return m, nil

		case "tab":
			// Toggle between dashboard and results explorer
			if m.state == StateDashboard {
				m.state = StateExplorer
			} else {
				m.state = StateDashboard
			}
			return m, nil

		case "m":
			if m.state == StateDashboard || m.state == StateExplorer {
				m.state = StateQueueManager
				m.selectedQueueIdx = 0
				m.inAddMode = false
			} else if m.state == StateQueueManager {
				m.state = StateDashboard
			}
			return m, nil

		case "q", "esc":
			switch m.state {
			case StateDashboard:
				return m, tea.Quit
			case StateExplorer:
				m.state = StateDashboard
			case StateFileMenu:
				m.state = StateExplorer
			case StateTextViewer:
				m.state = StateFileMenu
			case StateTriageViewer:
				m.state = StateFileMenu
			case StateTriageDetailViewer:
				m.state = StateTriageViewer
			case StateQueueManager:
				if m.inAddMode {
					m.inAddMode = false
				} else {
					m.state = StateDashboard
				}
			}
			return m, nil

		case "up", "k":
			switch m.state {
			case StateExplorer:
				if m.selectedFileIdx > 0 {
					m.selectedFileIdx--
				}
			case StateFileMenu:
				if m.selectedMenuIdx > 0 {
					m.selectedMenuIdx--
				}
			case StateTextViewer, StateTriageDetailViewer:
				if m.viewTextOffset > 0 {
					m.viewTextOffset--
				}
			case StateTriageViewer:
				if m.selectedTriageIdx > 0 {
					m.selectedTriageIdx--
				}
			case StateQueueManager:
				if m.inAddMode {
					if m.selectedAddIdx > 0 {
						m.selectedAddIdx--
					}
				} else {
					if m.selectedQueueIdx > 0 {
						m.selectedQueueIdx--
					}
				}
			}

		case "down", "j":
			switch m.state {
			case StateExplorer:
				if m.selectedFileIdx < len(m.files)-1 {
					m.selectedFileIdx++
				}
			case StateFileMenu:
				if m.selectedMenuIdx < 3 {
					m.selectedMenuIdx++
				}
			case StateTextViewer, StateTriageDetailViewer:
				maxOffset := len(m.viewTextLines) - (m.terminalHeight - 6)
				if maxOffset < 0 {
					maxOffset = 0
				}
				if m.viewTextOffset < maxOffset {
					m.viewTextOffset++
				}
			case StateTriageViewer:
				file := m.files[m.selectedFileIdx]
				if m.selectedTriageIdx < len(file.Triages)-1 {
					m.selectedTriageIdx++
				}
			case StateQueueManager:
				scanQueueMutex.Lock()
				qLen := len(scanQueue)
				scanQueueMutex.Unlock()

				if m.inAddMode {
					excludedCount := len(m.getExcludedFiles())
					if m.selectedAddIdx < excludedCount-1 {
						m.selectedAddIdx++
					}
				} else {
					if m.selectedQueueIdx < qLen-1 {
						m.selectedQueueIdx++
					}
				}
			}

		case "pageup", "b":
			if m.state == StateTextViewer || m.state == StateTriageDetailViewer {
				pageSize := m.terminalHeight - 6
				m.viewTextOffset -= pageSize
				if m.viewTextOffset < 0 {
					m.viewTextOffset = 0
				}
			}

		case "pagedown", "space":
			if m.state == StateTextViewer || m.state == StateTriageDetailViewer {
				pageSize := m.terminalHeight - 6
				maxOffset := len(m.viewTextLines) - pageSize
				if maxOffset < 0 {
					maxOffset = 0
				}
				m.viewTextOffset += pageSize
				if m.viewTextOffset > maxOffset {
					m.viewTextOffset = maxOffset
				}
			}

		case "enter":
			switch m.state {
			case StateExplorer:
				if len(m.files) > 0 {
					m.state = StateFileMenu
					m.selectedMenuIdx = 0
				}
			case StateFileMenu:
				file := m.files[m.selectedFileIdx]
				switch m.selectedMenuIdx {
				case 0: // View Context
					m.viewTitle = "Context Briefing: " + file.Filepath
					m.viewTextLines = strings.Split(file.Context, "\n")
					m.viewTextOffset = 0
					m.state = StateTextViewer
				case 1: // View Report
					m.viewTitle = "Scan Report Findings: " + file.Filepath
					m.viewTextLines = strings.Split(file.Report, "\n")
					m.viewTextOffset = 0
					m.state = StateTextViewer
				case 2: // View Triages
					m.state = StateTriageViewer
					m.selectedTriageIdx = 0
				case 3: // Back
					m.state = StateExplorer
				}
			case StateTriageViewer:
				file := m.files[m.selectedFileIdx]
				if len(file.Triages) > 0 && m.selectedTriageIdx < len(file.Triages) {
					triage := file.Triages[m.selectedTriageIdx]
					m.viewTitle = "Triage Verdict: " + triage.FindingTitle

					var sb strings.Builder
					sb.WriteString(fmt.Sprintf("Finding: %s\n", triage.FindingTitle))
					sb.WriteString(fmt.Sprintf("Verdict: %s (Confidence: %.0f%%)\n", triage.Verdict, triage.Confidence*100))
					sb.WriteString(fmt.Sprintf("Voters: %s\n\n", triage.VerdictsStr))
					sb.WriteString("=== Final Triage Decision Reasoning ===\n")
					sb.WriteString(triage.Reasoning)
					sb.WriteString("\n\n")

					if len(triage.AllRounds) > 0 {
						sb.WriteString("=== Skeptical Review Multi-Rounds ===\n")
						for _, r := range triage.AllRounds {
							sb.WriteString(fmt.Sprintf("[Round %d] Verdict: %s | Confidence: %.0f%%\n", r.Round, r.Verdict, r.Confidence*100))
							sb.WriteString(fmt.Sprintf("Grep Lookup: %v\n", r.GrepUsed))
							if r.GrepUsed {
								sb.WriteString(fmt.Sprintf("Grep Output: %s\n", r.GrepResults))
							}
							sb.WriteString(fmt.Sprintf("Reasoning:\n%s\n", r.Reasoning))
							sb.WriteString("--------------------------------------------------\n")
						}
					}

					m.viewTextLines = strings.Split(sb.String(), "\n")
					m.viewTextOffset = 0
					m.state = StateTriageDetailViewer
				}
			case StateQueueManager:
				if m.inAddMode {
					excluded := m.getExcludedFiles()
					if len(excluded) > 0 && m.selectedAddIdx < len(excluded) {
						selectedFile := excluded[m.selectedAddIdx]
						scanQueueMutex.Lock()
						scanQueue = append(scanQueue, selectedFile)
						scanQueueMutex.Unlock()
						m.logs = append(m.logs, fmt.Sprintf("➕ Added to queue: %s", filepath.Base(selectedFile)))
						m.inAddMode = false
					}
				}
			}
		case "a", "+":
			if m.state == StateQueueManager {
				excluded := m.getExcludedFiles()
				if len(excluded) > 0 {
					m.inAddMode = true
					m.selectedAddIdx = 0
				} else {
					m.logs = append(m.logs, "⚠️ No pending files available to add to the queue.")
				}
			}
			return m, nil

		case "d", "x":
			if m.state == StateQueueManager && !m.inAddMode {
				scanQueueMutex.Lock()
				if len(scanQueue) > 0 && m.selectedQueueIdx < len(scanQueue) {
					removedFile := scanQueue[m.selectedQueueIdx]
					scanQueue = append(scanQueue[:m.selectedQueueIdx], scanQueue[m.selectedQueueIdx+1:]...)
					if m.selectedQueueIdx >= len(scanQueue) && m.selectedQueueIdx > 0 {
						m.selectedQueueIdx--
					}
					m.logs = append(m.logs, fmt.Sprintf("🗑️ Removed from queue: %s", filepath.Base(removedFile)))
				}
				scanQueueMutex.Unlock()
			}
			return m, nil

		case "K", "U":
			if m.state == StateQueueManager && !m.inAddMode {
				scanQueueMutex.Lock()
				if len(scanQueue) > 1 && m.selectedQueueIdx > 0 {
					scanQueue[m.selectedQueueIdx], scanQueue[m.selectedQueueIdx-1] = scanQueue[m.selectedQueueIdx-1], scanQueue[m.selectedQueueIdx]
					m.selectedQueueIdx--
				}
				scanQueueMutex.Unlock()
			}
			return m, nil

		case "J", "D":
			if m.state == StateQueueManager && !m.inAddMode {
				scanQueueMutex.Lock()
				if len(scanQueue) > 1 && m.selectedQueueIdx < len(scanQueue)-1 {
					scanQueue[m.selectedQueueIdx], scanQueue[m.selectedQueueIdx+1] = scanQueue[m.selectedQueueIdx+1], scanQueue[m.selectedQueueIdx]
					m.selectedQueueIdx++
				}
				scanQueueMutex.Unlock()
			}
			return m, nil
		}
	}

	return m, nil
}

// View prints the terminal screen
func (m BubbleModel) View() string {
	var sb strings.Builder

	// Top title bar
	title := titleStyle.Render(fmt.Sprintf(" NANO-ANALYZER EXPLORER - Model: %s ", m.modelName))
	sb.WriteString(title + "\n\n")

	switch m.state {
	case StateDashboard:
		sb.WriteString(m.renderDashboard())
	case StateExplorer:
		sb.WriteString(m.renderExplorer())
	case StateFileMenu:
		sb.WriteString(m.renderFileMenu())
	case StateTextViewer:
		sb.WriteString(m.renderTextViewer())
	case StateTriageViewer:
		sb.WriteString(m.renderTriageViewer())
	case StateTriageDetailViewer:
		sb.WriteString(m.renderTextViewer())
	case StateQueueManager:
		sb.WriteString(m.renderQueueManager())
	}

	return sb.String()
}

func (m BubbleModel) renderDashboard() string {
	runDuration := time.Since(m.startTime).Round(time.Second)

	// AFL Panel 1: Process info
	procInfo := fmt.Sprintf(
		"Run duration : %v\nTarget path  : %s\nTotal files  : %d\nCompleted    : %d\nSkipped/Err  : %d/%d\nCache hits   : %d",
		runDuration, m.targetPath, m.totalFiles, m.completedScans, m.skippedScans, m.errorScans, m.cachedScans,
	)
	procTitle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#87D7FF")).Render("PROCESS TIMING & STATS")
	if scanPaused {
		procTitle += " " + lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF5F5F")).Render("[PAUSED]")
	}
	procBox := boxStyle.Render(procTitle + "\n\n" + procInfo)

	// AFL Panel 2: Severities
	severityInfo := fmt.Sprintf(
		"CRITICAL : %s\nHIGH     : %s\nMEDIUM   : %s\nLOW      : %s",
		redStyle.Render(fmt.Sprintf("%d findings", m.criticalCount)),
		orangeStyle.Render(fmt.Sprintf("%d findings", m.highCount)),
		yellowStyle.Render(fmt.Sprintf("%d findings", m.mediumCount)),
		blueStyle.Render(fmt.Sprintf("%d findings", m.lowCount)),
	)
	sevBox := boxStyle.Render(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#87D7FF")).Render("OVERALL RESULTS") + "\n\n" + severityInfo)

	// API limit Box
	apiInfo := fmt.Sprintf(
		"Active Queries : %d\nMax In-Flight  : %d\nTotal API Calls: %d",
		m.capInFlight, m.capMax, atomic.LoadInt64(&totalLLMCalls),
	)
	apiBox := boxStyle.Render(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#87D7FF")).Render("API CONCURRENCY") + "\n\n" + apiInfo)

	// Join horizontally
	topGrid := lipgloss.JoinHorizontal(lipgloss.Top, procBox, sevBox, apiBox)

	// AFL Panel 3: Live logs scroll
	logLinesCount := m.terminalHeight - 15
	if logLinesCount < 3 {
		logLinesCount = 3
	}

	var logSb strings.Builder
	startIdx := len(m.logs) - logLinesCount
	if startIdx < 0 {
		startIdx = 0
	}
	for i := startIdx; i < len(m.logs); i++ {
		logSb.WriteString(m.logs[i] + "\n")
	}

	logBox := boxStyle.Width(m.terminalWidth - 4).Height(logLinesCount).Render(
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#87D7FF")).Render("REAL-TIME EVENT STREAM") + "\n\n" + logSb.String(),
	)

	// Footer instructions
	footer := greyStyle.Render(" [Tab] Explore Results | [m] Manage Queue | [p] Pause/Resume | [Q/Esc] Quit scan ")

	return lipgloss.JoinVertical(lipgloss.Left, topGrid, "\n", logBox, "\n", footer)
}

func (m BubbleModel) renderExplorer() string {
	var sb strings.Builder
	sb.WriteString(whiteStyle.Render("🎯 SELECT A FILE TO EXPLORE RESULT DETAILS:") + "\n\n")

	listHeight := m.terminalHeight - 8
	if listHeight < 5 {
		listHeight = 5
	}

	// Calculate bounds
	startIdx := m.selectedFileIdx - (listHeight / 2)
	if startIdx < 0 {
		startIdx = 0
	}
	endIdx := startIdx + listHeight
	if endIdx > len(m.files) {
		endIdx = len(m.files)
		startIdx = endIdx - listHeight
		if startIdx < 0 {
			startIdx = 0
		}
	}

	for i := startIdx; i < endIdx; i++ {
		file := m.files[i]
		relPath := file.Filepath
		if strings.HasPrefix(relPath, m.targetPath) {
			relPath = strings.TrimPrefix(relPath, m.targetPath)
			relPath = strings.TrimPrefix(relPath, "/")
		}

		cursor := "  "
		if i == m.selectedFileIdx {
			cursor = "👉"
		}

		statusSymbol := "⬜"
		if file.Scanned {
			if file.Status == "success" {
				if file.Severities["critical"] > 0 || file.Severities["high"] > 0 {
					statusSymbol = "🔴"
				} else if file.Severities["medium"] > 0 {
					statusSymbol = "🟡"
				} else {
					statusSymbol = "🟢"
				}
			} else if file.Status == "error" {
				statusSymbol = "❌"
			}
		}

		sevSummary := ""
		if file.Scanned && file.Status == "success" {
			sevSummary = fmt.Sprintf(" (Crit:%d, High:%d, Med:%d, Low:%d)",
				file.Severities["critical"], file.Severities["high"], file.Severities["medium"], file.Severities["low"])
		}

		line := fmt.Sprintf("%s %s %s%s", cursor, statusSymbol, relPath, sevSummary)
		if i == m.selectedFileIdx {
			sb.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFF87")).Render(line) + "\n")
		} else {
			sb.WriteString(line + "\n")
		}
	}

	// Pad blank lines
	for i := endIdx - startIdx; i < listHeight; i++ {
		sb.WriteString("\n")
	}

	sb.WriteString("\n" + greyStyle.Render(" [Tab] Dashboard | [m] Manage Queue | [Up/Down] Navigate | [Enter] Select file | [Q/Esc] Back "))
	return sb.String()
}

func (m BubbleModel) renderFileMenu() string {
	file := m.files[m.selectedFileIdx]
	relPath := file.Filepath
	if strings.HasPrefix(relPath, m.targetPath) {
		relPath = strings.TrimPrefix(relPath, m.targetPath)
		relPath = strings.TrimPrefix(relPath, "/")
	}

	var sb strings.Builder
	sb.WriteString(whiteStyle.Render(fmt.Sprintf("📂 File: %s", relPath)) + "\n\n")

	options := []string{
		"1. View Context Briefing (Stage 1)",
		"2. View Scan Report Findings (Stage 2)",
		"3. View Triage Decisions & Reviews (Stage 3)",
		"4. Back to file list",
	}

	for i, opt := range options {
		cursor := "  "
		if i == m.selectedMenuIdx {
			cursor = "👉"
			sb.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFF87")).Render(fmt.Sprintf("%s %s", cursor, opt)) + "\n")
		} else {
			sb.WriteString(fmt.Sprintf("%s %s", cursor, opt) + "\n")
		}
	}

	sb.WriteString("\n" + greyStyle.Render(" [Up/Down] Navigate | [Enter] Select option | [Q/Esc] Back "))
	return sb.String()
}

func (m BubbleModel) renderTriageViewer() string {
	file := m.files[m.selectedFileIdx]
	relPath := file.Filepath
	if strings.HasPrefix(relPath, m.targetPath) {
		relPath = strings.TrimPrefix(relPath, m.targetPath)
		relPath = strings.TrimPrefix(relPath, "/")
	}

	var sb strings.Builder
	sb.WriteString(whiteStyle.Render(fmt.Sprintf("🔬 Triage Findings for: %s", relPath)) + "\n\n")

	if len(file.Triages) == 0 {
		sb.WriteString("  No triage findings reported or all findings were skipped.\n\n")
	} else {
		for i, triage := range file.Triages {
			cursor := "  "
			if i == m.selectedTriageIdx {
				cursor = "👉"
			}

			verdictSymbol := "🟢"
			if triage.Verdict == "INVALID" {
				verdictSymbol = "❌"
			} else if triage.Verdict == "UNCERTAIN" {
				verdictSymbol = "❓"
			}

			line := fmt.Sprintf("%s %s %s [%s, Confidence: %.0f%%]", cursor, verdictSymbol, triage.FindingTitle, triage.Verdict, triage.Confidence*100)
			if i == m.selectedTriageIdx {
				sb.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFF87")).Render(line) + "\n")
			} else {
				sb.WriteString(line + "\n")
			}
		}
	}

	sb.WriteString("\n" + greyStyle.Render(" [Up/Down] Navigate | [Enter] View details | [Q/Esc] Back "))
	return sb.String()
}

func (m BubbleModel) renderTextViewer() string {
	var sb strings.Builder
	sb.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#87D7FF")).Render(m.viewTitle) + "\n\n")

	pageHeight := m.terminalHeight - 6
	if pageHeight < 5 {
		pageHeight = 5
	}

	endIdx := m.viewTextOffset + pageHeight
	if endIdx > len(m.viewTextLines) {
		endIdx = len(m.viewTextLines)
	}

	for i := m.viewTextOffset; i < endIdx; i++ {
		sb.WriteString(m.viewTextLines[i] + "\n")
	}

	// Pad blank lines
	for i := endIdx - m.viewTextOffset; i < pageHeight; i++ {
		sb.WriteString("\n")
	}

	// Show paging indicators
	pct := 100
	if len(m.viewTextLines) > 0 {
		pct = int(float64(endIdx) / float64(len(m.viewTextLines)) * 100)
	}
	sb.WriteString("\n" + greyStyle.Render(fmt.Sprintf(" [Space/Down] Scroll Down | [b/Up] Scroll Up | [Q/Esc] Close Viewer (Progress: %d%%) ", pct)))
	return sb.String()
}

func (m BubbleModel) getExcludedFiles() []string {
	scanQueueMutex.Lock()
	inQueue := make(map[string]bool)
	for _, fp := range scanQueue {
		inQueue[fp] = true
	}
	scanQueueMutex.Unlock()

	var excluded []string
	for _, f := range m.files {
		if !inQueue[f.Filepath] && f.Status == "pending" {
			excluded = append(excluded, f.Filepath)
		}
	}
	return excluded
}

func (m BubbleModel) renderQueueManager() string {
	var sb strings.Builder
	sb.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#87D7FF")).Render("📋 INTERACTIVE SCAN QUEUE MANAGER") + "\n\n")

	scanQueueMutex.Lock()
	qCopy := make([]string, len(scanQueue))
	copy(qCopy, scanQueue)
	scanQueueMutex.Unlock()

	if m.inAddMode {
		sb.WriteString(whiteStyle.Render("➕ SELECT A PENDING FILE TO ADD TO THE SCAN QUEUE:") + "\n\n")
		excluded := m.getExcludedFiles()
		if len(excluded) == 0 {
			sb.WriteString(greyStyle.Render("No pending files available to add.") + "\n")
		} else {
			for i, fp := range excluded {
				cursor := "  "
				if i == m.selectedAddIdx {
					cursor = "👉"
				}
				line := fmt.Sprintf("%s %s", cursor, getRelativePath(m.targetPath, fp))
				if i == m.selectedAddIdx {
					sb.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFF87")).Render(line) + "\n")
				} else {
					sb.WriteString(line + "\n")
				}
			}
		}
		sb.WriteString("\n" + greyStyle.Render(" [Up/Down] Navigate | [Enter] Add file | [Esc] Cancel "))
	} else {
		sb.WriteString(whiteStyle.Render("⏳ CURRENT PENDING SCAN QUEUE:") + "\n\n")
		if len(qCopy) == 0 {
			sb.WriteString(greyStyle.Render("(Queue is empty - all discovered files scanned or excluded)") + "\n")
		} else {
			for i, fp := range qCopy {
				cursor := "  "
				if i == m.selectedQueueIdx {
					cursor = "👉"
				}
				line := fmt.Sprintf("%s %d. %s", cursor, i+1, getRelativePath(m.targetPath, fp))
				if i == m.selectedQueueIdx {
					sb.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFF87")).Render(line) + "\n")
				} else {
					sb.WriteString(line + "\n")
				}
			}
		}
		sb.WriteString("\n" + greyStyle.Render(" [Up/Down] Select | [a/+] Add file | [d/x] Remove | [K] Move Up | [J] Move Down | [Esc/m] Back "))
	}

	return sb.String()
}
