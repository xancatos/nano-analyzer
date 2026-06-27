# Nano-analyzer

**A minimal LLM-powered zero-day vulnerability scanner by [AISLE](https://aisle.com).**

![aisle-nano-analyzer-diagram](aisle-nano-analyzer.png)

> **Research prototype for demonstration purposes.** This is a simple, single-file harness that is able to detect real zero-day vulnerabilities. Note that it is a prototype, biased towards C/C++ memory safety bugs, and will produce false positives. We are sharing it as-is in the spirit of open research — expect sharp corners.

## What it does

Nano-analyzer is a simple single-file Python scanner that sends source code through a three-stage LLM pipeline:

1. **Context generation** — a model writes a security briefing about the file: what it does, where untrusted data flows, which buffers exist and how big they are.
2. **Vulnerability scan** — the same model, primed with the context, hunts for zero-day bugs function by function and outputs structured findings.
3. **Skeptical triage** — each finding is challenged over multiple rounds by a skeptical reviewer that can grep the codebase to verify (or refute) defenses. An arbiter makes the final call.

Results are saved as Markdown and JSON files for human review.

## Current limitations

This is a v0.1 prototype. Please keep the following in mind:

- **C/C++ bias.** The prompts, few-shot examples, and heuristics are heavily tuned for C/C++ memory safety vulnerabilities (buffer overflows, NULL derefs, integer overflows, type confusion). It will scan other languages but is much less effective there.
- **False positives.** Even with multi-round triage, expect findings that don't hold up on closer inspection. Always verify manually.
- **False negatives.** The scanner can miss entire vulnerability classes — logic bugs, race conditions, cryptographic issues, authentication bypasses, etc. A clean scan does not mean the code is safe.
- **Single-file analysis.** Each file is scanned independently. Cross-file vulnerabilities that depend on interactions between compilation units will likely be missed.
- **LLM-dependent.** Results vary with the model used. Different models will find different things and hallucinate different false positives.

## Setup

### Requirements

- Go 1.18+ (with CGO enabled)
- A C compiler (GCC or Clang) for compiling Tree-sitter parser grammars
- An OpenAI API key (for OpenAI models) or an OpenRouter API key (for other providers)
- Optional: [ripgrep](https://github.com/BurntSushi/ripgrep) (`rg`) for triage grep lookups

### Install & Build

```bash
git clone https://github.com/weareaisle/nano-analyzer.git
cd nano-analyzer
# Build Go executable (native)
go build -o nano-analyzer .
# Run:
./nano-analyzer --help
```

### Cross-Compilation

Since `nano-analyzer` requires CGO (for SQLite and Tree-sitter grammars), cross-compiling requires a target C toolchain.

#### Target: Intel Mac (`darwin/amd64`)
On macOS, Clang can target `x86_64` natively:
```bash
CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -o nano-analyzer-amd64 .
```

#### Target: Linux (`linux/amd64`)
We recommend using **Zig** as a drop-in C compiler to cross-compile and statically link C libraries:
1. Install Zig:
   ```bash
   brew install zig
   ```
2. Build static binary using `zig cc`:
   ```bash
   CGO_ENABLED=1 GOOS=linux GOARCH=amd64 CC="zig cc -target x86_64-linux-musl" go build -o nano-analyzer-linux-amd64 .
   ```

### API keys

Set your API key as an environment variable:

```bash
# For OpenAI models (model names without a slash, e.g. "gpt-5.4-nano"):
export OPENAI_API_KEY=sk-...

# For OpenRouter models (model names with a slash, e.g. "qwen/qwen3-32b"):
export OPENROUTER_API_KEY=sk-or-...
```

The scanner determines which key to use based on the model name: if it contains a `/`, it routes through OpenRouter; otherwise it uses the OpenAI API directly.

## Usage

### Basic scan

```bash
# Scan a single file
./nano-analyzer ./path/to/file.c

# Scan a directory recursively
./nano-analyzer ./path/to/src/
```

### Common options

```bash
# Use a different model
./nano-analyzer ./src --model gpt-5.4

# Control parallelism
./nano-analyzer ./src --parallel 30

# Bypass SQLite Cache and force fresh LLM calls
./nano-analyzer ./src --no-cache

# Clear current cached entries before scan begins
./nano-analyzer ./src --clear-cache

# Specify a custom location for SQLite database cache
./nano-analyzer ./src --db-path ./my-cache.db

# Point triage grep at the full repo root (useful when scanning a subdirectory)
./nano-analyzer ./lib/crypto/ --repo-dir ./
```

### All flags

| Flag | Default | Description |
|------|---------|-------------|
| `path` | *(required)* | File or directory to scan |
| `-model` | `gpt-5.4-nano` | Model for all stages (context, scan, triage) |
| `-parallel` | `50` | Max concurrent scan API calls |
| `-triage-threshold` | `medium` | Triage findings at or above this severity |
| `-triage-rounds` | `5` | Triage rounds per finding |
| `-triage-parallel` | `50` | Max concurrent triage API calls |
| `-max-connections` | `parallel + triage-parallel` | Total API call cap |
| `-min-confidence` | `0.0` | Only show findings above this confidence (0.0–1.0) |
| `-project` | directory name | Project name used in triage prompts |
| `-repo-dir` | auto | Repo root for grep lookups (auto: parent dir for files, scan dir for folders) |
| `-output-dir` | `""` (disabled) | Where to save results as local files. If empty, local file output is disabled and all results are stored only in the SQLite DB. |
| `-max-chars` | `200,000` | Skip files larger than this |
| `-verbose-triage` | off | Show per-round triage progress |
| `-db-path` | `~/.nano-analyzer/nano-analyzer.db` | SQLite database file location |
| `-no-cache` | off | Force fresh scans bypassing SQLite Cache |
| `-clear-cache` | off | Delete existing scanning & triage cache records |
| `-tui` | `true` | Enable the interactive AFL-style Bubble Tea terminal UI status dashboard and results explorer |

## Interactive TUI Mode

By default, `nano-analyzer` launches an interactive Bubble Tea terminal user interface. The UI features:
- **Dashboard**: Real-time event statistics including execution duration, API concurrency slots, total OpenRouter API calls made, and a live log stream.
- **Results Explorer**: Press `Tab` to switch to the Results Explorer screen. Select any scanned file using `Up`/`Down` and `Enter` to explore vulnerability briefing reports, scan details, and multi-round skeptical reviewer debates.
- **Interactive Queue Manager**: Press `m` on the Dashboard or Explorer to manage the active scan queue dynamically. Rearrange files (using `K`/`J`), remove/exclude files from scanning (using `d`/`x`), or add unscanned files (using `a`/`+`).
- **Pause & Resume**: Press `p` on the Dashboard to pause background scanning at any moment and resume it when ready.

If you prefer logging output directly to the standard terminal instead of the TUI, set the `--tui=false` flag.

## Output

By default, all results are stored in the SQLite database cache (`~/.nano-analyzer/nano-analyzer.db`). If you specify an `--output-dir` path, results are also written locally in Markdown and JSON files:

```
<output-dir>/
├── summary.json              # machine-readable scan summary
├── summary.md                # human-readable scan summary
├── <filename>.md             # raw scanner output per file
├── <filename>.context.md     # context briefing per file
├── <filename>.json           # full result data per file
├── triages/                  # detailed triage reasoning
│   └── T0001_<file>_<title>.md
├── findings/                 # findings that survived triage
│   └── VULN-001_<file>.md
├── triage.json               # all triage verdicts
└── triage_survivors.md       # summary of validated findings
```

## How triage works

When a scan finds a medium-or-above severity issue, the triage pipeline kicks in:

1. A skeptical reviewer examines the finding against the actual code and can **grep the codebase** to verify or refute claimed defenses.
2. This repeats for multiple rounds (default: 5), with each reviewer seeing prior arguments and encouraged to find *new* evidence rather than rehash old points.
3. A final **arbiter** reads all rounds and makes a VALID/INVALID call.
4. The confidence score (e.g. 80% \[VVIVV→V\]) reflects the fraction of rounds that said VALID.

Findings that survive triage are written to the `findings/` directory with full reasoning chains.

## Disclaimer

This tool is a research prototype. It is not a replacement for professional security audits, manual code review, or established static analysis tools. Do not rely on it as your sole security assessment. Use at your own risk.

## License

Apache License 2.0
