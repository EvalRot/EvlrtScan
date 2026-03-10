# 🔫 Quickfire — Burp Suite Vulnerability Scanner Plugin

**Quickfire** is a Burp Suite extension for targeted vulnerability scanning using custom YAML templates. Unlike Burp's built-in Active Scan, Quickfire gives you full control over payloads, detection logic, and which parameters to test — while keeping track of what's already been scanned.

Built for pentesters who want precision over automation.

---

## ✨ Key Features

- **YAML-based scan templates** — define payloads and detection rules in simple `.yaml` files
- **Interactive scan configuration** — choose exactly which parameters and templates to use per request
- **Coverage map** — track which endpoints have been scanned and with which templates
- **Multi-threaded engine** — configurable thread pool with rate limiting
- **Built-in detection rules** — body contains, regex, status code change, response time, payload reflection, body diff, header check
- **Persistent coverage** — scan progress survives Burp restarts (Montoya Persistence API)
- **Export / Import** — transfer coverage data between Burp projects via JSON

---

## 🏗 Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                        Burp Suite                                │
│                                                                  │
│  ┌──────────────┐    ┌────────────────────┐   ┌───────────────┐  │
│  │ Proxy Traffic │    │  Context Menu       │   │  Quickfire    │  │
│  │ Listener      │    │  "Quickfire—Scan.." │   │  Tab (UI)     │  │
│  └──────┬───────┘    └────────┬───────────┘   │ ┌───────────┐ │  │
│         │                     │               │ │Coverage Map│ │  │
│         │                     ▼               │ │Findings Tab│ │  │
│         │            ┌────────────────┐       │ └───────────┘ │  │
│         │            │ ScanConfigDialog│       └───────┬───────┘  │
│         │            │ (param select,  │              │          │
│         │            │  template pick) │              │          │
│         │            └───────┬────────┘              │          │
│         │                    │ submitJob()            │          │
│         ▼                    ▼                        │          │
│  ┌──────────────┐   ┌────────────────┐               │          │
│  │ Coverage      │   │  ScanEngine    │               │          │
│  │ Tracker       │◄──│  (orchestrator)│               │          │
│  │               │   └───────┬────────┘               │          │
│  │ RouteNorm.    │           │ enqueue()              │          │
│  │ EndpointRec.  │   ┌───────▼────────┐               │          │
│  │ Persistence   │   │   ScanQueue    │               │          │
│  └──────────────┘   │ (BlockingQueue) │               │          │
│                      └───────┬────────┘               │          │
│                              │ take()                 │          │
│                      ┌───────▼────────┐               │          │
│                      │ ScanWorkerPool │───────────────┘          │
│                      │ (N threads)    │  findings → UI           │
│                      │                │                          │
│                      │ ┌────────────┐ │                          │
│                      │ │RateLimiter │ │                          │
│                      │ └────────────┘ │                          │
│                      │ PayloadInjector│                          │
│                      │ DetectionEngine│                          │
│                      └────────────────┘                          │
└──────────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
src/main/java/
├── Extension.java                  # Entry point — wires everything together
│
├── template/                       # YAML template system
│   ├── ScanTemplate.java           # Data model (payloads, detection config)
│   ├── TemplateLoader.java         # Loads & validates .yaml files from disk
│   └── detection/
│       ├── DetectionRule.java       # Interface for all rules
│       ├── DetectionEngine.java     # Factory + OR/AND evaluator
│       └── rules/
│           ├── BodyContainsRule     # Response body substring match
│           ├── BodyRegexRule        # Response body regex match
│           ├── BodyDiffRule         # Levenshtein distance vs baseline
│           ├── StatusCodeRule       # Status code change or match list
│           ├── ResponseTimeRule     # Time-based blind (via Montoya TimingData)
│           ├── PayloadReflectedRule # Payload appears in response body
│           └── HeaderContainsRule   # Specific header value check
│
├── engine/                         # Scan execution engine
│   ├── ScanEngine.java             # Top-level orchestrator
│   ├── ScanJob.java                # One scan operation (request × templates × params)
│   ├── ScanTask.java               # Atomic unit: 1 payload + 1 insertion point
│   ├── ScanFinding.java            # Confirmed vulnerability record
│   ├── ScanOptions.java            # Per-scan settings (threads, delay, timeout)
│   ├── ScanQueue.java              # Thread-safe LinkedBlockingQueue
│   ├── ScanWorkerPool.java         # Fixed thread pool executing tasks
│   ├── SimpleRateLimiter.java      # Token bucket rate limiter
│   ├── InsertionPoint.java         # Injection target (query, body, json, cookie, header, path)
│   ├── InsertionPointParser.java   # Extracts all insertion points from a request
│   └── PayloadInjector.java        # Applies payload with APPEND/REPLACE/INSERT strategy
│
├── coverage/                       # Coverage tracking & persistence
│   ├── CoverageTracker.java        # Central store + Montoya persistence + JSON export/import
│   ├── EndpointRecord.java         # Per-endpoint scan status & findings
│   └── RouteNormalizer.java        # /users/123 → /users/{id}
│
├── handler/                        # Burp integration handlers
│   ├── ProxyTrafficListener.java   # Registers proxy traffic in coverage map
│   └── ContextMenuProvider.java    # Right-click → "Quickfire — Scan..."
│
└── ui/                             # Swing UI components
    ├── QuickfireTab.java           # Main Burp tab container
    ├── CoverageTab.java            # Tree view + detail pane + export/import
    ├── FindingsTab.java            # Table with severity coloring + request/response
    └── ScanConfigDialog.java       # Modal dialog for scan launch configuration
```

---

## ⚙️ How It Works

### 1. Template Loading

On startup, Quickfire loads all `.yaml` / `.yml` files from `~/.quickfire/templates/` (configurable). Each template defines:

```yaml
id: sqli-error-based
name: "SQL Injection — Error Based"
category: injection
severity: high
tags: [sqli, owasp-a03]
injection_strategy: APPEND          # APPEND | REPLACE | INSERT
payloads:
  - "'"
  - "' OR '1'='1"
  - "' AND 1=2--"
detection:
  logic: OR                         # OR | AND
  baseline: true                    # send original request first for comparison
  rules:
    - type: body_contains
      values: ["SQL syntax", "SQLSTATE", "mysql_fetch"]
      case_sensitive: false
    - type: status_code_change
      to: [500, 502, 503]
```

Templates define **what** to inject and **how** to detect — but **not where**. Insertion points are chosen interactively.

### 2. Scan Initiation

1. User right-clicks a request in Repeater / Proxy History → **"🔫 Quickfire — Scan..."**
2. `InsertionPointParser` extracts all potential injection targets from the request:
   - Query parameters, body parameters, JSON values, cookies, headers, URL path segments
3. `ScanConfigDialog` opens — shows grouped insertion points and available templates
4. User selects what to scan, configures threads/delay, clicks **"▶ Start Scan"**

### 3. Scan Execution Pipeline

```
User clicks "Start Scan"
        │
        ▼
  ScanEngine.submitJob()
        │
        ├── Creates ScanJob (metadata + progress tracking)
        ├── Registers job in ScanQueue.activeJobs
        │
        └── Spawns background prep thread ──►
                │
                ├── Sends baseline request (if any template needs it)
                │
                └── Generates ScanTasks (template × point × payload)
                    and enqueues them into ScanQueue
                            │
                            ▼
                    ┌─── ScanQueue (LinkedBlockingQueue) ───┐
                    │  task1, task2, task3, ... taskN        │
                    └───────────────┬───────────────────────┘
                                    │
                           take() ──┤── take() ── take()
                                    │
                    ┌───────────────▼───────────────────────┐
                    │        ScanWorkerPool (N threads)      │
                    │                                        │
                    │  For each task:                         │
                    │   1. rateLimiter.acquire()    ← sleep │
                    │   2. PayloadInjector.inject() ← build │
                    │   3. api.http().sendRequest() ← send  │
                    │   4. DetectionEngine.evaluate()← check│
                    │   5. job.onTaskComplete()     ← report│
                    │                                        │
                    └────────────────────────────────────────┘
```

**Key design points:**
- `ScanEngine` creates a single `ScanQueue` and passes the same reference to `ScanWorkerPool` (constructor injection). Both classes operate on the **same object** in JVM memory.
- `LinkedBlockingQueue.take()` blocks worker threads when the queue is empty. When `offer()` is called, Java's built-in `ReentrantLock` + `Condition` mechanism wakes a sleeping thread.
- `SimpleRateLimiter` is a token-bucket limiter. Worker threads voluntarily call `acquire()` before sending. If the interval since the last request is too short, `Thread.sleep()` pauses the **calling thread** until enough time has passed.

### 4. Detection

After sending a request, the worker evaluates all rules from the template against the response:

| Rule Type | What it checks |
|---|---|
| `body_contains` | Response body includes substring(s) |
| `body_regex` | Response body matches regex pattern |
| `body_diff` | Levenshtein distance vs baseline exceeds threshold |
| `status_code_change` | Status code changed to specific value(s) |
| `response_time` | Response time ≥ threshold (via Montoya `TimingData` API) |
| `payload_reflected` | Injected payload appears verbatim in response |
| `header_contains` | Specific header contains value(s) |

Rules are evaluated with **OR** (any match = finding) or **AND** (all must match) logic.

### 5. Coverage Tracking

Every request through Burp Proxy and every completed scan is tracked:

- `ProxyTrafficListener` registers all endpoints passively
- `RouteNormalizer` groups similar URLs: `/api/users/123/posts` → `/api/users/{id}/posts`
- `EndpointRecord` tracks per-template scan status for each endpoint
- `CoverageTracker` stores everything in a `ConcurrentHashMap` and persists via Montoya Persistence API

**Coverage states:**
- ⛔ **Not scanned** — endpoint seen but never tested
- ⚠ **Partial** — scanned with some templates but not all
- ✅ **Full** — scanned with all active templates

**Memory footprint**: ~1-2 MB for 1,000 endpoints × 10 templates. Negligible in a typical Burp session.

**Export / Import**: Coverage data can be exported as JSON and imported into another Burp project. Merge logic uses timestamps to keep the most recent data.

---

## 🚀 Build & Install

### Prerequisites
- Java 21+
- Gradle (wrapper included)

### Build
```bash
cd ExtensionTemplateProject
./gradlew jar --no-daemon
```

Output: `build/libs/quickfire.jar`

### Install in Burp Suite
1. Open Burp Suite → **Extensions** → **Installed**
2. Click **Add** → Type: **Java** → Select `quickfire.jar`
3. A new **"🔫 Quickfire"** tab appears

### First Run
On first load, Quickfire creates `~/.quickfire/templates/` with 4 starter templates:
- `injection/sqli-error.yaml` — SQL injection (error-based)
- `injection/sqli-timebased.yaml` — SQL injection (time-based blind)
- `injection/nosqli-mongo.yaml` — NoSQL injection (MongoDB)
- `xss/xss-reflected.yaml` — Reflected XSS

---

## 📝 Writing Custom Templates

Create a new `.yaml` file in `~/.quickfire/templates/`:

```yaml
id: ssti-jinja2
name: "SSTI — Jinja2"
category: injection
severity: critical
tags: [ssti, jinja2, rce]
author: your-handle
description: "Detects Server-Side Template Injection in Jinja2/Python"

injection_strategy: REPLACE    # REPLACE | APPEND | INSERT
payloads:
  - "{{7*7}}"
  - "{{config}}"
  - "{{''.__class__.__mro__[1].__subclasses__()}}"

detection:
  logic: OR
  baseline: false
  rules:
    - type: body_contains
      values:
        - "49"
        - "<Config"
        - "subprocess.Popen"
      case_sensitive: true
    - type: body_regex
      pattern: "\\b49\\b"
```

### Injection Strategies

| Strategy | Behavior | Example (original: `admin`) |
|---|---|---|
| `APPEND` | `originalValue + payload` | `admin'` |
| `REPLACE` | `payload` (replaces value entirely) | `'` |
| `INSERT` | `payload + originalValue` | `'admin` |

### Available Detection Rules

```yaml
# String match in response body
- type: body_contains
  values: ["error", "exception"]
  case_sensitive: false              # optional, default: true

# Regex match in response body
- type: body_regex
  pattern: "\\d{3}-\\d{2}-\\d{4}"   # SSN pattern

# Status code changed from baseline to specific value(s)
- type: status_code_change
  to: [500, 502, 503]

# Status code is in a specific list (no baseline needed)
- type: status_code_in
  to: [200, 302]

# Time-based blind detection
- type: response_time
  min_ms: 5000                       # 5 seconds

# Payload reflected in response body
- type: payload_reflected

# Response body significantly different from baseline
- type: body_diff
  threshold: 0.3                     # 0.0 = identical, 1.0 = completely different

# Specific header contains value(s)
- type: header_contains
  header: "Location"
  values: ["redirect", "login"]
```

---

## 🔧 Configuration

Settings are stored via Montoya Persistence API (per Burp project):

| Setting | Default | Description |
|---|---|---|
| `quickfire.templatesDir` | `~/.quickfire/templates/` | Path to YAML templates directory |
| `quickfire.threads` | `5` | Number of scan worker threads |
| `quickfire.maxRps` | `10.0` | Maximum requests per second |

---

## 📦 Dependencies

| Library | Version | Purpose |
|---|---|---|
| [Montoya API](https://portswigger.github.io/burp-extensions-montoya-api/) | latest | Burp Suite extension API |
| [SnakeYAML](https://github.com/snakeyaml/snakeyaml) | 2.3 | YAML template parsing |
| [Gson](https://github.com/google/gson) | 2.11.0 | JSON serialization for coverage export/import |

All dependencies are bundled into the JAR (fat jar via Gradle).

---

## 🛣 Roadmap

- [ ] **Active Scans Panel** — view running jobs, pause/resume/cancel
- [ ] **Settings Panel** — configure templates path, threads, RPS from UI
- [ ] **Auto-scan mode** — automatically scan new proxy traffic with selected templates
- [ ] **Nuclei template import** — convert Nuclei YAML templates to Quickfire format
- [ ] **Findings export** — export findings as Markdown/HTML report

---

## 📄 License

MIT