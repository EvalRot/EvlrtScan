# 🔫 EvlrtScan — Burp Suite Vulnerability Scanner Plugin

**EvlrtScan** is a Burp Suite extension for targeted vulnerability scanning using custom YAML templates. Unlike Burp's built-in Active Scan, EvlrtScan gives you full control over payloads, detection logic, and which parameters to test — while keeping track of what's already been scanned.

Built for pentesters who want precision over automation.

---

## ✨ Key Features

- **YAML-based scan templates** — define payloads (including payload groups) and detection rules in `.yaml` files
- **Interactive scan configuration** — choose exactly which parameters and templates to use per request
- **Coverage map** — track which endpoints have been scanned and with which templates
- **Multi-threaded engine** — configurable thread pool with rate limiting
- **Smart Diff detection** — structural and content-aware response comparison with dynamic/reflection masking
- **Differential detection** — expression-based cross-response comparison for boolean-based and operator injection
- **Inline regex matching** — `.match("regex")` operator directly inside expressions
- **Encoding-aware injection** — auto-detects URL-encoding, Base64, Unicode; supports forced encoding retry for JSON values
- **Template validation** — bracket balance, expression syntax, reference checks on load
- **Persistent coverage** — scan progress survives Burp restarts (Montoya Persistence API)
- **Export / Import** — transfer coverage data between Burp projects via JSON

---

## 🏗 Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                        Burp Suite                                │
│                                                                  │
│  ┌──────────────┐    ┌────────────────────┐   ┌───────────────┐  │
│  │ Proxy Traffic │    │  Context Menu       │   │  EvlrtScan    │  │
│  │ Listener      │    │  "EvlrtScan—Scan.." │   │  Tab (UI)     │  │
│  └──────┬───────┘    └────────┬───────────┘   │ ┌───────────┐ │  │
│         │                     │               │ │Coverage Map│ │  │
│         │                     ▼               │ │Findings Tab│ │  │
│         │            ┌────────────────┐       │ │Templates   │ │  │
│         │            │ ScanConfigDialog│       │ └───────────┘ │  │
│         │            │ (param select,  │       └───────┬───────┘  │
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
│                      │ SmartDiffEngine│                          │
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
│   ├── ScanTemplate.java           # Data model (payloads, payload groups, detection config)
│   ├── TemplateLoader.java         # Loads & validates .yaml files from disk
│   ├── TemplateValidator.java      # Validates templates: fields, expressions, bracket balance
│   └── detection/
│       ├── DetectionRule.java       # Interface for all rules
│       ├── DetectionEngine.java     # Factory + OR/AND evaluator
│       ├── DiffExpression.java      # Recursive-descent expression parser & evaluator
│       ├── rules/
│       │   ├── BodyContainsRule         # Response body substring match
│       │   ├── BodyRegexRule            # Response body regex match
│       │   ├── BodyDiffRule             # Levenshtein distance vs baseline
│       │   ├── StatusCodeRule           # Status code change or match list
│       │   ├── ResponseTimeRule         # Time-based blind (via Montoya TimingData)
│       │   ├── PayloadReflectedRule     # Payload appears in response body
│       │   ├── HeaderContainsRule       # Specific header value check
│       │   ├── DifferentialDetectionRule# Expression-based cross-response body diff
│       │   └── SmartDiffDetectionRule   # Smart structural+content comparison with expressions
│       └── smartdiff/
│           ├── SmartDiffEngine.java     # Dynamic/Reflection mask builder + Jaccard comparator
│           ├── SmartDiffResult.java     # Content & structure similarity scores
│           ├── ParsedResponse.java      # Key-value representation of a response
│           ├── ResponseParser.java      # Content-Type dispatcher (JSON/HTML/XML)
│           ├── JsonResponseParser.java  # Flattens JSON to key-value map
│           ├── HtmlResponseParser.java  # Extracts structure from HTML
│           └── XmlResponseParser.java   # Extracts structure from XML
│
├── engine/                         # Scan execution engine
│   ├── ScanEngine.java             # Top-level orchestrator
│   ├── ScanJob.java                # One scan operation (request × templates × params)
│   ├── ScanTask.java               # Atomic unit: 1 payload + 1 insertion point
│   ├── GroupScanTask.java          # Group task: N payloads sent as a group for cross-comparison
│   ├── ScanFinding.java            # Confirmed vulnerability record
│   ├── ScanOptions.java            # Per-scan settings (threads, delay, timeout)
│   ├── ScanQueue.java              # Thread-safe LinkedBlockingQueue
│   ├── ScanWorkerPool.java         # Fixed thread pool executing tasks
│   ├── SimpleRateLimiter.java      # Token bucket rate limiter
│   ├── InsertionPoint.java         # Injection target (query, body, json, cookie, header, path)
│   ├── InsertionPointParser.java   # Extracts all insertion points from a request
│   ├── PayloadInjector.java        # Applies payload with APPEND/REPLACE/INSERT/WRAP strategy
│   ├── PayloadEncoder.java         # Encoding helpers (URL, Base64, Unicode)
│   └── EncodingDetector.java       # Auto-detects parameter encoding format
│
├── coverage/                       # Coverage tracking & persistence
│   ├── CoverageTracker.java        # Central store + Montoya persistence + JSON export/import
│   ├── EndpointRecord.java         # Per-endpoint scan status & findings
│   └── RouteNormalizer.java        # /users/123 → /users/{id}
│
├── handler/                        # Burp integration handlers
│   ├── ProxyTrafficListener.java   # Registers proxy traffic in coverage map
│   ├── TrafficFilter.java          # Scope-aware traffic filtering for coverage
│   └── ContextMenuProvider.java    # Right-click → "EvlrtScan — Scan..."
│
└── ui/                             # Swing UI components
    ├── EvlrtScanTab.java           # Main Burp tab container
    ├── CoverageTab.java            # Tree view + detail pane + export/import
    ├── FindingsTab.java            # Table with severity coloring + request/response
    ├── TemplatesTab.java           # Template management UI
    └── ScanConfigDialog.java       # Modal dialog for scan launch configuration
```

---

## ⚙️ How It Works

### 1. Template Loading & Validation

On startup, EvlrtScan loads all `.yaml` / `.yml` files from the configured templates directory. Each template is **validated** before being accepted:

- Required fields check (`id`, `name`, payloads/payload_group, detection rules)
- Expression syntax validation (bracket balance, no consecutive AND/OR, no leading/trailing operators)
- Expression reference validation (all `p1`, `p2`, etc. must match defined `payload_group` ids)
- Regex pattern compilation check
- Rule-type-specific constraints (e.g., `smart_diff` requires `payload_group`)

Invalid templates are rejected with detailed error messages in the Burp log.

### 2. Template Types

#### Simple Payloads — One request per payload

```yaml
id: sqli-error-based
name: "SQL Injection — Error Based"
category: injection
severity: high
tags: [sqli, owasp-a03]
injection_strategy: APPEND
payloads:
  - "'"
  - "' OR '1'='1"
  - "' AND 1=2--"
detection:
  logic: OR
  baseline: true
  rules:
    - type: body_contains
      values: ["SQL syntax", "SQLSTATE", "mysql_fetch"]
      case_sensitive: false
    - type: status_code_change
      to: [500, 502, 503]
```

#### Payload Groups — Multiple payloads sent as a group, then cross-compared

```yaml
id: nosql-boolean-operator
name: NoSQL Injection (Operator Injection)
category: nosqli
severity: high
injection_strategy: WRAP

payload_group:
  - id: p1
    value: '"$eq": "{{ORIGINAL}}"'
    json_type: object
  - id: p2
    value: '"$ne": "{{ORIGINAL}}"'
    json_type: object
  - id: p3
    value: '"$eq": "{{RANDOM}}"'
    json_type: object

detection:
  baseline: true
  rules:
    - type: smart_diff
      content_threshold: 0.90
      expression: >
        ((baseline.body ~ p1.body) AND (baseline.body !~ p2.body))
        OR ((baseline.status ~ p1.status) AND (baseline.status !~ p2.status))
```

Templates define **what** to inject and **how** to detect — but **not where**. Insertion points are chosen interactively.

### 3. Injection Strategies

| Strategy | Behavior | Example (original: `admin`) |
|---|---|---|
| `APPEND` | `originalValue + payload` | `admin'` |
| `REPLACE` | `payload` (replaces value entirely) | `'` |
| `INSERT` | `payload + originalValue` | `'admin` |
| `WRAP` | Payload template with `{{ORIGINAL}}` / `{{RANDOM}}` placeholders | `{"$eq": "admin"}` |

**Placeholders** (available in all strategies):
- `{{ORIGINAL}}` — replaced with the original parameter value
- `{{RANDOM}}` — replaced with a random value matching the original's type/length (number → random number, string → random string)

### 4. Encoding Detection & Handling

`EncodingDetector` automatically identifies parameter encoding:

| Encoding | Detection | Behavior |
|---|---|---|
| `PLAIN` | Default | Payload injected as-is |
| `URL_ENCODED` | Contains `%XX` sequences | Payload is URL-encoded before injection |
| `BASE64` | Valid Base64 with strict heuristics | Payload is Base64-encoded |
| `BASE64_URL_ENCODED` | URL-decoded value is Base64 | Payload is Base64 → URL encoded |
| `UNICODE` | Contains `\uXXXX` sequences | Payload is Unicode-escaped |

For JSON parameters detected as `PLAIN`, the engine automatically creates an additional scan task with forced **Unicode encoding** — useful for bypassing WAFs.

### 5. Scan Initiation

1. User right-clicks a request in Repeater / Proxy History → **"🔫 EvlrtScan — Scan..."**
2. `InsertionPointParser` extracts all potential injection targets from the request:
   - Query parameters, body parameters (form-encoded)
   - **JSON values** (including objects and arrays — crucial for NoSQL injection)
   - Cookies, headers, URL path segments
   - Auto-detects JSON bodies even without explicit `Content-Type: application/json`
3. `ScanConfigDialog` opens — shows grouped insertion points and available templates
4. User selects what to scan, configures threads/delay, clicks **"▶ Start Scan"**

### 6. Scan Execution Pipeline

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
                ├── For simple payloads: creates ScanTask per (template × point × payload)
                │
                └── For payload_groups: creates GroupScanTask per (template × point)
                    (+optional Unicode retry task for JSON params)
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
                    │  Simple tasks:                          │
                    │   1. rateLimiter.acquire()              │
                    │   2. PayloadInjector.inject()           │
                    │   3. api.http().sendRequest()           │
                    │   4. DetectionEngine.evaluate()         │
                    │   5. job.onTaskComplete()               │
                    │                                        │
                    │  Group tasks (smart_diff):              │
                    │   1. Build Dynamic Mask (2 extra reqs)  │
                    │   2. Build Reflection Mask (probe req)  │
                    │   3. Send all payloads in group         │
                    │   4. Parse, mask, compute Jaccard sim.  │
                    │   5. Evaluate expression                │
                    │                                        │
                    └────────────────────────────────────────┘
```

### 7. Detection Rules

#### Simple Detection Rules (per-response)

| Rule Type | What it checks |
|---|---|
| `body_contains` | Response body includes substring(s) |
| `body_regex` | Response body matches regex pattern |
| `body_diff` | Levenshtein distance vs baseline exceeds threshold |
| `status_code_change` | Status code changed to specific value(s) |
| `time_based` | Response time ≥ threshold ms (via Montoya `TimingData` API) |
| `payload_reflected` | Injected payload appears verbatim in response |
| `header_regex` | Specific header matches regex |

Rules are evaluated with **OR** (any match = finding) or **AND** (all must match) logic.

#### Differential Detection (expression-based)

The `differential` rule type uses an expression language for cross-response comparison:

```yaml
- type: differential
  threshold: 0.1
  expression: "(baseline ~ p1) AND (baseline !~ p2) AND (p1 !~ p2)"
```

#### Smart Diff Detection

The `smart_diff` rule type provides intelligent response comparison that ignores dynamic content:

1. **Dynamic Mask** — identifies keys that change across identical requests (timestamps, CSRF tokens, etc.)
2. **Reflection Mask** — identifies keys where injected values are reflected
3. **Jaccard Similarity** — compares masked responses using content and structure metrics separately

```yaml
- type: smart_diff
  content_threshold: 0.90
  structure_threshold: 0.95
  expression: >
    ((baseline.body ~ p1.body) AND (baseline.body !~ p2.body))
    OR p1.match("syntax error|Mongo|unexpected identifier")
```

**Similarity logic:**
- **Similar (`~`)**: both content AND structure are above their thresholds
- **Different (`!~`)**: either content OR structure is below its threshold

### 8. Expression Language

The DSL supports the following operators and constructs:

```
expr       = or_expr
or_expr    = and_expr ("OR" and_expr)*
and_expr   = atom ("AND" atom)*
atom       = "(" expr ")" | match_call | comparison
match_call = operand ".match" "(" quoted_string ")"
comparison = operand operator operand
operand    = ref.property | number | "quoted_string"
```

**Operators:**

| Operator | Description | Context |
|---|---|---|
| `~` | Similar (content & structure above thresholds) | `smart_diff`: Jaccard; `differential`: body diff ratio |
| `!~` | Different (content or structure below threshold) | Same as above, negated |
| `==` | Equal (string or numeric) | Status codes, headers |
| `!=` | Not equal | Status codes, headers |
| `<`, `>`, `<=`, `>=` | Relational (numeric) | Status codes, numeric headers |
| `.match("regex")` | Regex search in response body | Inline regex match (case-insensitive, DOTALL) |

**Operand properties:**

| Syntax | Resolves to |
|---|---|
| `p1` or `p1.body` | Response body of payload p1 |
| `p1.status` | HTTP status code of response p1 |
| `baseline` or `baseline.body` | Baseline response body |
| `baseline.status` | Baseline status code |

**Examples:**

```yaml
# Boolean-based: baseline ≈ p1, baseline ≠ p2
expression: "(baseline ~ p1) AND (baseline !~ p2)"

# Status code comparison
expression: "p1.status == 200 AND p2.status != 200"

# Inline regex match on specific response
expression: >
  p1.match("syntax error|Mongo|unexpected identifier") 
  OR p2.match("syntax error")

# Combined: smart diff + regex fallback
expression: >
  ((baseline.body ~ p1.body) AND (baseline.body !~ p2.body))
  OR p1.match("error|exception|syntax")
```

### 9. Coverage Tracking

Every request through Burp Proxy and every completed scan is tracked:

- `ProxyTrafficListener` registers all endpoints passively
- `TrafficFilter` controls scope-based filtering (defaults to capturing all traffic when scope is not configured)
- `RouteNormalizer` groups similar URLs: `/api/users/123/posts` → `/api/users/{id}/posts`
- `EndpointRecord` tracks per-template scan status for each endpoint
- `CoverageTracker` stores everything in a `ConcurrentHashMap` and persists via Montoya Persistence API

**Coverage states:**
- ⛔ **Not scanned** — endpoint seen but never tested
- ⚠ **Partial** — scanned with some templates but not all
- ✅ **Full** — scanned with all active templates

**Export / Import**: Coverage data can be exported as JSON and imported into another Burp project.

---

## 📝 Writing Custom Templates

Create a new `.yaml` file in your templates directory:

```yaml
id: ssti-jinja2
name: "SSTI — Jinja2"
category: injection
severity: critical
tags: [ssti, jinja2, rce]
author: your-handle
description: "Detects Server-Side Template Injection in Jinja2/Python"

injection_strategy: REPLACE
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

# Time-based blind detection
- type: time_based
  min_ms: 5000                       # 5 seconds

# Payload reflected in response body
- type: payload_reflected

# Response body significantly different from baseline
- type: body_diff
  threshold: 0.3                     # 0.0 = identical, 1.0 = completely different

# Specific header matches regex
- type: header_regex
  header: "Location"
  pattern: "redirect|login"

# Differential — expression-based cross-response comparison
- type: differential
  threshold: 0.1
  expression: "(baseline ~ p1) AND (baseline !~ p2)"

# Smart Diff — structural + content aware comparison
- type: smart_diff
  content_threshold: 0.90
  structure_threshold: 0.95
  expression: >
    (baseline ~ p1) AND (baseline !~ p2)
    OR p1.match("error|exception")
```

### Payload Group with JSON Type

For NoSQL injection and similar attacks, use `payload_group` with `json_type`:

```yaml
injection_strategy: WRAP

payload_group:
  - id: p1
    value: '"$eq": "{{ORIGINAL}}"'
    json_type: object                  # wraps in { } → {"$eq": "value"}
  - id: p2
    value: '"$ne": "{{ORIGINAL}}"'
    json_type: object
  - id: p3
    value: '"$eq": "{{RANDOM}}"'
    json_type: object
```

**`json_type` options:**
- `keep` (default) — preserve the original JSON type
- `object` — wrap the value in `{ }` and parse as a JSON object
- `array` — wrap the value in `[ ]` and parse as a JSON array

### Special Characters in YAML Payloads

To include quotes and special chars in payload values:

```yaml
# Single-quoted string with escaped single quotes
- value: '{{ORIGINAL}}''""`{'

# Double-quoted string
- value: "{{ORIGINAL}}\"test"
```

---

## 🔧 Configuration

Settings are stored via Montoya Persistence API (per Burp project):

| Setting | Default | Description |
|---|---|---|
| Templates Directory | configurable | Path to YAML templates directory |
| Threads | `5` | Number of scan worker threads |
| Max RPS | `10.0` | Maximum requests per second |

---

## 🐛 Remote Debugging

To debug the plugin running in Burp Suite (e.g., on a VM):

### 1. Start Burp with debug agent

```bash
java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005 -jar burpsuite.jar
```

### 2. Connect from IDE

**IntelliJ IDEA:**  Run → Edit Configurations → Add "Remote JVM Debug" → Host: VM IP, Port: 5005

**VS Code:** Create `.vscode/launch.json`:
```json
{
  "type": "java",
  "name": "Debug Burp (Remote)",
  "request": "attach",
  "hostName": "VM_IP",
  "port": 5005
}
```

---

## 📦 Dependencies

| Library | Version | Purpose |
|---|---|---|
| [Montoya API](https://portswigger.github.io/burp-extensions-montoya-api/) | latest | Burp Suite extension API |
| [SnakeYAML](https://github.com/snakeyaml/snakeyaml) | 2.3 | YAML template parsing |
| [Gson](https://github.com/google/gson) | 2.11.0 | JSON serialization for coverage export/import & JSON body parsing |

All dependencies are bundled into the JAR (fat jar via Gradle).

---

## 🛣 Roadmap

- [ ] **Auto-scan mode** — automatically scan new proxy traffic with selected templates
- [ ] **Nuclei template import** — convert Nuclei YAML templates to EvlrtScan format
- [ ] **Findings export** — export findings as Markdown/HTML report
- [x] ~~Active Scans Panel — view running jobs, pause/resume/cancel~~
- [x] ~~Settings Panel — configure templates path, threads, RPS from UI~~

---

## 📄 License

MIT