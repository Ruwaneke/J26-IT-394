# 🛡 Sentinel

**Sentinel** is a VS Code Extension that provides **real-time intelligent code security analysis** as you type.

It is **Component 1** of a 4-component research system investigating whether adaptive, behaviour-aware security feedback improves developers' secure coding behaviour over time.

---

## Features

| Feature | Status |
|---|---|
| Real-time SQL Injection detection | ✅ Phase 2 |
| Real-time XSS detection | ✅ Phase 6 |
| Hardcoded Secret detection | ✅ Phase 6 |
| Red underline + Problems panel | ✅ Phase 3 |
| Hover explanation panel | ✅ Phase 3 |
| [Explain] [Fix] [Ignore] code actions | ✅ Phase 4 |
| Behaviour events → Member 2 backend | ✅ Phase 5 |
| Sentinel Security Alert terminal | ✅ Phase 6 |
| VS Code Security Dashboard | ✅ Phase 5 |
| AI-powered context analysis | 🔜 Phase 7 |
| AST/data-flow analysis | 🔜 Phase 7 |

---

## Project Structure

```
sentinel/
├── src/
│   ├── extension.ts                  ← Entry point
│   ├── analyzer/
│   │   ├── securityAnalyzer.ts       ← Rule orchestrator
│   │   └── types.ts                  ← SecurityFinding (team contract)
│   ├── rules/
│   │   ├── sqlInjectionRule.ts
│   │   ├── xssRule.ts
│   │   └── hardcodedSecretRule.ts
│   ├── diagnostics/
│   │   ├── diagnosticManager.ts      ← Problems panel + hover
│   │   └── vulnerabilityMetadata.ts  ← Explanations & secure examples
│   ├── events/
│   │   └── securityEventClient.ts    ← Member 2 backend API client
│   └── util/
│       └── uuid.ts
├── .vscode/
│   ├── launch.json                   ← F5 debug config
│   └── tasks.json                    ← Build task
├── package.json
├── tsconfig.json
└── README.md
```

---

## Getting Started

### 1. Install dependencies
```bash
cd sentinel
npm install
```

### 2. Compile
```bash
npm run compile
```

### 3. Run in Extension Development Host
Press **F5** in VS Code (with `sentinel/` open as the workspace).

---

## Usage

Open any source file (.cs, .js, .ts, .py, .java...) and start typing. Sentinel will:

1. Analyze the code after a short debounce delay (default 400ms)
2. Show **red underlines** on vulnerable patterns
3. List issues in the **Problems panel** (Ctrl+Shift+M)
4. Show rich explanations when you **hover** over the underline
5. Show **[Explain] [Fix] [Ignore]** actions via the 💡 lightbulb

### Test SQL Injection Detection

Paste this into a `.cs` file:
```csharp
string query = "SELECT * FROM Users WHERE id=" + userId;
```
Sentinel should immediately flag it as SQL_INJECTION with HIGH severity.

---

## Configuration

| Setting | Default | Description |
|---|---|---|
| `sentinel.enabled` | `true` | Enable/disable analysis |
| `sentinel.debounceMs` | `400` | Delay before analyzing (ms) |
| `sentinel.backendUrl` | `http://localhost:8080` | Member 2 backend API |
| `sentinel.developerId` | `DEV001` | Fallback ID for local learning data only (backend uses GitHub identity) |

---

## Team Interfaces

### SecurityFinding (Component 1 → Component 2)
```typescript
interface SecurityFinding {
  id: string;
  type: VulnerabilityType;
  severity: Severity;
  confidence: number;      // 0.0–1.0
  message: string;
  fileName: string;
  lineNumber: number;
  columnNumber: number;
  codeSnippet: string;
  detectedAt: string;      // ISO 8601
}
```

### Developer Identity (POST /api/auth/github)
Sent after GitHub sign-in. The backend finds or creates the developer and returns its `id`,
which the extension stores in the session and uses as `developerId` in every request below.
```json
{ "githubId": "1234567", "githubUsername": "octocat", "email": "octocat@github.com" }
```

### Security Event API (POST /api/security-events)
Sent when a vulnerability is detected.
```json
{
  "developerId": 1,
  "vulnerabilityType": "SQL_INJECTION",
  "severity": "HIGH",
  "fileName": "UserController.cs",
  "lineNumber": 42,
  "message": "Possible SQL injection"
}
```

### Developer Interaction API (POST /api/developer-interactions)
Sent when the developer acts on a finding. `securityEventId` is the `id` returned when the event was created.
Actions map to `OPEN` (explanation / secure example viewed), `FIX`, `IGNORE` (incl. false positive) and `DISMISS`.
```json
{
  "securityEventId": 10,
  "developerId": 1,
  "action": "OPEN",
  "sessionId": "SESSION-xxx",
  "source": "VSCODE",
  "metadata": "{\"extensionAction\":\"EXPLANATION_VIEWED\",\"confidence\":0.95}"
}
```

Events are only sent while signed in with GitHub; they are queued until the developer ID is available.

---

## Research Context

This is Member 1's contribution to the research project:

> **"An intelligent real-time secure coding environment that detects vulnerabilities, monitors developer responses, adapts security feedback according to behavioural patterns, and evaluates developer security improvement over time."**

**Member 2** — Developer Behaviour Tracker (receives events from this extension)  
**Member 3** — Intelligent Feedback Engine (will provide AI explanations)  
**Member 4** — Analytics & Web Dashboard (visualizes research results)
