# Component 1 (Sentinel) → Component 2 (Behaviour Tracker) API

Component 1 makes its data available to Component 2 in two ways:

| Channel | Direction | When to use |
|---|---|---|
| **Push** | C1 `POST {sentinel.backendUrl}/api/security-events` | C2 receives every `SecurityEvent` as it happens (existing, batched every 1 s, 3 retries) |
| **Pull** | C2 `GET http://127.0.0.1:{sentinel.api.port}/api/v1/...` | C2 fetches live findings, history, behaviour, feedback and shift data on demand |

The pull API runs inside the VS Code extension host. It starts when the extension activates and listens on `127.0.0.1` only.

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `sentinel.api.enabled` | `true` | Run the API server |
| `sentinel.api.port` | `7420` | Port |
| `sentinel.api.key` | `""` | If set, every request except `/health` must send header `X-Sentinel-Api-Key: <key>` |

When any of these settings changes, the server restarts.

## Response envelope

```json
{ "success": true,  "apiVersion": "v1", "generatedAt": "2026-10-21T06:23:23.837Z", "data": { ... } }
{ "success": false, "apiVersion": "v1", "error": "Unknown endpoint: /api/v1/nope" }
```

Status codes: `200` OK, `401` bad or missing API key, `404` unknown endpoint, `405` method other than GET, `500` internal error.

## Endpoints

All endpoints are `GET`. If `developerId` is omitted, the API uses the developer currently signed in to VS Code (their GitHub username).

| Endpoint | `data` contents |
|---|---|
| `/api/v1/health` | `status`, `component`, `extensionVersion`, `sessionId`, `startedAt`, `database` (Neon status) |
| `/api/v1/findings/live` | `count`, `findings: SecurityFinding[]`: the open warnings in the editor right now |
| `/api/v1/events?since=<ISO>&limit=<n≤1000>` | `count`, `events: SecurityEvent[]`: the same events as the push channel, from an in-memory buffer (last 1000). Poll with `since` set to the last `timestamp` you received |
| `/api/v1/vulnerabilities?developerId=&status=OPEN\|FIXED\|IGNORED\|ALL&limit=` | `developerId`, `count`, `records: DbVulnerabilityRecord[]` |
| `/api/v1/stats?developerId=` | `developerId`, `stats: VulnerabilityStats` |
| `/api/v1/developers/{id}/insights` | The full `DeveloperInsights` snapshot (see below). The developer dashboard shows the same data |
| `/api/v1/developers/{id}/behaviour` | `behaviour`, `trend`, `fixRateByType` |
| `/api/v1/developers/{id}/feedback` | `feedback: FeedbackItem[]`, `ratings: FeedbackRating[]` |
| `/api/v1/developers/{id}/shifts` | `assigned: Shift[]`, `active: ShiftSession \| null`, `sessions: ShiftSession[]` |

The types are defined in:

- `SecurityFinding`, `SecurityEvent`: `component-1-sentinel/src/analyzer/types.ts`
- `DbVulnerabilityRecord`, `VulnerabilityStats`: `component-1-sentinel/src/data/neonDatabaseService.ts`
- `DeveloperInsights`, `BehaviourProfile`, `FeedbackItem`, `FeedbackRating`: `component-1-sentinel/src/analytics/developerInsights.ts`
- `Shift`, `ShiftSession`: `component-1-sentinel/src/data/projectStore.ts`

### `DeveloperInsights` (abridged)

```jsonc
{
  "developerId": "octocat",
  "totals": { "identified": 6, "fixed": 3, "open": 2, "ignored": 1, "liveWarnings": 1, "fixRate": 50, "openRate": 33.3 },
  "severity":     { "CRITICAL": 2, "HIGH": 2, "MEDIUM": 2, "LOW": 0, "INFO": 0 },
  "liveSeverity": { "CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0 },
  "owasp": [{ "id": "A03:2021", "name": "Injection", "count": 5 }],
  "fixRateByType": [{ "vulnerabilityType": "SQL_INJECTION", "detected": 3, "fixed": 2, "ignored": 0, "open": 1, "fixRate": 66.7 }],
  "trend": [{ "date": "2026-10-20", "detected": 2, "fixed": 1 }],          // last 14 days
  "topFiles": [{ "fileName": "app.js", "open": 1, "total": 2 }],
  "behaviour": {
    "pattern": "STEADY",                 // PROACTIVE_FIXER | STEADY | DISMISSIVE | AT_RISK | NEW
    "patternLabel": "Fixes most warnings over time",
    "responsivenessRate": 75,            // fixed / (fixed + ignored), %
    "ignoreRate": 16.7,                  // ignored / identified, %
    "meanTimeToFixMinutes": 10, "medianTimeToFixMinutes": 10,
    "repeatedMistakes": [{ "vulnerabilityType": "SQL_INJECTION", "occurrences": 3, "fixed": 2 }],
    "suppressedTypes": [],
    "actionCounts": { "FEEDBACK_RATED": 1 }
  },
  "feedback": [{ "vulnerabilityType": "SQL_INJECTION", "title": "SQL Injection", "priority": "HIGH", "reason": "...", "recommendation": "...", "secureExample": "...", "references": ["https://..."] }],
  "feedbackRatings": [{ "findingId": null, "vulnerabilityType": "XSS", "helpful": true, "comment": "clear!", "ratedAt": "..." }],
  "shift": { "sessionsCompleted": 1, "totalShiftMinutes": 60, "findingsPerHour": 1, "averageSecurityScore": 72, "latestTrend": "improving" }
}
```

### Behaviour pattern rules

The rules are checked in this order:

1. **NEW**: fewer than 3 findings identified.
2. **DISMISSIVE**: ignore rate is 40% or higher.
3. **AT_RISK**: some vulnerability type has occurred 5 or more times and less than half of those occurrences were fixed.
4. **PROACTIVE_FIXER**: fix rate is 70% or higher and the median time to fix is 30 minutes or less.
5. **STEADY**: anything else.

## Quick test

```bash
curl -s http://127.0.0.1:7420/api/v1/health | jq
curl -s -H "X-Sentinel-Api-Key: $KEY" "http://127.0.0.1:7420/api/v1/events?since=2026-10-21T00:00:00Z" | jq '.data.count'
```
