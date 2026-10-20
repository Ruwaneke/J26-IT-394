#!/bin/bash
# ============================================================================
# Component 2 – Behaviour Tracker: Synthetic Test Data Generator
# ============================================================================
#
# PURPOSE:
#   Generates SYNTHETIC/TEST behaviour records in the Component 2 backend
#   so you can verify that data collection, storage, and querying work
#   correctly. This is NOT real research data — it is explicitly labelled
#   as synthetic data for development and testing purposes only.
#
# PREREQUISITES:
#   1. Component 2 backend running on http://localhost:8080
#      (cd component-2-behaviour-tracker/backend && mvn spring-boot:run)
#   2. curl installed
#   3. jq installed (optional, for pretty output)
#
# USAGE:
#   chmod +x generate-test-data.sh
#   ./generate-test-data.sh
#
# WHAT IT CREATES:
#   - 3 test developers (if they don't already exist)
#   - 15 security events across the developers
#   - 40+ behaviour log entries (OPEN, FIX, IGNORE, DISMISS, REOPEN actions)
#   - Full lifecycle transitions on security events
#   - Varied timestamps, sessions, and sources
#
# ============================================================================

set -euo pipefail

BACKEND_URL="${BACKEND_URL:-http://localhost:8080}"
API="$BACKEND_URL/api"

# Colours for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Component 2 – Synthetic Test Data Generator${NC}"
echo -e "${CYAN}  Target: ${BACKEND_URL}${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# ── Check backend is running ────────────────────────────────────────────────

echo -n "Checking backend connectivity... "
if ! curl -sf "$API/developers" > /dev/null 2>&1; then
  echo -e "${RED}FAILED${NC}"
  echo -e "${RED}Cannot reach $BACKEND_URL. Make sure the backend is running:${NC}"
  echo -e "${YELLOW}  cd component-2-behaviour-tracker/backend${NC}"
  echo -e "${YELLOW}  mvn spring-boot:run${NC}"
  exit 1
fi
echo -e "${GREEN}OK${NC}"
echo ""

# ── Helper functions ────────────────────────────────────────────────────────

post() {
  local url="$1"
  local data="$2"
  local response
  response=$(curl -sf -X POST "$url" \
    -H "Content-Type: application/json" \
    -d "$data" 2>&1) || {
    echo -e "${RED}  FAILED: POST $url${NC}"
    echo -e "${RED}  Response: $response${NC}"
    return 1
  }
  echo "$response"
}

get_id() {
  # Extract "id" from JSON response (works without jq)
  echo "$1" | grep -o '"id":[0-9]*' | head -1 | grep -o '[0-9]*'
}

timestamp_offset() {
  # Generate an ISO timestamp offset from now by N seconds
  local offset_seconds="$1"
  if [[ "$(uname)" == "Darwin" ]]; then
    date -u -v"-${offset_seconds}S" "+%Y-%m-%dT%H:%M:%S"
  else
    date -u -d "-${offset_seconds} seconds" "+%Y-%m-%dT%H:%M:%S"
  fi
}

# ── Step 1: Create Test Developers ──────────────────────────────────────────

echo -e "${YELLOW}Step 1: Creating test developers...${NC}"

DEV_IDS=()

for dev_id_str in "synthetic-dev-alpha" "synthetic-dev-beta" "synthetic-dev-gamma"; do
  response=$(post "$API/developers" "{\"developerIdentifier\": \"$dev_id_str\"}" 2>&1) || {
    # Developer might already exist, try to find them
    existing=$(curl -sf "$API/developers" 2>/dev/null)
    dev_db_id=$(echo "$existing" | grep -o "\"id\":[0-9]*,\"developerIdentifier\":\"$dev_id_str\"" | grep -o '"id":[0-9]*' | grep -o '[0-9]*')
    if [ -n "$dev_db_id" ]; then
      echo -e "  ${GREEN}✓${NC} $dev_id_str already exists (id: $dev_db_id)"
      DEV_IDS+=("$dev_db_id")
      continue
    fi
    echo -e "  ${RED}✗${NC} Failed to create $dev_id_str"
    continue
  }
  dev_db_id=$(get_id "$response")
  echo -e "  ${GREEN}✓${NC} Created $dev_id_str (id: $dev_db_id)"
  DEV_IDS+=("$dev_db_id")
done

if [ ${#DEV_IDS[@]} -lt 1 ]; then
  echo -e "${RED}No developers available. Cannot continue.${NC}"
  exit 1
fi

echo ""

# ── Step 2: Create Security Events ─────────────────────────────────────────

echo -e "${YELLOW}Step 2: Creating security events...${NC}"

EVENT_IDS=()
EVENT_OWNERS=()

# Vulnerability types, severities, files for realistic test data
VULN_TYPES=("SQL_INJECTION" "XSS" "HARDCODED_SECRET" "INSECURE_DESERIALIZATION" "PATH_TRAVERSAL" "COMMAND_INJECTION" "OPEN_REDIRECT" "WEAK_CRYPTO" "CSRF" "SSRF" "XXE" "LDAP_INJECTION" "LOG_INJECTION" "INSECURE_RANDOM" "MISSING_AUTH")
SEVERITIES=("CRITICAL" "HIGH" "MEDIUM" "LOW")
FILES=("src/main/java/UserController.java" "src/main/java/AuthService.java" "src/main/java/PaymentGateway.java" "src/main/java/FileUploadHandler.java" "src/main/java/DatabaseHelper.java" "src/controllers/apiController.js" "src/services/emailService.ts" "src/utils/cryptoUtils.py" "src/handlers/webhookHandler.go" "src/routes/adminRoutes.rb")
MESSAGES=("User input concatenated into SQL query without parameterisation" "Unescaped user content rendered in HTML template" "API key hardcoded in source file" "Untrusted data deserialised without validation" "User-controlled path used in file system access" "Shell command built with unsanitised input" "Redirect URL taken from query parameter without allow-list check" "Deprecated cryptographic algorithm in use" "Form submission lacks CSRF token verification" "Server-side request target derived from user input")

event_count=15
for i in $(seq 0 $((event_count - 1))); do
  # Round-robin developer assignment
  dev_idx=$((i % ${#DEV_IDS[@]}))
  dev_id="${DEV_IDS[$dev_idx]}"

  vuln_type="${VULN_TYPES[$((i % ${#VULN_TYPES[@]}))]}"
  severity="${SEVERITIES[$((i % ${#SEVERITIES[@]}))]}"
  file="${FILES[$((i % ${#FILES[@]}))]}"
  message="${MESSAGES[$((i % ${#MESSAGES[@]}))]}"
  line=$((10 + RANDOM % 200))

  # Stagger detection timestamps: events detected over the past 7 days
  offset_seconds=$(( (event_count - i) * 43200 )) # ~12h apart
  detected_at=$(timestamp_offset $offset_seconds)

  payload=$(cat <<EOF
{
  "developerId": $dev_id,
  "vulnerabilityType": "$vuln_type",
  "severity": "$severity",
  "fileName": "$file",
  "lineNumber": $line,
  "message": "$message [SYNTHETIC TEST DATA]",
  "detectedAt": "$detected_at"
}
EOF
)

  response=$(post "$API/security-events" "$payload" 2>&1) || {
    echo -e "  ${RED}✗${NC} Failed to create event $((i+1))"
    continue
  }
  event_id=$(get_id "$response")
  echo -e "  ${GREEN}✓${NC} Event $((i+1))/$event_count: $vuln_type ($severity) → developer $dev_id (event id: $event_id)"
  EVENT_IDS+=("$event_id")
  EVENT_OWNERS+=("$dev_id")
done

echo ""
echo -e "  Created ${GREEN}${#EVENT_IDS[@]}${NC} security events"
echo ""

# ── Step 3: Generate Behaviour Actions ──────────────────────────────────────

echo -e "${YELLOW}Step 3: Generating developer behaviour actions...${NC}"

ACTIONS=("OPEN" "FIX" "IGNORE" "DISMISS" "REOPEN")
SOURCES=("VSCODE" "VSCODE" "VSCODE" "WEB_DASHBOARD" "API_TEST")
action_count=0
error_count=0

# For each security event, generate a realistic sequence of developer actions
for idx in $(seq 0 $((${#EVENT_IDS[@]} - 1))); do
  event_id="${EVENT_IDS[$idx]}"
  dev_id="${EVENT_OWNERS[$idx]}"

  # Determine a realistic action sequence based on the event index
  case $((idx % 5)) in
    0) # Quick fix: OPEN → FIX
      sequences=("OPEN" "FIX")
      ;;
    1) # Ignored: OPEN → IGNORE
      sequences=("OPEN" "IGNORE")
      ;;
    2) # Full lifecycle: OPEN → FIX → REOPEN → FIX
      sequences=("OPEN" "FIX" "REOPEN" "FIX")
      ;;
    3) # Dismissed: OPEN → DISMISS
      sequences=("OPEN" "DISMISS")
      ;;
    4) # Ignored then reopened: OPEN → IGNORE → REOPEN → FIX
      sequences=("OPEN" "IGNORE" "REOPEN" "FIX")
      ;;
  esac

  # Calculate base time offset for this event's actions (offset from event detection)
  base_offset=$(( (${#EVENT_IDS[@]} - idx) * 43200 ))

  for action_idx in $(seq 0 $((${#sequences[@]} - 1))); do
    action="${sequences[$action_idx]}"

    # Each action happens some time after the previous one
    action_offset=$(( base_offset - (action_idx + 1) * 300 - RANDOM % 600 ))
    if [ $action_offset -lt 0 ]; then
      action_offset=0
    fi
    action_timestamp=$(timestamp_offset $action_offset)

    session_id="SESSION-SYNTH-$(printf '%04d' $((idx * 10 + action_idx)))"
    source="${SOURCES[$((action_idx % ${#SOURCES[@]}))]}"

    payload=$(cat <<EOF
{
  "securityEventId": $event_id,
  "developerId": $dev_id,
  "action": "$action",
  "actionTimestamp": "$action_timestamp",
  "sessionId": "$session_id",
  "source": "$source",
  "metadata": "{\"generator\": \"synthetic-test-data\", \"eventIndex\": $idx, \"actionIndex\": $action_idx}"
}
EOF
)

    response=$(post "$API/developer-interactions" "$payload" 2>&1) || {
      echo -e "  ${RED}✗${NC} Event $event_id: $action failed"
      error_count=$((error_count + 1))
      continue
    }
    log_id=$(get_id "$response")
    echo -e "  ${GREEN}✓${NC} Event $event_id: ${CYAN}$action${NC} by dev $dev_id (log id: $log_id, session: $session_id)"
    action_count=$((action_count + 1))
  done
done

echo ""
echo -e "  Generated ${GREEN}$action_count${NC} behaviour actions ($error_count errors)"
echo ""

# ── Step 4: Verification ───────────────────────────────────────────────────

echo -e "${YELLOW}Step 4: Verifying data...${NC}"
echo ""

# Count records
for dev_id in "${DEV_IDS[@]}"; do
  interactions=$(curl -sf "$API/developer-interactions/developer/$dev_id" 2>/dev/null)
  count=$(echo "$interactions" | grep -o '"id":' | wc -l | tr -d ' ')
  events=$(curl -sf "$API/security-events/developer/$dev_id" 2>/dev/null)
  event_count=$(echo "$events" | grep -o '"id":' | wc -l | tr -d ' ')
  echo -e "  Developer $dev_id: ${GREEN}$event_count${NC} security events, ${GREEN}$count${NC} behaviour logs"
done

echo ""

# Test behaviour summary endpoint
echo -e "  Testing behaviour summary for developer ${DEV_IDS[0]}..."
summary=$(curl -sf "$API/developer-behaviour/${DEV_IDS[0]}" 2>/dev/null) || {
  echo -e "  ${RED}✗${NC} Behaviour summary endpoint failed"
  summary=""
}
if [ -n "$summary" ]; then
  classification=$(echo "$summary" | grep -o '"behaviourClassification":"[^"]*"' | cut -d'"' -f4)
  total_events=$(echo "$summary" | grep -o '"totalSecurityEvents":[0-9]*' | grep -o '[0-9]*')
  fix_rate=$(echo "$summary" | grep -o '"fixRate":[0-9.]*' | grep -o '[0-9.]*')
  echo -e "  ${GREEN}✓${NC} Classification: ${CYAN}$classification${NC}, Events: $total_events, Fix rate: ${fix_rate}%"
fi

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Synthetic test data generation complete!${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${YELLOW}NOTE: This is SYNTHETIC TEST DATA for development/testing only.${NC}"
echo -e "  ${YELLOW}It is NOT real research data.${NC}"
echo ""
echo -e "  Useful verification commands:"
echo -e "    curl $API/developers"
echo -e "    curl $API/security-events"
echo -e "    curl $API/developer-interactions"
echo -e "    curl $API/behaviour-logs"
echo -e "    curl $API/developer-behaviour/{developerId}"
echo ""
echo -e "  Database verification (psql):"
echo -e "    psql -d developer_behavior -c 'SELECT COUNT(*) FROM behaviour_logs;'"
echo -e "    psql -d developer_behavior -c 'SELECT action_type, COUNT(*) FROM behaviour_logs GROUP BY action_type;'"
echo -e "    psql -d developer_behavior -c 'SELECT d.developer_identifier, COUNT(bl.id) FROM developers d LEFT JOIN behaviour_logs bl ON d.id = bl.developer_id GROUP BY d.developer_identifier;'"
echo ""
