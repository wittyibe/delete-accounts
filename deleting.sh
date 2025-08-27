#!/bin/bash
#
# superb-checker-deletions.sh
# Purpose: Infer deletion/closure of accounts on Bumble, Tinder, POF, AshleyMadison, Match
# Methods:
#   - Password reset vs. signup contradiction
#   - Optional direct profile URL checks + Wayback last-seen snapshot date
#   - Keyword heuristics in responses
#
# Inputs:
#   - targets.csv with columns:
#       type,value,username,profile_url
#     Where "type" ∈ {email, phone, username}
#     Example:
#       email,prcsmama@gmail.com,,https://www.pof.com/viewprofile?user=prcsmama
#       email,lcummings73@outlook.com,,
#
# Outputs:
#   - logs/*.log (raw responses & debug)
#   - results/deletion_results.csv
#
# Notes:
#   - For Wayback checks, we query: https://web.archive.org/wayback/available?url=<profile_url>
#   - If you have known profile URLs, include them in targets.csv for much stronger signals.
#

set -euo pipefail

mkdir -p logs results

CSV_OUT="results/deletion_results.csv"
echo "Platform,Type,Value,Deletion_Status,Confidence,Reason,Evidence_URL,Wayback_LastSeen,HTTP_Code,Timestamp" > "$CSV_OUT"

ts() { date '+%Y-%m-%d %H:%M:%S'; }

# --- Utility: print+tee to log ---
log() {
  local msg="$1"
  echo "[$(ts)] $msg"
}

# --- Utility: safe curl with standard browser-ish headers ---
hcurl() {
  # $1: output_file  $2...: curl args
  local out="$1"; shift
  curl -sSL -D /tmp/headers.$$ -o "$out" \
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126 Safari/537.36" \
    -H "Accept: text/html,application/json;q=0.9,*/*;q=0.8" \
    -H "Accept-Language: en-US,en;q=0.9" \
    "$@" ; echo $? >/tmp/exitcode.$$
}

http_code_from_headers() {
  # parse saved headers
  awk 'toupper($1)=="HTTP/"{code=$2} END{print code}' /tmp/headers.$$
}

# --- Wayback last-seen snapshot for a URL (if present) ---
wayback_lastseen() {
  # Return ISO date of last snapshot if any, else blank
  local url="$1"
  [[ -z "$url" ]] && { echo ""; return; }
  local wb_json="/tmp/wb.$$.json"
  curl -sS "https://web.archive.org/wayback/available?url=$(python3 - <<PY
import urllib.parse,sys
print(urllib.parse.quote(sys.argv[1]))
PY
"$url")" > "$wb_json" || true

# crude parse without jq:
# Look for "timestamp":"YYYYMMDDhhmmss"
local ts_line
ts_line=$(grep -o '"timestamp":"[0-9]\{14\}"' "$wb_json" | head -n1 || true)

echo "AshleyMadison,$type,$value,$deletion,$conf,$reason,$evidence_url,$wb_last,$code_reset,$(ts)" >> "$CSV_OUT"
cat "$reset_body" >> "logs/${base}.log" 2>/dev/null || true
echo -e "\n--- SIGNUP RESPONSE ---\n" >> "logs/${base}.log"
cat "$signup_body" >> "logs/${base}.log" 2>/dev/null || true
}

# ---------- BUMBLE ----------
bumble_check_deletion() {
  local type="$1" value="$2" prof_url="$3"
  local base="bumble_$(echo "$value" | tr -c 'A-Za-z0-9' '_')"
  local reset_body="/tmp/${base}_reset.html"
  local signup_body="/tmp/${base}_signup.html"

  # Password reset (email-based)
  hcurl "$reset_body" -X POST "https://bumble.com/api/v1/users/password-reset" \
    -H "Content-Type: application/json" \
    --data "{\"email\":\"$value\"}"
  local code_reset=$(http_code_from_headers)

  # Bumble’s sign-up tends to be phone-based / app flow; use a placeholder probe endpoint:
  hcurl "$signup_body" -X POST "https://bumble.com/api/v1/users" \
    -H "Content-Type: application/json" \
    --data "{\"email\":\"$value\",\"password\":\"fakePassw0rd!\"}"
  local code_signup=$(http_code_from_headers)

  local used_hint=$(egrep -i 'already in use|exists|registered' "$signup_body" || true)
local deletion="UNKNOWN" conf="low" reason="Insufficient signals"
if [[ "$code_reset" == "200" && -z "$used_hint" ]]; then
    deletion="POSSIBLY_DELETED"; conf="low"; reason="Reset accepted; signup did not block email (weak due to app flow)."
elif [[ "$code_reset" != "200" && -z "$used_hint" ]]; then
    deletion="NOT_FOUND_OR_LONG_AGO_DELETED"; conf="low"; reason="Reset rejected; signup gave no in-use hint."
elif [[ "$code_reset" == "200" && -n "$used_hint" ]]; then
    deletion="ACTIVE_OR_NOT_DELETED"; conf="low"; reason="Reset accepted; signup suggests in use (weak signal)."
fi

  local wb_last=""; local evidence_url=""
  if [[ -n "$prof_url" ]]; then
    hcurl /tmp/bumble_prof.$$ -I "$prof_url"
    local prof_code=$(http_code_from_headers)
    evidence_url="$prof_url"
    if [[ "$prof_code" == "404" || "$prof_code" == "410" ]]; then
      wb_last=$(wayback_lastseen "$prof_url")
      if [[ -n "$wb_last" ]]; then
        deletion="LIKELY_DELETED"; conf="high"; reason="Profile URL gone; last seen in Wayback."
      else
        deletion="LIKELY_DELETED"; conf="medium"; reason="Profile URL returns $prof_code."
      fi
    fi
  fi

  echo "Bumble,$type,$value,$deletion,$conf,$reason,$evidence_url,$wb_last,$code_reset,$(ts)" >> "$CSV_OUT"
  cat "$reset_body" >> "logs/${base}.log" 2>/dev/null || true
  echo -e "\n--- SIGNUP RESPONSE ---\n" >> "logs/${base}.log"
  cat "$signup_body" >> "logs/${base}.log" 2>/dev/null || true
}

# ---------- TINDER ----------
tinder_check_deletion() {
  local type="$1" value="$2" prof_url="$3"
  local base="tinder_$(echo "$value" | tr -c 'A-Za-z0-9' '_')"
  local reset_body="/tmp/${base}_reset.html"
  local signup_body="/tmp/${base}_signup.html"

  hcurl "$reset_body" -X POST "https://api.gotinder.com/v2/auth/reset_password" \
    -H "Content-Type: application/json" \
    --data "{\"email\":\"$value\"}"
  local code_reset=$(http_code_from_headers)

  # Tinder signup is app-driven; we probe a generic web entry point for contradiction hints
  hcurl "$signup_body" -X POST "https://api.gotinder.com/v2/auth/register" \
    -H "Content-Type: application/json" \
    --data "{\"email\":\"$value\",\"password\":\"fakePassw0rd!\"}"
  local code_signup=$(http_code_from_headers)

  local used_hint=$(egrep -i 'already in use|exists|registered' "$signup_body" || true)

  local deletion="UNKNOWN" conf="low" reason="Insufficient signals"
  if [[ "$code_reset" == "200" && -z "$used_hint" ]]; then
    deletion="POSSIBLY_DELETED"; conf="low"; reason="Reset accepted; signup didn’t flag email (weak web signal)."
  elif [[ "$code_reset" != "200" && -z "$used_hint" ]]; then
    deletion="NOT_FOUND_OR_LONG_AGO_DELETED"; conf="low"; reason="Reset rejected; signup gave no in-use hint."
  elif [[ "$code_reset" == "200" && -n "$used_hint" ]]; then
    deletion="ACTIVE_OR_NOT_DELETED"; conf="low"; reason="Reset accepted; signup hints in-use."
  fi

  local wb_last=""; local evidence_url=""
  if [[ -n "$prof_url" ]]; then
    hcurl /tmp/tinder_prof.$$ -I "$prof_url"
    local prof_code=$(http_code_from_headers)
    evidence_url="$prof_url"
    if [[ "$prof_code" == "404" || "$prof_code" == "410" ]]; then
      wb_last=$(wayback_lastseen "$prof_url")
      if [[ -n "$wb_last" ]]; then
        deletion="LIKELY_DELETED"; conf="high"; reason="Profile URL gone; last seen in Wayback."
      else
        deletion="LIKELY_DELETED"; conf="medium"; reason="Profile URL returns $prof_code."
  fi

  echo "Tinder,$type,$value,$deletion,$conf,$reason,$evidence_url,$wb_last,$code_reset,$(ts)" >> "$CSV_OUT"
  cat "$reset_body" >> "logs/${base}.log" 2>/dev/null || true
  echo -e "\n--- SIGNUP RESPONSE ---\n" >> "logs/${base}.log"
  cat "$signup_body" >> "logs/${base}.log" 2>/dev/null || true

# ==============================
# DRIVER
# ==============================

if [[ ! -f "targets.csv" ]]; then
  cat <<'EOF'
[!] Missing targets.csv
Create targets.csv with:
type,value,username,profile_url
email,prcsmama@gmail.com,prcsmama,https://www.pof.com/viewprofile?user=prcsmama
email,lcummings73@outlook.com,,
phone,9092408360,,
EOF
  exit 1
fi

while IFS=, read -r type value username profile_url; do
    [[ "$type" == "type" ]] && continue # skip header
    [[ -z "$type" || -z "$value" ]] && continue
    
    # Normalize whitespace
    type="$(echo "$type" | xargs)"
    value="$(echo "$value" | xargs)"
    username="$(echo "$username" | xargs)"
    profile_url="$(echo "$profile_url" | xargs)"
    
#!/bin/bash
# deleting.sh
# Runs deletion/account checks across multiple platforms.

# Run each platform check (Bumble, Tinder, POF, AshleyMadison, Match)
while IFS=',' read -r type value profile_url; do
    bumble_check_deletion "$type" "$value" "$profile_url"
    tinder_check_deletion "$type" "$value" "$profile_url"
    pof_check_deletion "$type" "$value" "$profile_url"
    am_check_deletion "$type" "$value" "$profile_url"
    match_check_deletion "$type" "$value" "$profile_url"
done < targets.csv

echo "Complete. See results/deletion_results.csv and logs/ for evidence."
