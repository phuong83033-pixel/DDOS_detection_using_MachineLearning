#!/bin/bash
# run_lab.sh - run one full lab scenario: baseline -> attack -> defense -> recovery.
#
#   ./run_lab.sh http [bots] [clients]
#   ./run_lab.sh udp
#   ./run_lab.sh syn
#   ./run_lab.sh none        # baseline only: checks for false alarms
#   ./run_lab.sh flash       # flash crowd: legitimate users, 4x the requests
#   NODEFENSE=1 ./run_lab.sh http   # detection only (nothing is blocked)
#   NODEFENSE=1 RECORD=1 ./run_lab.sh http   # also save flow features as training data
#   MODE=entropy|ml ./run_lab.sh http         # force the detector mode
#   VIEW=1 ./run_lab.sh http                  # also start the viewer: http://localhost:8080 shows the victim page
#
# BASELINE, ATTACK and TAIL (seconds) can be set in the environment.
# Results go to output/results (current run) and output/runs (one folder per run).
set -eu
cd "$(dirname "${BASH_SOURCE[0]}")"
export COMPOSE_FILE=sources/docker/docker-compose.yml   # every "docker compose" below uses this file

ATTACK_KIND=${1:-http}
BOTS=${2:-20}
CLIENTS=${3:-6}
BASELINE=${BASELINE:-60}
ATTACK=${ATTACK:-120}
TAIL=${TAIL:-40}
TOTAL=$((BASELINE + ATTACK + TAIL))
export BASELINE ATTACK TOTAL
export DETECTOR_MODE=${MODE:-auto}
export RECORD_FLOWS=${RECORD:-0}
[ "${RECORD:-0}" = "1" ] && export DETECTOR_MODE=entropy || true
export DEFENSE=$([ "${NODEFENSE:-0}" = "1" ] && echo 0 || echo 1)
export FLASH_MULT=$([ "$ATTACK_KIND" = "flash" ] && echo 4 || echo 1)
case "$ATTACK_KIND" in http|udp) export ATTACK_TYPE=$ATTACK_KIND ;; *) export ATTACK_TYPE=http ;; esac

echo "=== Scenario: $ATTACK_KIND  bots=$BOTS  clients=$CLIENTS  timeline=${BASELINE}s + ${ATTACK}s + ${TAIL}s ==="

docker compose --profile syn --profile view down --remove-orphans >/dev/null 2>&1 || true
find output/results -mindepth 1 ! -name .gitkeep -delete 2>/dev/null || true
echo "ts,source,event,detail" > output/results/events.csv

docker compose --profile syn build --quiet
docker compose up -d --wait victim
docker compose exec -T victim sh -c 'echo $(( $(date +%s) + 15 )) > /results/t0'
echo "{\"attack\": \"$ATTACK_KIND\", \"baseline\": $BASELINE, \"attack_seconds\": $ATTACK, \"total\": $TOTAL}" > output/results/timeline.json
echo "--- T0 = $(cat output/results/t0), run lasts ${TOTAL}s"

SERVICES="detector client"
SCALE="--scale client=$CLIENTS"
PROFILE=""
if [ "$ATTACK_KIND" = "http" ] || [ "$ATTACK_KIND" = "udp" ]; then
    SERVICES="$SERVICES bot"; SCALE="$SCALE --scale bot=$BOTS"
elif [ "$ATTACK_KIND" = "syn" ]; then
    SERVICES="$SERVICES syn_attacker"; PROFILE="--profile syn"
fi
# shellcheck disable=SC2086
[ "${VIEW:-0}" = "1" ] && { SERVICES="$SERVICES viewer"; PROFILE="$PROFILE --profile view"; echo "--- viewer: open http://localhost:8080"; }
docker compose $PROFILE up -d $SCALE $SERVICES

sleep $((TOTAL + 30))

docker compose logs --no-color detector > output/results/detector.log 2>&1 || true
docker compose logs --no-color client > output/results/client.log 2>&1 || true
docker compose --profile syn --profile view down --remove-orphans >/dev/null 2>&1 || true

RUN_DIR="output/runs/${ATTACK_KIND}$([ "$DEFENSE" = 0 ] && echo -nodefense)_$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RUN_DIR"
cp -r output/results/. "$RUN_DIR"/
rm -f "$RUN_DIR/.gitkeep"
echo "--- saved to $RUN_DIR"
python3 output/analyze_results.py "$RUN_DIR" --attack "$ATTACK_KIND"
