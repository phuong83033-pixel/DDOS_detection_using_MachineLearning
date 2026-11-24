# DDoS Detection Lab: how to run it

Topic 10, *Detecting DDoS Attacks Using Machine Learning*. A small web server is attacked
by 20 bot containers while 6 legitimate users keep using it. A detector reads packet headers
in real time, raises an alarm, finds the attackers and blocks them, and the lab measures what
the users experienced before, during and after.

Everything runs in Docker on an isolated network (`internal: true`): no traffic leaves your
computer, and the attack tools only ever point at the lab's own victim container.

---

## 1. One-time setup

You need:

1. **Docker Desktop** (with WSL2 on Windows), installed and **running** (whale icon in the tray, "Engine running").
2. **Python 3.10 or newer**, with these packages:

```powershell
pip install numpy pandas matplotlib scikit-learn==1.7.2 joblib
```

Use scikit-learn 1.7.2 exactly: it is the version the detector container uses, and the trained
model in `detection/models/` must load in both places.

3. This folder. Open PowerShell inside it:

```powershell
cd C:\CS\Information\new
```

The first run builds the Docker images (a few minutes, needs Internet once). Later runs reuse them.

---

## 2a. The quick demo (one command, 60 seconds)

```powershell
./run_demo.ps1
```

Everything starts by itself: the victim, the detector, 6 legitimate users, 20 bots and the viewer.

| Time | What happens |
|---|---|
| 0 - 20 s | Normal traffic. The detector learns what normal looks like. |
| 20 - 40 s | The 20 bots flood the victim. The detector raises the alarm about 5 s later and blocks them. |
| 40 - 60 s | The users carry on; the victim is back to normal. |

Open <http://localhost:8080> while it runs to see the victim's page. At the end the results are saved
in `output/runs/demo_<date>` and a summary and chart are printed.

**The victim's page is a small live status page.** It shows ONLINE / SLOW / DOWN, the response time, the full-page load time,
the open connections and the requests per second (two charts of the last 60 s), and a log of every state change.
All numbers are measured by your browser; nothing needs to be started. At the 20 s mark you will see it turn
DOWN or SLOW and the requests per second jump to about 1,000, then return to ONLINE when the bots are blocked.
(If you still see the old wall of words, press Ctrl+F5 once.) The page body is padded to exactly the same
64 KB as before, so the traffic the model was trained on is unchanged; keep that size if you edit `sources/victim/index.html`.

The same demo without the script: open a terminal in `sources/docker` and run `docker compose up -d --build`
(Compose loads `docker-compose.override.yml` there, which adds the automatic start and the 20 s + 20 s timeline).
Watch with `docker compose logs -f detector`, and stop with `docker compose down`.

The demo looks at the traffic in 2.5-second windows. The detector learns the baseline in the first 15 s, and it raises the alarm
only after 2 suspicious windows in a row (`CONFIRM_WINDOWS=2`), which is 5 s after the attack starts; then it blocks the bots every 2.5 s.
Waiting for a second window also protects against one-off spikes. You can change it: `$env:CONFIRM_WINDOWS = "3"` before
`./run_demo.ps1` (or `WINDOW` for the window length). The long scenarios below use 5-second windows and raise the alarm at once.

## 2. Run a scenario

Each command runs one complete experiment and ends with a printed summary and a chart.

```powershell
./run_lab.ps1 -Attack http     # 20 bots send real HTTP requests
./run_lab.ps1 -Attack udp      # 20 bots send UDP datagrams
./run_lab.ps1 -Attack flash    # NOT an attack: the legitimate users send 4x the requests
./run_lab.ps1 -Attack none     # nothing happens: checks that the detector stays quiet
```

**Seeing the victim's web page.** Add `-View` (Linux/macOS: `VIEW=1 ./run_lab.sh http`) and open
<http://localhost:8080> while the run is going. A small proxy forwards your browser to the victim, so you
see the page load normally, slow down or time out during the attack, and come back once the detector blocks the bots.
The proxy is only reachable from your own machine, and it is the only part of the lab that touches a normal network.

```powershell
./run_lab.ps1 -Attack http -View
```

If PowerShell refuses to run the script, use:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_lab.ps1 -Attack http
```

**How long it takes:** about 4.5 minutes per run (60 s normal traffic, 120 s attack, 40 s to recover) plus about 1 minute of start-up and shutdown. Do not close the window while it runs.

**The red text is normal.** Docker prints its progress to the error stream, which PowerShell shows in red. It does not mean something failed. A real failure stops the script with a message such as `compose build failed`.

### Useful options

| Option | Meaning |
|---|---|
| `-NoDefense` | detect only: the detector records what it *would* block but blocks nothing (shows the full damage of the attack) |
| `-Mode entropy` | use the entropy + K-means detector only (no machine learning) |
| `-Mode ml` | require the trained model (stops with an error if it is missing); the default `auto` uses it when `detection/models/ddos_model.joblib` exists |
| `-Bots 10` / `-Clients 4` | number of attacker / legitimate-user containers |
| `-Baseline 60 -AttackSeconds 120 -Tail 40` | lengths of the three phases in seconds |
| `-NoAnalyze` | skip the chart and summary |
| `-Record` | also save every flow's features as training data (use together with `-NoDefense`) |

Example, a quick 2-minute test: `./run_lab.ps1 -Attack http -Baseline 45 -AttackSeconds 40 -Tail 20`
(the detector needs about 30 s of baseline to learn what normal looks like, so keep the baseline at 45 s or more).

On Linux or macOS use `./run_lab.sh http` (settings are environment variables, see the top of the script).

---

## 3. Read the results

Every run is saved in its own folder, `output/runs/<scenario>_<date>-<time>/`. Open:

* **`ddos_analysis.png`**: the chart. Four panels share one time axis: client success rate and latency, packets per second, source entropy with the alarm, and SYN signals with the number of blocked addresses. Red shading is the attack; the vertical lines mark the alarm and the start of the defense.
* **`summary.txt`**: the numbers (also printed at the end of the run):

| Line | Meaning |
|---|---|
| Detection delay | seconds from the first attack packet to the alarm |
| Time to defense | seconds until the first address was blocked |
| Client recovery | seconds until real users were back above 90% success |
| Client success, 4 phases | what real users experienced: baseline, attack before the defense, attack with the defense, after |
| Blocked sources, precision / recall | of the addresses blocked, how many really were bots / how many bots were caught |
| Legitimate clients blocked | must be `none` |
| Window-level detection | precision, recall, F1, false-positive rate and MCC of the detector, next to a plain "packets per second" threshold |
| Capture | packets the kernel saw and how many the detector missed |

Other files in the folder: `events.csv` (the shared timeline: attack start, alarm, every block), `detector_windows.csv` (one row per 5-second window), `client_*.csv` (every request of every user), `detector.log`, `summary.json`.

### What good results look like (reference runs, ML mode)

| Scenario | Alarm | Bots blocked | Clients blocked | Client success |
|---|---|---|---|---|
| `http` | 5 s | 20 of 20 | 0 | 47% during the attack, 99% once blocked (recovered in 5 s) |
| `udp` | 5 s | 20 of 20 | 0 | 100% always (see limits below) |
| `flash` | no alarm | 0 | 0 | 100% (a packet-rate threshold would false-alarm in 12 of 19 windows) |
| `none` | no alarm | 0 | 0 | 100% |

---

## 4. The model

The detector has two layers. Layer 1 raises the alarm from window statistics (packet rate, source entropy, number of distinct sources, SYN/ACK ratio): the alarm needs a rate surge **and** a change in who is sending, so a flash crowd does not trigger it. Layer 2 finds the attackers: the trained Random Forest classifies each flow and a source is blocked after 3 attack flows, or, without a model, K-means plus the entropy-ratio test from the midterm report.

The trained model is already in `detection/models/`. To **retrain** it:

```powershell
# 1. record training flows from the lab (detection only, nothing blocked); repeat for udp, flash
./run_lab.ps1 -Attack http -NoDefense -Record -NoAnalyze
./run_lab.ps1 -Attack udp  -NoDefense -Record -NoAnalyze
./run_lab.ps1 -Attack flash -NoDefense -Record -NoAnalyze

# 2. train on CIC-IDS-2017 + the recorded runs (takes about 3 minutes)
python detection/train_model.py
```

This writes `detection/models/ddos_model.joblib` and `detection/models/evaluation.txt`. The evaluation reports three tests: the dataset with whole blocks held out, each lab run held out in turn, and a dataset-only model tested on the lab.

To check the feature extractor: `python detection/test_extractor.py` (31 checks, must all pass).

The dataset file is expected at `detection/data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` (CIC-IDS-2017, already there). `python detection/check_dataset.py` confirms it is complete.

---

## 5. If something goes wrong

| Problem | What to do |
|---|---|
| `failed to connect to the docker API` | Docker Desktop is not running. Start it and wait for "Engine running". |
| The script stops at `compose build failed` | Read the error above it. Usually no Internet on the first run, or Docker is out of disk space. |
| A run was interrupted (Ctrl+C) | Clean up with `docker compose -f sources/docker/docker-compose.yml --profile syn down --remove-orphans`, then run again. |
| `ModuleNotFoundError` in Python | Re-run the `pip install` line from step 1. |
| Warning about the scikit-learn version when the model loads | The packages differ from the detector's. Install `scikit-learn==1.7.2`, or retrain with `python detection/train_model.py`. |
| The detector says mode `ENTROPY` when you expected `ML` | `detection/models/ddos_model.joblib` is missing or failed to load. Check `output/runs/<run>/detector.log`. |
| Everything is slow or the chart shows lost packets | Close heavy programs. The summary line `Capture: ... dropped` tells you how many packets the detector missed. |
| Disk space | Old runs are in `output/runs/` (about 3 MB each); delete the ones you don't need. |

---

## 6. Honest limits (say these when presenting)

* **The SYN flood scenario is not finished.** The `syn_attacker` service and the SYN-cookie defense exist in the code but were never made to work in this lab, so do not demo `-Attack syn`.
* **A model trained only on CIC-IDS-2017 does not work on lab traffic** (it catches 0 of 20 bots): the dataset has no UDP flood and its HTTP flood differs from the lab's `ab` tool. That is why recorded lab flows are part of the training data. The 99.95% F1 on the dataset shows how easy that dataset is, not how well the system works in the real world.
* The lab has 20 bots against a deliberately small server; a real botnet is far larger.
* At this rate the UDP flood is detected and blocked but does not reduce availability: nginx does not listen on UDP.
* The detector's packet capture is written in Python and kept up (0 packets lost) at about 12,000 packets per second.

---

## 7. What is in this folder

```
new/
├── run_demo.ps1                 the 60 s demo, one command, everything automatic
├── run_lab.ps1, run_lab.sh      run one long scenario from start to chart
├── README.md
├── sources/                     everything that makes up the lab
│   ├── docker/                  docker-compose.yml, docker-compose.override.yml (the demo) and the Dockerfiles
│   ├── attacker/                entrypoint_attacker.sh (the bots)
│   ├── victim/                  nginx.conf and index.html (the web server)
│   ├── client/                  client_monitor.py (the legitimate users)
│   └── common/                  labcommon.py (shared start time and event log)
├── detection/                   the detector and the model
│   ├── detector.py, capture.py, flow_extractor.py, ml_layer.py
│   ├── train_model.py, test_extractor.py, check_dataset.py
│   ├── requirements-detector.txt
│   ├── models/                  trained model, evaluation.txt, feature_importance.png
│   └── data/                    CIC-IDS-2017 Friday DDoS file
├── output/                      everything a run produces
│   ├── results/                 the run in progress (overwritten by the next run)
│   ├── runs/                    one folder per finished run: chart, summary, logs
│   └── analyze_results.py       turns a run into a chart and a summary
└── docs/                        Project_Documentation.docx, Upgrade_Plan_DDoS_Lab.docx, topics PDF
```

The Docker images are built from the project root, so they can copy files from `sources/` and
`detection/`. `.dockerignore` keeps `output/`, `docs/`, the dataset and the models out of the build.
