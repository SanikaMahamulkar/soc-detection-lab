# SOC Detection Engineering Lab

A hands-on blue-team project: deploying a working SIEM (Wazuh), generating and detecting real attacker behaviour (Atomic Red Team, MITRE ATT&CK-mapped), writing custom detection rules, and producing incident response runbooks.

This project complements [aws-cloud-security-baseline](https://github.com/SanikaMahamulkar/aws-cloud-security-baseline) — that project built cloud-native infrastructure and detection; this one focuses on the analyst/detection-engineering side: log analysis, rule tuning, and structured incident response.

## Status: In Progress

## Tech stack

- **SIEM:** Wazuh 4.9.2 (manager, indexer, dashboard) — deployed via Docker Compose
- **Target/victim host:** Ubuntu 22.04 container, running the Wazuh agent
- **Attack simulation:** Atomic Red Team (planned)
- **Detection rules:** Custom Wazuh rules, informed by Sigma rule concepts (planned)

## Architecture

- `wazuh/` — Wazuh Docker Compose stack (manager, indexer, dashboard) and configuration
- SSL certificates are generated locally via Wazuh's official certs generator and are gitignored (regenerable, never committed)
- A separate Ubuntu container (`soc-target`) runs the Wazuh agent and acts as the monitored/attacked endpoint

## Progress log

- [x] Wazuh SIEM deployed via Docker Compose (manager, indexer, dashboard) — all three services healthy
- [x] SSL certificates generated for internal service communication
- [x] Target container (Ubuntu 22.04) provisioned and connected to the Wazuh Docker network
- [x] Wazuh agent installed and registered on the target (agent name: `soc-target-01`)
- [x] Agent confirmed active and reporting in the Wazuh dashboard
- [x] Baseline activity generation and verification of log ingestion — 382 alerts confirmed indexed via direct Wazuh indexer API query, full pipeline (agent → manager → indexer → dashboard) validated end-to-end
- [ ] Atomic Red Team attack simulation (MITRE ATT&CK mapped)
- [x] Custom detection rule authoring and tuning — 4 MITRE ATT&CK-mapped FIM rules written and tested (see wazuh-rules/local_rules.xml, detection-notes.md)
- [ ] False-positive rate documentation
- [ ] Incident response runbooks (3+ scenarios)
- [ ] Full project report

## Known Issues / Notes

- Wazuh does not yet publish native `arm64` Docker images for the manager/indexer/dashboard; these run under emulation on Apple Silicon, which works correctly but is slower to start than on `amd64` hosts.
- The Wazuh agent `.deb` package's `lsb-release` dependency did not resolve cleanly via `apt-get install -y -qq` on a minimal Ubuntu base image; running `apt --fix-broken install` resolved the full dependency chain (`python3`, `distro-info-data`, `lsb-release`) and allowed the agent package to finish configuring.
- Dashboard default credentials (`admin` / `SecretPassword`) are Wazuh's published demo defaults, used here for a local lab. These would be rotated before any shared or production-like deployment.

## Author

Sanika Mahamulkar — MSc Cybersecurity, University of Bristol
