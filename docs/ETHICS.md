# Ethics & Legal Use — Class Honeypot

This project is a **defensive telemetry honeypot** for university coursework. It is **not** an attack toolkit.

## Allowed

- Deploy only on systems **you own**, or that your **instructor / lab staff explicitly approve**.
- Collect attacker interactions against **your** honeypot for analysis and class reports.
- Share **anonymized / aggregated** findings with your class as required by the assignment.
- Store downloaded samples in a quarantine volume for static review — **never execute** them on a general-purpose machine.

## Forbidden

- Do **not** deploy this on someone else’s network, cloud account, or campus hosts without written approval.
- Do **not** use this stack (or its logs) to attack, scan, phish, or harass third parties.
- Do **not** run captured binaries, scripts, or archives from `downloads/`.
- Do **not** publish raw logs that contain personal data beyond what your instructor requires; follow campus IR / privacy guidance.

## Safety defaults in this repo

- Published host ports default to **2222 (SSH)** and **2223 (Telnet)**, not 22/23.
- No exploit PoCs, malware runners, or offensive playbooks are included.
- Downloads are written to disk only; the compose stack does not execute them.

## If something goes wrong

Stop the stack (`docker compose down`), preserve logs for your instructor, and escalate through your course’s incident process. Do not “hunt back” at source IPs.

## Acknowledgement

By deploying this repo you confirm you have authorization for the target host and will use it only for defensive coursework.
