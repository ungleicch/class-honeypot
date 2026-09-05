# Class Honeypot (Cowrie)

Deployable **Cowrie** SSH/Telnet medium-interaction honeypot for Tom’s university cybersecurity class. Docker Compose stack you can put on a **lab VM / VPS you own or that an instructor approved**, collect attacker telemetry, and write a report.

> **Ethics first:** only on owned/approved systems. No attacking others. See [docs/ETHICS.md](docs/ETHICS.md).

## What you get

| Piece | Role |
| --- | --- |
| `docker-compose.yml` | Pinned `cowrie/cowrie:3.0.13` stack |
| `cowrie/etc/cowrie.cfg` | JSON logging, download capture, SSH/Telnet listen ports |
| `scripts/analyze_logs.py` | Stdlib parser → markdown summary |
| `scripts/enrich_ips.py` | Optional soft geo/ISP enrichment (fail-soft, rate-limited) |
| `sample-output/` | Fake sample log + summary for README / screenshots |
| `docs/ETHICS.md` | Deployment rules for class |

## Telemetry collected

Cowrie is configured to maximize **defensive** class telemetry:

- Source IP, source port, timestamp
- SSH client version / banner
- Username / password attempts (success & failure)
- Interactive session commands
- Downloaded files → quarantine volume (**never execute**)
- Session connect/close (duration / success signals in JSON)

Logs land at:

```text
cowrie/var/log/cowrie/cowrie.json   # primary (JSON lines)
cowrie/var/log/cowrie/cowrie.log    # text log
cowrie/var/lib/cowrie/downloads/   # captured payloads (quarantine)
```

## Ports (class-safe defaults)

| Host port | Container | Service |
| ---: | ---: | --- |
| **2222** | 2222 | SSH honeypot |
| **2223** | 2223 | Telnet honeypot |

**Why not 22?** Binding host port 22 needs root (or a privileged redirect) and can collide with a real SSH daemon. For class labs, keep **2222** and document that attackers hitting 22 won’t reach you unless you redirect.

### Optional: redirect real 22 → 2222 (advanced)

Only on a dedicated honeypot host, with instructor approval, and after moving real admin SSH elsewhere:

```bash
# nftables example (review before use; needs root)
sudo nft add table ip nat
sudo nft 'add chain ip nat PREROUTING { type nat hook prerouting priority -100; }'
sudo nft add rule ip nat PREROUTING tcp dport 22 redirect to 2222

# iptables equivalent idea:
# sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

Same idea for 23 → 2223 if you enable public Telnet exposure. Prefer cloud security-group / firewall allowlists limited to what the assignment needs.

## Quick start

### Requirements

- Docker Engine + Docker Compose v2
- Linux lab VM / VPS (or local Docker Desktop)
- Authorization to expose the chosen ports

### Deploy

```bash
cd /path/to/class-honeypot
cp .env.example .env          # edit ports/hostname if needed
mkdir -p cowrie/var/log/cowrie cowrie/var/lib/cowrie/downloads

# Ensure the container user can write logs/downloads (UID often 1000; try 999 if needed)
sudo chown -R 1000:1000 cowrie/var

docker compose pull
docker compose up -d
docker compose ps
docker compose logs -f --tail=50
```

Validate compose file locally:

```bash
docker compose config
```

### Smoke-test from another host (or localhost)

```bash
ssh -p 2222 root@YOUR_HOST_IP
# try a few passwords; Cowrie will fake a shell on success
```

Do **not** point scanners at networks you don’t own.

### Analyze

```bash
# Against live logs (after traffic arrives)
python3 scripts/analyze_logs.py | tee report.md

# Against the included fake sample
python3 scripts/analyze_logs.py --log sample-output/cowrie.json.sample

# Optional enrichment (needs outbound HTTP; fails soft)
python3 scripts/enrich_ips.py --log cowrie/var/log/cowrie/cowrie.json
```

`analyze_logs.py` is **stdlib-only** (Python 3.9+). No `pip install` required.

### Stop / wipe runtime data

```bash
docker compose down
# optional: delete captured logs/downloads (keep .gitkeep)
rm -f cowrie/var/log/cowrie/cowrie.json cowrie/var/log/cowrie/cowrie.log
rm -rf cowrie/var/lib/cowrie/downloads/*
```

## Image pin

This repo pins:

```text
cowrie/cowrie:3.0.13
```

Verified on Docker Hub (tag `3.0.13`, also published as `3.0` / `latest` at the same digest when this lab was built). To re-pin later:

```bash
curl -s 'https://hub.docker.com/v2/repositories/cowrie/cowrie/tags?page_size=20' \
  | python3 -c "import sys,json; print('\n'.join(t['name'] for t in json.load(sys.stdin)['results']))"
```

Then edit `image:` in `docker-compose.yml`.

## Repo layout

```text
class-honeypot/
  README.md
  docker-compose.yml
  .env.example
  .gitignore
  docs/ETHICS.md
  cowrie/etc/cowrie.cfg          # telemetry overrides
  cowrie/var/log/cowrie/         # JSON logs (runtime)
  cowrie/var/lib/cowrie/downloads/
  scripts/analyze_logs.py
  scripts/enrich_ips.py
  sample-output/                 # fake sample for class screenshots
```

## Class report tips

1. Run for an agreed window (e.g. 24–72h) on an approved host.
2. Export `cowrie.json` and run `analyze_logs.py`.
3. Discuss top credentials, commands, client banners, and download hashes — **not** how to weaponize them.
4. Note limitations: medium-interaction SSH/Telnet only; skilled attackers may fingerprint Cowrie.
5. Cite ethics constraints and where the stack was authorized to run.

## Forbidden in this project

- No exploit PoCs, malware runners, or “how to attack” content
- No executing files from `downloads/`
- No scanning / probing third-party networks

## License / course use

Built for coursework. Cowrie itself is upstream open source ([cowrie/cowrie](https://github.com/cowrie/cowrie)); follow its license for the image. This wrapper is for defensive classroom telemetry only.
