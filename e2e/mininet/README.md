# Mininet (optional)

Mininet is **not** wired into the default e2e scripts. It is useful when you need:

- Many emulated hosts behind a **software switch**
- **TCLink** delay/loss between nodes
- Flows that do not map 1:1 to “one Docker container per host”

## Constraints

- Best supported on **Linux** with **`CAP_NET_ADMIN`** (often **`--privileged`** in Docker).
- Your **scanner** must have **IP connectivity** into Mininet’s subnet (NAT, Linux bridge to the host, or running nmap **inside** the Mininet root namespace).

## Suggested workflow

1. Install Mininet on a Linux VM or use a privileged container image that includes Mininet + Python.
2. Start a topology (e.g. linear: `h1 ... hN` + one switch), assign `10.0.0.0/8` (or a smaller RFC1918 block), start `python3 -m http.server 80` on each host in the background (`host.cmd('... &')`).
3. From a machine that can route to those IPs, run:

   ```bash
   python -m network_scanner 10.0.0.0/24 ...
   ```

4. Point **`OLLAMA_HOST`** at your real Ollama service, or run a **mock** server reachable from that same host.

For a single-machine loopback-style lab, **Docker Compose scaling** (`e2e/docker-compose.yml`) is usually simpler and is what this repo tests first.
