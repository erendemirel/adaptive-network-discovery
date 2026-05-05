# VPN in the e2e lab (advanced)

A full **site-to-site or remote-access VPN** (WireGuard, OpenVPN, IPsec) is **not** baked into the default compose stack: it needs key material, `CAP_NET_ADMIN` (often **`privileged: true`**), and sometimes **TUN** devices, which varies across Docker Desktop vs Linux.

**Reasonable next steps if you need it:**

1. Add a **WireGuard** image (e.g. `linuxserver/wireguard` or `wg-easy`) on a dedicated compose profile.
2. Attach the **scanner** container (or a **jump** container) as a **WG peer** with routes to `10.10.0.0/24` (or your internal subnet).
3. Run the same `python -m network_scanner` from inside the peer’s network namespace so discovery crosses the tunnel.

Keep the **mock LLM** / **Ollama** services on `e2e_control` only; do not route lab traffic through the model.

For most strategist/nmap integration tests, the **`nat-portfwd` + `internal-web`** pair already gives you **“not directly on the scan subnet”** behavior without VPN complexity.
