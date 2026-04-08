# AIVPN Admin Web

`aivpn-admin-web` is a minimal server-side web UI that manages clients by running `aivpn-admin --json`. It does not import or expose the VPN gateway internals.

Default bind is `127.0.0.1:27449`. Use `AIVPN_ADMIN_TOKEN` or `--token` to require a bearer token:

```bash
cargo run -p aivpn-admin-web -- \
  --clients-db ./config/clients.json \
  --key-file ./config/server.key \
  --server-ip 203.0.113.10:443 \
  --token change-me
```

API examples:

```bash
curl -H 'Authorization: Bearer change-me' http://127.0.0.1:27449/api/clients
curl -X POST -H 'Authorization: Bearer change-me' -H 'Content-Type: application/json' \
  --data '{"name":"phone"}' http://127.0.0.1:27449/api/clients
```

Docker Compose publishes the UI on host port `27449` by default:

```bash
AIVPN_ADMIN_TOKEN=change-me AIVPN_SERVER_IP=203.0.113.10:443 docker compose up -d aivpn-admin-web
```

The current UI supports list, add, show connection key, rename, enable, disable, remove, and a Grafana link. QR code rendering is still a follow-up.
