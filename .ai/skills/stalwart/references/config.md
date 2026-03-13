# Stalwart Configuration

Configuration file: `stalwart/config.toml` (mounted read-only at `/opt/stalwart/etc/config.toml`)

## Key Settings

- **Data storage**: SQLite in `/opt/stalwart/data` (host: `./stalwart-data/`)
- **HTTP listener**: Port 8080 (mapped to host 8443)
- **Admin credentials**: `admin` / `secret` (set via `ADMIN_SECRET` env var)
- **OAuth2**: Built-in OAuth2 authorization server

## Endpoints

| Endpoint                                          | Purpose                        |
|---------------------------------------------------|--------------------------------|
| `http://localhost:8443/.well-known/jmap`           | JMAP session discovery         |
| `http://localhost:8443/`                           | Web admin UI                   |
| `http://localhost:8443/.well-known/oauth-authorization-server` | OAuth2 discovery    |
| `http://localhost:8443/authorize/code`             | OAuth2 authorization (browser) |
| `http://localhost:8443/auth/device`                | OAuth2 device flow             |
